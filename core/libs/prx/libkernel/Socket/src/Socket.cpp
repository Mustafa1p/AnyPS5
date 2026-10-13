#include <cstdint>
#include <cstddef>
#include "SceTypes.hpp"
#include "prx/libc/include/General.hpp"
#include "prx/libkernel/File/include/RandomDevice.hpp"
#include "prx/libkernel/Socket/include/SocketPoll.hpp"
#include "prx/libkernel/Socket/include/SocketSelectDeadline.hpp"
#include "prx/libkernel/Socket/include/SocketRuntime.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <thread>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
extern "C" _invalid_parameter_handler _set_thread_local_invalid_parameter_handler(_invalid_parameter_handler);
#else
#include <poll.h>
#endif

namespace {

constexpr int GuestEinval = 22;
constexpr int SelectDescriptorLimit = 1024;
constexpr int SelectPollSliceMilliseconds = 10;

struct GuestTimeval {
    std::int64_t seconds;
    std::int64_t microseconds;
};

std::atomic<KernelSocketPoll::Poller> g_socketPoller{nullptr};
std::atomic<KernelSocketPoll::Closer> g_socketCloser{nullptr};
std::atomic<KernelSocketPoll::OptionSetter> g_socketOptionSetter{nullptr};

bool DescriptorSet(const void* set, int descriptor) {
    return set != nullptr && ((static_cast<const std::uint64_t*>(set)[descriptor / 64] >> (descriptor % 64)) & 1u) != 0;
}

void UnknownDescriptor(int descriptor, bool polled) {
    const auto what = "select on descriptor " + std::to_string(descriptor) + (polled ? " (not a libSceNet socket)" : " (libSceNet is not loaded)");
    NotImplemented_nid_no_patch(what.c_str());
}

void ClearDescriptor(void* set, int descriptor) {
    if (set != nullptr) static_cast<std::uint64_t*>(set)[descriptor / 64] &= ~(std::uint64_t{1} << (descriptor % 64));
}

struct PollGroup {
    KernelSocketPoll::Poller poll;
    std::vector<KernelSocketPoll::Entry> entries;
    std::vector<std::size_t> slots;
};

int KernelSockets(KernelSocketPoll::Entry* entries, int count, int timeoutMilliseconds) {
    return GuestSockets::Poll(entries, count, timeoutMilliseconds);
}

#ifdef _WIN32

enum class DescriptorKind { RegularFile, PipeReadable, PipePending, PipeUnsupported, Other, Invalid, Failed };

void IgnoreInvalidParameter(const wchar_t*, const wchar_t*, const wchar_t*, unsigned int, std::uintptr_t) {}

DescriptorKind InspectDescriptor(int descriptor, short events) {
    const auto previous = _set_thread_local_invalid_parameter_handler(IgnoreInvalidParameter);
    const auto native = ::_get_osfhandle(descriptor);
    _set_thread_local_invalid_parameter_handler(previous);
    if (native == -1 || native == -2) return DescriptorKind::Invalid;
    const auto handle = reinterpret_cast<HANDLE>(native);
    ::SetLastError(ERROR_SUCCESS);
    const auto type = ::GetFileType(handle);
    if (type == FILE_TYPE_UNKNOWN && ::GetLastError() == ERROR_INVALID_HANDLE) return DescriptorKind::Invalid;
    if (type == FILE_TYPE_PIPE) {
        if (events != KernelSocketPoll::Readable) return DescriptorKind::PipeUnsupported;
        DWORD flags = 0;
        if (!::GetNamedPipeInfo(handle, &flags, nullptr, nullptr, nullptr))
            return ::GetLastError() == ERROR_INVALID_HANDLE ? DescriptorKind::Invalid : DescriptorKind::Other;
        if ((flags & PIPE_TYPE_MESSAGE) != 0) return DescriptorKind::Other;
        DWORD available = 0;
        if (::PeekNamedPipe(handle, nullptr, 0, nullptr, &available, nullptr))
            return available != 0 ? DescriptorKind::PipeReadable : DescriptorKind::PipePending;
        const auto error = ::GetLastError();
        if (error == ERROR_BROKEN_PIPE) return DescriptorKind::PipeReadable;
        if (error == ERROR_INVALID_HANDLE) return DescriptorKind::Invalid;
        return error == ERROR_ACCESS_DENIED ? DescriptorKind::PipeUnsupported : DescriptorKind::Other;
    }
    if (type != FILE_TYPE_DISK) return DescriptorKind::Other;
    BY_HANDLE_FILE_INFORMATION information{};
    if (!::GetFileInformationByHandle(handle, &information)) return DescriptorKind::Failed;
    return (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ? DescriptorKind::RegularFile : DescriptorKind::Other;
}

int HostPoll(KernelSocketPoll::Entry* descriptors, int count, int timeoutMilliseconds) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMilliseconds);
    for (;;) {
        int ready = 0;
        for (int index = 0; index < count; ++index) {
            auto& entry = descriptors[index];
            entry.revents = 0;
            const auto kind = InspectDescriptor(entry.descriptor, entry.events);
            if (kind == DescriptorKind::Invalid) return -9;
            if (kind == DescriptorKind::Failed) return -5;
            if (kind == DescriptorKind::PipeUnsupported) NotImplemented_nid_no_patch("select Windows pipe endpoint or write/exception readiness");
            if (kind == DescriptorKind::RegularFile) {
                if ((entry.events & KernelSocketPoll::Urgent) != 0) NotImplemented_nid_no_patch("select regular-file exception readiness");
                entry.revents = entry.events & (KernelSocketPoll::Readable | KernelSocketPoll::Writable);
            } else if (kind == DescriptorKind::PipeReadable) entry.revents = KernelSocketPoll::Readable;
            else if (kind != DescriptorKind::PipePending) UnknownDescriptor(entry.descriptor, g_socketPoller.load() != nullptr);
            if (entry.revents != 0) ++ready;
        }
        const auto now = std::chrono::steady_clock::now();
        if (ready != 0 || now >= deadline) return ready;
        std::this_thread::sleep_until(std::min(deadline, now + std::chrono::milliseconds(SelectPollSliceMilliseconds)));
    }
}

#else

short HostEventFlags(short events) {
    short flags = 0;
    if ((events & KernelSocketPoll::Readable) != 0) flags |= POLLIN;
    if ((events & KernelSocketPoll::Writable) != 0) flags |= POLLOUT;
    return flags;
}

short KernelEventFlags(short revents) {
    short flags = 0;
    if ((revents & POLLIN) != 0) flags |= KernelSocketPoll::Readable;
    if ((revents & POLLOUT) != 0) flags |= KernelSocketPoll::Writable;
    if ((revents & POLLERR) != 0) flags |= KernelSocketPoll::Error;
    if ((revents & POLLHUP) != 0) flags |= KernelSocketPoll::HangUp;
    return flags;
}

int HostPoll(KernelSocketPoll::Entry* descriptors, int count, int timeoutMilliseconds) {
    std::vector<struct pollfd> native(static_cast<std::size_t>(count));
    for (std::size_t index = 0; index < native.size(); ++index) {
        native[index].fd = descriptors[index].descriptor;
        native[index].events = HostEventFlags(descriptors[index].events);
        native[index].revents = 0;
    }
    const int result = ::poll(native.data(), static_cast<nfds_t>(native.size()), timeoutMilliseconds);
    if (result < 0) return -errno;
    for (std::size_t index = 0; index < native.size(); ++index) {
        if ((native[index].revents & POLLNVAL) != 0) return -EBADF;
        descriptors[index].revents = KernelEventFlags(native[index].revents);
    }
    return result;
}

#endif

}

extern "C" {

const char* APS5_VABI __inet_ntop_nid_postfix(int family, const void* source, char* destination, std::uint32_t capacity);
int APS5_VABI __inet_pton_nid_postfix(int family, const char* text, void* destination);

const char* APS5_VABI inet_ntop_nid_postfix(int af, const void* src, char* dst, uint32_t size) {
    return __inet_ntop_nid_postfix(af, src, dst, size);
}

int APS5_VABI inet_pton_nid_postfix(int af, const char* src, void* dst) {
    return __inet_pton_nid_postfix(af, src, dst);
}

int* APS5_VABI __error_nid_postfix();

void KernelSetSocketPoller_nid_no_patch(KernelSocketPoll::Poller poller) {
    g_socketPoller.store(poller);
}

void KernelSetSocketCloser_nid_no_patch(KernelSocketPoll::Closer closer) {
    g_socketCloser.store(closer);
}

bool KernelCloseSocket_nid_no_patch(int descriptor, int* error) {
    const auto closer = g_socketCloser.load();
    return closer != nullptr && closer(descriptor, error);
}

void KernelSetSocketOptionSetter_nid_no_patch(KernelSocketPoll::OptionSetter setter) {
    g_socketOptionSetter.store(setter);
}

bool KernelSetSocketOption_nid_no_patch(int descriptor, int level, int option, const void* value, std::uint32_t length, int* error) {
    const auto setter = g_socketOptionSetter.load();
    return setter != nullptr && setter(descriptor, level, option, value, length, error);
}

int APS5_VABI select_nid_postfix(int nfds, void* readfds, void* writefds, void* exceptfds, const void* timeout) {
    const auto* limit = static_cast<const GuestTimeval*>(timeout);
    if (nfds < 0 || nfds > SelectDescriptorLimit || (limit != nullptr && (limit->seconds < 0 || limit->microseconds < 0 || limit->microseconds >= 1000000))) {
        *__error_nid_postfix() = GuestEinval;
        return -1;
    }
    PollGroup kernel{&KernelSockets, {}, {}};
    PollGroup net{nullptr, {}, {}};
    std::vector<KernelSocketPoll::Entry> devices;
    std::vector<KernelSocketPoll::Entry> requested;
    for (int descriptor = 0; descriptor < nfds; ++descriptor) {
        short events = 0;
        if (DescriptorSet(readfds, descriptor)) events |= KernelSocketPoll::Readable;
        if (DescriptorSet(writefds, descriptor)) events |= KernelSocketPoll::Writable;
        if (DescriptorSet(exceptfds, descriptor)) events |= KernelSocketPoll::Urgent;
        if (events == 0) continue;
        if (GuestSockets::IsOpen(descriptor)) {
            kernel.entries.push_back({descriptor, events, 0});
            kernel.slots.push_back(requested.size());
            requested.push_back({descriptor, events, 0});
        } else if (File::IsRandomDevice(descriptor)) devices.push_back({descriptor, events, static_cast<short>(events & (KernelSocketPoll::Readable | KernelSocketPoll::Writable))});
        else if (descriptor <= 2) devices.push_back({descriptor, events, static_cast<short>(descriptor == 0 ? 0 : events & KernelSocketPoll::Writable)});
        else {
            net.entries.push_back({descriptor, events, 0});
            net.slots.push_back(requested.size());
            requested.push_back({descriptor, events, 0});
        }
    }
    for (const auto& device : devices) requested.push_back(device);
    const bool devicesReady = std::any_of(devices.begin(), devices.end(), [](const auto& entry) { return entry.revents != 0; });
    std::vector<PollGroup> groups;
    if (!kernel.entries.empty()) groups.push_back(std::move(kernel));
    if (!net.entries.empty()) {
        PollGroup hosts{&HostPoll, {}, {}};
        net.poll = g_socketPoller.load();
        if (net.poll != nullptr) {
            for (auto& socket : net.entries) socket.revents = 0;
            const int probe = net.poll(net.entries.data(), static_cast<int>(net.entries.size()), 0);
            if (probe < 0) {
                *__error_nid_postfix() = -probe;
                return -1;
            }
        }
        for (std::size_t index = 0; index < net.entries.size();) {
            if (net.poll != nullptr && (net.entries[index].revents & KernelSocketPoll::Unknown) == 0) {
                ++index;
                continue;
            }
            const int descriptor = net.entries[index].descriptor;
            hosts.entries.push_back({descriptor, net.entries[index].events, 0});
            hosts.slots.push_back(net.slots[index]);
            net.entries.erase(net.entries.begin() + static_cast<std::ptrdiff_t>(index));
            net.slots.erase(net.slots.begin() + static_cast<std::ptrdiff_t>(index));
        }
        if (!net.entries.empty()) groups.push_back(std::move(net));
        if (!hosts.entries.empty()) groups.push_back(std::move(hosts));
    }
    const auto start = std::chrono::steady_clock::now();
    const auto deadline = limit == nullptr ? std::chrono::steady_clock::time_point::max()
        : KernelSocketSelect::DeadlineAfter(start, limit->seconds, limit->microseconds);
    bool firstPoll = true;
    for (;;) {
        int waitMilliseconds = 100;
        if (limit != nullptr) {
            const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline - std::chrono::steady_clock::now()).count();
            const auto roundedMilliseconds = remaining > 0 ? remaining / 1000 + (remaining % 1000 != 0) : 0;
            waitMilliseconds = static_cast<int>(std::clamp<std::int64_t>(roundedMilliseconds, 0, 100));
        }
        if (devicesReady) waitMilliseconds = 0;
        if (firstPoll) waitMilliseconds = 0;
        firstPoll = false;
        if (groups.empty()) {
            if (waitMilliseconds > 0) std::this_thread::sleep_for(std::chrono::milliseconds(waitMilliseconds));
        } else {
            const int slice = groups.size() == 1 ? waitMilliseconds : std::min(waitMilliseconds, SelectPollSliceMilliseconds);
            const auto sliceEnd = std::chrono::steady_clock::now() + std::chrono::milliseconds(waitMilliseconds);
            for (;;) {
                int groupReady = 0;
                for (auto& group : groups) {
                    for (auto& entry : group.entries) entry.revents = 0;
                    const int result = group.poll(group.entries.data(), static_cast<int>(group.entries.size()), slice);
                    if (result < 0) {
                        *__error_nid_postfix() = -result;
                        return -1;
                    }
                    for (std::size_t index = 0; index < group.entries.size(); ++index) requested[group.slots[index]].revents = group.entries[index].revents;
                    groupReady += result;
                }
                if (groups.size() == 1 || groupReady > 0 || std::chrono::steady_clock::now() >= sliceEnd) break;
            }
        }
        int ready = 0;
        for (const auto& entry : requested) {
            if ((entry.revents & KernelSocketPoll::Unknown) != 0) UnknownDescriptor(entry.descriptor, true);
            const bool readable = (entry.events & KernelSocketPoll::Readable) != 0 && (entry.revents & (KernelSocketPoll::Readable | KernelSocketPoll::HangUp | KernelSocketPoll::Error)) != 0;
            const bool writable = (entry.events & KernelSocketPoll::Writable) != 0 && (entry.revents & (KernelSocketPoll::Writable | KernelSocketPoll::Error)) != 0;
            const bool urgent = (entry.events & KernelSocketPoll::Urgent) != 0 && (entry.revents & KernelSocketPoll::Urgent) != 0;
            ready += static_cast<int>(readable) + static_cast<int>(writable) + static_cast<int>(urgent);
        }
        if (ready > 0) {
            for (const auto& entry : requested) {
                if ((entry.revents & (KernelSocketPoll::Readable | KernelSocketPoll::HangUp | KernelSocketPoll::Error)) == 0) ClearDescriptor(readfds, entry.descriptor);
                if ((entry.revents & (KernelSocketPoll::Writable | KernelSocketPoll::Error)) == 0) ClearDescriptor(writefds, entry.descriptor);
                if ((entry.revents & KernelSocketPoll::Urgent) == 0) ClearDescriptor(exceptfds, entry.descriptor);
            }
            return ready;
        }
        if (limit != nullptr && std::chrono::steady_clock::now() >= deadline) {
            for (const auto& entry : requested) {
                ClearDescriptor(readfds, entry.descriptor);
                ClearDescriptor(writefds, entry.descriptor);
                ClearDescriptor(exceptfds, entry.descriptor);
            }
            return 0;
        }
    }
}

}
