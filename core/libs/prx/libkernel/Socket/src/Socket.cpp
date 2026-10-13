#include <cstdint>
#include <cstddef>
#include "SceTypes.hpp"
#include "prx/libc/include/General.hpp"
#include "prx/libkernel/Socket/include/SocketPoll.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <thread>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
extern "C" _invalid_parameter_handler _set_thread_local_invalid_parameter_handler(_invalid_parameter_handler);
#else
#include <sys/stat.h>
#endif

namespace {

constexpr int GuestEinval = 22;
constexpr int GuestEbadf = 9;
constexpr int GuestEio = 5;
constexpr int SelectDescriptorLimit = 1024;
constexpr int PipeProbeMilliseconds = 10;

struct GuestTimeval {
    std::int64_t seconds;
    std::int64_t microseconds;
};

std::atomic<KernelSocketPoll::Poller> g_socketPoller{nullptr};

enum class DescriptorKind { RegularFile, PipeReadable, PipePending, PipeUnsupported, Other, Invalid, Failed };

#ifdef _WIN32
void IgnoreInvalidParameter(const wchar_t*, const wchar_t*, const wchar_t*, unsigned int, std::uintptr_t) {}
#endif

DescriptorKind InspectDescriptor(int descriptor, short events) {
#ifdef _WIN32
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
#else
    (void)events;
    struct stat information{};
    if (::fstat(descriptor, &information) != 0) return errno == EBADF ? DescriptorKind::Invalid : DescriptorKind::Failed;
    return S_ISREG(information.st_mode) ? DescriptorKind::RegularFile : DescriptorKind::Other;
#endif
}

std::chrono::steady_clock::time_point Deadline(std::chrono::steady_clock::time_point start, const GuestTimeval* limit) {
    using Clock = std::chrono::steady_clock;
    if (limit == nullptr) return Clock::time_point::max();
    const auto room = Clock::duration::max() - std::max(start.time_since_epoch(), Clock::duration::zero());
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(room);
    if (limit->seconds > seconds.count()) return Clock::time_point::max();
    const auto requestedSeconds = std::chrono::seconds(limit->seconds);
    if (std::chrono::microseconds(limit->microseconds) > room - requestedSeconds) return Clock::time_point::max();
    return start + requestedSeconds + std::chrono::microseconds(limit->microseconds);
}

bool DescriptorSet(const void* set, int descriptor) {
    return set != nullptr && ((static_cast<const std::uint64_t*>(set)[descriptor / 64] >> (descriptor % 64)) & 1u) != 0;
}

void ClearDescriptor(void* set, int descriptor) {
    if (set != nullptr) static_cast<std::uint64_t*>(set)[descriptor / 64] &= ~(std::uint64_t{1} << (descriptor % 64));
}

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

int APS5_VABI select_nid_postfix(int nfds, void* readfds, void* writefds, void* exceptfds, const void* timeout) {
    const auto* limit = static_cast<const GuestTimeval*>(timeout);
    if (nfds < 0 || nfds > SelectDescriptorLimit || (limit != nullptr && (limit->seconds < 0 || limit->microseconds < 0 || limit->microseconds >= 1000000))) {
        *__error_nid_postfix() = GuestEinval;
        return -1;
    }
    std::vector<KernelSocketPoll::Entry> entries;
    for (int descriptor = 0; descriptor < nfds; ++descriptor) {
        short events = 0;
        if (DescriptorSet(readfds, descriptor)) events |= KernelSocketPoll::Readable;
        if (DescriptorSet(writefds, descriptor)) events |= KernelSocketPoll::Writable;
        if (DescriptorSet(exceptfds, descriptor)) events |= KernelSocketPoll::Urgent;
        if (events != 0) entries.push_back({descriptor, events, 0});
    }
    const auto start = std::chrono::steady_clock::now();
    const auto deadline = Deadline(start, limit);
    bool firstPoll = true;
    bool hasPipe = false;
    for (;;) {
        int waitMilliseconds = 100;
        if (limit != nullptr) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) waitMilliseconds = 0;
            else if (deadline != std::chrono::steady_clock::time_point::max()) {
                const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline - now).count();
                waitMilliseconds = static_cast<int>(std::clamp<std::int64_t>((remaining + 999) / 1000, 0, 100));
            }
        }
        if (hasPipe) waitMilliseconds = std::min(waitMilliseconds, PipeProbeMilliseconds);
        if (firstPoll) waitMilliseconds = 0;
        firstPoll = false;
        if (!entries.empty()) {
            const auto pollStarted = std::chrono::steady_clock::now();
            const auto poller = g_socketPoller.load();
            for (auto& entry : entries) entry.revents = KernelSocketPoll::Unknown;
            const int result = poller == nullptr ? 0 : poller(entries.data(), static_cast<int>(entries.size()), waitMilliseconds);
            if (result < 0) {
                *__error_nid_postfix() = -result;
                return -1;
            }
            for (auto& entry : entries) {
                if ((entry.revents & KernelSocketPoll::Unknown) == 0) continue;
                const auto kind = InspectDescriptor(entry.descriptor, entry.events);
                if (kind == DescriptorKind::Invalid || kind == DescriptorKind::Failed) {
                    *__error_nid_postfix() = kind == DescriptorKind::Invalid ? GuestEbadf : GuestEio;
                    return -1;
                }
                if (kind == DescriptorKind::PipeUnsupported) NotImplemented_nid_no_patch("select pipe endpoint or write/exception readiness");
                if (kind == DescriptorKind::PipeReadable || kind == DescriptorKind::PipePending) {
                    hasPipe = true;
                    entry.revents = kind == DescriptorKind::PipeReadable ? KernelSocketPoll::Readable : 0;
                } else {
                    if (kind != DescriptorKind::RegularFile) NotImplemented_nid_no_patch("select on non-regular file descriptors");
                    if ((entry.events & KernelSocketPoll::Urgent) != 0) NotImplemented_nid_no_patch("select regular-file exception readiness");
                    entry.revents = entry.events & (KernelSocketPoll::Readable | KernelSocketPoll::Writable);
                }
            }
            int ready = 0;
            for (const auto& entry : entries) {
                const bool readable = (entry.events & KernelSocketPoll::Readable) != 0 && (entry.revents & (KernelSocketPoll::Readable | KernelSocketPoll::HangUp | KernelSocketPoll::Error)) != 0;
                const bool writable = (entry.events & KernelSocketPoll::Writable) != 0 && (entry.revents & (KernelSocketPoll::Writable | KernelSocketPoll::Error)) != 0;
                const bool urgent = (entry.events & KernelSocketPoll::Urgent) != 0 && (entry.revents & KernelSocketPoll::Urgent) != 0;
                ready += static_cast<int>(readable) + static_cast<int>(writable) + static_cast<int>(urgent);
            }
            if (ready > 0) {
                for (const auto& entry : entries) {
                    if ((entry.revents & (KernelSocketPoll::Readable | KernelSocketPoll::HangUp | KernelSocketPoll::Error)) == 0) ClearDescriptor(readfds, entry.descriptor);
                    if ((entry.revents & (KernelSocketPoll::Writable | KernelSocketPoll::Error)) == 0) ClearDescriptor(writefds, entry.descriptor);
                    if ((entry.revents & KernelSocketPoll::Urgent) == 0) ClearDescriptor(exceptfds, entry.descriptor);
                }
                return ready;
            }
            if (hasPipe && waitMilliseconds > 0) {
                const GuestTimeval slice{0, static_cast<std::int64_t>(waitMilliseconds) * 1000};
                const auto idleDeadline = Deadline(pollStarted, &slice);
                if (std::chrono::steady_clock::now() < idleDeadline) std::this_thread::sleep_until(idleDeadline);
            }
        } else if (waitMilliseconds > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(waitMilliseconds));
        }
        if (limit != nullptr && std::chrono::steady_clock::now() >= deadline && (!hasPipe || waitMilliseconds == 0)) {
            for (const auto& entry : entries) {
                ClearDescriptor(readfds, entry.descriptor);
                ClearDescriptor(writefds, entry.descriptor);
                ClearDescriptor(exceptfds, entry.descriptor);
            }
            return 0;
        }
    }
}

}
