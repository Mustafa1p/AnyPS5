#include "prx/libc/include/general/VabiMacros.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#else
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#endif

using Select = int (APS5_VABI *)(int, void*, void*, void*, const void*);
#ifdef ANYPS5_PATCHED_SELECT
static int* (APS5_VABI *__error_nid_postfix)();
#else
extern "C" int* APS5_VABI __error_nid_postfix();
extern "C" int APS5_VABI select_nid_postfix(int, void*, void*, void*, const void*);
#endif

namespace {

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct Set {
    std::uint64_t before = 0x41327b9865acdef0;
    std::array<std::uint64_t, 16> bits{};
    std::uint64_t after = 0xa16394bec8527fd0;
    void Add(int descriptor) { bits.at(descriptor / 64) |= std::uint64_t{1} << (descriptor % 64); }
    bool operator==(const Set&) const = default;
};

struct Timeval {
    std::int64_t seconds;
    std::int64_t microseconds;
    bool operator==(const Timeval&) const = default;
};

struct Timeout {
    std::uint64_t before = 0xd184c95632af708b;
    Timeval value;
    std::uint64_t after = 0x925b30e7a6d148fc;
    bool operator==(const Timeout&) const = default;
};

int NativeOpen(const std::filesystem::path& path) {
#ifdef _WIN32
    return _wopen(path.c_str(), _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY, _S_IREAD | _S_IWRITE);
#else
    return open(path.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600);
#endif
}
int NativeClose(int descriptor) {
#ifdef _WIN32
    return _close(descriptor);
#else
    return close(descriptor);
#endif
}
std::int64_t NativeSeek(int descriptor, std::int64_t position, int origin) {
#ifdef _WIN32
    return _lseeki64(descriptor, position, origin);
#else
    return lseek(descriptor, position, origin);
#endif
}
int NativeRead(int descriptor, void* data, unsigned size) {
#ifdef _WIN32
    return _read(descriptor, data, size);
#else
    return static_cast<int>(read(descriptor, data, size));
#endif
}
int NativeWrite(int descriptor, const void* data, unsigned size) {
#ifdef _WIN32
    return _write(descriptor, data, size);
#else
    return static_cast<int>(write(descriptor, data, size));
#endif
}

class DiskFile {
    std::filesystem::path path;
    int descriptor;
public:
    static constexpr char payload[] = "select-disk-contents\x01\x7f";
    explicit DiskFile(unsigned sequence) {
        path = std::filesystem::temp_directory_path() / ("anyps5-select-" + std::to_string(
#ifdef _WIN32
            GetCurrentProcessId()
#else
            getpid()
#endif
        ) + "-" + std::to_string(sequence));
        std::filesystem::remove(path);
        descriptor = NativeOpen(path);
        Require(descriptor >= 0 && descriptor < 1023, "native disk descriptor outside guest set range");
        Require(NativeWrite(descriptor, payload, sizeof(payload)) == sizeof(payload), "native disk write");
        Require(NativeSeek(descriptor, 3, SEEK_SET) == 3, "native disk seek");
    }
    ~DiskFile() {
        if (descriptor >= 0) NativeClose(descriptor);
        std::error_code error;
        std::filesystem::remove(path, error);
    }
    int Fd() const { return descriptor; }
    void Check(std::int64_t position) const {
        Require(NativeSeek(descriptor, 0, SEEK_CUR) == position, "select changed native file offset");
        Require(NativeSeek(descriptor, 0, SEEK_SET) == 0, "native oracle seek");
        std::array<char, sizeof(payload) + 4> contents{};
        Require(NativeRead(descriptor, contents.data(), contents.size()) == sizeof(payload), "select changed file length");
        Require(std::memcmp(contents.data(), payload, sizeof(payload)) == 0, "select changed file contents");
        Require(NativeSeek(descriptor, position, SEEK_SET) == position, "native oracle restore");
    }
    int Close() {
        const int old = descriptor;
        Require(NativeClose(descriptor) == 0, "native disk close");
        descriptor = -1;
        return old;
    }
};

void CheckValidation(Select select) {
    Set read, write, except;
    read.Add(0); read.Add(1023);
    write.Add(1); except.Add(2);
    const auto expectedRead = read;
    const auto expectedWrite = write;
    const auto expectedExcept = except;
    Timeout timeout{0xd184c95632af708b, {0, 0}, 0x925b30e7a6d148fc};
    const auto expectedTimeout = timeout;
    for (int nfds : {-1, 1025}) {
        *__error_nid_postfix() = 0;
        Require(select(nfds, read.bits.data(), write.bits.data(), except.bits.data(), &timeout.value) == -1 &&
            *__error_nid_postfix() == 22, "invalid nfds must report guest EINVAL");
        Require(read == expectedRead && write == expectedWrite && except == expectedExcept && timeout == expectedTimeout,
            "invalid nfds changed sets, guards or timeout");
    }
    for (const Timeval invalid : {Timeval{-1, 0}, Timeval{0, -1}, Timeval{0, 1000000}}) {
        timeout.value = invalid;
        const auto originalTimeout = timeout;
        *__error_nid_postfix() = 0;
        Require(select(3, read.bits.data(), write.bits.data(), except.bits.data(), &timeout.value) == -1 &&
            *__error_nid_postfix() == 22, "invalid timeval must report guest EINVAL");
        Require(read == expectedRead && write == expectedWrite && except == expectedExcept && timeout == originalTimeout,
            "invalid timeval changed sets, guards or timeout");
    }
    timeout.value = {0, 30000};
    const auto timedTimeout = timeout;
    const auto start = std::chrono::steady_clock::now();
    Require(select(0, nullptr, nullptr, nullptr, &timeout.value) == 0, "null sets timed wait");
    const auto elapsed = std::chrono::steady_clock::now() - start;
    Require(elapsed >= std::chrono::milliseconds(25) && elapsed < std::chrono::seconds(2), "null sets wait duration");
    Require(timeout == timedTimeout, "null sets wait changed timeout or guards");
    Set ignored;
    ignored.Add(1023);
    const auto expectedIgnored = ignored;
    timeout.value = {0, 0};
    Require(select(0, ignored.bits.data(), nullptr, nullptr, &timeout.value) == 0 && ignored == expectedIgnored,
        "nfds zero changed ignored bits or guards");
}

void CheckFiles(Select select) {
    DiskFile first(1), second(2);
    const int nfds = std::max(first.Fd(), second.Fd()) + 1;
    Set read, write, except;
    read.Add(first.Fd()); read.Add(second.Fd()); read.Add(1023);
    write.Add(first.Fd()); write.Add(second.Fd()); write.Add(1023);
    except.Add(1023);
    const auto expectedRead = read;
    const auto expectedWrite = write;
    const auto expectedExcept = except;
    Timeout timeout{0xd184c95632af708b, {2, 123456}, 0x925b30e7a6d148fc};
    const auto expectedTimeout = timeout;
    const auto start = std::chrono::steady_clock::now();
    Require(select(nfds, read.bits.data(), write.bits.data(), except.bits.data(), &timeout.value) == 4,
        "two regular files must count read and write bits separately");
    Require(std::chrono::steady_clock::now() - start < std::chrono::seconds(1), "ready disk files waited for timeout");
    Require(read == expectedRead && write == expectedWrite && except == expectedExcept && timeout == expectedTimeout,
        "ready disk select changed bits, guards or timeout");
    first.Check(3); second.Check(3);
    Set singleRead, singleWrite;
    singleRead.Add(first.Fd()); singleRead.Add(1023);
    singleWrite.Add(first.Fd()); singleWrite.Add(1023);
    const auto expectedSingleRead = singleRead;
    const auto expectedSingleWrite = singleWrite;
    for (const Timeval limit : {Timeval{0, 0}, Timeval{std::numeric_limits<std::int64_t>::max(), 999999}}) {
        timeout.value = limit;
        const auto originalTimeout = timeout;
        const auto immediate = std::chrono::steady_clock::now();
        Require(select(first.Fd() + 1, singleRead.bits.data(), singleWrite.bits.data(), nullptr, &timeout.value) == 2,
            "immediate disk readiness with zero or enormous valid timeout");
        Require(std::chrono::steady_clock::now() - immediate < std::chrono::seconds(1), "immediate disk readiness stalled");
        Require(singleRead == expectedSingleRead && singleWrite == expectedSingleWrite && timeout == originalTimeout,
            "immediate select changed bits, guards or timeout");
        first.Check(3); second.Check(3);
    }
    Require(NativeSeek(first.Fd(), 0, SEEK_END) == sizeof(DiskFile::payload), "native seek EOF");
    char byte = 0x5a;
    Require(NativeRead(first.Fd(), &byte, 1) == 0 && byte == 0x5a, "native oracle EOF");
    Set eof;
    eof.Add(first.Fd()); eof.Add(1023);
    const auto expectedEof = eof;
    Require(select(first.Fd() + 1, eof.bits.data(), nullptr, nullptr, nullptr) == 1 && eof == expectedEof,
        "EOF disk descriptor must remain readable with unchanged guards");
    first.Check(sizeof(DiskFile::payload));
    const int closed = second.Close();
    read.Add(closed); write.Add(closed);
    const auto failedRead = read;
    const auto failedWrite = write;
    const auto failedExcept = except;
    timeout.value = {0, 0};
    const auto failedTimeout = timeout;
    *__error_nid_postfix() = 0;
    Require(select(nfds, read.bits.data(), write.bits.data(), except.bits.data(), &timeout.value) == -1 &&
        *__error_nid_postfix() == 9, "closed native descriptor must report guest EBADF even beside ready file");
    Require(read == failedRead && write == failedWrite && except == failedExcept && timeout == failedTimeout,
        "failed select changed input sets, guards or timeout");
    first.Check(sizeof(DiskFile::payload));
}

Select LoadSelect(const char* argument) {
    const auto path = std::filesystem::path(argument);
    Require(path.is_absolute(), "patched kernel path must be absolute");
#ifdef _WIN32
    const auto module = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    Require(module != nullptr, "load patched kernel");
    std::array<wchar_t, 32768> loadedPath{};
    const auto length = GetModuleFileNameW(module, loadedPath.data(), static_cast<DWORD>(loadedPath.size()));
    Require(length != 0 && length < loadedPath.size() && std::filesystem::equivalent(path, loadedPath.data()),
        "loaded kernel path differs from provided artifact");
    const auto address = GetProcAddress(module, "T8fER+tIGgk");
#ifdef ANYPS5_PATCHED_SELECT
    const auto libcPath = path.parent_path() / "libc.prx";
    const auto libc = LoadLibraryExW(libcPath.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    Require(libc != nullptr, "load patched libc errno");
    const auto libcLength = GetModuleFileNameW(libc, loadedPath.data(), static_cast<DWORD>(loadedPath.size()));
    Require(libcLength != 0 && libcLength < loadedPath.size() && std::filesystem::equivalent(libcPath, loadedPath.data()),
        "loaded libc path differs from provided kernel artifact directory");
    __error_nid_postfix = reinterpret_cast<decltype(__error_nid_postfix)>(GetProcAddress(libc, "9BcDykPmo1I"));
    Require(__error_nid_postfix != nullptr, "resolve patched errno NID");
#endif
#else
    const auto module = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    Require(module != nullptr, "load patched kernel");
    const auto address = dlsym(module, "T8fER+tIGgk");
    Dl_info information{};
    Require(address != nullptr && dladdr(address, &information) != 0 && information.dli_fname != nullptr &&
        std::filesystem::equivalent(path, information.dli_fname), "loaded kernel path differs from provided artifact");
#ifdef ANYPS5_PATCHED_SELECT
    const auto libcPath = path.parent_path() / "libc.prx";
    const auto libc = dlopen(libcPath.c_str(), RTLD_NOW | RTLD_LOCAL);
    Require(libc != nullptr, "load patched libc errno");
    __error_nid_postfix = reinterpret_cast<decltype(__error_nid_postfix)>(dlsym(libc, "9BcDykPmo1I"));
    Require(__error_nid_postfix != nullptr && dladdr(reinterpret_cast<void*>(__error_nid_postfix), &information) != 0 &&
        information.dli_fname != nullptr && std::filesystem::equivalent(libcPath, information.dli_fname),
        "loaded libc errno path differs from provided kernel artifact directory");
#endif
#endif
    Require(address != nullptr, "resolve select NID");
    std::printf("Loaded patched kernel: %s\n", path.string().c_str());
    return reinterpret_cast<Select>(address);
}

}

int main(int argc, char** argv) {
    try {
#ifdef ANYPS5_PATCHED_SELECT
        Require(argc == 2, "expected absolute patched kernel path");
        const auto select = LoadSelect(argv[1]);
#else
        static_cast<void>(argc);
        static_cast<void>(argv);
        const Select select = select_nid_postfix;
#endif
        CheckValidation(select);
        std::puts("Guest select validation and timed wait passed");
        CheckFiles(select);
        std::puts("Guest select regular-file bounded contract passed");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "Guest select failed: %s\n", error.what());
        return 71;
    }
}
