#include "SceTypes.hpp"
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <thread>
#include <windows.h>

extern "C" {
int APS5_VABI scePthreadCreate(Pthread*, const PthreadAttr*, PthreadEntry, void*, const char*);
int APS5_VABI scePthreadJoin(Pthread, void**);
Pthread APS5_VABI scePthreadSelf();
int APS5_VABI scePthreadGetaffinity(Pthread, KernelCpumask*);
KernelCpumask APS5_VABI sceKernelGetAvailableCpumask();
int APS5_VABI sceKernelGetCurrentCpu();
int APS5_VABI pthread_setaffinity_np_nid_postfix(Pthread, std::size_t, const void*);
int* APS5_VABI __error_nid_postfix();
}

struct Api {
    decltype(&scePthreadCreate) create;
    decltype(&scePthreadJoin) join;
    decltype(&scePthreadSelf) self;
    decltype(&scePthreadGetaffinity) get;
    decltype(&sceKernelGetAvailableCpumask) available;
    decltype(&sceKernelGetCurrentCpu) cpu;
    decltype(&pthread_setaffinity_np_nid_postfix) set;
    decltype(&__error_nid_postfix) error;
};

Api api{};
constexpr std::uintptr_t Returned = 0x12345678bbcc0044ull;
constexpr std::uint64_t Guard = 0x7ca5e19bd46230f8ull;
constexpr std::uint64_t Witness = 0xf4c1286ae39b057dull;

void Require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "%s\n", message); std::exit(72); }
}

template<typename Predicate>
void Until(Predicate condition) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!condition()) {
        Require(std::chrono::steady_clock::now() < deadline, "affinity worker phase timed out");
        std::this_thread::yield();
    }
}

struct Worker {
    std::atomic<int> command{0};
    std::atomic<int> ack{0};
    KernelCpumask expected = 0;
    KernelCpumask observed = 0;
    std::uint64_t witness = 0;
    Pthread thread = nullptr;
};

void* APS5_VABI Run(void* argument) {
    auto* worker = static_cast<Worker*>(argument);
    worker->ack.store(1, std::memory_order_release);
    for (;;) {
        const int command = worker->command.load(std::memory_order_acquire);
        if (command == 3) return reinterpret_cast<void*>(Returned);
        if (command == 1 && worker->ack.load(std::memory_order_relaxed) != 2) {
            Require(api.get(api.self(), &worker->observed) == 0, "worker own affinity query failed");
            Require(worker->observed == worker->expected, "worker did not observe assigned affinity");
            const int cpu = api.cpu();
            Require(cpu >= 0 && cpu < 64 && (worker->observed & (KernelCpumask{1} << cpu)), "worker CPU outside its singleton mask");
            worker->witness = Witness ^ worker->observed;
            worker->ack.store(2, std::memory_order_release);
        }
        std::this_thread::yield();
    }
}

void Start(Worker& worker) {
    Require(api.create(&worker.thread, nullptr, Run, &worker, "affinity lifetime") == 0, "guest worker creation failed");
    Until([&] { return worker.ack.load(std::memory_order_acquire) == 1; });
}

void Join(Worker& worker) {
    worker.command.store(3, std::memory_order_release);
    void* value = nullptr;
    Require(api.join(worker.thread, &value) == 0, "guest worker join failed");
    Require(reinterpret_cast<std::uintptr_t>(value) == Returned, "guest callback or join truncated 64-bit value");
}

struct Mask {
    std::uint64_t before = Guard;
    std::array<std::uint64_t, 4> words{};
    std::uint64_t after = Guard;
};

void CheckOperations() {
    const auto available = api.available();
    const auto first = available & (~available + 1);
    const auto rest = available & ~first;
    const auto second = rest & (~rest + 1);
    Require(first != 0 && second != 0, "test requires two available guest CPUs");
    KernelCpumask parent = 0;
    Require(api.get(api.self(), &parent) == 0, "creator mask read failed");
    Worker target{}, other{};
    Start(target);
    Start(other);
    Mask request{};
    request.words = {first | (1ull << 40), 0xfedcba9876543210ull, 1, ~0ull};
    const auto original = request;
    *api.error() = 117;
    Require(api.set(target.thread, 32, request.words.data()) == 0 && *api.error() == 117, "live setter success or errno behavior changed");
    Require(std::memcmp(&request, &original, sizeof(request)) == 0, "setter changed mask input or guards");
    target.expected = first;
    target.command.store(1, std::memory_order_release);
    Until([&] { return target.ack.load(std::memory_order_acquire) == 2; });
    Require(target.witness == (Witness ^ first), "target witness missing");
    request.words[0] = second;
    other.expected = second;
    Require(api.set(other.thread, 32, request.words.data()) == 0, "second live target update failed");
    other.command.store(1, std::memory_order_release);
    Until([&] { return other.ack.load(std::memory_order_acquire) == 2; });
    KernelCpumask mask = 0;
    Require(api.get(target.thread, &mask) == 0 && mask == first, "setter changed bystander target");
    Require(api.get(api.self(), &mask) == 0 && mask == parent, "setter changed creator mask");
    for (const std::size_t bytes : {0u, 8u, 31u, 33u, 64u}) {
        Require(api.set(target.thread, bytes, request.words.data()) == 34, "live invalid size did not return ERANGE");
        Require(api.set(api.self(), bytes, nullptr) == 34, "size/null precedence changed");
    }
    Require(api.set(target.thread, 32, nullptr) == 14, "live null mask did not return EFAULT");
    request.words[0] = 1ull << 40;
    Require(api.set(target.thread, 32, request.words.data()) == 11, "empty clipped mask did not return EDEADLK");
    Require(api.get(target.thread, &mask) == 0 && mask == first, "failed request changed target mask");
    Require(api.set(nullptr, 0, nullptr) == 22, "null handle precedence changed");
    Require(*api.error() == 117, "POSIX setter wrote guest errno");
    Join(target);
    Join(other);
    request.words[0] = available;
    Require(api.set(target.thread, 32, request.words.data()) == 3, "joined target did not return project ESRCH");
    Require(api.set(target.thread, 0, nullptr) == 3, "joined target validation precedence changed");
    Require(api.get(api.self(), &mask) == 0 && mask == parent, "postjoin control changed creator mask");
    request.words[0] = first;
    const auto selfRequest = request;
    Require(api.set(api.self(), 32, request.words.data()) == 0, "original self setter path failed");
    Require(api.get(api.self(), &mask) == 0 && mask == first, "self setter mask readback failed");
    const int ownCpu = api.cpu();
    Require(ownCpu >= 0 && ownCpu < 64 && (first & (KernelCpumask{1} << ownCpu)), "self current CPU outside singleton mask");
    Require(std::memcmp(&request, &selfRequest, sizeof(request)) == 0, "self setter changed input or guards");
    request.words[0] = parent;
    Require(api.set(api.self(), 32, request.words.data()) == 0, "self original mask restore failed");
    Require(api.get(api.self(), &mask) == 0 && mask == parent, "self original mask restore readback failed");
    std::puts("affinity operations, callbacks, masks and errors passed");
}

void CheckFinishing() {
    const auto available = api.available();
    const auto first = available & (~available + 1);
    Require(first != 0, "test requires an available guest CPU");
    KernelCpumask parent = 0;
    Require(api.get(api.self(), &parent) == 0, "creator mask read failed");
    Mask request{};
    request.words = {first, ~0ull, 1, Guard};
    const auto original = request;
    for (int iteration = 0; iteration < 48; ++iteration) {
        Worker target{};
        Start(target);
        Require(api.set(target.thread, 32, request.words.data()) == 0, "live finishing control update failed");
        target.command.store(3, std::memory_order_release);
        bool finished = false;
        Until([&] {
            const int result = api.set(target.thread, 32, request.words.data());
            Require(result == 0 || result == 3, "finishing target returned unexpected affinity error");
            finished = result == 3;
            return finished;
        });
        Require(finished, "target did not report project ESRCH after finishing");
        Require(api.set(target.thread, 0, nullptr) == 3, "finished target validation precedence changed");
        Join(target);
        Require(api.set(target.thread, 32, request.words.data()) == 3, "joined target did not report project ESRCH");
        Require(std::memcmp(&request, &original, sizeof(request)) == 0, "finishing requests changed input or guards");
        KernelCpumask current = 0;
        Require(api.get(api.self(), &current) == 0 && current == parent, "finishing requests changed creator mask");
    }
    std::puts("48 normal worker finish/join affinity lifecycles passed");
}

#ifdef ANYPS5_PATCHED_AFFINITY
template<typename Function>
Function Resolve(HMODULE module, const char* nid) {
    const auto pointer = GetProcAddress(module, nid);
    Require(pointer != nullptr, nid);
    return reinterpret_cast<Function>(pointer);
}
#endif

int main(int argc, char** argv) {
    const char* mode = nullptr;
#ifdef ANYPS5_PATCHED_AFFINITY
    Require(argc == 3, "expected patched kernel path and operations/finishing mode");
    const auto supplied = std::filesystem::absolute(argv[1]);
    const auto module = LoadLibraryExW(supplied.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    Require(module != nullptr, "patched kernel load failed");
    std::array<wchar_t, 32768> path{};
    const auto count = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
    Require(count != 0 && count < path.size() && std::filesystem::equivalent(supplied, path.data()), "loaded kernel from a different build");
    const auto libc = GetModuleHandleW(L"libc.prx");
    Require(libc != nullptr, "patched libc dependency missing");
    const auto libcCount = GetModuleFileNameW(libc, path.data(), static_cast<DWORD>(path.size()));
    Require(libcCount != 0 && libcCount < path.size() && std::filesystem::equivalent(supplied.parent_path() / "libc.prx", path.data()), "loaded libc from a different build");
    api = {Resolve<decltype(api.create)>(module, "6UgtwV+0zb4"), Resolve<decltype(api.join)>(module, "onNY9Byn-W8"), Resolve<decltype(api.self)>(module, "aI+OeCz8xrQ"), Resolve<decltype(api.get)>(module, "rcrVFJsQWRY"), Resolve<decltype(api.available)>(module, "La9uyZv4Kvw"), Resolve<decltype(api.cpu)>(module, "g0VTBxfJyu0"), Resolve<decltype(api.set)>(module, "5KWrg7-ZqvE"), Resolve<decltype(api.error)>(libc, "9BcDykPmo1I")};
    std::printf("actual patched kernel=%s\n", supplied.string().c_str());
    mode = argv[2];
#else
    Require(argc == 2, "expected operations/finishing mode");
    api = {scePthreadCreate, scePthreadJoin, scePthreadSelf, scePthreadGetaffinity, sceKernelGetAvailableCpumask, sceKernelGetCurrentCpu, pthread_setaffinity_np_nid_postfix, __error_nid_postfix};
    mode = argv[1];
#endif
    if (!std::strcmp(mode, "operations")) CheckOperations();
    else if (!std::strcmp(mode, "finishing")) CheckFinishing();
    else Require(false, "unknown affinity test mode");
}
