#include "SceTypes.hpp"
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

extern "C" {
int APS5_VABI scePthreadCreate(Pthread*, const PthreadAttr*, PthreadEntry, void*, const char*);
int APS5_VABI scePthreadJoin(Pthread, void**);
Pthread APS5_VABI scePthreadSelf();
int APS5_VABI scePthreadGetthreadid();
int APS5_VABI scePthreadGetaffinity(Pthread, KernelCpumask*);
KernelCpumask APS5_VABI sceKernelGetAvailableCpumask();
int APS5_VABI sceKernelGetCurrentCpu();
int APS5_VABI cpuset_getaffinity_nid_postfix(int, int, std::int64_t, std::size_t, void*);
int APS5_VABI cpuset_setaffinity_nid_postfix(int, int, std::int64_t, std::size_t, const void*);
int* APS5_VABI __error_nid_postfix();
}

struct Api {
    decltype(&scePthreadCreate) create;
    decltype(&scePthreadJoin) join;
    decltype(&scePthreadSelf) self;
    decltype(&scePthreadGetthreadid) tid;
    decltype(&scePthreadGetaffinity) affinity;
    decltype(&sceKernelGetAvailableCpumask) available;
    decltype(&sceKernelGetCurrentCpu) cpu;
    decltype(&cpuset_getaffinity_nid_postfix) get;
    decltype(&cpuset_setaffinity_nid_postfix) set;
    decltype(&__error_nid_postfix) error;
};

Api api{};
constexpr std::uint64_t Guard = 0xd4e792af36c1580bull;
constexpr std::uint64_t Untouched = 0xa5a5a5a5a5a5a5a5ull;
constexpr std::uintptr_t Returned = 0x123456780badf00dull;
constexpr std::uint64_t Witness = 0x68df294eac7135b0ull;

void Require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "%s\n", message); std::exit(72); }
}

struct GuardedMask {
    std::uint64_t before = Guard;
    std::array<std::uint64_t, 4> words{Untouched, Untouched, Untouched, Untouched};
    std::uint64_t after = Guard;
};

void CheckMask(const GuardedMask& mask, std::size_t bytes, KernelCpumask expected) {
    Require(mask.before == Guard && mask.after == Guard, "affinity output changed guards");
    Require(mask.words[0] == expected, "affinity output selected the wrong thread or mask");
    for (std::size_t index = 1; index < mask.words.size(); ++index)
        Require(mask.words[index] == (index * 8 < bytes ? 0 : Untouched), "affinity output size or padding mismatch");
}

void Query(std::int64_t tid, std::size_t bytes, KernelCpumask expected) {
    GuardedMask result{};
    Require(api.get(3, 1, tid, bytes, result.words.data()) == 0, "live thread affinity query failed");
    CheckMask(result, bytes, expected);
}

void Change(std::int64_t tid, std::size_t bytes, KernelCpumask expected) {
    GuardedMask request{};
    request.words.fill(0);
    request.words[0] = expected;
    const auto original = request;
    Require(api.set(3, 1, tid, bytes, request.words.data()) == 0, "live thread affinity update failed");
    Require(std::memcmp(&request, &original, sizeof(request)) == 0, "affinity setter modified input");
}

struct Worker {
    std::atomic<int> id{0};
    std::atomic<int> command{0};
    std::atomic<int> observed{0};
    KernelCpumask initial = 0;
    KernelCpumask first = 0;
    KernelCpumask second = 0;
    std::uint64_t witness = 0;
    Pthread thread = nullptr;
    bool joined = false;

    ~Worker() {
        if (thread && !joined) {
            command.store(3, std::memory_order_release);
            api.join(thread, nullptr);
        }
    }
};

template<typename Predicate>
void Until(Predicate condition) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!condition()) {
        Require(std::chrono::steady_clock::now() < deadline, "guest thread handshake timed out");
        std::this_thread::yield();
    }
}

void* APS5_VABI Run(void* argument) {
    auto* worker = static_cast<Worker*>(argument);
    Require(api.affinity(api.self(), &worker->initial) == 0, "worker initial affinity query failed");
    worker->id.store(api.tid(), std::memory_order_release);
    int previous = 0;
    for (;;) {
        const int command = worker->command.load(std::memory_order_acquire);
        if (command == 3) break;
        if (command != previous) {
            const KernelCpumask expected = command == 1 ? worker->first : worker->second;
            KernelCpumask observed = 0;
            Require(api.affinity(api.self(), &observed) == 0 && observed == expected, "worker did not observe other-thread update");
            Query(-1, 32, expected);
            const int cpu = api.cpu();
            Require(cpu >= 0 && cpu < 64 && (expected & (KernelCpumask{1} << cpu)) != 0, "worker current CPU outside selected guest mask");
            worker->witness = Witness ^ static_cast<std::uint64_t>(command);
            previous = command;
            worker->observed.store(command, std::memory_order_release);
        }
        std::this_thread::yield();
    }
    return reinterpret_cast<void*>(Returned);
}

void Start(Worker& worker, KernelCpumask first, KernelCpumask second) {
    worker.first = first;
    worker.second = second;
    Require(api.create(&worker.thread, nullptr, Run, &worker, "cpuset worker") == 0, "create guest worker failed");
    Until([&] { return worker.id.load(std::memory_order_acquire) != 0; });
}

void Join(Worker& worker) {
    worker.command.store(3, std::memory_order_release);
    void* result = nullptr;
    Require(api.join(worker.thread, &result) == 0, "join guest worker failed");
    worker.joined = true;
    Require(reinterpret_cast<std::uintptr_t>(result) == Returned, "guest callback or join truncated return value");
}

void CheckMissing(std::int64_t tid) {
    GuardedMask mask{};
    const auto original = mask;
    *api.error() = 0;
    Require(api.get(3, 1, tid, 32, mask.words.data()) == -1 && *api.error() == 3, "finished thread query did not report ESRCH");
    Require(std::memcmp(&mask, &original, sizeof(mask)) == 0, "missing thread query changed output");
    mask.words.fill(0);
    mask.words[0] = api.available();
    *api.error() = 0;
    Require(api.set(3, 1, tid, 32, mask.words.data()) == -1 && *api.error() == 3, "finished thread update did not report ESRCH");
}

void CheckOperations(bool setFirst) {
    KernelCpumask parentMask = 0;
    Require(api.affinity(api.self(), &parentMask) == 0, "parent affinity query failed");
    const KernelCpumask available = api.available();
    Require(available != 0, "no available guest CPUs");
    const KernelCpumask first = available & (~available + 1);
    const KernelCpumask rest = available & ~first;
    const KernelCpumask second = rest ? (rest & (~rest + 1)) : first;
    Worker worker{};
    Start(worker, first, second);
    const auto id = worker.id.load(std::memory_order_acquire);
    Require(id != api.tid(), "guest worker returned parent's thread id");
    if (setFirst) Change(id, 32, worker.initial);
    for (std::size_t size : {8u, 16u, 24u, 32u}) Query(id, size, worker.initial);
    Change(id, 32, first);
    worker.command.store(1, std::memory_order_release);
    Until([&] { return worker.observed.load(std::memory_order_acquire) == 1; });
    Require(worker.witness == (Witness ^ 1), "worker first witness missing");
    Query(id, 32, first);
    Query(-1, 32, parentMask);
    Change(id, 8, second);
    worker.command.store(2, std::memory_order_release);
    Until([&] { return worker.observed.load(std::memory_order_acquire) == 2; });
    Require(worker.witness == (Witness ^ 2), "worker second witness missing");
    for (std::size_t size : {8u, 16u, 24u, 32u}) Query(id, size, second);
    Query(-1, 32, parentMask);
    GuardedMask invalid{};
    const auto original = invalid;
    for (std::size_t size : {7u, 33u}) {
        Require(api.get(3, 1, id, size, invalid.words.data()) == -1 && *api.error() == 34, "invalid query size did not report ERANGE");
        Require(api.set(3, 1, id, size, invalid.words.data()) == -1 && *api.error() == 34, "invalid update size did not report ERANGE");
    }
    Require(api.get(3, 1, id, 32, nullptr) == -1 && *api.error() == 14, "null query did not report EFAULT");
    Require(api.set(3, 1, id, 32, nullptr) == -1 && *api.error() == 14, "null update did not report EFAULT");
    Require(std::memcmp(&invalid, &original, sizeof(invalid)) == 0, "invalid request changed output");
    invalid.words.fill(0);
    Require(api.set(3, 1, id, 32, invalid.words.data()) == -1 && *api.error() == 11, "empty update did not report EDEADLK");
    invalid.words[0] = first;
    invalid.words[1] = 1;
    Require(api.set(3, 1, id, 32, invalid.words.data()) == -1 && *api.error() == 22, "high CPU bit did not report EINVAL");
    Query(id, 32, second);
    Join(worker);
    CheckMissing(id);
    Query(-1, 32, parentMask);
    for (int iteration = 0; iteration < 48; ++iteration) {
        Worker racing{};
        Start(racing, first, second);
        const auto racingId = racing.id.load(std::memory_order_acquire);
        Change(racingId, 32, first);
        racing.command.store(3, std::memory_order_release);
        for (int call = 0; call < 64; ++call) {
            GuardedMask output{};
            const int result = api.get(3, 1, racingId, 32, output.words.data());
            if (result == 0) CheckMask(output, 32, first);
            else Require(result == -1 && *api.error() == 3, "racing query returned unexpected error");
            GuardedMask input{};
            input.words.fill(0);
            input.words[0] = first;
            const int changed = api.set(3, 1, racingId, 32, input.words.data());
            Require(changed == 0 || (changed == -1 && *api.error() == 3), "racing update returned unexpected error");
        }
        Join(racing);
        CheckMissing(racingId);
    }
    std::puts("guest cpuset live-thread operations passed");
}

#ifdef ANYPS5_PATCHED_CPUSET
template<typename Function, typename Module>
Function Resolve(Module module, const char* nid) {
#ifdef _WIN32
    const auto pointer = GetProcAddress(module, nid);
#else
    const auto pointer = dlsym(module, nid);
#endif
    Require(pointer != nullptr, nid);
    return reinterpret_cast<Function>(pointer);
}
#endif

int main(int argc, char** argv) {
#ifdef ANYPS5_PATCHED_CPUSET
    Require(argc == 2 || (argc == 3 && !std::strcmp(argv[2], "set-first")), "expected actual patched kernel path and optional set-first");
#ifdef _WIN32
    const auto module = LoadLibraryExW(std::filesystem::absolute(argv[1]).c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    Require(module != nullptr, "load actual patched kernel failed");
    std::array<wchar_t, 32768> path{};
    const auto count = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
    Require(count != 0 && count < path.size() && std::filesystem::equivalent(std::filesystem::absolute(argv[1]), std::filesystem::path(path.data())), "loaded kernel from another build");
    const auto libc = GetModuleHandleW(L"libc.prx");
    Require(libc != nullptr, "patched libc dependency missing");
    const auto libcCount = GetModuleFileNameW(libc, path.data(), static_cast<DWORD>(path.size()));
    Require(libcCount != 0 && libcCount < path.size() && std::filesystem::equivalent(std::filesystem::absolute(argv[1]).parent_path() / "libc.prx", std::filesystem::path(path.data())), "loaded libc from another build");
#else
    const auto module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    Require(module != nullptr, "load actual patched kernel failed");
    const auto libc = dlopen((std::filesystem::absolute(argv[1]).parent_path() / "libc.prx").c_str(), RTLD_NOW | RTLD_LOCAL);
    Require(libc != nullptr, "load patched libc dependency failed");
#endif
    api = {Resolve<decltype(api.create)>(module, "6UgtwV+0zb4"), Resolve<decltype(api.join)>(module, "onNY9Byn-W8"), Resolve<decltype(api.self)>(module, "aI+OeCz8xrQ"), Resolve<decltype(api.tid)>(module, "EI-5-jlq2dE"), Resolve<decltype(api.affinity)>(module, "rcrVFJsQWRY"), Resolve<decltype(api.available)>(module, "La9uyZv4Kvw"), Resolve<decltype(api.cpu)>(module, "g0VTBxfJyu0"), Resolve<decltype(api.get)>(module, "Pdgml4rbxYk"), Resolve<decltype(api.set)>(module, "0Ma-LQjv6So"), Resolve<decltype(api.error)>(libc, "9BcDykPmo1I")};
#else
    (void)argc;
    (void)argv;
    api = {scePthreadCreate, scePthreadJoin, scePthreadSelf, scePthreadGetthreadid, scePthreadGetaffinity, sceKernelGetAvailableCpumask, sceKernelGetCurrentCpu, cpuset_getaffinity_nid_postfix, cpuset_setaffinity_nid_postfix, __error_nid_postfix};
#endif
    try { CheckOperations(argc == 3); }
    catch (const std::exception& error) { std::fprintf(stderr, "guest cpuset operation failed: %s\n", error.what()); return 71; }
}
