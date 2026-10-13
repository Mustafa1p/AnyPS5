#include "SceTypes.hpp"
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <thread>
#include <windows.h>

extern "C" {
int APS5_VABI _Mtx_init_nid_postfix(void**, int);
void APS5_VABI _Mtx_destroy_nid_postfix(void**);
int APS5_VABI _Mtx_lock_nid_postfix(void**);
int APS5_VABI _Mtx_unlock_nid_postfix(void**);
int APS5_VABI _Cnd_init_nid_postfix(void**);
void APS5_VABI _Cnd_destroy_nid_postfix(void**);
int APS5_VABI _Cnd_wait_nid_postfix(void**, void**);
int APS5_VABI _Cnd_signal_nid_postfix(void**);
int APS5_VABI _Cnd_broadcast_nid_postfix(void**);
int APS5_VABI pthread_create_nid_postfix(Pthread*, const PthreadAttr*, PthreadEntry, void*);
int APS5_VABI pthread_join_nid_postfix(Pthread, void**);
int APS5_VABI open_nid_postfix(const char*, int, int);
std::int64_t APS5_VABI lseek_nid_postfix(int, std::int64_t, int);
std::int64_t APS5_VABI write_nid_postfix(int, const void*, std::size_t);
int APS5_VABI close_nid_postfix(int);
}

struct Api {
    decltype(&_Mtx_init_nid_postfix) mutexInit;
    decltype(&_Mtx_destroy_nid_postfix) mutexDestroy;
    decltype(&_Mtx_lock_nid_postfix) lock;
    decltype(&_Mtx_unlock_nid_postfix) unlock;
    decltype(&_Cnd_init_nid_postfix) conditionInit;
    decltype(&_Cnd_destroy_nid_postfix) conditionDestroy;
    decltype(&_Cnd_wait_nid_postfix) wait;
    decltype(&_Cnd_signal_nid_postfix) signal;
    decltype(&_Cnd_broadcast_nid_postfix) broadcast;
    decltype(&pthread_create_nid_postfix) create;
    decltype(&pthread_join_nid_postfix) join;
    decltype(&open_nid_postfix) open;
    decltype(&lseek_nid_postfix) seek;
    decltype(&write_nid_postfix) write;
    decltype(&close_nid_postfix) close;
};

Api api{};
constexpr std::uint64_t Guard = 0xd725a3816cef490bull;
constexpr std::uint64_t ReturnBase = 0x12345678bbcc0044ull;
constexpr std::uint64_t Signature = 0xc0d1c7105a5af00dull;
constexpr unsigned Generations = 16;
constexpr unsigned Lifecycles = 3;

void Require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "%s\n", message); std::exit(72); }
}

struct Slot {
    std::uint64_t before = Guard;
    void* value = nullptr;
    std::uint64_t after = Guard;
};

struct Context {
    Slot mutex;
    Slot condition;
    void* mutexIdentity = nullptr;
    void* conditionIdentity = nullptr;
    bool stop = false;
    unsigned generation = 0;
    unsigned tokens = 0;
    unsigned completed = 0;
    std::array<bool, 2> waiting{};
    std::array<unsigned, 2> counts{};
    std::array<unsigned, 2> sums{};
    std::array<unsigned, 2> returnedWaits{};
};

struct Argument {
    std::uint64_t before = Guard;
    Context* context = nullptr;
    unsigned index = 0;
    unsigned seal = 0x35ca;
    std::uint64_t after = Guard;
};

void CheckSlots(const Context& context, bool destroyed = false) {
    for (const auto* slot : {&context.mutex, &context.condition})
        Require(slot->before == Guard && slot->after == Guard, "condition or mutex handle changed guards");
    Require(context.mutex.value == (destroyed ? nullptr : context.mutexIdentity), "mutex operation changed opaque handle value");
    Require(context.condition.value == (destroyed ? nullptr : context.conditionIdentity), "condition operation changed opaque handle value");
}

void Lock(Context& context) {
    Require(api.lock(&context.mutex.value) == 0, "guest mutex lock failed");
}

void Unlock(Context& context) {
    Require(api.unlock(&context.mutex.value) == 0, "guest mutex unlock failed");
}

template<typename Predicate>
void Until(Context& context, Predicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    for (;;) {
        Lock(context);
        const bool done = predicate();
        Unlock(context);
        if (done) return;
        Require(std::chrono::steady_clock::now() < deadline, "condition lifecycle rendezvous timed out");
        std::this_thread::yield();
    }
}

void* APS5_VABI Consume(void* input) {
    const auto* argument = static_cast<const Argument*>(input);
    Require(argument->before == Guard && argument->after == Guard && argument->seal == 0x35ca && argument->index < 2, "guest callback argument or ABI mismatch");
    auto& context = *argument->context;
    const unsigned index = argument->index;
    unsigned seen = 0;
    Lock(context);
    for (;;) {
        while (!context.stop && context.generation == seen) {
            context.waiting[index] = true;
            Require(api.wait(&context.condition.value, &context.mutex.value) == 0, "guest condition wait failed");
            context.waiting[index] = false;
            ++context.returnedWaits[index];
            Require(api.lock(&context.mutex.value) == 3, "condition wait did not restore nonrecursive mutex ownership");
            CheckSlots(context);
        }
        if (context.stop) break;
        Require(context.generation == seen + 1 && context.tokens > 0, "consumer observed skipped generation or missing protected token");
        seen = context.generation;
        --context.tokens;
        ++context.completed;
        ++context.counts[index];
        context.sums[index] += seen * (index + 1);
    }
    Unlock(context);
    return reinterpret_cast<void*>(ReturnBase ^ (index + 1));
}

struct Witness {
    std::uint32_t count1;
    std::uint32_t count2;
    std::uint32_t sum1;
    std::uint32_t sum2;
    std::uint64_t join1;
    std::uint64_t join2;
    std::uint64_t signature;
    std::uint32_t generations;
    std::uint32_t consumed;
};

void CheckLifecycle() {
    Witness witness{0, 0, 0, 0, 0, 0, Signature, Generations, 0};
    for (unsigned lifecycle = 0; lifecycle < Lifecycles; ++lifecycle) {
        Context context{};
        Require(api.mutexInit(&context.mutex.value, 2) == 0 && context.mutex.value != nullptr, "guest mutex initialization failed");
        Require(api.conditionInit(&context.condition.value) == 0 && context.condition.value != nullptr, "guest condition initialization failed");
        context.mutexIdentity = context.mutex.value;
        context.conditionIdentity = context.condition.value;
        CheckSlots(context);
        Require(api.signal(&context.condition.value) == 0 && api.broadcast(&context.condition.value) == 0, "empty waiter notification failed");
        std::array<Argument, 2> arguments{{{Guard, &context, 0, 0x35ca, Guard}, {Guard, &context, 1, 0x35ca, Guard}}};
        const auto unchanged = arguments;
        std::array<Pthread, 2> threads{};
        for (unsigned index = 0; index < 2; ++index)
            Require(api.create(&threads[index], nullptr, Consume, &arguments[index]) == 0, "create actual SysV condition consumer failed");
        Until(context, [&] { return context.waiting[0] && context.waiting[1]; });
        for (unsigned generation = 1; generation <= Generations; ++generation) {
            Lock(context);
            Require(context.tokens == 0 && (generation == 1 || context.completed == 2), "previous protected tokens did not complete");
            context.generation = generation;
            context.tokens = 2;
            context.completed = 0;
            if (generation & 1) {
                Require(api.signal(&context.condition.value) == 0 && api.signal(&context.condition.value) == 0, "two consumer notifications failed");
            } else {
                Require(api.broadcast(&context.condition.value) == 0, "two consumer broadcast failed");
            }
            CheckSlots(context);
            Unlock(context);
            Until(context, [&] { return context.completed == 2 && context.waiting[0] && context.waiting[1]; });
        }
        Lock(context);
        Require(context.tokens == 0 && context.completed == 2, "final protected token accounting failed");
        context.stop = true;
        Require(api.broadcast(&context.condition.value) == 0, "normal consumer stop broadcast failed");
        Unlock(context);
        std::array<void*, 2> values{};
        for (unsigned index = 0; index < 2; ++index) {
            Require(api.join(threads[index], &values[index]) == 0, "join condition consumer failed");
            Require(reinterpret_cast<std::uintptr_t>(values[index]) == (ReturnBase ^ (index + 1)), "guest condition callback or join truncated return");
            Require(context.counts[index] == Generations && context.sums[index] == Generations * (Generations + 1) / 2 * (index + 1), "independent per-consumer token witness mismatch");
            Require(context.returnedWaits[index] >= Generations, "condition wait dependency did not execute through generations");
        }
        Require(std::memcmp(arguments.data(), unchanged.data(), sizeof(arguments)) == 0, "condition callbacks modified argument bytes or guards");
        Require(!context.waiting[0] && !context.waiting[1], "joined consumer retained wait marker");
        CheckSlots(context);
        witness.count1 += context.counts[0];
        witness.count2 += context.counts[1];
        witness.sum1 += context.sums[0];
        witness.sum2 += context.sums[1];
        witness.join1 = reinterpret_cast<std::uintptr_t>(values[0]);
        witness.join2 = reinterpret_cast<std::uintptr_t>(values[1]);
        witness.consumed += context.counts[0] + context.counts[1];
        api.conditionDestroy(&context.condition.value);
        api.mutexDestroy(&context.mutex.value);
        CheckSlots(context, true);
    }
    const int file = api.open("/app0/condition-witness.bin", 2, 0);
    Require(file >= 0, "open native guest condition witness failed");
    Require(api.seek(file, 32, 0) == 32, "seek native guest condition witness failed");
    Require(api.write(file, &witness, sizeof(witness)) == sizeof(witness), "write native guest condition witness failed");
    Require(api.close(file) == 0, "close native guest condition witness failed");
    std::puts("condition lifecycle: 3 lifecycles, 48 generations, 96 protected tokens passed");
}

template<typename Function>
Function Resolve(HMODULE module, const char* nid) {
    const auto address = GetProcAddress(module, nid);
    Require(address != nullptr, nid);
    return reinterpret_cast<Function>(address);
}

HMODULE Load(const std::filesystem::path& supplied) {
    const auto module = LoadLibraryExW(supplied.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    Require(module != nullptr, "load actual condition lifecycle module failed");
    std::array<wchar_t, 32768> actual{};
    const auto count = GetModuleFileNameW(module, actual.data(), static_cast<DWORD>(actual.size()));
    Require(count != 0 && count < actual.size() && std::filesystem::equivalent(supplied, actual.data()), "condition lifecycle loaded module from another build");
    return module;
}

int main(int argc, char** argv) {
    Require(argc == 2, "expected supplied actual patched library directory");
    const auto libraries = std::filesystem::absolute(argv[1]);
    const auto libc = Load(libraries / "libc.prx");
    const auto kernel = Load(libraries / "libkernel.prx");
    api = {Resolve<decltype(api.mutexInit)>(libc, "YaHc3GS7y7g"), Resolve<decltype(api.mutexDestroy)>(libc, "5Lf51jvohTQ"), Resolve<decltype(api.lock)>(libc, "iS4aWbUonl0"), Resolve<decltype(api.unlock)>(libc, "gTuXQwP9rrs"), Resolve<decltype(api.conditionInit)>(libc, "SreZybSRWpU"), Resolve<decltype(api.conditionDestroy)>(libc, "7yMFgcS8EPA"), Resolve<decltype(api.wait)>(libc, "vEaqE-7IZYc"), Resolve<decltype(api.signal)>(libc, "0uuqgRz9qfo"), Resolve<decltype(api.broadcast)>(libc, "VsP3daJgmVA"), Resolve<decltype(api.create)>(kernel, "OxhIB8LB-PQ"), Resolve<decltype(api.join)>(kernel, "h9CcP3J0oVM"), Resolve<decltype(api.open)>(kernel, "wuCroIGjt2g"), Resolve<decltype(api.seek)>(kernel, "Oy6IpwgtYOk"), Resolve<decltype(api.write)>(kernel, "FN4gaPmuFV8"), Resolve<decltype(api.close)>(kernel, "bY-PO6JhzhQ")};
    std::printf("actual patched condition modules: %s\n", libraries.string().c_str());
    CheckLifecycle();
}
