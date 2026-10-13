#include "prx/libc/include/ApplicationHeap.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <new>
#include <stdexcept>
#include <string>
#include <thread>
#ifdef ANYPS5_PATCHED_ALLOCATION
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#endif

using Handler = void (APS5_VABI *)();
using Allocate = void* (APS5_VABI *)(std::size_t);
using AllocateNothrow = void* (APS5_VABI *)(std::size_t, const void*) noexcept;
using SetHandler = Handler (APS5_VABI *)(Handler) noexcept;
using GetHandler = Handler (APS5_VABI *)() noexcept;

#ifndef ANYPS5_PATCHED_ALLOCATION
extern "C" {
Handler APS5_VABI _ZSt15set_new_handlerPFvvE_nid_postfix(Handler) noexcept;
Handler APS5_VABI _ZSt15get_new_handlerv_nid_postfix() noexcept;
void* APS5_VABI _Znwm_nid_postfix(std::size_t);
void* APS5_VABI _Znam_nid_postfix(std::size_t);
void* APS5_VABI _ZnwmRKSt9nothrow_t_nid_postfix(std::size_t, const void*) noexcept;
void* APS5_VABI _ZnamRKSt9nothrow_t_nid_postfix(std::size_t, const void*) noexcept;
}
#endif

namespace {

struct GuestApi {
    void (*registerHeap)(void* const*);
    SetHandler setHandler;
    GetHandler getHandler;
    std::array<Allocate, 2> allocate;
    std::array<AllocateNothrow, 2> allocateNothrow;
} api{};

unsigned failuresLeft = 0;
unsigned allocationCalls = 0;
unsigned handlerCalls = 0;
std::size_t lastSize = 0;
bool ordinaryError = false;

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void* APS5_VABI HeapAllocate(std::size_t size) {
    ++allocationCalls;
    lastSize = size;
    if (ordinaryError) throw std::runtime_error("allocator lifecycle error");
    if (failuresLeft != 0) { --failuresLeft; return nullptr; }
    return std::malloc(size);
}

void APS5_VABI ReleaseHeapMemory(void* pointer) { std::free(pointer); }
void* APS5_VABI HeapCalloc(std::size_t count, std::size_t size) { return std::calloc(count, size); }
void* APS5_VABI HeapReallocate(void* pointer, std::size_t size) { return std::realloc(pointer, size); }
void* APS5_VABI HeapAlign(std::size_t, std::size_t size) { return HeapAllocate(size); }
void* APS5_VABI HeapRealign(void* pointer, std::size_t size, std::size_t) { return HeapReallocate(pointer, size); }
int APS5_VABI HeapPosixAlign(void** pointer, std::size_t, std::size_t size) {
    *pointer = HeapAllocate(size);
    return *pointer ? 0 : 12;
}

void APS5_VABI RetryHandler() { ++handlerCalls; }
void APS5_VABI RemoveHandler() {
    ++handlerCalls;
    api.setHandler(nullptr);
}
void APS5_VABI ThrowHandler() { ++handlerCalls; throw std::bad_alloc(); }
void APS5_VABI ThrowOrdinaryHandler() { ++handlerCalls; throw std::runtime_error("handler lifecycle error"); }
void APS5_VABI ReplaceHandler() {
    ++handlerCalls;
    Require(api.setHandler(RetryHandler) == ReplaceHandler, "handler replacement lost previous callback");
}
void APS5_VABI ReentrantHandler() {
    ++handlerCalls;
    failuresLeft = 0;
    void* nested = api.allocate[0](7);
    Require(nested != nullptr, "handler could not allocate outside the failed allocator callback");
    std::memset(nested, 0xa7, 7);
    ReleaseHeapMemory(nested);
}

void Reset(unsigned failures) {
    failuresLeft = failures;
    allocationCalls = 0;
    handlerCalls = 0;
    ordinaryError = false;
}

template<typename TAction>
void RequireBadAlloc(TAction action) {
    bool caught = false;
    try { action(); } catch (const std::bad_alloc&) { caught = true; }
    Require(caught, "throwing allocation did not report bad_alloc");
}

void CheckSuccessfulAllocation(void* pointer, std::size_t size) {
    Require(pointer != nullptr, "successful allocation returned null");
    Require(reinterpret_cast<std::uintptr_t>(pointer) % alignof(std::max_align_t) == 0,
        "allocation does not satisfy ordinary object alignment");
    std::memset(pointer, 0x5c, size);
    ReleaseHeapMemory(pointer);
}

void CheckForms() {
    for (auto allocate : api.allocate) {
        api.setHandler(nullptr);
        Reset(1);
        RequireBadAlloc([&] { allocate(19); });
        Require(allocationCalls == 1 && handlerCalls == 0, "no-handler failure was retried");

        api.setHandler(RetryHandler);
        Reset(3);
        CheckSuccessfulAllocation(allocate(19), 19);
        Require(allocationCalls == 4 && handlerCalls == 3 && lastSize == 19, "handler retry sequence is incorrect");
        Reset(0);
        CheckSuccessfulAllocation(allocate(19), 19);
        Require(allocationCalls == 1 && handlerCalls == 0, "successful allocation invoked the handler");

        api.setHandler(RemoveHandler);
        Reset(10);
        RequireBadAlloc([&] { allocate(19); });
        Require(allocationCalls == 2 && handlerCalls == 1 && api.getHandler() == nullptr,
            "allocation did not reload a removed handler");

        api.setHandler(ThrowHandler);
        Reset(1);
        RequireBadAlloc([&] { allocate(19); });
        Require(allocationCalls == 1 && handlerCalls == 1, "handler exception was retried");

        api.setHandler(ThrowOrdinaryHandler);
        Reset(1);
        bool ordinaryHandlerCaught = false;
        try { allocate(19); } catch (const std::runtime_error&) { ordinaryHandlerCaught = true; }
        Require(ordinaryHandlerCaught && allocationCalls == 1 && handlerCalls == 1,
            "throwing allocation did not propagate the handler runtime_error");

        api.setHandler(ReplaceHandler);
        Reset(2);
        CheckSuccessfulAllocation(allocate(19), 19);
        Require(allocationCalls == 3 && handlerCalls == 2 && api.getHandler() == RetryHandler,
            "allocation did not reload a replaced handler");

        api.setHandler(ReentrantHandler);
        Reset(1);
        CheckSuccessfulAllocation(allocate(19), 19);
        Require(allocationCalls == 3 && handlerCalls == 1, "handler could not reenter guest allocation");

        api.setHandler(RetryHandler);
        Reset(1);
        void* zero = allocate(0);
        Require(zero != nullptr && lastSize > 0 && allocationCalls == 2 && handlerCalls == 1,
            "zero-byte allocation failed to provide storage through the retry loop");
        ReleaseHeapMemory(zero);

        Reset(0);
        ordinaryError = true;
        bool caught = false;
        try { allocate(19); } catch (const std::runtime_error&) { caught = true; }
        Require(caught && allocationCalls == 1 && handlerCalls == 0,
            "throwing allocation swallowed a non-allocation failure or invoked the handler");
    }
    for (auto allocate : api.allocateNothrow) {
        api.setHandler(nullptr);
        Reset(1);
        Require(allocate(19, &std::nothrow) == nullptr && allocationCalls == 1 && handlerCalls == 0,
            "nothrow failure did not return null");
        api.setHandler(RetryHandler);
        Reset(2);
        CheckSuccessfulAllocation(allocate(19, &std::nothrow), 19);
        Require(allocationCalls == 3 && handlerCalls == 2, "nothrow allocation omitted the handler retry loop");
        Reset(0);
        CheckSuccessfulAllocation(allocate(19, &std::nothrow), 19);
        Require(allocationCalls == 1 && handlerCalls == 0, "successful nothrow allocation invoked the handler");
        Reset(1);
        void* zero = allocate(0, &std::nothrow);
        Require(zero != nullptr && lastSize > 0 && allocationCalls == 2 && handlerCalls == 1,
            "zero-byte nothrow allocation failed to provide storage through the retry loop");
        ReleaseHeapMemory(zero);
        api.setHandler(RemoveHandler);
        Reset(10);
        Require(allocate(19, &std::nothrow) == nullptr && allocationCalls == 2 && handlerCalls == 1,
            "nothrow allocation did not reload a removed handler");
        api.setHandler(ThrowHandler);
        Reset(1);
        Require(allocate(19, &std::nothrow) == nullptr && allocationCalls == 1 && handlerCalls == 1,
            "nothrow allocation did not contain a handler exception");
        api.setHandler(ThrowOrdinaryHandler);
        Reset(1);
        Require(allocate(19, &std::nothrow) == nullptr && allocationCalls == 1 && handlerCalls == 1,
            "nothrow allocation did not contain the handler runtime_error");
        api.setHandler(RetryHandler);
        Reset(0);
        ordinaryError = true;
        Require(allocate(19, &std::nothrow) == nullptr && allocationCalls == 1 && handlerCalls == 0,
            "nothrow allocation did not contain a non-bad_alloc exception");
    }
    Reset(0);
    api.setHandler(nullptr);
}

void CheckConcurrentHandlers() {
    std::atomic<bool> invalid{false};
    std::array<std::thread, 6> workers;
    for (std::size_t index = 0; index < workers.size(); ++index) {
        workers[index] = std::thread([index, &invalid] {
            const Handler value = index % 2 ? RetryHandler : ThrowHandler;
            for (unsigned iteration = 0; iteration < 2000; ++iteration) {
                const auto previous = api.setHandler(value);
                const auto current = api.getHandler();
                const auto valid = [](Handler handler) { return !handler || handler == RetryHandler || handler == ThrowHandler; };
                if (!valid(previous) || !valid(current)) invalid.store(true);
            }
        });
    }
    for (auto& worker : workers) worker.join();
    Require(!invalid.load(), "concurrent handler access returned an invalid callback");
    api.setHandler(nullptr);
}

#ifdef ANYPS5_PATCHED_ALLOCATION
template<typename TFunction, typename TModule>
TFunction LoadFunction(TModule module, const char* name) {
#ifdef _WIN32
    const auto address = GetProcAddress(module, name);
#else
    const auto address = dlsym(module, name);
#endif
    if (!address) throw std::runtime_error(std::string("patched libc export unavailable: ") + name);
    return reinterpret_cast<TFunction>(address);
}
#endif

}

int main(int argc, char** argv) {
    try {
#ifdef ANYPS5_PATCHED_ALLOCATION
        Require(argc == 2, "expected the patched libc path");
        const auto path = std::filesystem::absolute(argv[1]);
#ifdef _WIN32
        const auto module = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
#else
        const auto module = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
#endif
        Require(module != nullptr, "could not load patched libc");
#ifdef _WIN32
        std::array<wchar_t, 32768> loadedPath{};
        const auto length = GetModuleFileNameW(module, loadedPath.data(), static_cast<DWORD>(loadedPath.size()));
        Require(length != 0 && length < loadedPath.size(), "could not identify loaded libc path");
        Require(std::filesystem::equivalent(path, std::filesystem::path(loadedPath.data())),
            "host exception runtime loaded libc from a different build");
#elif defined(__linux__)
        const auto rawThrow = dlsym(RTLD_DEFAULT, "__cxa_throw");
        Dl_info exceptionRuntime{};
        Require(rawThrow != nullptr && dladdr(rawThrow, &exceptionRuntime) != 0 && exceptionRuntime.dli_fname != nullptr,
            "could not identify the host exception runtime");
        Require(std::filesystem::equivalent(path, std::filesystem::path(exceptionRuntime.dli_fname)),
            "host exception runtime loaded libc from a different build");
#endif
        std::printf("Loaded patched libc: %s\n", path.string().c_str());
        api = {LoadFunction<decltype(api.registerHeap)>(module, "ApplicationHeapRegister_nid_no_patch"),
            LoadFunction<SetHandler>(module, "RqeErO3cFHU"), LoadFunction<GetHandler>(module, "CkY0AVa-frg"),
            {LoadFunction<Allocate>(module, "fJnpuVVBbKk"), LoadFunction<Allocate>(module, "hdm0YfMa7TQ")},
            {LoadFunction<AllocateNothrow>(module, "ryUxD-60bKM"), LoadFunction<AllocateNothrow>(module, "Jh5qUcwiSEk")}};
#else
        static_cast<void>(argc);
        static_cast<void>(argv);
        api = {ApplicationHeapRegister_nid_no_patch, _ZSt15set_new_handlerPFvvE_nid_postfix,
            _ZSt15get_new_handlerv_nid_postfix, {_Znwm_nid_postfix, _Znam_nid_postfix},
            {_ZnwmRKSt9nothrow_t_nid_postfix, _ZnamRKSt9nothrow_t_nid_postfix}};
#endif
        Require(api.getHandler() == nullptr, "initial guest handler was not null");
        Require(api.setHandler(RetryHandler) == nullptr && api.getHandler() == RetryHandler,
            "set/get handler failed to preserve the callback");
        Require(api.setHandler(nullptr) == RetryHandler && api.getHandler() == nullptr,
            "handler removal did not return the previous callback");
        std::array<void*, 10> heap{reinterpret_cast<void*>(HeapAllocate), reinterpret_cast<void*>(ReleaseHeapMemory),
            reinterpret_cast<void*>(HeapCalloc), reinterpret_cast<void*>(HeapReallocate),
            reinterpret_cast<void*>(HeapAlign), reinterpret_cast<void*>(HeapRealign), reinterpret_cast<void*>(HeapPosixAlign)};
        api.registerHeap(heap.data());
        CheckForms();
        CheckConcurrentHandlers();
        std::puts("Guest allocation contracts passed");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}
