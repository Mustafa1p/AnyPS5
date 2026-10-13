#include "prx/libc/include/general/VabiMacros.hpp"
#include "prx/libc/include/specifics/itanium/CxxAbi.hpp"
#include <array>
#include <csignal>
#include <csetjmp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <new>
#include <string>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace LibcException { struct Header; }

using Destructor = void (APS5_VABI *)(void*);
using DynamicCast = void* (APS5_VABI *)(const void*, const __cxxabiv1::__class_type_info*, const __cxxabiv1::__class_type_info*, std::ptrdiff_t);
using InitializeException = LibcException::Header* (APS5_VABI *)(void*, std::type_info*, Destructor) noexcept;
using AllocateException = void* (APS5_VABI *)(std::size_t);
using ReleaseException = void (APS5_VABI *)(void*);
using Terminate = void (APS5_VABI *)();
using Exit = void (APS5_VABI *)(int);
using RegisterExit = int (APS5_VABI *)(void (APS5_VABI *)());
using RegisterDestructor = int (APS5_VABI *)(Destructor, void*, void*);
using Finalize = void (APS5_VABI *)(void*);

namespace {

void Require(bool condition, const char* message) {
    if (!condition) { std::fprintf(stderr, "%s\n", message); std::exit(71); }
}

template<typename TFunction, typename TModule>
TFunction Function(TModule module, const char* name) {
#ifdef _WIN32
    const auto address = GetProcAddress(module, name);
#else
    const auto address = dlsym(module, name);
#endif
    Require(address != nullptr, name);
    return reinterpret_cast<TFunction>(address);
}

struct Left { virtual ~Left() = default; int left = 31; };
struct Right { virtual ~Right() = default; int right = 47; };
struct Multiple : Left, Right { int both = 59; };
struct Unrelated { virtual ~Unrelated() = default; };

const __cxxabiv1::__class_type_info* ClassInfo(const std::type_info& type) {
    return static_cast<const __cxxabiv1::__class_type_info*>(&type);
}

unsigned destroyed = 0;
void* destroyedObject = nullptr;
bool destroyedValue = false;
void APS5_VABI DestroyObject(void* pointer) {
    destroyedObject = pointer;
    destroyedValue = *static_cast<unsigned*>(pointer) == 0x68ab52cd;
    ++destroyed;
}
#ifdef _WIN32
void NativeDestroyObject(void* pointer) {
    destroyedObject = pointer;
    destroyedValue = *static_cast<unsigned*>(pointer) == 0x68ab52cd;
    ++destroyed;
}
#endif

std::array<char, 32768> marker{};
std::jmp_buf recoveryJump;
void RecoverAbort(int signal) { if (signal == SIGABRT) std::longjmp(recoveryJump, 1); }
void WriteMarker(const char* text) {
    if (auto* stream = std::fopen(marker.data(), "ab")) { std::fputs(text, stream); std::fclose(stream); }
}
void WriteExitMarker() { WriteMarker("native atexit\n"); }
void APS5_VABI GuestExitMarker() { WriteMarker("guest atexit\n"); }
void APS5_VABI GuestDestructorMarker(void* text) { WriteMarker(static_cast<const char*>(text)); }

unsigned finalized = 0;
unsigned finalizedValues = 0;
void APS5_VABI FinalizeObject(void* pointer) {
    ++finalized;
    finalizedValues |= *static_cast<unsigned*>(pointer);
}

template<typename TModule>
void CheckFinalization(TModule module) {
    unsigned first = 1;
    unsigned second = 2;
    unsigned dso = 0;
    Require(Function<RegisterDestructor>(module, "tsvEmnenz48")(FinalizeObject, &first, &dso) == 0,
        "register primary guest destructor");
    Require(Function<RegisterDestructor>(module, "l0kCOn6OlBw")(FinalizeObject, &second, &dso) == 0,
        "register alias guest destructor");
    const auto finalize = Function<Finalize>(module, "UG9RaPseTbE");
    finalize(&dso);
    finalize(&dso);
    Require(finalized == 2 && finalizedValues == 3,
        "explicit finalization did not call both guest destructors once with their arguments");
}

void CheckTermination(const char* executable, const char* library, const char* mode) {
    const bool abnormal = !std::strcmp(mode, "abort") || !std::strcmp(mode, "stack-fail");
    const int expectedStatus = !std::strcmp(mode, "immediate") ? 39 : 37;
    const auto temporary = std::filesystem::temp_directory_path() /
        (std::string("anyps5-termination-") + mode + "-" + std::to_string(
#ifdef _WIN32
            GetCurrentProcessId()
#else
            getpid()
#endif
        ));
    std::filesystem::remove(temporary);
#ifdef _WIN32
    const auto path = std::filesystem::absolute(executable).wstring();
    auto arguments = L"\"" + path + L"\" \"" + std::filesystem::path(library).wstring() + L"\" " +
        std::filesystem::path(mode).wstring() + L" \"" + temporary.wstring() + L"\"";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    Require(CreateProcessW(path.c_str(), arguments.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
        nullptr, nullptr, &startup, &process) != 0, "launch termination probe");
    const auto waited = WaitForSingleObject(process.hProcess, 5000);
    if (waited != WAIT_OBJECT_0) TerminateProcess(process.hProcess, 72);
    DWORD status = 0;
    const bool queried = GetExitCodeProcess(process.hProcess, &status) != 0;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    Require(waited == WAIT_OBJECT_0 && queried && status == static_cast<DWORD>(abnormal ? 3 : expectedStatus),
        "termination probe did not report its expected exit code");
#else
    const auto child = fork();
    Require(child >= 0, "fork termination probe");
    if (child == 0) {
        execl(executable, executable, library, mode, temporary.c_str(), static_cast<char*>(nullptr));
        _exit(72);
    }
    int status = 0;
    Require(waitpid(child, &status, 0) == child &&
        (abnormal ? (WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT) :
            (WIFEXITED(status) && WEXITSTATUS(status) == expectedStatus)),
        "termination probe did not report its expected signal or exit code");
#endif
    std::string content;
    if (auto* stream = std::fopen(temporary.string().c_str(), "rb")) {
        std::array<char, 256> bytes{};
        const auto length = std::fread(bytes.data(), 1, bytes.size(), stream);
        std::fclose(stream);
        content.assign(bytes.data(), length);
    }
    if (abnormal || !std::strcmp(mode, "immediate")) {
        Require(content.empty(), "abnormal or immediate termination ran an exit callback");
    } else if (std::strstr(mode, "recover-host") != nullptr) {
        Require(content == "native atexit\n", "host exit after guest abort recovery ran guest callbacks");
    } else {
        const std::array<const char*,4> expected{"native atexit\n", "guest atexit\n",
            "guest __cxa_atexit destructor\n", "guest cxa_atexit destructor\n"};
        std::size_t expectedLength = 0;
        for (const auto text : expected) {
            expectedLength += std::strlen(text);
            const auto position = content.find(text);
            Require(position != std::string::npos && content.find(text, position + std::strlen(text)) == std::string::npos,
                "normal exit did not invoke each registered callback exactly once");
        }
        Require(content.size() == expectedLength, "normal exit marker contained unexpected bytes");
        Require(content.find(expected[3]) < content.find(expected[2]) && content.find(expected[2]) < content.find(expected[1]),
            "guest atexit and Cxa callbacks did not share reverse registration order");
    }
}

}

int main(int argc, char** argv) {
    Require(argc >= 3 && argc <= 4, "expected patched libc path and mode");
#ifdef _WIN32
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    const auto module = LoadLibraryExW(std::filesystem::absolute(argv[1]).c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
#else
    const auto module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
#endif
    Require(module != nullptr, "load patched runtime");
#ifdef _WIN32
    std::array<wchar_t, 32768> loadedPath{};
    const auto length = GetModuleFileNameW(module, loadedPath.data(), static_cast<DWORD>(loadedPath.size()));
    Require(length != 0 && length < loadedPath.size() &&
        std::filesystem::equivalent(std::filesystem::absolute(argv[1]), std::filesystem::path(loadedPath.data())),
        "runtime loaded libc from another build");
#endif
    if (!std::strcmp(argv[2], "rtti")) {
        const auto cast = Function<DynamicCast>(module, "hMAe+TWS9mQ");
        Multiple object;
        Left* left = &object;
        Right* right = &object;
        Require(static_cast<void*>(left) != static_cast<void*>(right), "multiple inheritance probe has no adjustment");
        Require(cast(right, ClassInfo(typeid(Right)), ClassInfo(typeid(Multiple)), -1) == &object,
            "guest dynamic cast did not adjust the derived pointer");
        Require(cast(left, ClassInfo(typeid(Left)), ClassInfo(typeid(Right)), -1) == right,
            "guest dynamic cast did not cross-cast between bases");
        Require(cast(left, ClassInfo(typeid(Left)), ClassInfo(typeid(Unrelated)), -1) == nullptr,
            "guest dynamic cast accepted an unrelated class");
        Require(cast(nullptr, ClassInfo(typeid(Left)), ClassInfo(typeid(Right)), -1) == nullptr,
            "guest dynamic cast did not preserve null");
    } else if (!std::strcmp(argv[2], "exception")) {
        const auto allocate = Function<AllocateException>(module, "cfAXurvfl5o");
        const auto initialize = Function<InitializeException>(module, "L4b+ak+yTSc");
        const auto release = Function<ReleaseException>(module, "MQFPAqQPt1s");
        void* object = allocate(sizeof(unsigned));
        new (object) unsigned(0x68ab52cd);
        initialize(object, const_cast<std::type_info*>(&typeid(unsigned)), DestroyObject);
        Function<ReleaseException>(module, "PsrRUg671K0")(object);
        release(object);
        Require(destroyed == 1 && destroyedObject == object && destroyedValue,
            "guest exception destructor did not receive the initialized object");
        CheckFinalization(module);
#ifdef _WIN32
        const auto nativeAllocate = Function<void* (*)(std::size_t)>(module, "__cxa_allocate_exception");
        const auto nativeInitialize = Function<void* (*)(void*, std::type_info*, void (*)(void*))>(module, "__cxa_init_primary_exception");
        destroyed = 0;
        destroyedObject = nullptr;
        destroyedValue = false;
        void* nativeObject = nativeAllocate(sizeof(unsigned));
        new (nativeObject) unsigned(0x68ab52cd);
        nativeInitialize(nativeObject, const_cast<std::type_info*>(&typeid(unsigned)), NativeDestroyObject);
        Function<ReleaseException>(module, "PsrRUg671K0")(nativeObject);
        release(nativeObject);
        Require(destroyed == 1 && destroyedObject == nativeObject && destroyedValue,
            "native primary exception adapter did not preserve its native destructor callback");
#endif
    } else if (!std::strcmp(argv[2], "exit-contract")) {
        Require(argc == 3, "exit-contract parent arguments");
        for (const auto mode : {"host-normal", "host-return", "guest-normal", "immediate",
            "abort-recover-host", "stack-recover-host", "abort-recover-guest", "stack-recover-guest"})
            CheckTermination(argv[0], argv[1], mode);
    } else if (!std::strcmp(argv[2], "abort") || !std::strcmp(argv[2], "stack-fail") || argc == 4) {
        if (argc == 3) CheckTermination(argv[0], argv[1], argv[2]);
        else {
            Require(std::snprintf(marker.data(), marker.size(), "%s", argv[3]) > 0, "copy marker path");
            Require(std::atexit(WriteExitMarker) == 0, "register native exit marker");
            Require(Function<RegisterExit>(module, "8G2LB+A3rzg")(GuestExitMarker) == 0, "register guest exit marker");
            static char primary[] = "guest __cxa_atexit destructor\n";
            static char alias[] = "guest cxa_atexit destructor\n";
            Require(Function<RegisterDestructor>(module, "tsvEmnenz48")(GuestDestructorMarker, primary, nullptr) == 0,
                "register primary guest termination destructor");
            Require(Function<RegisterDestructor>(module, "l0kCOn6OlBw")(GuestDestructorMarker, alias, nullptr) == 0,
                "register alias guest termination destructor");
            if (!std::strcmp(argv[2], "host-normal")) std::exit(37);
            if (!std::strcmp(argv[2], "host-return")) return 37;
            if (!std::strcmp(argv[2], "guest-normal")) Function<Exit>(module, "uMei1W9uyNo")(37);
            if (!std::strcmp(argv[2], "immediate")) Function<Exit>(module, "wZi5ly2guNw")(39);
            if (std::strstr(argv[2], "recover-") != nullptr) {
                Require(std::signal(SIGABRT, RecoverAbort) != SIG_ERR, "install native SIGABRT recovery handler");
                if (setjmp(recoveryJump) == 0)
                    Function<Terminate>(module, std::strstr(argv[2], "stack-") == argv[2] ? "Ou3iL1abvng" : "L1SBTkC+Cvw")();
                if (std::strstr(argv[2], "recover-guest") != nullptr) Function<Exit>(module, "uMei1W9uyNo")(37);
                std::exit(37);
            }
            Function<Terminate>(module, !std::strcmp(argv[2], "abort") ? "L1SBTkC+Cvw" : "Ou3iL1abvng")();
            Require(false, "termination function returned");
        }
    } else Require(false, "unknown runtime probe mode");
    std::puts("Guest runtime ABI probe passed");
}
