#include "prx/libc/include/general/VabiMacros.hpp"
#include "prx/libc/include/specifics/itanium/CxxAbi.hpp"
#include <array>
#include <csignal>
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

using Destructor = void (APS5_VABI *)(void*);
using DynamicCast = void* (APS5_VABI *)(const void*, const __cxxabiv1::__class_type_info*, const __cxxabiv1::__class_type_info*, std::ptrdiff_t);
using InitializeException = void* (APS5_VABI *)(void*, std::type_info*, Destructor) noexcept;
using AllocateException = void* (APS5_VABI *)(std::size_t);
using ReleaseException = void (APS5_VABI *)(void*);
using Terminate = void (APS5_VABI *)();
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

std::string marker;
void WriteMarker(const char* text) {
    if (auto* stream = std::fopen(marker.c_str(), "ab")) { std::fputs(text, stream); std::fclose(stream); }
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
    Require(waited == WAIT_OBJECT_0 && queried && status == 3,
        "termination probe did not report the host abort exit code");
#else
    const auto child = fork();
    Require(child >= 0, "fork termination probe");
    if (child == 0) {
        execl(executable, executable, library, mode, temporary.c_str(), static_cast<char*>(nullptr));
        _exit(72);
    }
    int status = 0;
    Require(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT,
        "termination probe did not report SIGABRT");
#endif
    if (std::filesystem::exists(temporary)) {
        if (auto* stream = std::fopen(temporary.string().c_str(), "rb")) {
            std::array<char, 128> content{};
            const auto length = std::fread(content.data(), 1, content.size(), stream);
            std::fclose(stream);
            std::fprintf(stderr, "%.*s", static_cast<int>(length), content.data());
        }
        Require(false, "abnormal termination ran an atexit callback");
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
        release(object);
        Require(destroyed == 1 && destroyedObject == object && destroyedValue,
            "guest exception destructor did not receive the initialized object");
        CheckFinalization(module);
    } else if (!std::strcmp(argv[2], "abort") || !std::strcmp(argv[2], "stack-fail")) {
        if (argc == 3) CheckTermination(argv[0], argv[1], argv[2]);
        else {
            marker = argv[3];
            Require(std::atexit(WriteExitMarker) == 0, "register native exit marker");
            Require(Function<RegisterExit>(module, "8G2LB+A3rzg")(GuestExitMarker) == 0, "register guest exit marker");
            char primary[] = "guest __cxa_atexit destructor\n";
            char alias[] = "guest cxa_atexit destructor\n";
            Require(Function<RegisterDestructor>(module, "tsvEmnenz48")(GuestDestructorMarker, primary, nullptr) == 0,
                "register primary guest termination destructor");
            Require(Function<RegisterDestructor>(module, "l0kCOn6OlBw")(GuestDestructorMarker, alias, nullptr) == 0,
                "register alias guest termination destructor");
            Function<Terminate>(module, !std::strcmp(argv[2], "abort") ? "L1SBTkC+Cvw" : "Ou3iL1abvng")();
            Require(false, "termination function returned");
        }
    } else Require(false, "unknown runtime probe mode");
    std::puts("Guest runtime ABI probe passed");
}
