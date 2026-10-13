#define NOMINMAX
#include <windows.h>
#include <elfpatcher/windows/WindowsStandardStreamStubBuilder.hpp>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace Elfpatcher::Windows;
using Fileno = int (*)(void*);
using OsHandle = std::intptr_t (*)(int);
using OpenHandle = int (*)(std::intptr_t, int);
using Reopen = void* (*)(const char*, const char*, void*);
using Duplicate = int (*)(int, int);
using Close = int (*)(int);
using FileAction = int (*)(void*);
using Error = int* (*)();

struct Report {
    std::array<unsigned char, 32> prefix;
    std::array<int, 3> beforeFd;
    std::array<int, 3> afterFd;
    std::array<std::uintptr_t, 3> beforeStd;
    std::array<std::uintptr_t, 3> afterStd;
    std::array<std::intptr_t, 3> beforeCrt;
    std::array<std::intptr_t, 3> afterCrt;
    std::array<char, 32> input;
    DWORD beforeHandles;
    DWORD afterHandles;
    unsigned duplicateCalls;
    unsigned closeHandleCalls;
    unsigned closeCalls;
    unsigned fcloseCalls;
    unsigned closedDuplicate;
    unsigned originalHandlesValid;
    unsigned flushCalls;
    int firstAllocatedFd;
    unsigned expectedError;
    unsigned temporaryDescriptorLive;
    unsigned reopenedStreamLive;
    unsigned inputCrtQueried;
    std::uintptr_t cleanupStreamHandle;
    unsigned cleanupStreamClosed;
    int cleanupResult;
    unsigned omittedGetterMask;
    DWORD beforeSnapshotHandles;
    int cleanupDescriptor;
    std::array<unsigned char, 32> suffix;
};

Report report{};
HMODULE targetModule = nullptr;
bool targetActive = false;
std::string fault;
std::filesystem::path witness;
HANDLE ownedDuplicate = nullptr;
bool unassociatedInput = false;
void* closedOutput = nullptr;

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template<typename T> T Function(const char* name) {
    const auto address = GetProcAddress(targetModule, name);
    Require(address != nullptr, "CRT test function unavailable");
    return reinterpret_cast<T>(address);
}

void* Stream(unsigned index) {
    if (targetModule == GetModuleHandleA("ucrtbase.dll")) return Function<void* (*)(unsigned)>("__acrt_iob_func")(index);
    return static_cast<unsigned char*>(Function<void* (*)()>("__iob_func")()) + index * 48;
}

void Snapshot(bool before) {
    const std::array<DWORD, 3> ids = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
    for (unsigned index = 0; index < 3; ++index) {
        const auto stream = Stream(index);
        const bool closed = !before && stream == closedOutput;
        const int descriptor = closed ? -1 : Function<Fileno>("_fileno")(stream);
        if (closed) report.omittedGetterMask |= 1u << index;
        (before ? report.beforeFd : report.afterFd)[index] = descriptor;
        (before ? report.beforeStd : report.afterStd)[index] = reinterpret_cast<std::uintptr_t>(GetStdHandle(ids[index]));
        (before ? report.beforeCrt : report.afterCrt)[index] = descriptor >= 0 && !(unassociatedInput && index == 0) ? Function<OsHandle>("_get_osfhandle")(descriptor) : -1;
    }
}

void WriteReport() {
    const auto handle = CreateFileW(witness.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    Require(handle != INVALID_HANDLE_VALUE, "cannot create stream witness");
    DWORD written = 0;
    const bool ok = WriteFile(handle, &report, sizeof(report), &written, nullptr) && written == sizeof(report);
    CloseHandle(handle);
    Require(ok, "cannot write stream witness");
}

BOOL WINAPI DuplicateProbe(HANDLE sourceProcess, HANDLE source, HANDLE destinationProcess, LPHANDLE destination,
                            DWORD access, BOOL inherit, DWORD options) {
    if (targetActive && !fault.empty() && report.duplicateCalls == 0)
        Require(GetProcessHandleCount(GetCurrentProcess(), &report.beforeHandles), "cannot read handle count before duplicate control");
    if (targetActive && fault == "win-duplicate") {
        ++report.duplicateCalls;
        report.expectedError = ERROR_ACCESS_DENIED;
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    const auto result = DuplicateHandle(sourceProcess, source, destinationProcess, destination, access, inherit, options);
    if (targetActive) {
        ++report.duplicateCalls;
        if (result) ownedDuplicate = *destination;
    }
    return result;
}

BOOL WINAPI CloseHandleProbe(HANDLE handle) {
    if (targetActive) ++report.closeHandleCalls;
    if (targetActive && fault == "cleanup-handle") { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    return CloseHandle(handle);
}

int OpenProbe(std::intptr_t handle, int flags) {
    if (fault == "open" || fault == "cleanup-handle") { report.expectedError = 24; *Function<Error>("_errno")() = 24; return -1; }
    const auto result = Function<OpenHandle>("_open_osfhandle")(handle, flags);
    if (report.firstAllocatedFd == -1 && result >= 0) report.firstAllocatedFd = result;
    return result;
}

void* ReopenProbe(const char* path, const char* mode, void* stream) {
    const auto result = Function<Reopen>("freopen")(fault == "reopen" || fault == "cleanup-close" ? "?:\\stdio-repair-invalid" : path, mode, stream);
    if (!result) {
        report.expectedError = static_cast<unsigned>(*Function<Error>("_errno")());
        closedOutput = stream;
    }
    return result;
}

int DuplicateDescriptorProbe(int source, int destination) {
    if (fault == "duplicate" || fault == "cleanup-fclose") { report.expectedError = 5; *Function<Error>("_errno")() = 5; return -1; }
    return Function<Duplicate>("_dup2")(source, destination);
}

int CloseProbe(int descriptor) {
    ++report.closeCalls;
    if (fault == "close" || fault == "cleanup-close") {
        if (fault == "close") report.expectedError = 9;
        *Function<Error>("_errno")() = 9;
        return -1;
    }
    return Function<Close>("_close")(descriptor);
}

int FcloseProbe(void* stream) {
    ++report.fcloseCalls;
    const auto descriptor = Function<Fileno>("_fileno")(stream);
    report.cleanupDescriptor = descriptor;
    Require(descriptor >= 0, "cleanup stream has no valid owned descriptor before fclose");
    const auto handle = Function<OsHandle>("_get_osfhandle")(descriptor);
    DWORD flags = 0;
    Require(GetHandleInformation(reinterpret_cast<HANDLE>(handle), &flags), "cleanup stream has no valid owned native handle before fclose");
    report.cleanupStreamHandle = static_cast<std::uintptr_t>(handle);
    if (fault == "cleanup-fclose") {
        *Function<Error>("_errno")() = 13;
        report.cleanupResult = -1;
        return -1;
    }
    report.cleanupResult = Function<FileAction>("fclose")(stream);
    if (report.cleanupResult == 0) closedOutput = stream;
    return report.cleanupResult;
}

int FlushProbe(void* stream) {
    ++report.flushCalls;
    const auto result = Function<FileAction>("fflush")(stream);
    if (fault == "flush") { *Function<Error>("_errno")() = 5; return -1; }
    return result;
}

FARPROC WINAPI AddressProbe(HMODULE module, LPCSTR name) {
    targetActive = module == targetModule;
    if (!targetActive) return GetProcAddress(module, name);
    const std::map<std::string, FARPROC> probes = {
        {"_open_osfhandle", reinterpret_cast<FARPROC>(OpenProbe)}, {"freopen", reinterpret_cast<FARPROC>(ReopenProbe)},
        {"_dup2", reinterpret_cast<FARPROC>(DuplicateDescriptorProbe)}, {"_close", reinterpret_cast<FARPROC>(CloseProbe)},
        {"fclose", reinterpret_cast<FARPROC>(FcloseProbe)}, {"fflush", reinterpret_cast<FARPROC>(FlushProbe)}
    };
    const auto found = probes.find(name);
    return found == probes.end() ? GetProcAddress(module, name) : found->second;
}

void WINAPI FailureProbe(DWORD status, DWORD, DWORD, const ULONG_PTR*) {
    Require(GetProcessHandleCount(GetCurrentProcess(), &report.beforeSnapshotHandles), "cannot read handle count before failure snapshot");
    Snapshot(false);
    Require(GetProcessHandleCount(GetCurrentProcess(), &report.afterHandles), "cannot read handle count after failure snapshot");
    DWORD flags = 0;
    report.closedDuplicate = ownedDuplicate && !GetHandleInformation(ownedDuplicate, &flags);
    report.originalHandlesValid = GetHandleInformation(reinterpret_cast<HANDLE>(report.beforeStd[1]), &flags) &&
        GetHandleInformation(reinterpret_cast<HANDLE>(report.beforeStd[2]), &flags);
    if (report.beforeStd[0] && report.beforeStd[0] != reinterpret_cast<std::uintptr_t>(INVALID_HANDLE_VALUE))
        report.originalHandlesValid &= GetHandleInformation(reinterpret_cast<HANDLE>(report.beforeStd[0]), &flags);
    report.temporaryDescriptorLive = 0;
    report.reopenedStreamLive = 0;
    report.cleanupStreamClosed = 0;
    if (report.cleanupStreamHandle)
        report.cleanupStreamClosed = !GetHandleInformation(reinterpret_cast<HANDLE>(report.cleanupStreamHandle), &flags) && GetLastError() == ERROR_INVALID_HANDLE;
    if ((fault == "close" || fault == "cleanup-close") && report.firstAllocatedFd >= 0) {
        const auto handle = Function<OsHandle>("_get_osfhandle")(report.firstAllocatedFd);
        report.temporaryDescriptorLive = GetHandleInformation(reinterpret_cast<HANDLE>(handle), &flags);
    }
    if (fault == "cleanup-fclose" && report.afterFd[1] >= 0)
        report.reopenedStreamLive = GetHandleInformation(reinterpret_cast<HANDLE>(report.afterCrt[1]), &flags);
    WriteReport();
    ExitProcess(status);
}

struct Program {
    unsigned char* memory = nullptr;
    PRUNTIME_FUNCTION table = nullptr;
    void (*repair)() = nullptr;
    void (*flush)() = nullptr;

    Program() {
        PeSection data{".startup", 0x1000, SectionRead | SectionWrite, {}};
        const WindowsStandardStreamStubBuilder builder(data);
        WindowsImports imports{};
        const std::map<std::string, FARPROC> functions = {
            {"GetModuleHandleA", reinterpret_cast<FARPROC>(GetModuleHandleA)}, {"GetProcAddress", reinterpret_cast<FARPROC>(AddressProbe)},
            {"GetStdHandle", reinterpret_cast<FARPROC>(GetStdHandle)}, {"GetCurrentProcess", reinterpret_cast<FARPROC>(GetCurrentProcess)},
            {"SetStdHandle", reinterpret_cast<FARPROC>(SetStdHandle)},
            {"DuplicateHandle", reinterpret_cast<FARPROC>(DuplicateProbe)}, {"CloseHandle", reinterpret_cast<FARPROC>(CloseHandleProbe)},
            {"GetLastError", reinterpret_cast<FARPROC>(GetLastError)}, {"WriteFile", reinterpret_cast<FARPROC>(WriteFile)},
            {"lstrlenA", reinterpret_cast<FARPROC>(lstrlenA)}, {"RaiseException", reinterpret_cast<FARPROC>(FailureProbe)}
        };
        memory = static_cast<unsigned char*>(VirtualAlloc(nullptr, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
        Require(memory != nullptr, "cannot allocate generated stream program");
        unsigned offset = 0x100;
        for (const auto& [name, function] : functions) {
            imports.Functions.emplace(name, offset);
            std::memcpy(memory + offset, &function, sizeof(function));
            offset += 8;
        }
        WindowsStubEmitter code(0x3000);
        const auto stub = builder.Build(code, imports);
        const auto bytes = code.TakeBytes();
        Require(data.Data.size() < 0x2000 && bytes.size() < 0xd000, "generated stream program overlaps storage");
        std::memcpy(memory + data.Rva, data.Data.data(), data.Data.size());
        std::memcpy(memory + 0x3000, bytes.data(), bytes.size());
        table = reinterpret_cast<PRUNTIME_FUNCTION>(memory + 0x400);
        for (unsigned index = 0; index < stub.Functions.size(); ++index) {
            const auto& range = stub.Functions[index];
            Require(range[0] < range[1] && range[0] >= 0x3000 && range[1] <= 0x3000 + bytes.size(), "invalid stream unwind range");
            Require(index == 0 || stub.Functions[index - 1][1] <= range[0], "unordered stream unwind ranges");
            table[index] = {range[0], range[1], range[2]};
        }
        Require(RtlAddFunctionTable(table, static_cast<DWORD>(stub.Functions.size()), reinterpret_cast<DWORD64>(memory)), "cannot register stream unwind ranges");
        for (const auto& range : stub.Functions) {
            DWORD64 imageBase = 0;
            const auto found = RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(memory) + range[0], &imageBase, nullptr);
            Require(found && imageBase == reinterpret_cast<DWORD64>(memory) && found->BeginAddress == range[0], "native stream unwind lookup failed");
        }
        repair = reinterpret_cast<void (*)()>(memory + stub.RepairRva);
        flush = reinterpret_cast<void (*)()>(memory + stub.FlushRva);
        FlushInstructionCache(GetCurrentProcess(), memory, 0x10000);
    }

    ~Program() {
        if (table) RtlDeleteFunctionTable(table);
        if (memory) VirtualFree(memory, 0, MEM_RELEASE);
    }
};

int Child(const std::string& runtime, const std::string& mode, const std::filesystem::path& path) {
    std::memset(&report, 0xaa, sizeof(report));
    report.duplicateCalls = report.closeHandleCalls = report.closeCalls = report.fcloseCalls = report.flushCalls = 0;
    report.beforeHandles = report.afterHandles = report.closedDuplicate = report.originalHandlesValid = 0;
    report.firstAllocatedFd = -1;
    report.expectedError = 0;
    report.temporaryDescriptorLive = report.reopenedStreamLive = 0;
    witness = path;
    fault = mode == "normal" || mode == "stdin" || mode == "slot0" ? "" : mode;
    unassociatedInput = mode == "slot0";
    report.inputCrtQueried = !unassociatedInput;
    report.cleanupStreamHandle = 0;
    report.cleanupStreamClosed = report.omittedGetterMask = report.beforeSnapshotHandles = 0;
    report.cleanupResult = -999;
    report.cleanupDescriptor = -1;
    targetModule = LoadLibraryA(runtime == "ucrt" ? "ucrtbase.dll" : "msvcrt.dll");
    Require(targetModule != nullptr, "cannot load known CRT test module");
    if (unassociatedInput) {
        const auto handle = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        Require(handle != INVALID_HANDLE_VALUE, "cannot prepare owned low descriptor");
        const auto descriptor = Function<OpenHandle>("_open_osfhandle")(reinterpret_cast<std::intptr_t>(handle), 0x8000);
        Require(descriptor >= 0, "cannot adopt owned low descriptor");
        Require(Function<Duplicate>("_dup2")(descriptor, 0) == 0, "cannot prepare descriptor zero");
        Require(Function<Close>("_close")(0) == 0, "cannot release owned descriptor zero");
        if (descriptor != 0) Require(Function<Close>("_close")(descriptor) == 0, "cannot release setup descriptor");
        Require(SetStdHandle(STD_INPUT_HANDLE, nullptr), "cannot restore unassociated input state");
    }
    const auto logPath = path.wstring() + L".log";
    const auto log = CreateFileW(logPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    Require(log != INVALID_HANDLE_VALUE, "cannot create stream test destination");
    for (const auto id : {STD_OUTPUT_HANDLE, STD_ERROR_HANDLE})
        if (!GetStdHandle(id) || GetStdHandle(id) == INVALID_HANDLE_VALUE) Require(SetStdHandle(id, log), "cannot attach stream test destination");
    Snapshot(true);
    Program program;
    program.repair();
    if (fault.empty()) program.repair();
    Snapshot(false);
    for (unsigned index = 0; index < 3; ++index) Require(report.beforeStd[index] == report.afterStd[index], "repair changed borrowed standard handle");
    Require(report.beforeFd[0] == report.afterFd[0] && report.beforeCrt[0] == report.afterCrt[0], "repair changed stdin association");
    for (unsigned index = 1; index < 3; ++index) {
        Require(report.afterFd[index] >= 0, "repair left an output unassociated");
        if (report.beforeFd[index] >= 0)
            Require(report.beforeFd[index] == report.afterFd[index] && report.beforeCrt[index] == report.afterCrt[index], "repair replaced a valid output association");
    }
    if (mode == "stdin") {
        using ReadLine = char* (*)(char*, int, void*);
        report.input.fill(static_cast<char>(0xaa));
        Require(Function<ReadLine>("fgets")(report.input.data(), static_cast<int>(report.input.size()), Stream(0)) != nullptr,
            "stdin pipe payload was consumed by repair");
        Require(std::strcmp(report.input.data(), "stdin-guard-91\n") == 0, "stdin pipe payload changed");
    }
    Function<int (*)(const char*, void*)>("fputs")("stream stdout witness\n", Stream(1));
    Function<int (*)(const char*, void*)>("fputs")("stream stderr witness\n", Stream(2));
    program.flush();
    WriteReport();
    return 11;
}

Report RunChild(const std::filesystem::path& executable, const std::string& runtime, const std::string& mode,
                unsigned outputs, const std::filesystem::path& path) {
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    HANDLE inputRead = nullptr, inputWrite = nullptr;
    Require(CreatePipe(&inputRead, &inputWrite, &attributes, 0), "cannot create stdin pipe");
    Require(SetHandleInformation(inputWrite, HANDLE_FLAG_INHERIT, 0), "cannot isolate stdin writer");
    DWORD written = 0;
    constexpr char payload[] = "stdin-guard-91\n";
    Require(WriteFile(inputWrite, payload, sizeof(payload) - 1, &written, nullptr) && written == sizeof(payload) - 1, "cannot prepare stdin witness");
    CloseHandle(inputWrite);
    const auto capturePath = path.wstring() + L".capture";
    const auto capture = CreateFileW(capturePath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, &attributes, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    Require(capture != INVALID_HANDLE_VALUE, "cannot create inherited output destination");
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = mode == "slot0" ? nullptr : inputRead;
    if (mode == "slot0") Require(SetHandleInformation(inputRead, HANDLE_FLAG_INHERIT, 0), "cannot isolate unassociated input control");
    startup.hStdOutput = outputs & 1 ? capture : nullptr;
    startup.hStdError = outputs & 2 ? capture : nullptr;
    PROCESS_INFORMATION process{};
    auto command = L"\"" + executable.wstring() + L"\" --child " + std::wstring(runtime.begin(), runtime.end()) +
        L" " + std::wstring(mode.begin(), mode.end()) + L" \"" + path.wstring() + L"\"";
    Require(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process), "cannot launch stream test child");
    CloseHandle(inputRead);
    CloseHandle(capture);
    const auto wait = WaitForSingleObject(process.hProcess, 10000);
    if (wait != WAIT_OBJECT_0) TerminateProcess(process.hProcess, 86);
    DWORD status = 0;
    Require(GetExitCodeProcess(process.hProcess, &status), "cannot read stream child result");
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    Require(wait == WAIT_OBJECT_0, "stream child timed out");
    const bool fatal = mode != "normal" && mode != "stdin" && mode != "slot0" && mode != "flush";
    if (status != (fatal ? 0xc0000142u : 11u))
        throw std::runtime_error("stream child returned status=" + std::to_string(status) + " runtime=" + runtime + " mode=" + mode +
            " outputs=" + std::to_string(outputs) + " witness=" + path.string());
    Report result{};
    std::ifstream file(path, std::ios::binary);
    Require(static_cast<bool>(file.read(reinterpret_cast<char*>(&result), sizeof(result))) && file.peek() == EOF, "stream witness length changed");
    Require(result.prefix == report.prefix && result.suffix == report.suffix, "stream witness guards changed");
    const auto readText = [](const std::filesystem::path& filename) {
        std::ifstream stream(filename, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
    };
    const auto log = readText(path.wstring() + L".log");
    const auto captured = readText(capturePath);
    if (fatal) {
        const bool cleanupFailure = mode == "close" || mode == "cleanup-handle" || mode == "cleanup-close" || mode == "cleanup-fclose";
        if (result.afterHandles != result.beforeHandles + (cleanupFailure ? 1u : 0u) ||
            result.beforeSnapshotHandles != result.beforeHandles + (cleanupFailure ? 1u : 0u)) {
            std::string associations;
            for (unsigned index = 0; index < 3; ++index)
                associations += " stream" + std::to_string(index) + "[fd=" + std::to_string(result.beforeFd[index]) + ":" +
                    std::to_string(result.afterFd[index]) + ",os=" + std::to_string(result.beforeStd[index]) + ":" +
                    std::to_string(result.afterStd[index]) + ",crt=" + std::to_string(result.beforeCrt[index]) + ":" +
                    std::to_string(result.afterCrt[index]) + "]";
            throw std::runtime_error("repair failure outstanding-handle accounting changed: runtime=" + runtime + " mode=" + mode +
                " outputs=" + std::to_string(outputs) + " before=" + std::to_string(result.beforeHandles) +
                " expected=" + std::to_string(result.beforeHandles + (cleanupFailure ? 1u : 0u)) +
                " actual=" + std::to_string(result.afterHandles) + " allocatedFd=" + std::to_string(result.firstAllocatedFd) +
                " beforeSnapshot=" + std::to_string(result.beforeSnapshotHandles) + " omittedGetterMask=" + std::to_string(result.omittedGetterMask) +
                " cleanupStreamHandle=" + std::to_string(result.cleanupStreamHandle) + " cleanupStreamClosed=" + std::to_string(result.cleanupStreamClosed) +
                " fcloseResult=" + std::to_string(result.cleanupResult) +
                " cleanupDescriptor=" + std::to_string(result.cleanupDescriptor) +
                " descriptorLive=" + std::to_string(result.temporaryDescriptorLive) + " streamLive=" + std::to_string(result.reopenedStreamLive) +
                " duplicateClosed=" + std::to_string(result.closedDuplicate) + " borrowedHandlesValid=" + std::to_string(result.originalHandlesValid) +
                " duplicates=" + std::to_string(result.duplicateCalls) + " CloseHandle=" + std::to_string(result.closeHandleCalls) +
                " close=" + std::to_string(result.closeCalls) + " fclose=" + std::to_string(result.fcloseCalls) +
                associations + " witness=" + path.string());
        }
        Require(result.originalHandlesValid, "repair failure closed a borrowed handle");
        Require((mode == "win-duplicate" || mode == "cleanup-fclose" || !cleanupFailure) ? (mode == "win-duplicate" || result.closedDuplicate) : !result.closedDuplicate,
            "repair failure temporary duplicate liveness changed");
        Require(result.duplicateCalls == 1, "failure path duplicated again");
        Require(result.closeHandleCalls == (mode == "open" || mode == "cleanup-handle" ? 1u : 0u), "failure cleanup used the wrong owner");
        Require(result.closeCalls == (mode == "open" || mode == "win-duplicate" || mode == "cleanup-handle" ? 0u : 1u), "failure cleanup missed temporary CRT descriptor");
        Require(result.fcloseCalls == (mode == "duplicate" || mode == "close" || mode == "cleanup-fclose" ? 1u : 0u), "failure cleanup missed reopened NUL stream");
        Require(result.temporaryDescriptorLive == (mode == "close" || mode == "cleanup-close" ? 1u : 0u), "temporary descriptor liveness was not reported accurately");
        Require(result.reopenedStreamLive == (mode == "cleanup-fclose" ? 1u : 0u), "reopened stream liveness was not reported accurately");
        if (result.fcloseCalls)
            Require(result.cleanupDescriptor >= 0 && result.cleanupStreamHandle && result.cleanupResult == (mode == "cleanup-fclose" ? -1 : 0) &&
                result.cleanupStreamClosed == (mode == "cleanup-fclose" ? 0u : 1u), "cleanup stream native handle ownership changed");
        Require(result.omittedGetterMask == (mode == "reopen" || mode == "cleanup-close" || mode == "duplicate" || mode == "close" ? 2u : 0u),
            "failure snapshot queried a closed output FILE or omitted a live one");
        const std::string stage = mode == "open" || mode == "cleanup-handle" ? "_open_osfhandle" : mode == "reopen" || mode == "cleanup-close" ? "freopen" :
            mode == "duplicate" || mode == "cleanup-fclose" ? "_dup2" : mode == "close" ? "_close" : "DuplicateHandle";
        const auto diagnostic = stage + ": " + (mode == "win-duplicate" ? "Win32 error " : "CRT errno ") + std::to_string(result.expectedError);
        Require(log.find("Windows CRT output repair failed: stdout in " + runtime + (runtime == "ucrt" ? "base.dll" : ".dll")) != std::string::npos &&
            log.find(diagnostic) != std::string::npos, "repair failure lost runtime, stage or numeric diagnostics");
        Require(result.beforeStd == result.afterStd, "repair failure changed a borrowed standard-handle slot");
        if (mode == "cleanup-handle") Require(log.find("CloseHandle (cleanup): Win32 error 6") != std::string::npos, "cleanup handle error was hidden");
        if (mode == "cleanup-close") Require(log.find("_close: CRT errno 9") != std::string::npos, "cleanup descriptor error was hidden");
        if (mode == "cleanup-fclose") Require(log.find("fclose: CRT errno 13") != std::string::npos, "cleanup stream error was hidden");
    } else {
        Require((outputs & 1 ? captured : log).find("stream stdout witness") != std::string::npos, "stdout witness reached the wrong destination");
        Require((outputs & 2 ? captured : log).find("stream stderr witness") != std::string::npos, "stderr witness reached the wrong destination");
        if (mode == "flush") Require(log.find("Windows CRT output flush failed") != std::string::npos && log.find("CRT errno 5") != std::string::npos,
            "flush error was not reported while preserving return code");
        if (mode == "slot0") Require(result.firstAllocatedFd == 0, "low descriptor control did not allocate slot zero");
    }
    return result;
}

}

int Run(int argc, char** argv) {
    try {
        if (argc == 5 && std::string(argv[1]) == "--child") return Child(argv[2], argv[3], argv[4]);
        std::memset(&report, 0xaa, sizeof(report));
        std::array<wchar_t, 32768> executable{};
        Require(GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size())) != 0, "cannot identify test executable");
        const auto* evidence = std::getenv("ANYPS5_STDIO_TEST_ARTIFACTS");
        const auto parent = evidence ? std::filesystem::path(evidence) : std::filesystem::temp_directory_path();
        if (evidence) std::filesystem::create_directories(parent);
        const auto directory = parent / ("anyps5-stdio-controls-" + std::to_string(GetCurrentProcessId()));
        Require(std::filesystem::create_directory(directory), "cannot create stream control directory");
        unsigned cases = 0;
        for (const std::string runtime : {"ucrt", "msvcrt"}) {
            for (unsigned outputs = 0; outputs < 4; ++outputs)
                for (const std::string mode : {"normal", "stdin"}) {
                    const auto result = RunChild(executable.data(), runtime, mode, outputs, directory / std::to_string(cases++));
                    Require(result.beforeFd[0] == result.afterFd[0], "valid stdin descriptor changed");
                    if (mode == "stdin") {
                        Require(std::strcmp(result.input.data(), "stdin-guard-91\n") == 0, "valid stdin pipe lost its payload");
                        for (std::size_t index = sizeof("stdin-guard-91\n"); index < result.input.size(); ++index)
                            Require(static_cast<unsigned char>(result.input[index]) == 0xaa, "stdin read crossed its payload guard");
                    }
                }
            for (const std::string mode : {"open", "reopen", "duplicate", "win-duplicate", "flush", "slot0", "close", "cleanup-handle", "cleanup-close", "cleanup-fclose"})
                RunChild(executable.data(), runtime, mode, 0, directory / std::to_string(cases++));
        }
        std::printf("%u native CRT stream, stdin pipe and failure cleanup cases passed\n", cases);
        if (!evidence) {
            Require(std::filesystem::weakly_canonical(directory).parent_path() == std::filesystem::weakly_canonical(parent), "stream cleanup escaped fixture parent");
            std::filesystem::remove_all(directory);
        }
        return 0;
    } catch (const std::exception& error) {
        DWORD written = 0;
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), error.what(), static_cast<DWORD>(std::strlen(error.what())), &written, nullptr);
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), "\n", 1, &written, nullptr);
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, char*, int) {
    return Run(__argc, __argv);
}
