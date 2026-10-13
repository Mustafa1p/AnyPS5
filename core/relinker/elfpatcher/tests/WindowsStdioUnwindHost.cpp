#define NOMINMAX
#include <windows.h>
#include <array>
#include <cstdint>
#include <cstring>

namespace {

struct Entry {
    RUNTIME_FUNCTION function;
    std::array<unsigned char, 24> unwind;
};

struct Witness {
    std::array<unsigned char, 32> prefix;
    DWORD count;
    std::array<Entry, 32> entries;
    std::array<unsigned char, 32> suffix;
};

}

extern "C" int shared() {
    auto* base = reinterpret_cast<unsigned char*>(GetModuleHandleW(nullptr));
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (!base || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return 71;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 72;
    const auto size = nt->OptionalHeader.SizeOfImage;
    const auto directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!directory.Size || directory.Size % sizeof(RUNTIME_FUNCTION) || directory.VirtualAddress > size ||
        directory.Size > size - directory.VirtualAddress) return 73;
    const auto count = directory.Size / sizeof(RUNTIME_FUNCTION);
    if (count > 32) return 74;
    auto* functions = reinterpret_cast<RUNTIME_FUNCTION*>(base + directory.VirtualAddress);
    Witness witness;
    std::memset(&witness, 0xaa, sizeof(witness));
    witness.count = static_cast<DWORD>(count);
    DWORD previousEnd = 0;
    for (DWORD index = 0; index < count; ++index) {
        const auto function = functions[index];
        if (function.BeginAddress < previousEnd || function.BeginAddress >= function.EndAddress ||
            function.EndAddress > size || function.UnwindData > size || 24 > size - function.UnwindData) return 75;
        previousEnd = function.EndAddress;
        auto* unwind = base + function.UnwindData;
        if ((unwind[0] & 7) != 1 || unwind[1] > function.EndAddress - function.BeginAddress || unwind[2] > 9) return 76;
        for (const auto address : {function.BeginAddress, function.EndAddress - 1}) {
            DWORD64 imageBase = 0;
            auto* found = RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(base + address), &imageBase, nullptr);
            if (!found || imageBase != reinterpret_cast<DWORD64>(base) ||
                std::memcmp(found, &function, sizeof(function))) return 77;
        }
        witness.entries[index].function = function;
        std::memcpy(witness.entries[index].unwind.data(), unwind, 24);
    }
    wchar_t path[32768];
    const auto length = GetEnvironmentVariableW(L"ANYPS5_STDIO_UNWIND_WITNESS", path, 32768);
    if (!length || length >= 32768) return 78;
    const auto handle = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return 79;
    DWORD written = 0;
    const bool ok = WriteFile(handle, &witness, sizeof(witness), &written, nullptr) && written == sizeof(witness);
    const bool closed = CloseHandle(handle);
    return ok && closed ? static_cast<int>(count) : 80;
}
