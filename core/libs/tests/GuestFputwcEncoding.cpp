#include "SceTypes.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>
#include <windows.h>

class FileStream;
extern "C" {
FileStream* APS5_VABI fopen_nid_postfix(const char*, const char*);
int APS5_VABI fclose_nid_postfix(FileStream*);
int APS5_VABI fflush_nid_postfix(FileStream*);
int APS5_VABI fputwc_nid_postfix(char16_t, FileStream*);
int APS5_VABI fseek_nid_postfix(FileStream*, std::int64_t, int);
std::int64_t APS5_VABI ftell_nid_postfix(FileStream*);
int APS5_VABI ferror_nid_postfix(FileStream*);
void APS5_VABI clearerr_nid_postfix(FileStream*);
int* APS5_VABI __error_nid_postfix();
}

void Require(bool value, const char* reason) {
    if (!value) { std::fprintf(stderr, "%s\n", reason); std::exit(75); }
}

struct Api {
    decltype(&fopen_nid_postfix) open;
    decltype(&fclose_nid_postfix) close;
    decltype(&fflush_nid_postfix) flush;
    decltype(&fputwc_nid_postfix) put;
    decltype(&fseek_nid_postfix) seek;
    decltype(&ftell_nid_postfix) tell;
    decltype(&ferror_nid_postfix) error;
    decltype(&clearerr_nid_postfix) clear;
    decltype(&__error_nid_postfix) guestErrno;
};

template<class T> T Resolve(HMODULE module, const char* nid) {
    const auto address = GetProcAddress(module, nid);
    Require(address != nullptr, nid);
    return reinterpret_cast<T>(reinterpret_cast<void*>(address));
}

std::vector<unsigned char> Snapshot() {
    std::ifstream bytes("app0/fputwc-witness.bin", std::ios::binary);
    return {std::istreambuf_iterator<char>(bytes), {}};
}

int main(int argc, char** argv) {
    Require(argc == 2, "Expected isolated library directory");
    const auto supplied = std::filesystem::absolute(argv[1]) / "libc.prx";
#ifdef ANYPS5_PATCHED_FPUTWC
    const auto module = LoadLibraryExW(supplied.wstring().c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    Require(module != nullptr, "Patched libc not loaded");
    const Api api{Resolve<decltype(&fopen_nid_postfix)>(module, "xeYO4u7uyJ0"), Resolve<decltype(&fclose_nid_postfix)>(module, "uodLYyUip20"), Resolve<decltype(&fflush_nid_postfix)>(module, "MUjC4lbHrK4"), Resolve<decltype(&fputwc_nid_postfix)>(module, "1QJWxoB6pCo"), Resolve<decltype(&fseek_nid_postfix)>(module, "rQFVBXp-Cxg"), Resolve<decltype(&ftell_nid_postfix)>(module, "Qazy8LmXTvw"), Resolve<decltype(&ferror_nid_postfix)>(module, "AHxyhN96dy4"), Resolve<decltype(&clearerr_nid_postfix)>(module, "St9nbxSoezk"), Resolve<decltype(&__error_nid_postfix)>(module, "9BcDykPmo1I")};
#else
    const auto module = GetModuleHandleW(L"libc.prx");
    const Api api{fopen_nid_postfix, fclose_nid_postfix, fflush_nid_postfix, fputwc_nid_postfix, fseek_nid_postfix, ftell_nid_postfix, ferror_nid_postfix, clearerr_nid_postfix, __error_nid_postfix};
#endif
    std::array<wchar_t, 32768> actual{};
    Require(module != nullptr && GetModuleFileNameW(module, actual.data(), actual.size()) != 0 && std::filesystem::equivalent(supplied, actual.data()), "Wrong physical libc");
    std::array<char, 64> path{"/app0/fputwc-witness.bin"};
    std::array<char, 16> mode{"r+b"};
    const auto pathCopy = path;
    const auto modeCopy = mode;
    FileStream* stream = api.open(path.data(), mode.data());
    Require(stream != nullptr, "Guest own-file open failed");
    Require(path == pathCopy && mode == modeCopy, "Open string input changed");
    Require(api.seek(stream, 32, 0) == 0 && api.tell(stream) == 32 && api.error(stream) == 0, "Initial stream state failed");
    const std::array<char16_t, 4> valid{u'A', 0x00e9, 0xd7ff, 0xe000};
    for (const auto value : valid) {
        *api.guestErrno() = 123;
        Require(api.put(value, stream) == value, "Valid character result failed");
        Require(*api.guestErrno() == 123 && api.error(stream) == 0, "Valid character errno/error state changed");
    }
    Require(api.flush(stream) == 0 && api.tell(stream) == 41, "Valid UTF8 byte count failed");
    const std::array<char16_t, 4> invalid{0xd800, 0xdbff, 0xdc00, 0xdfff};
    for (std::size_t index = 0; index < invalid.size(); ++index) {
        const auto before = Snapshot();
        const auto position = api.tell(stream);
        *api.guestErrno() = 123;
        Require(api.put(invalid[index], stream) == -1, "Surrogate was accepted");
        Require(*api.guestErrno() == 86, "Surrogate did not set guest EILSEQ");
        Require(api.error(stream) != 0, "Surrogate did not set stream error");
        Require(api.tell(stream) == position, "Surrogate changed file position");
        Require(api.flush(stream) == 0 && Snapshot() == before, "Surrogate changed host file bytes");
        api.clear(stream);
        Require(api.error(stream) == 0 && *api.guestErrno() == 86, "Clearerr did not clear flag and preserve errno");
        const auto recovery = static_cast<char16_t>(u'R' + index);
        *api.guestErrno() = 123;
        Require(api.put(recovery, stream) == recovery && *api.guestErrno() == 123 && api.error(stream) == 0, "Valid output did not recover");
        Require(api.flush(stream) == 0 && api.tell(stream) == position + 1, "Recovery write size failed");
    }
    Require(api.close(stream) == 0, "Own-file close failed");
    auto expected = std::vector<unsigned char>(256, 0xaa);
    const std::array<unsigned char, 13> output{0x41, 0xc3, 0xa9, 0xed, 0x9f, 0xbf, 0xee, 0x80, 0x80, 0x52, 0x53, 0x54, 0x55};
    std::copy(output.begin(), output.end(), expected.begin() + 32);
    Require(Snapshot() == expected, "Independent full guarded host file differs");
    std::puts("fputwc encoding edges, error/clearerr recovery and guarded13-byte file witness PASS");
}
