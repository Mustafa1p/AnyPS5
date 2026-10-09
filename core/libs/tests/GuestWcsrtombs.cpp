#include "prx/libc/include/general/VabiMacros.hpp"
#include <array>
#include <cerrno>
#include <clocale>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>
#ifdef ANYPS5_PATCHED_WCSRTOMBS
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#endif

#ifndef ANYPS5_PATCHED_WCSRTOMBS
extern "C" std::size_t APS5_VABI wcsrtombs_nid_postfix(char*, const std::uint16_t**, std::size_t, void*);
extern "C" int APS5_VABI swprintf_nid_postfix(char16_t*, std::size_t, const char16_t*, ...);
#else
static std::size_t (APS5_VABI *wcsrtombs_nid_postfix)(char*, const std::uint16_t**, std::size_t, void*);
static int (APS5_VABI *swprintf_nid_postfix)(char16_t*, std::size_t, const char16_t*, ...);
#endif

static void Require(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "%s\n", message);
        std::abort();
    }
}

static void CheckConversion() {
    const std::uint16_t text[] = {'a', 'b', 'c', 0};
    const std::uint16_t invalid[] = {'a', 0x100, 'b', 0};
    const std::uint16_t empty[] = {0};
    std::uint64_t state[2]{};
    const std::uint16_t* source = text;
    std::array<char, 8> buffer;
    buffer.fill('x');
    Require(wcsrtombs_nid_postfix(nullptr, &source, 0, state) == 3, "sizing ignores capacity");
    Require(source == text, "sizing preserves source");
    Require(wcsrtombs_nid_postfix(buffer.data() + 1, &source, 0, state) == 0, "zero capacity returns zero");
    Require(source == text && buffer[1] == 'x', "zero capacity preserves storage");
    Require(wcsrtombs_nid_postfix(buffer.data() + 1, &source, 2, state) == 2, "partial conversion length");
    Require(source == text + 2 && std::memcmp(buffer.data(), "xabxxxxx", 8) == 0, "partial conversion cursor and guards");
    Require(wcsrtombs_nid_postfix(buffer.data() + 3, &source, 2, state) == 1, "resume excludes terminator");
    Require(source == nullptr && std::memcmp(buffer.data(), "xabc\0xxx", 8) == 0, "resume terminates and preserves guards");
    buffer.fill('x');
    source = text;
    Require(wcsrtombs_nid_postfix(buffer.data() + 1, &source, 3, nullptr) == 3, "exact nonterminated capacity");
    Require(source == text + 3 && std::memcmp(buffer.data(), "xabcxxxx", 8) == 0, "terminator left for next call");
    Require(wcsrtombs_nid_postfix(buffer.data() + 4, &source, 1, nullptr) == 0 && source == nullptr, "terminator-only resume");
    source = empty;
    Require(wcsrtombs_nid_postfix(buffer.data() + 6, &source, 1, state) == 0 && source == nullptr, "empty string");
    Require(buffer[5] == 'x' && buffer[6] == 0 && buffer[7] == 'x', "empty string guards");
    source = invalid;
    buffer.fill('x');
    errno = 0;
    Require(wcsrtombs_nid_postfix(buffer.data() + 1, &source, 5, state) == static_cast<std::size_t>(-1), "encoding failure");
    Require(errno == 86 && source == invalid + 1 && std::memcmp(buffer.data(), "xaxxxxxx", 8) == 0, "encoding failure cursor and guards");
    source = invalid;
    errno = 0;
    Require(wcsrtombs_nid_postfix(nullptr, &source, 0, state) == static_cast<std::size_t>(-1), "sizing detects encoding failure");
    Require(errno == 86 && source == invalid, "sizing failure preserves source");
}

static void CheckFormatting() {
    std::array<char16_t, 40> buffer;
    buffer.fill(u'x');
    const auto result = swprintf_nid_postfix(buffer.data() + 1, 32, u"%d:%lld:%.2f:%ls:%s", -12,
        4294967297LL, 1.25, u"\u03a9", "ab");
    const std::u16string expected = u"-12:4294967297:1.25:\u03a9:ab";
    Require(result == static_cast<int>(expected.size()), "swprintf excludes terminator from length");
    Require(std::u16string(buffer.data() + 1) == expected, "swprintf guest strings and integer widths");
    Require(buffer[0] == u'x' && buffer[expected.size() + 2] == u'x', "swprintf output guards");
    int count = -1;
    Require(swprintf_nid_postfix(buffer.data() + 1, 32, u"ab%ncd", &count) == 4 && count == 2,
        "swprintf count conversion");
    Require(std::u16string(buffer.data() + 1) == u"abcd", "swprintf count output");
    buffer.fill(u'x');
    Require(swprintf_nid_postfix(buffer.data() + 1, 3, u"abcd") < 0, "swprintf reports truncation");
    Require(buffer[0] == u'x' && buffer[4] == u'x', "swprintf truncation guards");
    Require(swprintf_nid_postfix(buffer.data() + 1, 1, u"") == 0 && buffer[1] == 0,
        "swprintf empty output fits one unit");
    buffer.fill(u'x');
    Require(swprintf_nid_postfix(buffer.data() + 1, 0, u"a") < 0 && buffer[1] == u'x',
        "swprintf zero capacity preserves output");
}

int main(int argc, char** argv) {
#ifdef ANYPS5_PATCHED_WCSRTOMBS
    Require(argc == 2, "expected patched libc path");
#ifdef _WIN32
    const auto path = std::filesystem::absolute(argv[1]);
    const auto module = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    Require(module != nullptr, "load patched libc");
    std::array<wchar_t, 32768> loadedPath{};
    const auto length = GetModuleFileNameW(module, loadedPath.data(), static_cast<DWORD>(loadedPath.size()));
    Require(length != 0 && length < loadedPath.size(), "identify loaded libc path");
    Require(std::filesystem::equivalent(std::filesystem::absolute(argv[1]), std::filesystem::path(loadedPath.data())),
        "host exception runtime loaded libc from another build");
    std::printf("Loaded patched libc: %s\n", std::filesystem::absolute(argv[1]).string().c_str());
    const auto address = GetProcAddress(module, "sOOMlZoy1pg");
    const auto formattingAddress = GetProcAddress(module, "nJz16JE1txM");
#else
    const auto module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    Require(module != nullptr, "load patched libc");
    const auto address = dlsym(module, "sOOMlZoy1pg");
    const auto formattingAddress = dlsym(module, "nJz16JE1txM");
#endif
    Require(address != nullptr, "resolve patched wcsrtombs NID");
    wcsrtombs_nid_postfix = reinterpret_cast<decltype(wcsrtombs_nid_postfix)>(address);
    Require(formattingAddress != nullptr, "resolve patched swprintf NID");
    swprintf_nid_postfix = reinterpret_cast<decltype(swprintf_nid_postfix)>(formattingAddress);
#else
    static_cast<void>(argc);
    static_cast<void>(argv);
#endif
    Require(std::setlocale(LC_CTYPE, "C") != nullptr, "C locale available");
    CheckConversion();
    CheckFormatting();
    const char* utf8 = std::setlocale(LC_CTYPE, ".UTF-8");
    if (!utf8) utf8 = std::setlocale(LC_CTYPE, "C.UTF-8");
    if (utf8) CheckConversion();
    std::array<std::thread, 4> workers;
    for (auto& worker : workers) worker = std::thread([] { for (int i = 0; i < 100; ++i) CheckConversion(); });
    for (auto& worker : workers) worker.join();
}
