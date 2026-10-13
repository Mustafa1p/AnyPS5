#ifndef ELFPATCHER_WINDOWS_STANDARDSTREAMSTUBBUILDER_HPP
#define ELFPATCHER_WINDOWS_STANDARDSTREAMSTUBBUILDER_HPP

#include <elfpatcher/windows/WindowsImportBuilder.hpp>
#include <elfpatcher/windows/WindowsStubEmitter.hpp>
#include <array>
#include <map>

namespace Elfpatcher::Windows {

struct WindowsStandardStreamStub {
    std::uint32_t RepairRva;
    std::uint32_t FlushRva;
    std::vector<std::array<std::uint32_t, 3>> Functions;
};

class WindowsStandardStreamStubBuilder {
public:
    explicit WindowsStandardStreamStubBuilder(PeSection& data);
    WindowsStandardStreamStub Build(WindowsStubEmitter& code, const WindowsImports& imports) const;

private:
    std::map<std::string, std::uint32_t> storage;
    std::uint32_t unwindRva;
};

}

#endif
