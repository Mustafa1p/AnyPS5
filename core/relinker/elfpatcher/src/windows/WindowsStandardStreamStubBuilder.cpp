#include <elfpatcher/windows/WindowsStandardStreamStubBuilder.hpp>
#include <codegen/x86/X64Assembler.hpp>
#include <io/BufferUtils.hpp>

namespace Elfpatcher::Windows {

namespace {

using enum Codegen::X64Register;
using Assembler = Codegen::X64Assembler<WindowsStubEmitter>;
constexpr std::array<const char*, 9> CrtFunctions = {
    "", "_fileno", "_open_osfhandle", "freopen", "_dup2", "_close", "fflush", "fclose", "_errno"
};

}

WindowsStandardStreamStubBuilder::WindowsStandardStreamStubBuilder(PeSection& data) {
    Io::AlignBuffer(data.Data, 8);
    for (const auto* name : {"ucrtFunctions", "msvcrtFunctions", "runtime", "channel", "stage", "kind", "error", "heading", "inputHandle", "outputHandle", "errorHandle"}) {
        storage.emplace(name, CheckedRva(data.Rva + data.Data.size()));
        data.Data.resize(data.Data.size() + (std::string(name).ends_with("Functions") ? CrtFunctions.size() * 8 : 8));
    }
    storage.emplace("digits", CheckedRva(data.Rva + data.Data.size()));
    data.Data.resize(data.Data.size() + 32);
    const std::map<std::string, std::string> text = {
        {"ucrt", "ucrtbase.dll"}, {"msvcrt", "msvcrt.dll"},
        {"ucrtGetter", "__acrt_iob_func"}, {"msvcrtGetter", "__iob_func"},
        {"stdout", "stdout"}, {"stderr", "stderr"}, {"streams", "stdout/stderr"},
        {"repairHeading", "Windows CRT output repair failed: "},
        {"flushHeading", "Windows CRT output flush failed: "},
        {"in", " in "}, {"at", " at "}, {"separator", ": "}, {"newline", "\n"},
        {"winError", "Win32 error "}, {"crtError", "CRT errno "},
        {"duplicate", "DuplicateHandle"}, {"closeHandle", "CloseHandle (cleanup)"}, {"restore", "SetStdHandle (restore)"},
        {"nul", "NUL"}, {"mode", "w"}
    };
    for (const auto& [name, value] : text) {
        storage.emplace(name, CheckedRva(data.Rva + data.Data.size()));
        Io::AppendString(data.Data, value);
    }
    for (std::size_t index = 1; index < CrtFunctions.size(); ++index) {
        storage.emplace(CrtFunctions[index], CheckedRva(data.Rva + data.Data.size()));
        Io::AppendString(data.Data, CrtFunctions[index]);
    }
    Io::AlignBuffer(data.Data, 4);
    unwindRva = CheckedRva(data.Rva + data.Data.size());
    data.Data.insert(data.Data.end(), {1, 16, 9, 0, 16, 0x82, 12, 0xf0, 10, 0xe0, 8, 0xd0, 6, 0xc0, 4, 0x70, 3, 0x60, 2, 0x50, 1, 0x30, 0, 0});
}

WindowsStandardStreamStub WindowsStandardStreamStubBuilder::Build(WindowsStubEmitter& code, const WindowsImports& imports) const {
    Assembler a(code, imports.Functions, storage);
    const auto set = [&](const std::string& field, const std::string& name) {
        a.Data(Ax, name);
        a.Save(field, Ax);
    };
    const auto crt = [&](const std::size_t index) {
        set("stage", CrtFunctions[index]);
        a.Load(Ax, R12, static_cast<std::uint32_t>(index * 8));
        code.Emit({0xff, 0xd0});
    };
    const auto signedResult = [&] { code.Emit({0x48, 0x63, 0xc0}); };
    const auto boolResult = [&] { code.Emit({0x85, 0xc0}); };

    a.Begin("write");
    a.Mov(Si, Cx);
    a.Api("lstrlenA");
    code.Emit({0x89, 0xc0});
    a.Mov(Bx, Ax);
    for (const auto handle : {0xfffffff4u, 0xfffffff5u}) {
        a.Value(Cx, handle);
        a.Api("GetStdHandle");
        a.Test(Ax);
        a.Jump("writeNext" + std::to_string(handle), 0x84);
        a.CompareValue(Ax, 0xffffffffu);
        a.Jump("writeNext" + std::to_string(handle), 0x84);
        a.Mov(Cx, Ax);
        a.Mov(Dx, Si);
        a.Mov(R8, Bx);
        a.Address(R9, Sp, 56);
        a.Value(Ax, 0);
        a.Store(Sp, 32, Ax);
        a.Api("WriteFile");
        boolResult();
        a.Jump("writeNext" + std::to_string(handle), 0x84);
        a.Load(Ax, Sp, 56, 4);
        a.Compare(Ax, Bx);
        a.Jump("writeDone", 0x84);
        a.Mark("writeNext" + std::to_string(handle));
    }
    a.Mark("writeDone");
    a.End();

    a.Begin("number");
    a.Global(Ax, "error");
    a.Data(Di, "digits");
    a.AddValue(Di, 31);
    code.Emit({0xc6, 0x07, 0});
    a.Value(R8, 10);
    a.Mark("numberDigit");
    code.Emit({0x31, 0xd2, 0x49, 0xf7, 0xf0, 0x80, 0xc2, 0x30, 0x48, 0xff, 0xcf, 0x88, 0x17});
    a.Test(Ax);
    a.Jump("numberDigit", 0x85);
    a.Mov(Cx, Di);
    a.Call("write");
    a.End();

    a.Begin("report");
    for (const auto* name : {"heading", "channel"}) {
        a.Global(Cx, name);
        a.Call("write");
    }
    a.Text("in");
    a.Global(Cx, "runtime");
    a.Call("write");
    a.Text("at");
    a.Global(Cx, "stage");
    a.Call("write");
    a.Text("separator");
    a.Global(Cx, "kind");
    a.Call("write");
    a.Call("number");
    a.Text("newline");
    a.End();

    a.Begin("fatal");
    a.Call("report");
    a.Value(Cx, 0xc0000142u);
    a.Value(Dx, 1);
    a.Value(R8, 0);
    a.Value(R9, 0);
    a.Api("RaiseException");
    code.Emit({0x0f, 0x0b});
    a.End();

    a.Begin("winError");
    a.Api("GetLastError");
    code.Emit({0x89, 0xc0});
    a.Save("error", Ax);
    set("kind", "winError");
    a.End();

    a.Begin("crtError");
    a.Load(Ax, R12, 64);
    code.Emit({0xff, 0xd0});
    a.Load(Ax, Ax, 0, 4);
    a.Save("error", Ax);
    set("kind", "crtError");
    a.End();

    a.Begin("restoreHandles");
    a.Global(R13, "error");
    a.Global(R14, "stage");
    a.Global(R15, "kind");
    for (const auto& [id, name] : std::map<std::uint32_t, std::string>{
             {0xfffffff6u, "inputHandle"}, {0xfffffff5u, "outputHandle"}, {0xfffffff4u, "errorHandle"}}) {
        a.Value(Cx, id);
        a.Api("GetStdHandle");
        a.Global(Bx, name);
        a.Compare(Ax, Bx);
        a.Jump("restored" + name, 0x84);
        a.Value(Cx, id);
        a.Mov(Dx, Bx);
        set("stage", "restore");
        a.Api("SetStdHandle");
        boolResult();
        a.Jump("restored" + name, 0x85);
        a.Call("winError");
        a.Call("fatal");
        a.Mark("restored" + name);
    }
    a.Save("error", R13);
    a.Save("stage", R14);
    a.Save("kind", R15);
    a.End();

    a.Begin("cleanup");
    a.Mov(Bx, Cx);
    a.Mov(Bp, Dx);
    a.Mov(R12, R8);
    a.Mov(Di, R9);
    a.Global(R13, "error");
    a.Global(R14, "stage");
    a.Global(R15, "kind");
    a.CompareValue(Bx, 0xffffffffu);
    a.Jump("cleanupFile", 0x84);
    a.Mov(Cx, Bx);
    a.Test(Di);
    a.Jump("cleanupDescriptor", 0x84);
    set("stage", "closeHandle");
    a.Api("CloseHandle");
    boolResult();
    a.Jump("cleanupFile", 0x85);
    a.Call("winError");
    a.Call("restoreHandles");
    a.Call("report");
    a.Jump("cleanupFile");
    a.Mark("cleanupDescriptor");
    crt(5);
    boolResult();
    a.Jump("cleanupFile", 0x84);
    a.Call("crtError");
    a.Call("restoreHandles");
    a.Call("report");
    a.Mark("cleanupFile");
    a.Test(Bp);
    a.Jump("cleanupDone", 0x84);
    a.Mov(Cx, Bp);
    crt(7);
    boolResult();
    a.Jump("cleanupDone", 0x84);
    a.Call("crtError");
    a.Call("restoreHandles");
    a.Call("report");
    a.Mark("cleanupDone");
    a.Save("error", R13);
    a.Save("stage", R14);
    a.Save("kind", R15);
    a.End();

    a.Begin("repairOne");
    a.Mov(Bx, Cx);
    a.Mov(Bp, Dx);
    a.Mov(R12, R8);
    crt(1);
    signedResult();
    a.CompareValue(Ax, 0xfffffffeu);
    a.Jump("repairDone", 0x85);
    a.Mov(Cx, Bp);
    a.Api("GetStdHandle");
    a.Test(Ax);
    a.Jump("repairDone", 0x84);
    a.CompareValue(Ax, 0xffffffffu);
    a.Jump("repairDone", 0x84);
    a.Mov(Bp, Ax);
    a.Api("GetCurrentProcess");
    a.Mov(R15, Ax);
    a.Mov(Cx, R15);
    a.Mov(Dx, Bp);
    a.Mov(R8, R15);
    a.Address(R9, Sp, 56);
    a.Value(Ax, 0);
    a.Store(Sp, 32, Ax);
    a.Store(Sp, 40, Ax);
    a.Value(Ax, 2);
    a.Store(Sp, 48, Ax);
    set("stage", "duplicate");
    a.Api("DuplicateHandle");
    boolResult();
    a.Jump("repairDuplicateFailed", 0x84);
    a.Load(Si, Sp, 56);
    a.Mov(Cx, Si);
    a.Value(Dx, 0x8001);
    crt(2);
    signedResult();
    a.CompareValue(Ax, 0xffffffffu);
    a.Jump("repairOpenFailed", 0x84);
    a.Mov(Si, Ax);
    a.Data(Cx, "nul");
    a.Data(Dx, "mode");
    a.Mov(R8, Bx);
    crt(3);
    a.Test(Ax);
    a.Jump("repairReopenFailed", 0x84);
    a.Mov(Cx, Bx);
    crt(1);
    signedResult();
    a.Test(Ax);
    a.Jump("repairOwnedFileFailed", 0x88);
    a.Mov(Di, Ax);
    a.Compare(Si, Di);
    a.Jump("repairDone", 0x84);
    a.Mov(Cx, Si);
    a.Mov(Dx, Di);
    crt(4);
    boolResult();
    a.Jump("repairOwnedFileFailed", 0x85);
    a.Mov(Cx, Si);
    crt(5);
    boolResult();
    a.Jump("repairDone", 0x84);
    a.Call("crtError");
    a.Value(Cx, 0xffffffffffffffffu);
    a.Mov(Dx, Bx);
    a.Mov(R8, R12);
    a.Value(R9, 0);
    a.Call("cleanup");
    a.Call("restoreHandles");
    a.Call("fatal");
    a.Mark("repairOwnedFileFailed");
    a.Call("crtError");
    a.Mov(Cx, Si);
    a.Mov(Dx, Bx);
    a.Mov(R8, R12);
    a.Value(R9, 0);
    a.Call("cleanup");
    a.Call("restoreHandles");
    a.Call("fatal");
    a.Mark("repairReopenFailed");
    a.Call("crtError");
    a.Mov(Cx, Si);
    a.Value(Dx, 0);
    a.Mov(R8, R12);
    a.Value(R9, 0);
    a.Call("cleanup");
    a.Call("restoreHandles");
    a.Call("fatal");
    a.Mark("repairOpenFailed");
    a.Call("crtError");
    a.Mov(Cx, Si);
    a.Value(Dx, 0);
    a.Mov(R8, R12);
    a.Value(R9, 1);
    a.Call("cleanup");
    a.Call("restoreHandles");
    a.Call("fatal");
    a.Mark("repairDuplicateFailed");
    a.Call("winError");
    a.Call("restoreHandles");
    a.Call("fatal");
    a.Mark("repairDone");
    a.Call("restoreHandles");
    a.End();

    a.Begin("flushOne");
    a.Mov(Bx, Cx);
    a.Mov(R12, R8);
    crt(1);
    signedResult();
    a.Test(Ax);
    a.Jump("flushDone", 0x88);
    a.Mov(Cx, Bx);
    crt(6);
    boolResult();
    a.Jump("flushDone", 0x84);
    a.Call("crtError");
    a.Call("report");
    a.Mark("flushDone");
    a.End();

    for (const bool flushing : {false, true}) {
        const std::string phase = flushing ? "flush" : "repair";
        a.Begin(phase);
        set("heading", flushing ? "flushHeading" : "repairHeading");
        if (!flushing)
            for (const auto& [id, name] : std::map<std::uint32_t, std::string>{
                     {0xfffffff6u, "inputHandle"}, {0xfffffff5u, "outputHandle"}, {0xfffffff4u, "errorHandle"}}) {
                a.Value(Cx, id);
                a.Api("GetStdHandle");
                a.Save(name, Ax);
            }
        for (const std::string runtime : {"ucrt", "msvcrt"}) {
            set("channel", "streams");
            set("runtime", runtime);
            a.Data(Cx, runtime);
            a.Api("GetModuleHandleA");
            a.Test(Ax);
            a.Jump(phase + runtime + "Done", 0x84);
            a.Mov(Bx, Ax);
            a.Data(R12, runtime + "Functions");
            for (const std::size_t index : {8u, 0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u}) {
                const std::string name = index == 0 ? runtime + "Getter" : CrtFunctions[index];
                a.Data(Dx, name);
                a.Save("stage", Dx);
                a.Mov(Cx, Bx);
                a.Api("GetProcAddress");
                a.Test(Ax);
                a.Jump(phase + runtime + "ResolveFailed", 0x84);
                a.Store(R12, static_cast<std::uint32_t>(index * 8), Ax);
            }
            for (const std::uint32_t index : {1u, 2u}) {
                set("channel", index == 1 ? "stdout" : "stderr");
                set("stage", runtime + "Getter");
                a.Value(Cx, index);
                a.Load(Ax, R12);
                code.Emit({0xff, 0xd0});
                a.Test(Ax);
                a.Jump(phase + runtime + "GetterFailed", 0x84);
                if (runtime == "msvcrt") a.AddValue(Ax, index * 48);
                a.Mov(Cx, Ax);
                a.Value(Dx, index == 1 ? 0xfffffff5u : 0xfffffff4u);
                a.Mov(R8, R12);
                a.Call(phase + "One");
            }
            a.Jump(phase + runtime + "Done");
            a.Mark(phase + runtime + "ResolveFailed");
            a.Call("winError");
            a.Call(flushing ? "report" : "fatal");
            a.Jump(phase + runtime + "Done");
            a.Mark(phase + runtime + "GetterFailed");
            a.Call("crtError");
            a.Call(flushing ? "report" : "fatal");
            a.Mark(phase + runtime + "Done");
        }
        a.End();
    }
    a.Finish();
    WindowsStandardStreamStub result{a.Label("repair"), a.Label("flush"), {}};
    for (const auto& [start, end] : a.Functions()) result.Functions.push_back({start, end, unwindRva});
    return result;
}

}
