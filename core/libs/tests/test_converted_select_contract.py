import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import time

from test_converted_library_contract import Code, configure_fixture_loads, sha256

PAYLOAD = b"AnyPS5 select fixture payload."
IMPORTS = [
    ("open", "wuCroIGjt2g", "libkernel.prx"),
    ("select", "T8fER+tIGgk", "libkernel.prx"),
    ("read", "AqBioC2vF3I", "libkernel.prx"),
    ("lseek", "Oy6IpwgtYOk", "libkernel.prx"),
    ("close", "bY-PO6JhzhQ", "libkernel.prx"),
    ("__error", "9BcDykPmo1I", "libc.prx"),
    ("exit", "uMei1W9uyNo", "libc.prx"),
]
SLOTS = {name: 0x7000 + index * 8 for index, (name, _, _) in enumerate(IMPORTS)}


class SelectCode(Code):
    def address(self, opcode, offset):
        self.emit(opcode)
        self.u32(offset)

    def function(self, name):
        self.call(SLOTS[name])

    def descriptor(self):
        self.emit("4489e7")

    def cursor(self, expected, description):
        self.descriptor()
        self.emit("31f6ba01000000")
        self.function("lseek")
        self.emit("483d")
        self.u32(expected)
        self.failure("0f85", description)

    def sets(self):
        for offset in (0x10, 0xA0):
            self.address("488dbb", offset)
            self.emit("b91000000031c0f348ab")
            self.address("4c0faba3", offset)
        self.snapshot()

    def snapshot(self):
        for source, target in ((0x10, 0x300), (0xA0, 0x380)):
            self.address("488db3", source)
            self.address("488dbb", target)
            self.emit("b910000000f348a5")

    def unchanged_sets(self, description):
        for original, actual in ((0x300, 0x10), (0x380, 0xA0)):
            self.address("488db3", original)
            self.address("488dbb", actual)
            self.emit("b910000000f348a7")
            self.failure("0f85", description + (" readfds" if actual == 0x10 else " writefds"))

    def timeout(self, seconds=0, microseconds=0):
        for offset, value in ((0x240, seconds), (0x248, microseconds)):
            self.address("48c783", offset)
            self.u32(value & 0xFFFFFFFF)

    def unchanged_timeout(self, seconds, microseconds, description):
        for offset, value in ((0x240, seconds), (0x248, microseconds)):
            self.address("4881bb", offset)
            self.u32(value & 0xFFFFFFFF)
            self.failure("0f85", description)

    def select(self, nfds=None):
        if nfds is None:
            self.descriptor()
            self.emit("83c701")
        else:
            self.emit("bf")
            self.u32(nfds & 0xFFFFFFFF)
        self.address("488db3", 0x10)
        self.address("488d93", 0xA0)
        self.emit("31c9")
        self.address("4c8d83", 0x240)
        self.function("select")

    def guards(self, description):
        for offset, size in ((0, 16), (0x90, 16), (0x120, 0xE0), (0x200, 1),
                             (0x201 + len(PAYLOAD), 0x240 - 0x201 - len(PAYLOAD)),
                             (0x250, 0xB0), (0x400, 0x100)):
            self.sentinel(offset, size, description)

    def errno(self, expected, description):
        self.function("__error")
        self.emit("8338")
        self.emit(f"{expected:02x}")
        self.failure("0f85", description)

    def clear_errno(self):
        self.function("__error")
        self.emit("c70000000000")

    def finish(self):
        self.emit("31ff")
        self.function("exit")
        self.emit("0f0b")
        for index, (name, _) in enumerate(self.failures, 1):
            self.labels[name] = len(self.data)
            self.emit("bf")
            self.u32(index)
            self.function("exit")
            self.emit("0f0b")
        for position, name in self.branches:
            struct.pack_into("<i", self.data, position, self.labels[name] - position - 4)
        if len(self.data) >= 0x2000:
            raise AssertionError("Fixture code overlaps its dynamic section")
        return self.data


def fixture():
    code = SelectCode()
    code.emit("5341544881ec080500004889e34889dfb900050000b8aa000000fcf3aa")
    code.emit("488d3d")
    code.u32(0x7500 - (0x4000 + len(code.data) + 4))
    code.emit("be0200000031d2")
    code.function("open")
    code.emit("85c0")
    code.failure("0f88", "guest open must succeed")
    code.emit("3d00040000")
    code.failure("0f83", "opened descriptor must fit the guest 1024-bit set")
    code.emit("4189c4")
    code.cursor(0, "new file cursor must be zero")
    code.sets()
    code.timeout()
    code.select()
    code.status(2, "regular file must contribute both read and write readiness")
    code.unchanged_sets("ready descriptor bits and all other set bits must be preserved")
    code.unchanged_timeout(0, 0, "select must preserve the supplied timeout")
    code.cursor(0, "select must not consume file data or move its cursor")
    code.sentinel(0x200, 0x40, "select must not alter the read buffer")
    code.guards("select must preserve storage guards")
    code.descriptor()
    code.address("488db3", 0x201)
    code.emit("ba")
    code.u32(len(PAYLOAD))
    code.function("read")
    code.emit("483d")
    code.u32(len(PAYLOAD))
    code.failure("0f85", "guest read must return the complete independent payload")
    code.address("488dbb", 0x201)
    code.emit("488d35")
    code.u32(0x7580 - (0x4000 + len(code.data) + 4))
    code.emit("b9")
    code.u32(len(PAYLOAD))
    code.emit("f3a6")
    code.failure("0f85", "guest read payload must match host-created bytes")
    code.guards("guest read must preserve buffer and set guards")
    code.cursor(len(PAYLOAD), "guest read cursor must advance by the payload length")
    code.select()
    code.status(2, "regular file at EOF must remain readable and writable")
    code.unchanged_sets("EOF readiness must preserve both descriptor sets")
    code.unchanged_timeout(0, 0, "EOF readiness must preserve timeout")
    code.cursor(len(PAYLOAD), "EOF readiness must not move the file cursor")
    code.descriptor()
    code.address("488db3", 0x201)
    code.emit("ba")
    code.u32(len(PAYLOAD))
    code.function("read")
    code.status(0, "guest read after EOF readiness must return zero")
    code.address("488dbb", 0x201)
    code.emit("488d35")
    code.u32(0x7580 - (0x4000 + len(code.data) + 4))
    code.emit("b9")
    code.u32(len(PAYLOAD))
    code.emit("f3a6")
    code.failure("0f85", "EOF read must leave the previous buffer contents unchanged")
    code.guards("EOF read must preserve guards")
    code.descriptor()
    code.function("close")
    code.status(0, "guest close must succeed")
    code.clear_errno()
    code.select()
    code.status(0xFFFFFFFF, "select on the closed descriptor must fail")
    code.errno(9, "closed descriptor must set guest EBADF")
    code.unchanged_sets("closed descriptor error must leave both sets unchanged")
    code.unchanged_timeout(0, 0, "closed descriptor error must preserve timeout")
    code.guards("closed descriptor error must preserve guards")
    for nfds, seconds, microseconds, description in (
        (-1, 0, 0, "negative nfds"),
        (1025, 0, 0, "nfds beyond the guest set capacity"),
        (0, -1, 0, "negative timeval seconds"),
        (0, 0, -1, "negative timeval microseconds"),
        (0, 0, 1000000, "timeval microseconds at one million"),
    ):
        code.timeout(seconds, microseconds)
        code.clear_errno()
        code.select(nfds)
        code.status(0xFFFFFFFF, description + " must fail")
        code.errno(22, description + " must set guest EINVAL")
        code.unchanged_sets(description + " must leave both sets unchanged")
        code.unchanged_timeout(seconds, microseconds, description + " must preserve timeout")
        code.guards(description + " must preserve guards")
    body = code.finish()
    image = bytearray(0x9000)
    image[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", image, 16, 3, 62, 1, 0x4000, 64, 0, 0, 64, 56, 5, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", image, 64, 1, 7, 0x4000, 0x4000, 0x4000, 0x4000, 0x4000, 0x4000)
    for index in range(2, 5):
        struct.pack_into("<IIQQQQQQ", image, 64 + index * 56, 0x6FFFFF01, 0, 0, 0, 0, 0, 0, 1)
    strings = bytearray(b"\0")
    offsets = {}
    symbols = []
    for _, nid, library in IMPORTS:
        symbol = nid + ("#A#B" if library == "libkernel.prx" else "#A#C")
        symbols.append(symbol)
        for value in (symbol, library):
            if value not in offsets:
                offsets[value] = len(strings)
                strings.extend(value.encode() + b"\0")
    if len(strings) > 0x200:
        raise AssertionError("Fixture string table overlaps its hash table")
    image[0x6100:0x6100 + len(strings)] = strings
    tags = [(5, 0x6100), (10, len(strings)), (6, 0x6400), (11, 24),
            (4, 0x6300), (7, 0x6600), (8, len(IMPORTS) * 24), (9, 24),
            (1, offsets["libkernel.prx"]), (1, offsets["libc.prx"]),
            (0x61000045, (1 << 48) | offsets["libkernel.prx"]),
            (0x61000045, (2 << 48) | offsets["libc.prx"]), (0, 0)]
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", image, 0x6000 + index * 16, *tag)
    struct.pack_into("<IIQQQQQQ", image, 120, 2, 6, 0x6000, 0x6000, 0x6000, len(tags) * 16, len(tags) * 16, 8)
    struct.pack_into("<III", image, 0x6300, 1, len(IMPORTS) + 1, 1)
    for index in range(1, len(IMPORTS) + 1):
        struct.pack_into("<I", image, 0x6300 + 12 + index * 4, index + 1 if index < len(IMPORTS) else 0)
    for index, symbol in enumerate(symbols, 1):
        struct.pack_into("<IBBHQQ", image, 0x6400 + 24 * index, offsets[symbol], 0x12, 0, 0, 0, 0)
        struct.pack_into("<QQq", image, 0x6600 + 24 * (index - 1), 0x7000 + 8 * (index - 1), (index << 32) | 6, 0)
    image[0x4000:0x4000 + len(body)] = body
    path = b"/app0/select-fixture.bin\0"
    image[0x7500:0x7500 + len(path)] = path
    image[0x7580:0x7580 + len(PAYLOAD)] = PAYLOAD
    configure_fixture_loads(image, len(body), 0x6000)
    return image, [description for _, description in code.failures]


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: test_converted_select_contract.py <relinker> <patched-libraries>")
    if platform.machine().lower() not in ("amd64", "x86_64") or not (os.name == "nt" or sys.platform.startswith("linux")):
        raise RuntimeError("Converted select contract requires x86-64 Windows or native Linux")
    if sys.platform.startswith("linux") and ("microsoft" in platform.release().lower() or "microsoft" in Path("/proc/version").read_text(errors="replace").lower()):
        raise RuntimeError("WSL does not establish native Linux runtime acceptance")
    relinker, libraries = (Path(value).resolve() for value in sys.argv[1:])
    evidence = Path(os.environ.get("ANYPS5_TEST_EVIDENCE", tempfile.gettempdir()))
    evidence.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="anyps5-converted-select-", dir=evidence))
    (work / "sce_module").mkdir()
    runtime = work / "libs"
    runtime.mkdir()
    artifacts = []
    for name in ("libkernel.prx", "libc.prx"):
        original = libraries / name
        target = runtime / name
        shutil.copy2(original, target)
        if sha256(target) != sha256(original):
            raise AssertionError("Copied PRX differs from the requested patched artifact")
        artifacts.append({"source": str(original), "copy": str(target), "sha256": sha256(original), "kind": "patched-prx"})
    if os.name == "nt":
        for name in ("libgcc_s_seh-1.dll", "libstdc++-6.dll", "libwinpthread-1.dll"):
            candidates = [libraries / name, libraries / "unpatched" / name]
            candidates.extend(Path(part) / name for part in os.environ.get("PATH", "").split(os.pathsep) if part)
            original = next((p for p in candidates if p.is_file()), None)
            if original is None:
                raise FileNotFoundError("Cannot locate MinGW runtime " + name)
            target = runtime / name
            shutil.copy2(original, target)
            if sha256(target) != sha256(original):
                raise AssertionError("Copied runtime differs from the selected toolchain artifact")
            artifacts.append({"source": str(original), "copy": str(target), "sha256": sha256(original), "kind": "mingw-runtime"})
    (work / "app0").mkdir()
    payload = work / "app0" / "select-fixture.bin"
    payload.write_bytes(PAYLOAD)
    payload_hash = sha256(payload)
    source = work / "input.elf"
    image, expectations = fixture()
    source.write_bytes(image)
    output = work / ("output.exe" if os.name == "nt" else "output.elf")
    command = [str(relinker), "--registry", *(["--windows"] if os.name == "nt" else []), str(source), str(output)]
    runtime_command = [str(output)]
    manifest_path = work / "manifest.json"
    manifest = {"platform": platform.platform(), "machine": platform.machine(), "fixture_artifacts": str(work),
                "conversion_command": command, "runtime_command": runtime_command, "cwd": str(work),
                "runtime_environment_overrides": {"APS5_TRACE_EXIT": "1"}, "relinker_sha256": sha256(relinker),
                "source_sha256": sha256(source), "artifacts": artifacts, "contract": expectations,
                "payload_path": str(payload), "payload_sha256_before": payload_hash, "payload_hex": PAYLOAD.hex(),
                "claim": "bounded regular-file read/write select contract; exception descriptors, pipes, signals and full PS5 equivalence unverified"}
    def save():
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    save()
    start = time.monotonic()
    converted = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=10)
    manifest.update(conversion_returncode=converted.returncode, conversion_stdout=converted.stdout, conversion_stderr=converted.stderr)
    (work / "conversion.stdout.txt").write_text(converted.stdout, encoding="utf-8")
    (work / "conversion.stderr.txt").write_text(converted.stderr, encoding="utf-8")
    save()
    if converted.returncode != 0:
        raise AssertionError(("conversion failed", converted.returncode, converted.stderr, str(manifest_path)))
    registry_path = output.with_suffix(".registry.json")
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    imported = {(entry["nid"], entry["library"]) for entry in registry}
    required = {(nid + ("#A#B" if library == "libkernel.prx" else "#A#C"), library) for _, nid, library in IMPORTS}
    if imported != required:
        raise AssertionError(("actual imports do not match the seven guest contracts", imported, required))
    manifest.update(imports=sorted(imported), registry_sha256=sha256(registry_path), output_sha256=sha256(output))
    save()
    output.chmod(output.stat().st_mode | 0o111)
    environment = os.environ.copy()
    environment["APS5_TRACE_EXIT"] = "1"
    try:
        executed = subprocess.run(runtime_command, cwd=work, env=environment, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired as error:
        manifest.update(runtime_timeout=True, duration_seconds=time.monotonic() - start, payload_sha256_after=sha256(payload))
        save()
        raise AssertionError(("guest runtime timed out", str(manifest_path))) from error
    manifest.update(returncode=executed.returncode, stdout=executed.stdout, stderr=executed.stderr,
                    duration_seconds=time.monotonic() - start, payload_sha256_after=sha256(payload),
                    payload_unchanged=payload.read_bytes() == PAYLOAD and sha256(payload) == payload_hash)
    (work / "runtime.stdout.txt").write_text(executed.stdout, encoding="utf-8")
    (work / "runtime.stderr.txt").write_text(executed.stderr, encoding="utf-8")
    save()
    if executed.returncode != 0:
        expectation = expectations[executed.returncode - 1] if 0 < executed.returncode <= len(expectations) else "loader, ABI or process failure"
        raise AssertionError((expectation, executed.returncode, executed.stderr, str(manifest_path)))
    if not manifest["payload_unchanged"]:
        raise AssertionError(("host independently observed altered payload", str(manifest_path)))
    if "[libc] exit(0) called" not in executed.stderr:
        raise AssertionError(("guest did not terminate through patched libc exit", str(manifest_path)))
    print("Converted guest invoked seven actual patched NIDs; all " + str(len(expectations)) + " select contract checks passed")
    print("Evidence: " + str(manifest_path))


if __name__ == "__main__":
    main()
