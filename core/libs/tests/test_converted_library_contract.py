import hashlib
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

RANDOM_NID = "PI7jIZj4pcE"
EXIT_NID = "uMei1W9uyNo"
INVALID = 0x817C0016


class Code:
    def __init__(self):
        self.data = bytearray()
        self.labels = {}
        self.branches = []
        self.failures = []

    def emit(self, value):
        self.data.extend(bytes.fromhex(value))

    def u32(self, value):
        self.data.extend(struct.pack("<I", value))

    def call(self, address):
        self.emit("ff15")
        self.data.extend(struct.pack("<i", address - (0x4000 + len(self.data) + 4)))

    def branch(self, opcode, name):
        self.emit(opcode)
        self.branches.append((len(self.data), name))
        self.u32(0)

    def failure(self, opcode, description):
        name = "failure" + str(len(self.failures) + 1)
        self.failures.append((name, description))
        self.branch(opcode, name)

    def random(self, size, null=False):
        self.emit("31ff" if null else "488d7b10")
        self.emit("be")
        self.u32(size)
        self.call(0x4A20)

    def status(self, value, description):
        self.emit("3d")
        self.u32(value)
        self.failure("0f85", description)

    def sentinel(self, offset, size, description):
        self.emit("488dbb")
        self.u32(offset)
        self.emit("b9")
        self.u32(size)
        self.emit("b0aaf3ae")
        self.failure("0f85", description)

    def finish(self):
        self.emit("31ff")
        self.call(0x4A28)
        self.emit("0f0b")
        for index, (name, _) in enumerate(self.failures, 1):
            self.labels[name] = len(self.data)
            self.emit("bf")
            self.u32(index)
            self.call(0x4A28)
            self.emit("0f0b")
        for position, name in self.branches:
            struct.pack_into("<i", self.data, position, self.labels[name] - position - 4)
        if len(self.data) >= 0x600:
            raise AssertionError("Fixture code overlaps its dynamic section")
        return self.data


def configure_fixture_loads(image, code_size, data_start):
    if code_size <= 0 or 0x4000 + code_size > data_start or data_start >= len(image):
        raise AssertionError("Fixture code and data load ranges overlap or are empty")
    struct.pack_into("<IIQQQQQQ", image, 64,
                     1, 5, 0x4000, 0x4000, 0x4000, code_size, code_size, 0x1000)
    data_size = len(image) - data_start
    struct.pack_into("<IIQQQQQQ", image, 64 + 2 * 56,
                     1, 6, data_start, data_start, data_start, data_size, data_size, 0x1000)


def fixture():
    code = Code()
    code.emit("5341544881ecd80000004889e3")
    code.emit("4889dfb9c0000000b8aa000000fcf3aa")
    code.random(16, null=True)
    code.status(INVALID, "null buffer must report invalid argument")
    code.sentinel(0, 192, "null call must not alter fixture storage")
    code.random(65)
    code.status(INVALID, "65-byte request must report invalid argument")
    code.sentinel(0, 192, "oversize call must not write any byte")
    code.random(0)
    code.status(0, "nonnull zero-byte request must succeed")
    code.sentinel(0, 192, "zero-byte call must not write any byte")
    code.random(7)
    code.status(0, "seven-byte request must succeed")
    code.sentinel(0, 16, "partial request must preserve leading guard")
    code.sentinel(23, 169, "partial request must preserve all bytes beyond its range")
    code.emit("488d7b10b907000000b0aaf3ae")
    code.failure("0f84", "partial request must write data")
    code.emit("488d7b10b940000000b8aa000000f3aa")
    code.random(64)
    code.status(0, "64-byte request must succeed")
    code.sentinel(0, 16, "maximum request must preserve leading guard")
    code.sentinel(80, 112, "maximum request must preserve trailing storage")
    code.emit("488d7b10b940000000b0aaf3ae")
    code.failure("0f84", "maximum request must write data")
    code.emit("488d7b70be40000000")
    code.call(0x4A20)
    code.status(0, "second 64-byte request must succeed")
    code.sentinel(0, 16, "second request must preserve leading guard")
    code.sentinel(80, 32, "second request must preserve between-buffer guards")
    code.sentinel(176, 16, "second request must preserve trailing guard")
    code.emit("488d7b70b940000000b0aaf3ae")
    code.failure("0f84", "second maximum request must write data")
    code.emit("488d7b10488d7370b940000000f3a6")
    code.failure("0f84", "independent 64-byte requests must not repeat all bytes")
    body = code.finish()
    image = bytearray(0x8000)
    image[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", image, 16,
                     3, 62, 1, 0x4000, 64, 0, 0, 64, 56, 5, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", image, 64,
                     1, 7, 0x4000, 0x4000, 0x4000, 0x1000, 0x1000, 0x4000)
    for index in range(2, 5):
        struct.pack_into("<IIQQQQQQ", image, 64 + index * 56,
                         0x6FFFFF01, 0, 0, 0, 0, 0, 0, 1)
    strings = bytearray(b"\0")
    offsets = {}
    for value in (RANDOM_NID + "#A#B", "libSceRandom.prx", EXIT_NID + "#A#C", "libc.prx"):
        offsets[value] = len(strings)
        strings.extend(value.encode() + b"\0")
    if len(strings) > 0x40:
        raise AssertionError("Fixture string table overlaps its hash table")
    image[0x4800:0x4800 + len(strings)] = strings
    tags = [(5, 0x4800), (10, len(strings)), (6, 0x4880), (11, 24),
            (4, 0x4840), (7, 0x4900), (8, 48), (9, 24),
            (1, offsets["libSceRandom.prx"]), (1, offsets["libc.prx"]),
            (0x61000045, (1 << 48) | offsets["libSceRandom.prx"]),
            (0x61000045, (2 << 48) | offsets["libc.prx"]), (0, 0)]
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", image, 0x4600 + index * 16, *tag)
    struct.pack_into("<IIQQQQQQ", image, 120,
                     2, 6, 0x4600, 0x4600, 0x4600, len(tags) * 16, len(tags) * 16, 8)
    struct.pack_into("<IIIIII", image, 0x4840, 1, 3, 1, 0, 2, 0)
    for index, symbol in enumerate((RANDOM_NID + "#A#B", EXIT_NID + "#A#C"), 1):
        struct.pack_into("<IBBHQQ", image, 0x4880 + 24 * index,
                         offsets[symbol], 0x12, 0, 0, 0, 0)
        struct.pack_into("<QQq", image, 0x4900 + 24 * (index - 1),
                         0x4A20 + 8 * (index - 1), (index << 32) | 6, 0)
    image[0x4000:0x4000 + len(body)] = body
    return image, [description for _, description in code.failures]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: test_converted_library_contract.py <relinker> <patched-libraries>")
    if platform.machine().lower() not in ("amd64", "x86_64") or not (os.name == "nt" or sys.platform.startswith("linux")):
        raise RuntimeError("Converted-library runtime test requires x86-64 Windows or Linux")
    if sys.platform.startswith("linux"):
        kernel = platform.release().lower()
        version = Path("/proc/version")
        if "microsoft" in kernel or (version.is_file() and "microsoft" in version.read_text(errors="replace").lower()):
            raise RuntimeError("WSL execution does not establish native Linux runtime acceptance")
    relinker, libraries = (Path(value).resolve() for value in sys.argv[1:])
    evidence_directory = Path(os.environ.get("ANYPS5_TEST_EVIDENCE", tempfile.gettempdir()))
    evidence_directory.mkdir(parents=True, exist_ok=True)
    directory = tempfile.mkdtemp(prefix="anyps5-converted-random-", dir=evidence_directory)
    work = Path(directory)
    (work / "sce_module").mkdir()
    runtime = work / "libs"
    runtime.mkdir()
    artifacts = []
    for name in ("libSceRandom.prx", "libc.prx", "libkernel.prx"):
        original = libraries / name
        target = runtime / original.name
        shutil.copy2(original, target)
        original_hash = sha256(original)
        if sha256(target) != original_hash:
            raise AssertionError("Runtime PRX differs from the requested patched build: " + str(original))
        artifacts.append({"source": str(original), "sha256": original_hash})
    if not {"libSceRandom.prx", "libc.prx", "libkernel.prx"}.issubset({path.name for path in runtime.glob("*.prx")}):
        raise AssertionError("Patched runtime requires libSceRandom, libc and libkernel")
    if os.name == "nt":
        for name in ("libgcc_s_seh-1.dll", "libstdc++-6.dll", "libwinpthread-1.dll"):
            candidates = [libraries / name, libraries / "unpatched" / name]
            candidates.extend(Path(part) / name for part in os.environ.get("PATH", "").split(os.pathsep) if part)
            original = next((path for path in candidates if path.is_file()), None)
            if original is None:
                raise FileNotFoundError("Cannot locate the supported MinGW runtime " + name)
            shutil.copy2(original, runtime / name)
            original_hash = sha256(original)
            if sha256(runtime / name) != original_hash:
                raise AssertionError("Runtime DLL differs from its selected toolchain artifact: " + str(original))
            artifacts.append({"source": str(original), "sha256": original_hash, "kind": "mingw-runtime"})
    source = work / "input.elf"
    image, expectations = fixture()
    source.write_bytes(image)
    output = work / ("output.exe" if os.name == "nt" else "output.elf")
    command = [str(relinker), "--registry", *(["--windows"] if os.name == "nt" else []), str(source), str(output)]
    start = time.monotonic()
    converted = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=10)
    (work / "conversion.stdout.txt").write_text(converted.stdout, encoding="utf-8")
    (work / "conversion.stderr.txt").write_text(converted.stderr, encoding="utf-8")
    (work / "conversion.command.json").write_text(json.dumps(command) + "\n", encoding="utf-8")
    if converted.returncode != 0:
        raise AssertionError(("conversion failed", converted.returncode, converted.stdout, converted.stderr))
    registry = json.loads(output.with_suffix(".registry.json").read_text(encoding="utf-8"))
    imported = {(entry["nid"], entry["library"]) for entry in registry}
    required = {(RANDOM_NID + "#A#B", "libSceRandom.prx"), (EXIT_NID + "#A#C", "libc.prx")}
    if not required.issubset(imported):
        raise AssertionError(("actual fixture imports do not match contract", imported))
    output.chmod(output.stat().st_mode | 0o111)
    environment = os.environ.copy()
    environment["APS5_TRACE_EXIT"] = "1"
    executed = subprocess.run([str(output)], cwd=work, env=environment,
                              capture_output=True, text=True, timeout=10)
    manifest = {"platform": platform.platform(), "machine": platform.machine(),
                "command": command, "fixture_artifacts": str(work),
                "conversion_stdout": converted.stdout, "conversion_stderr": converted.stderr, "source_sha256": sha256(source), "output_sha256": sha256(output),
                "relinker_sha256": sha256(relinker), "imports": sorted(imported), "artifacts": artifacts,
                "duration_seconds": time.monotonic() - start, "returncode": executed.returncode,
                "stdout": executed.stdout, "stderr": executed.stderr,
                "contract": expectations, "claim": "bounded AnyPS5 random-buffer contract; console equivalence unverified"}
    manifest_path = work / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (work / "runtime.stdout.txt").write_text(executed.stdout, encoding="utf-8")
    (work / "runtime.stderr.txt").write_text(executed.stderr, encoding="utf-8")
    if executed.returncode != 0:
        expectation = expectations[executed.returncode - 1] if 0 < executed.returncode <= len(expectations) else "loader, ABI, or process failure"
        raise AssertionError((expectation, executed.returncode, executed.stdout, executed.stderr, str(manifest_path)))
    if "[libc] exit(0) called" not in executed.stderr:
        raise AssertionError(("clean shutdown did not call the patched libc exit", executed.stderr))
    print("Converted guest invoked patched random and libc NIDs; all " + str(len(expectations)) + " behavioral checks passed")
    print("Evidence: " + str(manifest_path))


if __name__ == "__main__":
    main()
