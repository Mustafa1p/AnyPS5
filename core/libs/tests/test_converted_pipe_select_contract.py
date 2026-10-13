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

from test_converted_library_contract import Code, sha256

PAYLOAD=b'abc'
IMPORTS=[('pipe', '-Jp7F+pXxNg', 'libkernel.prx'), ('select', 'T8fER+tIGgk', 'libkernel.prx'), ('read', 'AqBioC2vF3I', 'libkernel.prx'), ('write', 'FN4gaPmuFV8', 'libkernel.prx'), ('close', 'bY-PO6JhzhQ', 'libkernel.prx'), ('open', 'wuCroIGjt2g', 'libkernel.prx'), ('pthread_create', 'OxhIB8LB-PQ', 'libkernel.prx'), ('pthread_join', 'h9CcP3J0oVM', 'libkernel.prx'), ('usleep', 'QcteRwbsnV0', 'libkernel.prx'), ('__error', '9BcDykPmo1I', 'libc.prx'), ('exit', 'uMei1W9uyNo', 'libc.prx')]
SLOTS={name:0x7000+index*8 for index,(name,_,_) in enumerate(IMPORTS)}


class PipeCode(Code):
    def address(self,opcode,offset):
        self.emit(opcode);self.u32(offset)
    def static(self,opcode,address):
        self.emit(opcode);self.u32((address-(0x4000+len(self.data)+4))&0xffffffff)
    def function(self,name):
        self.call(SLOTS[name])
    def timeout(self,microseconds=0):
        for offset,value in ((0x240,0),(0x248,microseconds)):
            self.address('48c783',offset);self.u32(value)
    def sets(self):
        self.address('488dbb',0x10);self.emit('b91000000031c0f348ab')
        self.address('4c0faba3',0x10)
    def snapshot(self):
        self.address('488db3',0x10);self.address('488dbb',0x300);self.emit('b910000000f348a5')
    def unchanged_set(self,description):
        self.address('488db3',0x10);self.address('488dbb',0x300);self.emit('b910000000f348a7');self.failure('0f85',description)
    def mixed(self):
        self.sets();self.address('8b83',0x458);self.address('480fab83',0x10);self.snapshot()
        self.emit('4489e7');self.address('8b83',0x458);self.emit('39f80f4ff883c701')
        self.address('488db3',0x10);self.emit('31d231c9');self.address('4c8d83',0x240);self.function('select')
    def select(self,null=False):
        self.emit('4489e783c701');self.address('488db3',0x10);self.emit('31d231c9')
        if null:self.emit('4531c0')
        else:self.address('4c8d83',0x240)
        self.function('select')
    def ready(self,description):
        self.address('4c0fa3a3',0x10);self.failure('0f83',description)
    def empty(self,description):
        self.address('488dbb',0x10);self.emit('b91000000031c0f348af');self.failure('0f85',description)
    def guards(self,description):
        for offset,size in ((0,16),(0x90,0x171),(0x204,0x3c),(0x250,0xb0),(0x380,0xb0),(0x438,8),(0x450,8),(0x45c,4),(0x460,0xa0)):
            self.sentinel(offset,size,description+' '+hex(offset))
    def write(self):
        self.address('8bbb',0x434);self.static('488d35',0x7580);self.emit('ba03000000');self.function('write')
    def read(self,size):
        self.emit('4489e7');self.address('488db3',0x201);self.emit('ba');self.u32(size);self.function('read')
    def pipe(self):
        self.address('488dbb',0x430);self.function('pipe');self.status(0,'pipe creates two guest descriptors')
        self.address('448ba3',0x430);self.emit('4181fc00040000');self.failure('0f83','read descriptor fits 1024-bit ABI')
        self.address('83bb',0x434);self.emit('00');self.failure('0f88','write descriptor is nonnegative')
    def close(self,offset):
        self.address('8bbb',offset);self.function('close');self.status(0,'pipe descriptor close succeeds')
    def worker(self,cycle,null=False):
        self.address('488dbb',0x440);self.emit('31f6');self.branch('488d15','writer-'+str(cycle));self.emit('4889d9')
        self.function('pthread_create');self.status(0,'delayed guest SysV writer '+str(cycle)+' starts')
        self.sets();self.timeout(500000);self.select(null);self.status(1,'delayed writer '+str(cycle)+' makes read ready')
        self.ready('delayed writer '+str(cycle)+' retains selected read bit')
        self.address('488bbb',0x440);self.address('488db3',0x448);self.function('pthread_join')
        self.status(0,'join delayed guest writer '+str(cycle)+' succeeds')
        self.address('4881bb',0x448);self.u32(0x13579);self.failure('0f85','delayed writer full-width return is preserved')
        self.read(3);self.status(3,'delayed writer payload read is complete')
        self.address('81bb',0x201);self.u32(0xaa636261);self.failure('0f85','delayed writer abc preserves trailing byte')
        self.guards('delayed writer preserves guarded storage')
    def finish(self):
        for index,(name,_) in enumerate(self.failures,1):
            self.labels[name]=len(self.data);self.emit('bf');self.u32(index);self.function('exit');self.emit('0f0b')
        for position,name in self.branches:
            import struct
            struct.pack_into('<i',self.data,position,self.labels[name]-position-4)
        if len(self.data)>=0x2000:raise AssertionError('Fixture code overlaps dynamic section')
        return self.data


def fixture():
    code=PipeCode();code.emit('5341544881ec080500004889e34889dfb900050000b8aa000000fcf3aa')
    code.pipe();code.sets();code.timeout();code.select();code.status(0,'empty pipe with open writer is not read ready')
    code.empty('empty zero-time poll clears entire selected set');code.guards('empty poll preserves guards')
    code.sets();code.timeout(40000);code.select();code.status(0,'empty pipe finite timeout expires')
    code.empty('empty timed wait clears entire selected set');code.guards('timed wait preserves guards')
    code.static('488d3d',0x7500);code.emit('31f631d2');code.function('open')
    code.emit('85c0');code.failure('0f88','mixed ordinary-file guest open succeeds')
    code.emit('3d00040000');code.failure('0f83','mixed file descriptor fits guest bitmap')
    code.address('8983',0x458);code.timeout();code.mixed();code.status(1,'empty pipe and ordinary file select only file')
    code.address('4c0fbba3',0x300);code.unchanged_set('mixed empty pipe removes only pipe bit')
    code.write();code.status(3,'guest pipe write queues independent abc bytes')
    code.mixed();code.status(2,'queued pipe and ordinary file both select readable')
    code.unchanged_set('mixed ready pipe and file retain exactly both bits')
    code.close(0x458)

    for cycle in range(2):
        code.sets();code.timeout();code.select();code.status(1,'queued pipe repeated poll '+str(cycle)+' is readable')
        code.ready('queued poll '+str(cycle)+' retains read bit');code.guards('queued readiness preserves storage')
    code.read(2);code.status(2,'read consumes exactly the requested two bytes')
    code.address('81bb',0x201);code.u32(0xaaaa6261);code.failure('0f85','first read obtains ab and preserves suffix')
    code.sets();code.select();code.status(1,'remaining c byte keeps pipe readable');code.ready('partial read preserves readiness bit')
    code.read(1);code.status(1,'remaining byte read succeeds');code.address('80bb',0x201);code.emit('63');code.failure('0f85','remaining byte is c')
    code.sets();code.select();code.status(0,'drained pipe with open writer returns to pending');code.empty('drained pipe clears read set')
    code.close(0x434);code.sets();code.select();code.status(1,'closed final writer produces EOF read readiness');code.ready('EOF retains read bit')
    code.read(3);code.status(0,'read after EOF readiness returns zero');code.address('80bb',0x201);code.emit('63');code.failure('0f85','EOF read leaves buffer unchanged')
    code.guards('EOF readiness preserves guarded storage');code.close(0x430)
    code.sets();code.snapshot();code.function('__error');code.emit('c70000000000')
    code.select();code.status(0xffffffff,'closed pipe read descriptor select fails')
    code.function('__error');code.emit('833809');code.failure('0f85','closed pipe sets guest EBADF9')
    code.unchanged_set('closed descriptor error preserves full input bitmap');code.guards('closed pipe error preserves guards')

    code.pipe()
    for cycle,null in ((0,False),(1,True)):code.worker(cycle,null)
    code.close(0x434);code.close(0x430);code.emit('31ff');code.function('exit');code.emit('0f0b')
    for cycle in range(2):
        code.labels['writer-'+str(cycle)]=len(code.data);code.emit('534889fb')
        code.emit('bf50c30000');code.function('usleep');code.status(0,'writer sleep '+str(cycle)+' succeeds')
        code.write();code.status(3,'writer callback '+str(cycle)+' queues abc')
        code.emit('b8793501005bc3')
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
    return image, [description for _, description in code.failures]


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: test_converted_pipe_select_contract.py <relinker> <patched-libraries>")
    if platform.machine().lower() not in ("amd64", "x86_64") or not (os.name == "nt" or sys.platform.startswith("linux")):
        raise RuntimeError("Converted select contract requires x86-64 Windows or native Linux")
    if sys.platform.startswith("linux") and ("microsoft" in platform.release().lower() or "microsoft" in Path("/proc/version").read_text(errors="replace").lower()):
        raise RuntimeError("WSL does not establish native Linux runtime acceptance")
    relinker, libraries = (Path(value).resolve() for value in sys.argv[1:])
    evidence = Path(os.environ.get("ANYPS5_TEST_EVIDENCE", tempfile.gettempdir()))
    evidence.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="anyps5-converted-pipe-select-", dir=evidence))
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
                "source_sha256": sha256(source), "fixture_script_sha256": sha256(Path(__file__)), "helper_sha256": sha256(Path(__file__).with_name("test_converted_library_contract.py")), "artifacts": artifacts, "contract": expectations,
                "payload_path": str(payload), "payload_sha256_before": payload_hash, "payload_hex": PAYLOAD.hex(),
                "claim": "bounded anonymous pipe READ queued/EOF/deadline contract; write/exception/concurrent reader/close/full PS5 unverified"}
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
        raise AssertionError(("actual imports do not match the eleven guest contracts", imported, required))
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
    print("Converted guest invoked eleven actual patched NIDs; all " + str(len(expectations)) + " pipe read readiness checks passed")
    print("Evidence: " + str(manifest_path))


if __name__ == "__main__":
    main()
