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

HELPER = Path(__file__).resolve().with_name('test_converted_library_contract.py')
IMPORTS = [('create', 'OxhIB8LB-PQ', 'libkernel.prx'), ('join', 'h9CcP3J0oVM', 'libkernel.prx'), ('thread_id', '3eqs37G74-s', 'libkernel.prx'), ('get', 'Pdgml4rbxYk', 'libkernel.prx'), ('set', '5KWrg7-ZqvE', 'libkernel.prx'), ('cpu', 'g0VTBxfJyu0', 'libkernel.prx'), ('sleep', 'QcteRwbsnV0', 'libkernel.prx'), ('open', 'wuCroIGjt2g', 'libkernel.prx'), ('seek', 'Oy6IpwgtYOk', 'libkernel.prx'), ('write', 'FN4gaPmuFV8', 'libkernel.prx'), ('close', 'bY-PO6JhzhQ', 'libkernel.prx'), ('error', '9BcDykPmo1I', 'libc.prx'), ('exit', 'uMei1W9uyNo', 'libc.prx')]
SHARED = 0x7c00
JOIN_VALUE = 0x12345678bbcc0044
SIGNATURE = 0xc05e7f005a5a5a5a
ORIGINAL = bytes([0xaa]) * 256
EXPECTED = ORIGINAL[:32] + struct.pack('<QIIQQ', 16, 4, 1, JOIN_VALUE, SIGNATURE) + ORIGINAL[64:]


class CpusetCode(Code):
    def address(self, opcode, offset):
        self.emit(opcode)
        self.u32(offset)

    def static(self, opcode, address):
        self.emit(opcode)
        self.u32((address - (0x4000 + len(self.data) + 4)) & 0xffffffff)

    def function(self, name):
        self.call(0x7000 + 8 * [item[0] for item in IMPORTS].index(name))

    def store(self, offset, value):
        self.address('c783', offset)
        self.u32(value)

    def store64(self, offset, value):
        self.emit('48b8')
        self.data.extend(struct.pack('<Q', value))
        self.address('488983', offset)

    def expect(self, offset, value, description):
        self.address('81bb', offset)
        self.u32(value)
        self.failure('0f85', description)

    def equal(self, first, second, size, description):
        self.address('488dbb', first)
        self.address('488db3', second)
        self.emit('b9')
        self.u32(size)
        self.emit('fcf3a6')
        self.failure('0f85', description)

    def fill(self, offset, size, byte):
        self.address('488dbb', offset)
        self.emit('b9')
        self.u32(size)
        self.emit('b0' + format(byte, '02x') + 'fcf3aa')

    def cpuset(self, operation, output, size=32, self_id=False, null=False, missing=False):
        if operation == 'set':
            if self_id or missing:
                raise AssertionError('Setter control requires its actual created worker handle')
            self.address('488bbb', 0)
            self.emit('be')
            self.u32(size)
            if null:
                self.emit('31d2')
            else:
                self.address('488d93', output)
            self.function(operation)
            return
        self.emit('bf03000000be01000000')
        if missing:
            self.emit('48c7c2ffffff7f')
        elif self_id:
            self.emit('48c7c2ffffffff')
        else:
            self.address('488b93', 0x18)
        self.emit('b9')
        self.u32(size)
        if null:
            self.emit('4531c0')
        else:
            self.address('4c8d83', output)
        self.function(operation)

    def error(self, expected, description):
        self.status(0xffffffff, description + ' return -1')
        self.function('error')
        self.emit('8138')
        self.u32(expected)
        self.failure('0f85', description + ' errno')

    def mask(self, offset, value, description):
        self.expect(offset, value, description + ' low CPU bits')
        for word in range(4, 32, 4):
            self.expect(offset + word, 0, description + ' upper word ' + str(word))

    def phase(self, expected, name):
        self.emit('41bc88130000')
        self.labels['poll-' + name] = len(self.data)
        self.address('81bb', 0x20)
        self.u32(expected)
        self.branch('0f84', 'ready-' + name)
        self.emit('bfe8030000')
        self.function('sleep')
        self.status(0, name + ' poll sleep succeeds')
        self.emit('41ffcc')
        self.branch('0f85', 'poll-' + name)
        self.emit('31c0')
        self.status(1, name + ' rendezvous completes within bounded polls')
        self.labels['ready-' + name] = len(self.data)

    def guards(self, description):
        for offset, size in ((0x28, 8), (0x38, 8), (0x60, 32), (0xa0, 32),
                             (0xe0, 32), (0x120, 32), (0x160, 32), (0x1a0, 96), (0x220, 0x1e0)):
            self.sentinel(offset, size, description + ' guard ' + hex(offset))

    def finish(self):
        for index, (name, _) in enumerate(self.failures, 1):
            self.labels[name] = len(self.data)
            self.emit('bf')
            self.u32(index)
            self.function('exit')
            self.emit('0f0b')
        for position, name in self.branches:
            struct.pack_into('<i', self.data, position, self.labels[name] - position - 4)
        if len(self.data) >= 0x2000:
            raise AssertionError('Fixture instructions overlap metadata')
        return self.data


def fixture():
    c = CpusetCode()
    c.emit('5341544883ec08')
    c.static('488d1d', SHARED)
    c.store(0x20, 0)
    c.store(0x24, 0)
    c.function('thread_id')
    c.emit('4863c0')
    c.address('488983', 0x10)
    c.cpuset('get', 0x80, self_id=True)
    c.status(0, 'parent self affinity query succeeds')
    for word in range(8, 32, 4):
        c.expect(0x80 + word, 0, 'parent mask upper word ' + str(word) + ' is zero')
    c.emit('4889df31f6')
    c.branch('488d15', 'worker')
    c.emit('4889d9')
    c.function('create')
    c.status(0, 'create actual SysV guest worker succeeds')
    c.phase(1, 'worker-ready')
    c.address('488b83', 0x10)
    c.address('483983', 0x18)
    c.failure('0f84', 'worker publishes a different actual guest TID')
    c.cpuset('get', 0x100)
    c.status(0, 'read another live guest thread affinity')
    c.equal(0x100, 0x80, 32, 'new worker inherits parent affinity before modification')
    c.fill(0x140, 32, 0)
    c.store(0x140, 16)
    c.function('error')
    c.emit('c70075000000')
    c.cpuset('set', 0x140)
    c.status(0, 'set another live guest handle singleton CPU4')
    c.function('error')
    c.emit('813875000000')
    c.failure('0f85', 'successful POSIX setter preserves guest errno')
    c.mask(0x140, 16, 'setter does not modify its input')
    c.fill(0x100, 32, 0xaa)
    c.cpuset('get', 0x100)
    c.status(0, 'read changed live worker affinity')
    c.mask(0x100, 16, 'changed worker mask')
    c.cpuset('get', 0xc0, self_id=True)
    c.status(0, 'read unchanged parent affinity')
    c.equal(0xc0, 0x80, 32, 'targeted setter leaves parent affinity unchanged')
    c.store(0x148, 1)
    c.cpuset('set', 0x140)
    c.status(0, 'preserve existing acceptance of unused upper cpuset bytes')
    c.expect(0x148, 1, 'successful setter preserves unused input upper data')
    c.store(0x148, 0)
    c.fill(0x180, 32, 0)
    c.cpuset('set', 0x180)
    c.status(11, 'empty clipped mask returns direct EDEADLK')
    c.mask(0x180, 0, 'rejected zero input remains unchanged')
    c.cpuset('set', 0x140, size=31)
    c.status(34, 'live handle invalid size returns direct ERANGE')
    c.cpuset('set', 0x140, size=31, null=True)
    c.status(34, 'live handle size validation precedes null mask')
    c.cpuset('set', 0x140, null=True)
    c.status(14, 'live handle null mask returns direct EFAULT')
    c.fill(0x100, 32, 0xaa)
    c.cpuset('get', 0x100, size=7)
    c.error(34, 'short output reports ERANGE')
    c.sentinel(0x100, 32, 'short output error preserves entire buffer')
    c.cpuset('get', 0x100, size=7, missing=True)
    c.error(34, 'short output takes precedence over missing target')
    c.sentinel(0x100, 32, 'combined invalid size and missing TID preserves output')
    c.cpuset('get', 0x100, null=True)
    c.error(14, 'null output rejects without writing storage')
    c.sentinel(0x100, 32, 'null output error leaves previous guarded storage unchanged')
    c.cpuset('get', 0x100)
    c.status(0, 'read live target after rejected operations')
    c.mask(0x100, 16, 'rejected operations leave target unchanged')
    c.guards('before releasing worker')
    c.store(0x20, 2)
    c.address('488bbb', 0)
    c.address('488db3', 8)
    c.function('join')
    c.status(0, 'join actual guest worker succeeds')
    c.emit('48b8')
    c.data.extend(struct.pack('<Q', JOIN_VALUE))
    c.address('483983', 8)
    c.failure('0f85', 'join preserves full64-bit SysV callback return')
    c.expect(0x24, 1, 'worker callback ran exactly once')
    c.expect(0x30, 4, 'worker reports CPU4 through existing guest CPU model')
    c.mask(0x40, 16, 'worker independently observes its own updated mask')
    c.fill(0x100, 32, 0xaa)
    c.cpuset('get', 0x100)
    c.error(3, 'joined target TID reports ESRCH')
    c.sentinel(0x100, 32, 'dead target getter preserves entire output')
    c.cpuset('set', 0x140)
    c.status(3, 'joined target handle reports project direct ESRCH')
    c.cpuset('set', 0x140, size=31, null=True)
    c.status(3, 'joined target validation precedes size and mask errors')
    c.mask(0x140, 16, 'dead target setter preserves input')
    c.cpuset('get', 0xc0, self_id=True)
    c.status(0, 'parent self query still succeeds after target join')
    c.equal(0xc0, 0x80, 32, 'parent affinity remains unchanged after target lifecycle')
    c.guards('after target lifecycle')
    c.address('488b83', 0x40)
    c.address('488983', 0x200)
    c.address('8b83', 0x30)
    c.address('8983', 0x208)
    c.address('8b83', 0x24)
    c.address('8983', 0x20c)
    c.address('488b83', 8)
    c.address('488983', 0x210)
    c.store64(0x218, SIGNATURE)
    c.static('488d3d', 0x7800)
    c.emit('be0200000031d2')
    c.function('open')
    c.emit('85c0')
    c.failure('0f88', 'open real witness file')
    c.emit('4189c44489e7be2000000031d2')
    c.function('seek')
    c.emit('483d20000000')
    c.failure('0f85', 'seek witness to guarded offset32')
    c.emit('4489e7')
    c.address('488db3', 0x200)
    c.emit('ba20000000')
    c.function('write')
    c.emit('483d20000000')
    c.failure('0f85', 'write32 actual guest-observed witness bytes')
    c.emit('4489e7')
    c.function('close')
    c.status(0, 'close witness file')
    c.emit('31ff')
    c.function('exit')
    c.emit('0f0b')
    c.labels['worker'] = len(c.data)
    c.emit('5341544883ec084889fb')
    c.function('thread_id')
    c.emit('85c0')
    c.failure('0f8e', 'worker actual guest TID is positive')
    c.emit('4863c0')
    c.address('488983', 0x18)
    c.address('f08383', 0x24)
    c.emit('01')
    c.store(0x20, 1)
    c.phase(2, 'parent-update')
    c.cpuset('get', 0x40, self_id=True)
    c.status(0, 'worker self query succeeds after targeted update')
    c.mask(0x40, 16, 'worker observes CPU4 singleton through self query')
    c.function('cpu')
    c.address('8983', 0x30)
    c.status(4, 'worker current CPU is within updated singleton guest affinity')
    c.store(0x20, 3)
    c.emit('48b8')
    c.data.extend(struct.pack('<Q', JOIN_VALUE))
    c.emit('4883c408415c5bc3')
    body = c.finish()
    image = bytearray(0xa000)
    image[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', image, 16, 3, 62, 1, 0x4000, 64, 0, 0, 64, 56, 5, 64, 0, 0)
    for index in range(2, 5):
        struct.pack_into('<IIQQQQQQ', image, 64 + index * 56, 0x6fffff01, 0, 0, 0, 0, 0, 0, 1)
    configure_fixture_loads(image, len(body), 0x6000)
    strings, offsets, symbols = bytearray(b'\0'), {}, []
    for _, nid, library in IMPORTS:
        symbol = nid + ('#A#B' if library == 'libkernel.prx' else '#A#C')
        symbols.append(symbol)
        for value in (symbol, library):
            if value not in offsets:
                offsets[value] = len(strings)
                strings.extend(value.encode() + b'\0')
    if len(strings) >= 0x200 or (len(IMPORTS) + 1) * 24 > 0x200:
        raise AssertionError('Fixture dynamic metadata overlaps')
    image[0x6100:0x6100 + len(strings)] = strings
    tags = [(5, 0x6100), (10, len(strings)), (6, 0x6400), (11, 24), (4, 0x6300),
            (7, 0x6600), (8, len(IMPORTS) * 24), (9, 24), (1, offsets['libkernel.prx']),
            (1, offsets['libc.prx']), (0x61000045, (1 << 48) | offsets['libkernel.prx']),
            (0x61000045, (2 << 48) | offsets['libc.prx']), (0, 0)]
    for index, tag in enumerate(tags):
        struct.pack_into('<qQ', image, 0x6000 + index * 16, *tag)
    struct.pack_into('<IIQQQQQQ', image, 120, 2, 6, 0x6000, 0x6000, 0x6000, len(tags) * 16, len(tags) * 16, 8)
    struct.pack_into('<III', image, 0x6300, 1, len(IMPORTS) + 1, 1)
    for index in range(1, len(IMPORTS) + 1):
        struct.pack_into('<I', image, 0x6300 + 12 + index * 4, index + 1 if index < len(IMPORTS) else 0)
    for index, symbol in enumerate(symbols, 1):
        struct.pack_into('<IBBHQQ', image, 0x6400 + 24 * index, offsets[symbol], 0x12, 0, 0, 0, 0)
        struct.pack_into('<QQq', image, 0x6600 + 24 * (index - 1), 0x7000 + 8 * (index - 1), (index << 32) | 6, 0)
    image[0x4000:0x4000 + len(body)] = body
    path = b'/app0/pthread-affinity-witness.bin\0'
    image[0x7800:0x7800 + len(path)] = path
    image[SHARED:SHARED + 0x400] = bytes([0xaa]) * 0x400
    return image, [description for _, description in c.failures]


def main():
    if len(sys.argv) != 3 or os.name != 'nt' or platform.machine().lower() not in ('amd64', 'x86_64'):
        raise SystemExit('usage: Windows x86-64 test_converted_pthread_affinity_contract.py <relinker> <patched-libraries>')
    relinker, libraries = (Path(value).resolve() for value in sys.argv[1:])
    evidence = Path(os.environ.get('ANYPS5_TEST_EVIDENCE', tempfile.gettempdir()))
    evidence.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='anyps5-converted-pthread-affinity-', dir=evidence))
    (work / 'sce_module').mkdir()
    (work / 'app0').mkdir()
    runtime = work / 'libs'
    runtime.mkdir()
    artifacts = []
    for name in ('libc.prx', 'libkernel.prx', 'libgcc_s_seh-1.dll', 'libstdc++-6.dll', 'libwinpthread-1.dll'):
        candidates = [libraries / name, libraries / 'unpatched' / name]
        candidates.extend(Path(part) / name for part in os.environ.get('PATH', '').split(os.pathsep) if part)
        original = libraries / name if name.endswith('.prx') else next((p for p in candidates if p.is_file()), None)
        if original is None or not original.is_file():
            raise FileNotFoundError(name)
        target = runtime / name
        shutil.copy2(original, target)
        if sha256(target) != sha256(original):
            raise AssertionError('Copied runtime hash differs')
        artifacts.append({'source': str(original), 'copy': str(target), 'sha256': sha256(original)})
    payload = work / 'app0/pthread-affinity-witness.bin'
    payload.write_bytes(ORIGINAL)
    source = work / 'input.elf'
    image, expectations = fixture()
    source.write_bytes(image)
    output = work / 'output.exe'
    command = [str(relinker), '--registry', '--windows', str(source), str(output)]
    manifest = {'platform': platform.platform(), 'machine': platform.machine(), 'fixture_artifacts': str(work),
                'conversion_command': command, 'runtime_command': [str(output)], 'cwd': str(work),
                'environment_overrides': {'APS5_TRACE_EXIT': '1'}, 'artifacts': artifacts,
                'relinker_sha256': sha256(relinker), 'fixture_script_sha256': sha256(Path(__file__)),
                'helper_path': str(HELPER), 'helper_sha256': sha256(HELPER), 'source_sha256': sha256(source),
                'contract': expectations, 'join_value': JOIN_VALUE, 'payload_before_hex': ORIGINAL.hex(),
                'payload_expected_hex': EXPECTED.hex(), 'payload_path': str(payload),
                'claim': 'bounded live handle affinity metadata and normal join lifecycle in existing guest CPU model; deterministic concurrent deletion, stale-address reuse, host pinning and console unverified; local Linux deferred by user'}
    manifest_path = work / 'manifest.json'
    def save():
        manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    save()
    start = time.monotonic()
    converted = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=10)
    manifest.update(conversion_returncode=converted.returncode, conversion_stdout=converted.stdout, conversion_stderr=converted.stderr)
    save()
    if converted.returncode != 0:
        raise AssertionError(('conversion failed', converted.returncode, converted.stderr, str(manifest_path)))
    registry_path = output.with_suffix('.registry.json')
    imported = {(item['nid'], item['library']) for item in json.loads(registry_path.read_text())}
    required = {(nid + ('#A#B' if library == 'libkernel.prx' else '#A#C'), library) for _, nid, library in IMPORTS}
    if imported != required:
        raise AssertionError(('actual guest imports differ', imported, required))
    manifest.update(imports=sorted(imported), registry_sha256=sha256(registry_path), output_sha256=sha256(output))
    save()
    environment = os.environ.copy()
    environment['APS5_TRACE_EXIT'] = '1'
    try:
        executed = subprocess.run([str(output)], cwd=work, env=environment, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired as error:
        manifest.update(runtime_timeout=True, duration_seconds=time.monotonic() - start, payload_after_sha256=sha256(payload))
        save()
        raise AssertionError(('guest cpuset timed out', str(manifest_path))) from error
    manifest.update(returncode=executed.returncode, stdout=executed.stdout, stderr=executed.stderr,
                    duration_seconds=time.monotonic() - start, payload_after_sha256=sha256(payload),
                    payload_after_hex=payload.read_bytes().hex(), payload_matches_expected=payload.read_bytes() == EXPECTED,
                    artifact_hashes_after={item['copy']: sha256(Path(item['copy'])) for item in artifacts})
    save()
    if executed.returncode != 0:
        expectation = expectations[executed.returncode - 1] if 0 < executed.returncode <= len(expectations) else 'loader, ABI or process failure'
        raise AssertionError((expectation, executed.returncode, executed.stderr, str(manifest_path)))
    if not manifest['payload_matches_expected']:
        raise AssertionError(('host independently observed incorrect affinity witness or file guards', str(manifest_path)))
    if '[libc] exit(0) called' not in executed.stderr:
        raise AssertionError(('guest exit evidence missing', str(manifest_path)))
    if any(sha256(Path(item['copy'])) != item['sha256'] for item in artifacts):
        raise AssertionError('Runtime artifacts changed')
    print('Converted pthread handle affinity: ' + str(len(expectations)) + ' active checks and independent32-byte host file witness PASS')
    print('Evidence: ' + str(manifest_path))


if __name__ == '__main__':
    main()
