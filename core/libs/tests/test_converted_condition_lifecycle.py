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
IMPORTS = [('mutex_init', 'YaHc3GS7y7g', 'libc.prx'), ('mutex_destroy', '5Lf51jvohTQ', 'libc.prx'), ('lock', 'iS4aWbUonl0', 'libc.prx'), ('unlock', 'gTuXQwP9rrs', 'libc.prx'), ('condition_init', 'SreZybSRWpU', 'libc.prx'), ('condition_destroy', '7yMFgcS8EPA', 'libc.prx'), ('wait', 'vEaqE-7IZYc', 'libc.prx'), ('signal', '0uuqgRz9qfo', 'libc.prx'), ('broadcast', 'VsP3daJgmVA', 'libc.prx'), ('create', 'OxhIB8LB-PQ', 'libkernel.prx'), ('join', 'h9CcP3J0oVM', 'libkernel.prx'), ('sleep', 'QcteRwbsnV0', 'libkernel.prx'), ('open', 'wuCroIGjt2g', 'libkernel.prx'), ('seek', 'Oy6IpwgtYOk', 'libkernel.prx'), ('write', 'FN4gaPmuFV8', 'libkernel.prx'), ('close', 'bY-PO6JhzhQ', 'libkernel.prx'), ('exit', 'uMei1W9uyNo', 'libc.prx')]
SHARED = 0x9c00
RETURN_BASE = 0x12345678bbcc0044
SIGNATURE = 0xc0d1c7105a5af00d
ORIGINAL = bytes([0xaa]) * 256
RECORD = struct.pack('<IIIIQQQII', 48, 48, 408, 816, RETURN_BASE ^ 1, RETURN_BASE ^ 2, SIGNATURE, 16, 96)
EXPECTED = ORIGINAL[:32] + RECORD + ORIGINAL[80:]


class ConditionCode(Code):
    def address(self, opcode, offset):
        self.emit(opcode)
        self.u32(offset)

    def static(self, opcode, address):
        self.emit(opcode)
        self.u32((address - (0x4000 + len(self.data) + 4)) & 0xffffffff)

    def function(self, name):
        self.call(0x9000 + 8 * [item[0] for item in IMPORTS].index(name))

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

    def expect64(self, offset, value, description):
        self.emit('48b8')
        self.data.extend(struct.pack('<Q', value))
        self.address('483983', offset)
        self.failure('0f85', description)

    def equal(self, first, second, size, description):
        self.address('488dbb', first)
        self.address('488db3', second)
        self.emit('b9')
        self.u32(size)
        self.emit('fcf3a6')
        self.failure('0f85', description)

    def primitive(self, name, success=True):
        if name == 'wait':
            self.address('488dbb', 0x30)
            self.address('488db3', 0x10)
        elif name in ('mutex_init', 'mutex_destroy', 'lock', 'unlock'):
            self.address('488dbb', 0x10)
            if name == 'mutex_init':
                self.emit('be02000000')
        else:
            self.address('488dbb', 0x30)
        self.function(name)
        if success and name not in ('mutex_destroy', 'condition_destroy'):
            self.status(0, name + ' returns project success')

    def identities(self, description):
        self.equal(0x10, 0xe0, 8, description + ' preserves opaque mutex handle')
        self.equal(0x30, 0xe8, 8, description + ' preserves opaque condition handle')

    def guards(self, description):
        for offset, size in ((0, 16), (0x18, 24), (0x38, 24), (0x78, 8), (0x84, 4), (0x8c, 4), (0x94, 12), (0xa4, 4), (0xac, 4), (0xb4, 12), (0xd0, 16), (0x100, 256), (0x230, 464)):
            self.sentinel(offset, size, description + ' guard ' + hex(offset))

    def phase(self, completed, name):
        self.emit('41bc88130000')
        self.labels[name + '-poll'] = len(self.data)
        self.primitive('lock')
        for offset, value in ((0x6c, completed), (0x70, 1), (0x74, 1)):
            self.address('81bb', offset)
            self.u32(value)
            self.branch('0f85', name + '-notready')
        self.primitive('unlock')
        self.branch('e9', name + '-ready')
        self.labels[name + '-notready'] = len(self.data)
        self.primitive('unlock')
        self.emit('bfe8030000')
        self.function('sleep')
        self.status(0, name + ' poll sleep succeeds')
        self.emit('41ffcc')
        self.branch('0f85', name + '-poll')
        self.emit('31c0')
        self.status(1, name + ' protected predicate completes in bounded polls')
        self.labels[name + '-ready'] = len(self.data)

    def finish(self):
        for index, (name, _) in enumerate(self.failures, 1):
            self.labels[name] = len(self.data)
            self.emit('bf')
            self.u32(index)
            self.function('exit')
            self.emit('0f0b')
        for position, name in self.branches:
            struct.pack_into('<i', self.data, position, self.labels[name] - position - 4)
        if len(self.data) >= 0x4000:
            raise AssertionError('Condition instructions overlap dynamic metadata')
        return self.data


def fixture():
    c = ConditionCode()
    c.emit('534154415541564883ec08')
    c.static('488d1d', SHARED)
    for offset in (0xf0, 0xf4, 0xf8, 0xfc):
        c.store(offset, 0)
    c.emit('41be03000000')
    c.labels['lifecycle'] = len(c.data)
    c.store64(0x10, 0)
    c.store64(0x30, 0)
    for offset in (0x60, 0x64, 0x68, 0x6c, 0x70, 0x74, 0x80, 0x88, 0x90, 0xa0, 0xa8, 0xb0):
        c.store(offset, 0)
    c.primitive('mutex_init')
    c.address('4883bb', 0x10)
    c.emit('00')
    c.failure('0f84', 'mutex initialization publishes nonnull handle')
    c.primitive('condition_init')
    c.address('4883bb', 0x30)
    c.emit('00')
    c.failure('0f84', 'condition initialization publishes nonnull handle')
    for value, identity in ((0x10, 0xe0), (0x30, 0xe8)):
        c.address('488b83', value)
        c.address('488983', identity)
    c.primitive('signal')
    c.primitive('broadcast')
    for index, offset in enumerate((0x50, 0x58), 1):
        c.address('488dbb', offset)
        c.emit('31f6')
        c.branch('488d15', 'worker' + str(index))
        c.emit('4889d9')
        c.function('create')
        c.status(0, 'create actual SysV consumer ' + str(index))
    c.emit('bfe8030000')
    c.function('sleep')
    c.status(0, 'initial public guest sleep dependency succeeds')
    c.phase(0, 'initial-waiters')
    c.emit('41bd01000000')
    c.labels['generation'] = len(c.data)
    c.primitive('lock')
    c.expect(0x68, 0, 'producer obtains mutex with prior tokens consumed')
    c.address('4489ab', 0x64)
    c.store(0x68, 2)
    c.store(0x6c, 0)
    c.emit('41f7c501000000')
    c.branch('0f84', 'broadcast-generation')
    c.primitive('signal')
    c.primitive('signal')
    c.branch('e9', 'notifications-done')
    c.labels['broadcast-generation'] = len(c.data)
    c.primitive('broadcast')
    c.labels['notifications-done'] = len(c.data)
    c.identities('producer notification')
    c.primitive('unlock')
    c.phase(2, 'generation-complete')
    c.emit('41ffc54183fd10')
    c.branch('0f86', 'generation')
    c.primitive('lock')
    c.expect(0x68, 0, 'all final tokens consumed')
    c.expect(0x6c, 2, 'two consumers complete final generation')
    c.store(0x60, 1)
    c.primitive('broadcast')
    c.primitive('unlock')
    for index, (thread, joined, count, total, waits) in enumerate(((0x50, 0xc0, 0x80, 0x88, 0x90), (0x58, 0xc8, 0xa0, 0xa8, 0xb0)), 1):
        c.address('488bbb', thread)
        c.address('488db3', joined)
        c.function('join')
        c.status(0, 'join actual consumer ' + str(index))
        c.expect64(joined, RETURN_BASE ^ index, 'full64-bit callback return ' + str(index))
        c.expect(count, 16, 'per-consumer token count ' + str(index))
        c.expect(total, 136 * index, 'independent generation sum ' + str(index))
        c.address('83bb', waits)
        c.emit('10')
        c.failure('0f8c', 'actual wait dependency repeats through generations ' + str(index))
    c.expect(0x70, 0, 'joined first consumer no longer marks waiting')
    c.expect(0x74, 0, 'joined second consumer no longer marks waiting')
    c.identities('completed worker lifecycle')
    c.guards('before normal destroy')
    for source, target in ((0x80, 0xf0), (0xa0, 0xf4), (0x88, 0xf8), (0xa8, 0xfc)):
        c.address('8b83', source)
        c.address('0183', target)
    c.primitive('condition_destroy')
    c.primitive('mutex_destroy')
    c.expect64(0x10, 0, 'normal mutex destroy clears opaque handle slot')
    c.expect64(0x30, 0, 'normal condition destroy clears opaque handle slot')
    c.guards('after normal destroy')
    c.emit('41ffce')
    c.branch('0f85', 'lifecycle')
    for offset, value in ((0xf0, 48), (0xf4, 48), (0xf8, 408), (0xfc, 816)):
        c.expect(offset, value, 'aggregate protected witness ' + hex(offset))
    for source, target in ((0xf0, 0x200), (0xf4, 0x204), (0xf8, 0x208), (0xfc, 0x20c), (0x64, 0x228)):
        c.address('8b83', source)
        c.address('8983', target)
    for source, target in ((0xc0, 0x210), (0xc8, 0x218)):
        c.address('488b83', source)
        c.address('488983', target)
    c.store64(0x220, SIGNATURE)
    c.address('8b83', 0xf0)
    c.address('0383', 0xf4)
    c.address('8983', 0x22c)
    c.static('488d3d', 0x9800)
    c.emit('be0200000031d2')
    c.function('open')
    c.emit('85c0')
    c.failure('0f88', 'open real condition lifecycle witness')
    c.emit('4189c44489e7be2000000031d2')
    c.function('seek')
    c.emit('483d20000000')
    c.failure('0f85', 'seek witness to guarded offset32')
    c.emit('4489e7')
    c.address('488db3', 0x200)
    c.emit('ba30000000')
    c.function('write')
    c.emit('483d30000000')
    c.failure('0f85', 'write48 actual protected token and callback witness bytes')
    c.emit('4489e7')
    c.function('close')
    c.status(0, 'close real condition lifecycle witness')
    c.emit('31ff')
    c.function('exit')
    c.emit('0f0b')
    for index, (waiting, count, total, waits) in enumerate(((0x70, 0x80, 0x88, 0x90), (0x74, 0xa0, 0xa8, 0xb0)), 1):
        prefix = 'worker' + str(index)
        c.labels[prefix] = len(c.data)
        c.emit('5341544883ec084889fb4531e4')
        c.primitive('lock')
        c.labels[prefix + '-predicate'] = len(c.data)
        c.address('83bb', 0x60)
        c.emit('00')
        c.branch('0f85', prefix + '-stop')
        c.address('4439a3', 0x64)
        c.branch('0f85', prefix + '-consume')
        c.store(waiting, 1)
        c.primitive('wait')
        c.store(waiting, 0)
        c.address('ff83', waits)
        c.primitive('lock', success=False)
        c.status(3, 'wait restores nonrecursive mutex ownership ' + str(index))
        c.identities('waiter ' + str(index))
        c.branch('e9', prefix + '-predicate')
        c.labels[prefix + '-consume'] = len(c.data)
        c.emit('4489e0ffc0')
        c.address('3983', 0x64)
        c.failure('0f85', 'consumer sees next protected generation ' + str(index))
        c.address('448ba3', 0x64)
        c.address('83bb', 0x68)
        c.emit('00')
        c.failure('0f8e', 'consumer has a protected token ' + str(index))
        c.address('ff8b', 0x68)
        c.address('ff83', 0x6c)
        c.address('ff83', count)
        c.emit('4489e0')
        if index == 2:
            c.emit('6bc002')
        c.address('0183', total)
        c.branch('e9', prefix + '-predicate')
        c.labels[prefix + '-stop'] = len(c.data)
        c.primitive('unlock')
        c.emit('48b8')
        c.data.extend(struct.pack('<Q', RETURN_BASE ^ index))
        c.emit('4883c408415c5bc3')
    body = c.finish()
    image = bytearray(0xb000)
    image[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', image, 16, 3, 62, 1, 0x4000, 64, 0, 0, 64, 56, 5, 64, 0, 0)
    for index in range(2, 5):
        struct.pack_into('<IIQQQQQQ', image, 64 + index * 56, 0x6fffff01, 0, 0, 0, 0, 0, 0, 1)
    configure_fixture_loads(image, len(body), 0x8000)
    strings, offsets, symbols = bytearray(b'\0'), {}, []
    for _, nid, library in IMPORTS:
        symbol = nid + ('#A#B' if library == 'libc.prx' else '#A#C')
        symbols.append(symbol)
        for value in (symbol, library):
            if value not in offsets:
                offsets[value] = len(strings)
                strings.extend(value.encode() + b'\0')
    if len(strings) >= 0x200 or (len(IMPORTS) + 1) * 24 > 0x200:
        raise AssertionError('Condition dynamic metadata overlaps')
    image[0x8100:0x8100 + len(strings)] = strings
    tags = [(5, 0x8100), (10, len(strings)), (6, 0x8400), (11, 24), (4, 0x8300), (7, 0x8600), (8, len(IMPORTS) * 24), (9, 24), (1, offsets['libc.prx']), (1, offsets['libkernel.prx']), (0x61000045, (1 << 48) | offsets['libc.prx']), (0x61000045, (2 << 48) | offsets['libkernel.prx']), (0, 0)]
    for index, tag in enumerate(tags):
        struct.pack_into('<qQ', image, 0x8000 + index * 16, *tag)
    struct.pack_into('<IIQQQQQQ', image, 120, 2, 6, 0x8000, 0x8000, 0x8000, len(tags) * 16, len(tags) * 16, 8)
    struct.pack_into('<III', image, 0x8300, 1, len(IMPORTS) + 1, 1)
    for index in range(1, len(IMPORTS) + 1):
        struct.pack_into('<I', image, 0x8300 + 12 + index * 4, index + 1 if index < len(IMPORTS) else 0)
    for index, symbol in enumerate(symbols, 1):
        struct.pack_into('<IBBHQQ', image, 0x8400 + 24 * index, offsets[symbol], 0x12, 0, 0, 0, 0)
        struct.pack_into('<QQq', image, 0x8600 + 24 * (index - 1), 0x9000 + 8 * (index - 1), (index << 32) | 6, 0)
    image[0x4000:0x4000 + len(body)] = body
    path = b'/app0/condition-witness.bin\0'
    image[0x9800:0x9800 + len(path)] = path
    image[SHARED:SHARED + 0x400] = bytes([0xaa]) * 0x400
    return image, [description for _, description in c.failures]


def main():
    if len(sys.argv) != 3 or os.name != 'nt' or platform.machine().lower() not in ('amd64', 'x86_64'):
        raise SystemExit('usage: Windows x86-64 test_converted_condition_lifecycle.py <relinker> <patched-libraries>')
    relinker, libraries = (Path(value).resolve() for value in sys.argv[1:])
    evidence = Path(os.environ.get('ANYPS5_TEST_EVIDENCE', tempfile.gettempdir()))
    evidence.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='anyps5-converted-condition-', dir=evidence))
    (work / 'sce_module').mkdir()
    (work / 'app0').mkdir()
    runtime = work / 'libs'
    runtime.mkdir()
    artifacts = []
    for name in ('libc.prx', 'libkernel.prx', 'libgcc_s_seh-1.dll', 'libstdc++-6.dll', 'libwinpthread-1.dll'):
        candidates = [libraries / name]
        candidates.extend(Path(part) / name for part in os.environ.get('PATH', '').split(os.pathsep) if part)
        original = libraries / name if name.endswith('.prx') else next((path for path in candidates if path.is_file()), None)
        if original is None or not original.is_file():
            raise FileNotFoundError(name)
        target = runtime / name
        shutil.copyfile(original, target)
        if sha256(original) != sha256(target):
            raise AssertionError('Copied condition runtime hash differs')
        artifacts.append({'source': str(original), 'copy': str(target), 'sha256': sha256(original)})
    payload = work / 'app0/condition-witness.bin'
    payload.write_bytes(ORIGINAL)
    source, output = work / 'input.elf', work / 'output.exe'
    image, contract = fixture()
    source.write_bytes(image)
    command = [str(relinker), '--registry', '--windows', str(source), str(output)]
    manifest = {'conversion_command': command, 'runtime_command': [str(output)], 'cwd': str(work), 'platform': platform.platform(), 'artifacts': artifacts, 'relinker_sha256': sha256(relinker), 'fixture_script_sha256': sha256(Path(__file__)), 'helper_sha256': sha256(HELPER), 'source_sha256': sha256(source), 'contract': contract, 'imports': IMPORTS, 'payload_before_hex': ORIGINAL.hex(), 'payload_expected_hex': EXPECTED.hex(), 'claim': 'Verification-only existing condition/mutex source-model operations and normal lifecycle; project/title-disassembly ** ABI basis. Spurious wakeups and fairness allowed; no private PS5 layout/console/host scheduler/full-function claim. Destroy-to-null and nonrecursive relock-busy3 are project-source expectations.'}
    manifest_path = work / 'manifest.json'
    def save():
        manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    save()
    started = time.monotonic()
    converted = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=10)
    manifest.update(conversion_returncode=converted.returncode, conversion_stdout=converted.stdout, conversion_stderr=converted.stderr)
    save()
    if converted.returncode != 0:
        raise AssertionError(('condition conversion failed', str(manifest_path)))
    manifest['output_sha256'] = sha256(output)
    registry = output.with_suffix('.registry.json')
    rows = json.loads(registry.read_text())
    expected_imports = {(nid, library) for _, nid, library in IMPORTS}
    actual = {(row['nid'].split('#', 1)[0], row['library']) for row in rows}
    manifest['registry_sha256'] = sha256(registry)
    manifest['resolved_registry_imports'] = sorted(actual)
    save()
    manifest['callsite_counts'] = {row['nid'].split('#', 1)[0]: len(row['callSites']) for row in rows}
    if actual != expected_imports or len(rows) != len(IMPORTS) or any(not row['callSitesResolved'] or not row['callSites'] for row in rows):
        raise AssertionError(('unexpected actual condition import registry', str(manifest_path)))
    environment = os.environ.copy()
    environment['APS5_TRACE_EXIT'] = '1'
    try:
        executed = subprocess.run([str(output)], cwd=work, env=environment, capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired as error:
        manifest.update(timed_out=True, duration_seconds=time.monotonic() - started)
        save()
        raise AssertionError(('condition fixture timed out', str(manifest_path))) from error
    manifest.update(returncode=executed.returncode, stdout=executed.stdout, stderr=executed.stderr, duration_seconds=time.monotonic() - started, payload_after_hex=payload.read_bytes().hex(), payload_matches_expected=payload.read_bytes() == EXPECTED, artifact_hashes_after={item['copy']: sha256(Path(item['copy'])) for item in artifacts})
    save()
    if executed.returncode != 0:
        reason = contract[executed.returncode - 1] if 0 < executed.returncode <= len(contract) else 'loader or process failure'
        raise AssertionError((reason, executed.returncode, executed.stderr, str(manifest_path)))
    if not manifest['payload_matches_expected']:
        raise AssertionError(('independent condition host file witness mismatch', str(manifest_path)))
    if '[libc] exit(0) called' not in executed.stderr:
        raise AssertionError(('guest condition exit evidence missing', str(manifest_path)))
    if any(sha256(Path(item['copy'])) != item['sha256'] or sha256(Path(item['source'])) != item['sha256'] for item in artifacts):
        raise AssertionError('Condition runtime artifact changed')
    print('Converted condition lifecycle: ' + str(len(contract)) + ' active checks, 3 lifecycles, 48 generations, 96 tokens and48-byte host witness PASS')
    print('Evidence: ' + str(manifest_path))


if __name__ == '__main__':
    main()
