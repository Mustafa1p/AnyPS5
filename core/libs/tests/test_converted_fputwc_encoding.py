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

IMPORTS = [('fopen', 'xeYO4u7uyJ0'), ('fseek', 'rQFVBXp-Cxg'),
           ('ftell', 'Qazy8LmXTvw'), ('fputwc', '1QJWxoB6pCo'),
           ('ferror', 'AHxyhN96dy4'), ('clearerr', 'St9nbxSoezk'),
           ('fclose', 'uodLYyUip20'), ('__error', '9BcDykPmo1I'),
           ('exit', 'uMei1W9uyNo')]
ORIGINAL = bytes([0xaa]) * 256
VALID = [(0x41, bytes.fromhex('41')), (0xe9, bytes.fromhex('c3a9')),
         (0xd7ff, bytes.fromhex('ed9fbf')), (0xe000, bytes.fromhex('ee8080'))]
EXPECTED_BYTES = b''.join(encoded for _, encoded in VALID) + b'1234'
EXPECTED = ORIGINAL[:32] + EXPECTED_BYTES + ORIGINAL[32 + len(EXPECTED_BYTES):]


class WideFileCode(Code):
    def function(self, name):
        self.call(0x9000 + 8 * [symbol for symbol, _ in IMPORTS].index(name))

    def static(self, opcode, address):
        self.emit(opcode)
        self.u32((address - (0x4000 + len(self.data) + 4)) & 0xffffffff)

    def stream(self):
        self.emit('4c89e7')

    def position(self, expected, description):
        self.stream()
        self.function('ftell')
        self.emit('483d')
        self.u32(expected)
        self.failure('0f85', description)

    def error(self, expected, description):
        self.emit('41837d00')
        self.emit(f'{expected:02x}')
        self.failure('0f85', description)

    def set_errno(self):
        self.emit('41c745007b000000')

    def put(self, value, expected, description):
        self.emit('bf')
        self.u32(value)
        self.emit('4c89e6')
        self.function('fputwc')
        self.status(expected & 0xffffffff, description)

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
            raise AssertionError('fputwc fixture instructions overlap dynamic data')
        return self.data


def fixture():
    c = WideFileCode()
    c.emit('53415441554883ec10fc')
    c.static('488d1d', 0x9800)
    c.static('488d3d', 0x9400)
    c.static('488d35', 0x9440)
    c.function('fopen')
    c.emit('4885c0')
    c.failure('0f84', 'open an existing guarded witness in r+b mode')
    c.emit('4989c4')
    c.function('__error')
    c.emit('4885c0')
    c.failure('0f84', 'resolve the actual guest errno pointer')
    c.emit('4989c5')
    c.stream()
    c.emit('be2000000031d2')
    c.function('fseek')
    c.status(0, 'seek to guarded file offset32')
    position = 32
    for value, encoded in VALID:
        c.set_errno()
        c.put(value, value, f'valid U+{value:04X} returns the character')
        c.error(123, f'valid U+{value:04X} preserves errno')
        position += len(encoded)
        c.position(position, f'valid U+{value:04X} writes the expected UTF8 byte count')
        c.stream()
        c.function('ferror')
        c.status(0, f'valid U+{value:04X} has no stream error')
        c.sentinel(0, 256, f'valid U+{value:04X} preserves independent guest storage')
    for index, value in enumerate((0xd800, 0xdbff, 0xdc00, 0xdfff), 1):
        c.set_errno()
        c.put(value, -1, f'invalid U+{value:04X} returns WEOF')
        c.error(86, f'invalid U+{value:04X} sets guest EILSEQ86')
        c.position(position, f'invalid U+{value:04X} does not change file position')
        c.stream()
        c.function('ferror')
        c.emit('85c0')
        c.failure('0f84', f'invalid U+{value:04X} sets the public stream error')
        c.stream()
        c.function('clearerr')
        c.stream()
        c.function('ferror')
        c.status(0, f'clearerr clears U+{value:04X} stream error')
        c.error(86, f'clearerr and ferror preserve U+{value:04X} errno')
        c.set_errno()
        recovery = 0x30 + index
        c.put(recovery, recovery, f'valid output recovers after U+{value:04X}')
        c.error(123, f'recovery after U+{value:04X} preserves errno')
        position += 1
        c.position(position, f'recovery after U+{value:04X} writes one byte')
        c.stream()
        c.function('ferror')
        c.status(0, f'recovery after U+{value:04X} has no stream error')
        c.sentinel(0, 256, f'invalid U+{value:04X} and recovery preserve guest storage')
    c.stream()
    c.function('fclose')
    c.status(0, 'close and flush the owned stream')
    c.emit('31ff')
    c.function('exit')
    c.emit('0f0b')
    body = c.finish()
    image = bytearray(0xa000)
    image[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', image, 16, 3, 62, 1, 0x4000, 64, 0, 0, 64, 56, 5, 64, 0, 0)
    for index in range(2, 5):
        struct.pack_into('<IIQQQQQQ', image, 64 + index * 56, 0x6fffff01, 0, 0, 0, 0, 0, 0, 1)
    configure_fixture_loads(image, len(body), 0x8000)
    strings, offsets, symbols = bytearray(b'\0'), {}, []
    for _, nid in IMPORTS:
        symbol = nid + '#A#B'
        symbols.append(symbol)
        for value in (symbol, 'libc.prx'):
            if value not in offsets:
                offsets[value] = len(strings)
                strings.extend(value.encode() + b'\0')
    image[0x8100:0x8100 + len(strings)] = strings
    tags = [(5, 0x8100), (10, len(strings)), (6, 0x8400), (11, 24),
            (4, 0x8300), (7, 0x8600), (8, len(IMPORTS) * 24), (9, 24),
            (1, offsets['libc.prx']), (0x61000045, (1 << 48) | offsets['libc.prx']), (0, 0)]
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
    filename = b'/app0/fputwc-witness.bin\0'
    image[0x9400:0x9400 + len(filename)] = filename
    image[0x9440:0x9444] = b'r+b\0'
    image[0x9800:0x9900] = ORIGINAL
    return image, [description for _, description in c.failures]


def main():
    if len(sys.argv) != 3 or os.name != 'nt' or platform.machine().lower() not in ('amd64', 'x86_64'):
        raise SystemExit('usage: Windows x86-64 test_converted_fputwc_encoding.py <relinker> <patched-libraries>')
    relinker, libraries = (Path(value).resolve() for value in sys.argv[1:])
    evidence = Path(os.environ.get('ANYPS5_TEST_EVIDENCE', tempfile.gettempdir()))
    evidence.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='anyps5-converted-fputwc-', dir=evidence))
    (work / 'app0').mkdir()
    (work / 'sce_module').mkdir()
    runtime = work / 'libs'
    runtime.mkdir()
    artifacts = []
    for name in ('libc.prx', 'libkernel.prx', 'libgcc_s_seh-1.dll', 'libstdc++-6.dll', 'libwinpthread-1.dll'):
        candidates = [libraries / name]
        candidates.extend(Path(part) / name for part in os.environ.get('PATH', '').split(os.pathsep) if part)
        original = libraries / name if name.endswith('.prx') else next((path for path in candidates if path.is_file()), None)
        if original is None or not original.is_file():
            raise FileNotFoundError(name)
        copied = runtime / name
        shutil.copyfile(original, copied)
        if sha256(copied) != sha256(original):
            raise AssertionError('Copied fputwc runtime hash differs')
        artifacts.append({'source': str(original), 'copy': str(copied), 'sha256': sha256(original)})
    payload = work / 'app0/fputwc-witness.bin'
    payload.write_bytes(ORIGINAL)
    source, output = work / 'input.elf', work / 'output.exe'
    image, contract = fixture()
    source.write_bytes(image)
    command = [str(relinker), '--registry', '--windows', str(source), str(output)]
    manifest = {'conversion_command': command, 'runtime_command': [str(output)], 'cwd': str(work), 'platform': platform.platform(), 'artifacts': artifacts, 'relinker_sha256': sha256(relinker), 'fixture_script_sha256': sha256(Path(__file__)), 'helper_sha256': sha256(Path(__file__).with_name('test_converted_library_contract.py')), 'source_sha256': sha256(source), 'contract': contract, 'active_checks': len(contract), 'imports': IMPORTS, 'payload_before_hex': ORIGINAL.hex(), 'payload_expected_hex': EXPECTED.hex(), 'claim': 'Bounded existing char16_t/UTF8 project model: four invalid surrogate edges return WEOF/EILSEQ86 and set public stream error with no write, clearerr recovers; independent RFC3629 BMP bytes. No PS5 locale, wider wint_t, stream orientation, concurrent access or full-function claim.'}
    manifest_path = work / 'manifest.json'
    def save():
        manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    save()
    started = time.monotonic()
    result = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=10)
    manifest.update(conversion_returncode=result.returncode, conversion_stdout=result.stdout, conversion_stderr=result.stderr)
    save()
    if result.returncode != 0:
        raise AssertionError(('fputwc conversion failed', str(manifest_path)))
    registry_path = output.with_suffix('.registry.json')
    rows = json.loads(registry_path.read_text())
    resolved = {(row['nid'].split('#', 1)[0], row['library']) for row in rows}
    expected_imports = {(nid, 'libc.prx') for _, nid in IMPORTS}
    manifest.update(output_sha256=sha256(output), registry_sha256=sha256(registry_path), resolved_registry_imports=sorted(resolved), callsite_counts={row['nid'].split('#', 1)[0]: len(row['callSites']) for row in rows})
    save()
    if resolved != expected_imports or len(rows) != len(IMPORTS) or any(not row['callSitesResolved'] or not row['callSites'] for row in rows):
        raise AssertionError(('fputwc actual import registry differs', str(manifest_path)))
    environment = os.environ.copy()
    environment['APS5_TRACE_EXIT'] = '1'
    try:
        executed = subprocess.run([str(output)], cwd=work, env=environment, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired as error:
        manifest.update(timed_out=True, duration_seconds=time.monotonic() - started)
        save()
        raise AssertionError(('fputwc guest timed out', str(manifest_path))) from error
    manifest.update(returncode=executed.returncode, stdout=executed.stdout, stderr=executed.stderr, duration_seconds=time.monotonic() - started, payload_after_hex=payload.read_bytes().hex(), payload_matches_expected=payload.read_bytes() == EXPECTED)
    save()
    if executed.returncode != 0:
        reason = contract[executed.returncode - 1] if 0 < executed.returncode <= len(contract) else 'loader or process failure'
        raise AssertionError((reason, executed.returncode, executed.stderr, str(manifest_path)))
    if not manifest['payload_matches_expected'] or '[libc] exit(0) called' not in executed.stderr:
        raise AssertionError(('fputwc independent host witness or guest exit differs', str(manifest_path)))
    if any(sha256(Path(item['copy'])) != item['sha256'] or sha256(Path(item['source'])) != item['sha256'] for item in artifacts):
        raise AssertionError('fputwc runtime artifact changed')
    print('Converted fputwc encoding: ' + str(len(contract)) + ' active checks and independently guarded file bytes PASS')
    print('Evidence: ' + str(manifest_path))


if __name__ == '__main__':
    main()
