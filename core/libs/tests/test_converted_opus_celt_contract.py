import base64
import hashlib
import json
import os
import platform
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

from test_converted_library_contract import Code, configure_fixture_loads, sha256

IMPORTS = [('initialize', '2dA75YfXNrQ', 'libSceOpusDec.prx'),
           ('size', 'knmEFpLg-Rk', 'libSceOpusDec.prx'),
           ('create', 'KAIGiqYrtI4', 'libSceOpusDec.prx'),
           ('decode', '+CSUx-budSk', 'libSceOpusDec.prx'),
           ('destroy', '290AWkA-lck', 'libSceOpusDec.prx'),
           ('terminate', 'qOpZPAFEvIs', 'libSceOpusDec.prx'),
           ('open', 'wuCroIGjt2g', 'libkernel.prx'),
           ('seek', 'Oy6IpwgtYOk', 'libkernel.prx'),
           ('write', 'FN4gaPmuFV8', 'libkernel.prx'),
           ('close', 'bY-PO6JhzhQ', 'libkernel.prx'),
           ('exit', 'uMei1W9uyNo', 'libc.prx')]
LIBRARIES = ['libSceOpusDec.prx', 'libkernel.prx', 'libc.prx']
SHARED, PACKETS, STATE, PCM = 0x7c00, 0x8000, 0x8800, 0x9000


class AudioCode(Code):
    def address(self, opcode, offset):
        self.emit(opcode)
        self.u32(offset)

    def static(self, opcode, address):
        self.emit(opcode)
        self.u32((address - (0x4000 + len(self.data) + 4)) & 0xffffffff)

    def function(self, name):
        self.call(0x7000 + 8 * [entry[0] for entry in IMPORTS].index(name))

    def store(self, offset, value):
        self.address('c783', offset)
        self.u32(value)

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
            raise AssertionError('Audio instructions overlap metadata')
        return self.data


def fixture(channels, packet_bytes):
    packets = []
    offset = 0
    while offset < len(packet_bytes):
        length = struct.unpack_from('<I', packet_bytes, offset)[0]
        if length == 0 or offset + 4 + length > len(packet_bytes):
            raise AssertionError('Invalid reference packet framing')
        if not 16 <= packet_bytes[offset + 4] >> 3 <= 31:
            raise AssertionError('Reference is not CELT-only')
        packets.append((offset + 4, length))
        offset += length + 4
    if len(packets) != 8 or PACKETS + len(packet_bytes) > STATE - 16:
        raise AssertionError('Unexpected reference layout')
    frame_bytes = 960 * channels * 2
    output_bytes = frame_bytes * len(packets)
    c = AudioCode()
    c.emit('5341544883ec08fc')
    c.static('488d1d', SHARED)
    c.store(0, 0)
    c.emit('4889df')
    c.function('initialize')
    c.status(0, 'initialize an actual OpusDec context')
    c.address('83bb', 0)
    c.emit('00')
    c.failure('0f84', 'initialization assigns a nonzero opaque context')
    c.emit('bf')
    c.u32(channels)
    c.function('size')
    c.address('8983', 4)
    c.status(640, 'published existing OpusDec mono/stereo state size')
    c.emit('4889df')
    c.static('488d35', STATE)
    c.emit('ba80bb0000b9')
    c.u32(channels)
    c.function('create')
    c.status(0, 'create a 48000 Hz decoder')
    for index, (position, length) in enumerate(packets):
        c.static('488d35', PCM + index * frame_bytes - 16)
        c.address('488dbb', 64)
        c.emit('b910000000fcf3a4')
        c.static('488d3d', STATE)
        c.static('488d35', PACKETS + position)
        c.emit('ba')
        c.u32(length)
        c.static('488d0d', PCM + index * frame_bytes)
        c.emit('41b8')
        c.u32(frame_bytes)
        c.function('decode')
        c.address('8983', 32 + index * 4)
        c.status(frame_bytes, 'decode actual CELT packet ' + str(index) + ' produced byte count')
        c.static('488d3d', PCM + index * frame_bytes - 16)
        c.address('488db3', 64)
        c.emit('b910000000fcf3a6')
        c.failure('0f85', 'packet ' + str(index) + ' preserves preceding PCM bytes')
        c.sentinel(PCM - SHARED + (index + 1) * frame_bytes, 16, 'packet ' + str(index) + ' preserves following PCM guard')
    c.sentinel(STATE - SHARED - 16, 16, 'decoder storage prefix guard')
    c.sentinel(STATE - SHARED + 640, 16, 'decoder storage suffix guard')
    c.sentinel(PCM - SHARED - 16, 16, 'PCM prefix guard')
    c.sentinel(PCM - SHARED + output_bytes, 16, 'PCM suffix guard')
    c.static('488d3d', STATE)
    c.function('destroy')
    c.status(0, 'destroy decoder after sequential CELT packets')
    c.emit('4889df')
    c.function('terminate')
    c.status(0, 'terminate context after decoder destruction')
    c.sentinel(STATE - SHARED - 16, 16, 'decoder storage prefix guard after teardown')
    c.sentinel(STATE - SHARED + 640, 16, 'decoder storage suffix guard after teardown')
    c.sentinel(PCM - SHARED - 16, 16, 'PCM prefix guard after teardown')
    c.sentinel(PCM - SHARED + output_bytes, 16, 'PCM suffix guard after teardown')
    c.static('488d3d', PACKETS)
    c.static('488d35', 0x11800)
    c.emit('b9')
    c.u32(len(packet_bytes))
    c.emit('fcf3a6')
    c.failure('0f85', 'complete const packet input unchanged after decode and teardown')
    c.store(8, channels)
    c.store(12, 48000)
    c.store(16, len(packets))
    c.store(20, output_bytes)
    c.store(24, 0x43454c54)
    c.store(28, 0x50525831)
    c.static('488d3d', 0x7800)
    c.emit('be0200000031d2')
    c.function('open')
    c.emit('85c0')
    c.failure('0f88', 'open real guest audio witness')
    c.emit('4189c44489e7be2000000031d2')
    c.function('seek')
    c.emit('483d20000000')
    c.failure('0f85', 'seek past host file guard')
    for address, length, description in ((SHARED, 64, 'actual context and decoder return values'),
                                         (PCM, output_bytes, 'full actual decoded signed16 PCM')):
        c.emit('4489e7')
        c.static('488d35', address)
        c.emit('ba')
        c.u32(length)
        c.function('write')
        c.emit('483d')
        c.u32(length)
        c.failure('0f85', 'write ' + description)
    c.emit('4489e7')
    c.function('close')
    c.status(0, 'close audio witness file')
    c.emit('31ff')
    c.function('exit')
    c.emit('0f0b')
    body = c.finish()
    image = bytearray(0x12000)
    image[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', image, 16, 3, 62, 1, 0x4000, 64, 0, 0, 64, 56, 5, 64, 0, 0)
    for index in range(2, 5):
        struct.pack_into('<IIQQQQQQ', image, 64 + index * 56, 0x6fffff01, 0, 0, 0, 0, 0, 0, 1)
    configure_fixture_loads(image, len(body), 0x6000)
    strings, offsets, symbols = bytearray(b'\0'), {}, []
    for _, nid, library in IMPORTS:
        symbol = nid + '#A#' + 'BCD'[LIBRARIES.index(library)]
        symbols.append(symbol)
        for value in (symbol, library):
            if value not in offsets:
                offsets[value] = len(strings)
                strings.extend(value.encode() + b'\0')
    if len(strings) >= 0x200:
        raise AssertionError('Dynamic string table overlaps hash')
    image[0x6100:0x6100 + len(strings)] = strings
    tags = [(5, 0x6100), (10, len(strings)), (6, 0x6400), (11, 24), (4, 0x6300),
            (7, 0x6600), (8, len(IMPORTS) * 24), (9, 24)]
    tags.extend((1, offsets[library]) for library in LIBRARIES)
    tags.extend((0x61000045, ((index + 1) << 48) | offsets[library]) for index, library in enumerate(LIBRARIES))
    tags.append((0, 0))
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
    path = b'/app0/celt-witness.bin\0'
    image[0x7800:0x7800 + len(path)] = path
    image[SHARED:] = bytes([0xaa]) * (len(image) - SHARED)
    image[PACKETS:PACKETS + len(packet_bytes)] = packet_bytes
    image[0x11800:0x11800 + len(packet_bytes)] = packet_bytes
    return image, [description for _, description in c.failures], output_bytes


def run(relinker, libraries, vectors, vector_file, helper, channels):
    mode = 'mono' if channels == 1 else 'stereo'
    evidence = Path(os.environ.get('ANYPS5_TEST_EVIDENCE', tempfile.gettempdir()))
    evidence.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='anyps5-converted-opus-' + mode + '-', dir=evidence))
    (work / 'sce_module').mkdir()
    (work / 'app0').mkdir()
    (work / 'libs').mkdir()
    copies = []
    for name in LIBRARIES + ['libgcc_s_seh-1.dll', 'libstdc++-6.dll', 'libwinpthread-1.dll']:
        candidates = [libraries / name] + [Path(part) / name for part in os.environ['PATH'].split(os.pathsep)]
        original = next(path for path in candidates if path.is_file())
        target = work / 'libs' / name
        shutil.copy2(original, target)
        if sha256(original) != sha256(target):
            raise AssertionError('Runtime copy mismatch')
        copies.append({'source': str(original), 'copy': str(target), 'sha256': sha256(original)})
    vector = vectors[mode]
    packet_bytes = base64.b64decode(vector['packets_base64'], validate=True)
    expected_pcm = zlib.decompress(base64.b64decode(vector['reference_pcm_zlib_base64'], validate=True))
    if vector['channels'] != channels or hashlib.sha256(packet_bytes).hexdigest() != vector['packets_sha256'] or hashlib.sha256(expected_pcm).hexdigest() != vector['reference_pcm_sha256']:
        raise AssertionError('Independent reference vector integrity failed')
    source, output, payload = work / 'input.elf', work / 'output.exe', work / 'app0/celt-witness.bin'
    image, expectations, count = fixture(channels, packet_bytes)
    source.write_bytes(image)
    if len(expected_pcm) != count:
        raise AssertionError('Independent reference size mismatch')
    payload.write_bytes(bytes([0xaa]) * (count + 128))
    conversion_command = [str(relinker), '--registry', '--windows', str(source), str(output)]
    manifest = {'channels': channels, 'contract': expectations, 'fixed_tolerance_lsb': 1,
                'script_sha256': sha256(Path(__file__)), 'helper': str(helper), 'helper_sha256': sha256(helper),
                'reference_file': str(vector_file), 'reference_file_sha256': sha256(vector_file),
                'reference_vector_sha256': {'packets': vector['packets_sha256'], 'pcm': vector['reference_pcm_sha256']},
                'artifacts': copies, 'source_sha256': sha256(source), 'relinker_sha256': sha256(relinker),
                'conversion_command': conversion_command, 'runtime_command': [str(output)], 'cwd': str(work),
                'environment_overrides': {'APS5_TRACE_EXIT': '1'},
                'scope': 'existing OpusDec CELT config31, mono/stereo 48000Hz sequential8 packets; no complete API, CELT module, console or Linux claim'}
    manifest_path = work / 'manifest.json'
    def save():
        manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    save()
    converted = subprocess.run(conversion_command, cwd=work, capture_output=True, text=True, timeout=10)
    manifest.update(conversion_returncode=converted.returncode, conversion_stdout=converted.stdout, conversion_stderr=converted.stderr)
    save()
    if converted.returncode:
        raise AssertionError(('conversion', str(manifest_path)))
    registry = output.with_suffix('.registry.json')
    imports = {(item['nid'], item['library']) for item in json.loads(registry.read_text())}
    required = {(nid + '#A#' + 'BCD'[LIBRARIES.index(library)], library) for _, nid, library in IMPORTS}
    if imports != required:
        raise AssertionError(('import bindings', imports, required))
    manifest.update(imports=sorted(imports), registry_sha256=sha256(registry), output_sha256=sha256(output))
    environment = os.environ.copy()
    environment['APS5_TRACE_EXIT'] = '1'
    executed = subprocess.run([str(output)], cwd=work, env=environment, capture_output=True, text=True, timeout=15)
    actual = payload.read_bytes()
    manifest.update(returncode=executed.returncode, stdout=executed.stdout, stderr=executed.stderr,
                    payload_after_sha256=sha256(payload), payload_bytes=len(actual), payload_expected_bytes=count + 128)
    save()
    if executed.returncode:
        raise AssertionError(('guest', executed.returncode, str(manifest_path)))
    guard = bytes([0xaa]) * 32
    if len(actual) != count + 128 or actual[:32] != guard or actual[-32:] != guard:
        raise AssertionError('Host file guards changed')
    header = struct.unpack_from('<16I', actual, 32)
    expected_header = (640, channels, 48000, 8, count, 0x43454c54, 0x50525831) + (count // 8,) * 8
    if header[0] == 0 or header[1:] != expected_header:
        raise AssertionError(('Actual return values differ', header))
    decoded = struct.unpack('<' + str(count // 2) + 'h', actual[96:96 + count])
    expected = struct.unpack('<' + str(count // 2) + 'h', expected_pcm)
    differences = [abs(a - b) for a, b in zip(decoded, expected)]
    manifest.update(maximum_difference=max(differences), samples_outside_fixed_tolerance=sum(value > 1 for value in differences),
                    different_samples=sum(value != 0 for value in differences), sample_count=len(differences),
                    payload_guards_match=True, actual_header=list(header), runtime_hashes_after={item['copy']: sha256(Path(item['copy'])) for item in copies})
    save()
    if max(differences) > 1 or any(sha256(Path(item['copy'])) != item['sha256'] for item in copies):
        raise AssertionError(('independent PCM reference or runtime immutability failed', str(manifest_path)))
    print(json.dumps({'mode': mode, 'checks': len(expectations), 'samples': len(decoded), 'maximum_difference': max(differences), 'manifest': str(manifest_path)}))


if __name__ == '__main__':
    if len(sys.argv) != 3 or os.name != 'nt' or platform.machine().lower() not in ('amd64', 'x86_64'):
        raise SystemExit('usage: Windows x86-64 test_converted_opus_celt_contract.py <relinker> <patched-libraries>')
    relinker, libraries = [Path(value).resolve() for value in sys.argv[1:]]
    vector_file = Path(__file__).with_name('OpusCeltReference.json')
    reference = json.loads(vector_file.read_text(encoding='utf-8'))
    if reference['fixed_tolerance_lsb'] != 1:
        raise AssertionError('Reference acceptance tolerance changed')
    for channels in (1, 2):
        run(relinker, libraries, reference['vectors'], vector_file, Path(__file__).with_name('test_converted_library_contract.py'), channels)
