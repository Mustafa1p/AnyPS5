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

HELPER = Path(__file__).resolve().with_name('test_converted_library_contract.py')
from test_converted_library_contract import Code, configure_fixture_loads, sha256

IMPORTS = [('wcsrtombs', 'sOOMlZoy1pg'), ('swprintf', 'nJz16JE1txM'),
           ('__error', '9BcDykPmo1I'), ('exit', 'uMei1W9uyNo')]
SLOTS = {name: 0x7000 + index * 8 for index, (name, _) in enumerate(IMPORTS)}


class WideCode(Code):
    def __init__(self):
        super().__init__()
        self.constants = bytearray()
        self.constant_manifest = []

    def constant(self, data, name):
        while len(self.constants) % 8:
            self.constants.append(0)
        address = 0x7800 + len(self.constants)
        self.constants.extend(data)
        self.constant_manifest.append({'name': name, 'address': address, 'hex': data.hex()})
        return address

    def wide(self, text, name):
        return self.constant((text + '\0').encode('utf-16le'), name)

    def address(self, opcode, offset):
        self.emit(opcode)
        self.u32(offset)

    def static(self, opcode, address):
        self.emit(opcode)
        self.u32((address - (0x4000 + len(self.data) + 4)) & 0xffffffff)

    def function(self, name):
        self.call(SLOTS[name])

    def fill(self):
        self.address('488dbb', 0x40)
        self.emit('b9c0000000b8aa000000f3aa')

    def source(self, address):
        self.static('488d05', address)
        self.address('488983', 0x100)

    def source_is(self, address, description):
        if address is None:
            self.address('4883bb', 0x100)
            self.emit('00')
        else:
            self.static('488d05', address)
            self.address('483983', 0x100)
        self.failure('0f85', description)

    def result64(self, value, description):
        self.emit('483d')
        self.u32(value & 0xffffffff)
        self.failure('0f85', description)

    def output(self, expected, description):
        target = self.constant(expected, description + ' expected bytes')
        self.address('488dbb', 0x40)
        self.static('488d35', target)
        self.emit('b9')
        self.u32(len(expected))
        self.emit('f3a6')
        self.failure('0f85', description)

    def guards(self, written, description):
        self.sentinel(0x20, 0x20, description + ' leading guard')
        self.sentinel(0x40 + written, 0xc0 - written, description + ' trailing guard')
        self.sentinel(0x108, 0x38, description + ' source pointer guard')

    def convert(self, count, destination=True, state=True, offset=0):
        if destination:
            self.address('488dbb', 0x40 + offset)
        else:
            self.emit('31ff')
        self.address('488db3', 0x100)
        self.emit('ba')
        self.u32(count)
        if state:
            self.address('488d8b', 0x140)
        else:
            self.emit('31c9')
        self.function('wcsrtombs')

    def clear_errno(self):
        self.function('__error')
        self.emit('c70000000000')

    def errno(self, value, description):
        self.function('__error')
        self.emit('8138')
        self.u32(value)
        self.failure('0f85', description)

    def formatting(self, capacity, format_address):
        self.address('488dbb', 0x40)
        self.emit('be')
        self.u32(capacity)
        self.static('488d15', format_address)

    def stack_argument(self, offset, value):
        self.address('48c783', offset)
        self.u32(value & 0xffffffff)

    def finish(self):
        self.emit('31ff')
        self.function('exit')
        self.emit('0f0b')
        for index, (name, _) in enumerate(self.failures, 1):
            self.labels[name] = len(self.data)
            self.emit('bf')
            self.u32(index)
            self.function('exit')
            self.emit('0f0b')
        for position, name in self.branches:
            struct.pack_into('<i', self.data, position, self.labels[name] - position - 4)
        if len(self.data) >= 0x2000 or len(self.constants) >= 0x1800:
            raise AssertionError('Fixture section overlap')
        return self.data


def fixture():
    code = WideCode()
    code.emit('5341544881ec080200004889e34889dfb900020000b8aa000000fcf3aa')
    code.address('488dbb', 0x140)
    code.emit('b90200000031c0f348ab')
    text = code.wide('Az09', 'ASCII UTF-16 input')
    invalid = code.constant(struct.pack('<4H', ord('q'), 0x100, ord('z'), 0), 'unrepresentable UTF-16 input')
    empty = code.wide('', 'empty UTF-16 input')
    code.source(text)
    code.convert(0, destination=False)
    code.result64(4, 'sizing ignores capacity and excludes terminator')
    code.source_is(text, 'sizing preserves source pointer')
    code.guards(0, 'sizing writes no output')
    code.convert(0)
    code.result64(0, 'zero destination capacity converts zero bytes')
    code.source_is(text, 'zero capacity preserves source pointer')
    code.guards(0, 'zero capacity writes no output')
    code.convert(2)
    code.result64(2, 'partial conversion reports two bytes')
    code.source_is(text + 4, 'partial cursor advances by two UTF-16 units')
    code.output(b'Az', 'partial conversion independent ASCII output')
    code.guards(2, 'partial conversion preserves guards')
    code.convert(3, offset=2)
    code.result64(2, 'resume excludes terminator from result')
    code.source_is(None, 'complete resume nulls source pointer')
    code.output(b'Az09\0', 'resume writes expected bytes and terminator')
    code.guards(5, 'resume preserves guards')
    code.fill()
    code.source(text)
    code.convert(4, state=False)
    code.result64(4, 'exact nonterminated capacity returns four')
    code.source_is(text + 8, 'exact capacity leaves cursor at UTF-16 terminator')
    code.output(b'Az09', 'exact capacity preserves four ASCII bytes')
    code.guards(4, 'exact capacity leaves terminator storage unwritten')
    code.convert(1, state=False, offset=4)
    code.result64(0, 'terminator-only resume returns zero')
    code.source_is(None, 'terminator-only resume nulls source pointer')
    code.output(b'Az09\0', 'terminator-only resume appends one null byte')
    code.guards(5, 'terminator-only resume guards')
    code.fill()
    code.source(empty)
    code.convert(1)
    code.result64(0, 'empty input returns zero excluding null')
    code.source_is(None, 'empty input nulls source pointer')
    code.output(b'\0', 'empty input writes null byte')
    code.guards(1, 'empty input guards')
    code.fill()
    code.source(invalid)
    code.clear_errno()
    code.convert(5)
    code.result64(-1, 'unrepresentable UTF-16 conversion returns SIZE_MAX')
    code.source_is(invalid + 2, 'encoding failure points to failing UTF-16 unit')
    code.errno(86, 'encoding failure sets guest EILSEQ86')
    code.output(b'q', 'encoding failure retains only valid prefix')
    code.guards(1, 'encoding failure guards')
    code.fill()
    code.source(invalid)
    code.clear_errno()
    code.convert(0, destination=False)
    code.result64(-1, 'sizing detects unrepresentable UTF-16 unit')
    code.source_is(invalid, 'sizing error preserves original source pointer')
    code.errno(86, 'sizing error sets guest EILSEQ86')
    code.guards(0, 'sizing error writes no output')
    mixed_format = code.wide('%d|%lld|%.2f|%ls|%s', 'mixed integer floating wide narrow format')
    omega = code.wide('\u03a9', 'wide Omega string')
    narrow = code.constant(b'ab\0', 'narrow ASCII string')
    expected = '-17|4294967297|1.25|\u03a9|ab'
    code.fill()
    code.formatting(40, mixed_format)
    code.emit('b9efffffff49b8')
    code.data.extend(struct.pack('<Q', 4294967297))
    code.static('4c8d0d', omega)
    code.static('488d05', narrow)
    code.emit('48890348b8')
    code.data.extend(struct.pack('<d', 1.25))
    code.emit('66480f6ec0b801000000')
    code.function('swprintf')
    code.status(len(expected), 'mixed formatting counts UTF-16 units excluding null')
    encoded = (expected + '\0').encode('utf-16le')
    code.output(encoded, 'mixed SysV GP SSE and stack string output')
    code.guards(len(encoded), 'mixed formatting guards')
    spill_format = code.wide('%d,%d,%d,%d,%d,%d,%d;%.1f;%.1f', 'GP overflow and two SSE arguments format')
    spill_expected = '1,2,3,4,5,6,7;0.5;-2.0'
    code.fill()
    code.formatting(40, spill_format)
    code.emit('b90100000041b80200000041b903000000')
    for offset, value in zip((0, 8, 16, 24), (4, 5, 6, 7)):
        code.stack_argument(offset, value)
    for bits, suffix in ((0.5, '66480f6ec0'), (-2.0, '66480f6ec8')):
        code.emit('48b8')
        code.data.extend(struct.pack('<d', bits))
        code.emit(suffix)
    code.emit('b802000000')
    code.function('swprintf')
    code.status(len(spill_expected), 'GP overflow and two SSE argument result')
    encoded = (spill_expected + '\0').encode('utf-16le')
    code.output(encoded, 'GP overflow stack and two SSE argument bytes')
    code.guards(len(encoded), 'GP overflow formatting guards')
    count_format = code.wide('Q%nRS', 'count output format')
    code.fill()
    code.address('c783', 0x180)
    code.u32(0xffffffff)
    code.formatting(8, count_format)
    code.address('488d8b', 0x180)
    code.emit('31c0')
    code.function('swprintf')
    code.status(3, 'count conversion output length')
    code.address('83bb', 0x180)
    code.emit('01')
    code.failure('0f85', 'count conversion stores one UTF-16 unit before n')
    code.sentinel(0x178, 8, 'count conversion preserves leading int guard')
    code.sentinel(0x184, 12, 'count conversion writes only a four-byte int')
    code.output('QRS\0'.encode('utf-16le'), 'count conversion output bytes')
    code.guards(8, 'count formatting guards')
    truncated_format = code.wide('abcd', 'truncated output format')
    code.fill()
    code.formatting(3, truncated_format)
    code.emit('31c0')
    code.function('swprintf')
    code.emit('85c0')
    code.failure('0f89', 'truncation must return negative')
    for offset in (0x40, 0x42):
        code.address('6683bb', offset)
        code.emit('00')
        code.branch('0f84', 'truncated-null-present')
    code.address('6683bb', 0x44)
    code.emit('00')
    code.failure('0f85', 'truncation must contain a UTF-16 null within capacity')
    code.labels['truncated-null-present'] = len(code.data)
    code.guards(6, 'truncation preserves bytes outside capacity')
    code.fill()
    code.formatting(1, empty)
    code.emit('31c0')
    code.function('swprintf')
    code.status(0, 'empty formatting fits one UTF-16 unit')
    code.output(bytes(2), 'empty formatting null termination')
    code.guards(2, 'empty formatting guards')
    code.fill()
    code.formatting(0, truncated_format)
    code.emit('31c0')
    code.function('swprintf')
    code.emit('85c0')
    code.failure('0f89', 'zero capacity formatting must return negative')
    code.guards(0, 'zero capacity formatting leaves output unchanged')
    body = code.finish()
    image = bytearray(0xa000)
    image[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', image, 16, 3, 62, 1, 0x4000, 64, 0, 0, 64, 56, 5, 64, 0, 0)
    struct.pack_into('<IIQQQQQQ', image, 64, 1, 7, 0x4000, 0x4000, 0x4000, 0x6000, 0x6000, 0x4000)
    for index in range(2, 5):
        struct.pack_into('<IIQQQQQQ', image, 64 + index * 56, 0x6fffff01, 0, 0, 0, 0, 0, 0, 1)
    configure_fixture_loads(image, len(body), 0x6000)
    strings = bytearray(b'\0')
    offsets = {}
    symbols = [nid + '#A#B' for _, nid in IMPORTS]
    for value in (*symbols, 'libc.prx'):
        offsets[value] = len(strings)
        strings.extend(value.encode() + b'\0')
    image[0x6100:0x6100 + len(strings)] = strings
    tags = [(5, 0x6100), (10, len(strings)), (6, 0x6400), (11, 24), (4, 0x6300),
            (7, 0x6600), (8, len(IMPORTS) * 24), (9, 24), (1, offsets['libc.prx']),
            (0x61000045, (1 << 48) | offsets['libc.prx']), (0, 0)]
    for index, tag in enumerate(tags):
        struct.pack_into('<qQ', image, 0x6000 + index * 16, *tag)
    struct.pack_into('<IIQQQQQQ', image, 120, 2, 6, 0x6000, 0x6000, 0x6000, len(tags)*16, len(tags)*16, 8)
    struct.pack_into('<III', image, 0x6300, 1, len(IMPORTS)+1, 1)
    for index in range(1, len(IMPORTS)+1):
        struct.pack_into('<I', image, 0x6300+12+index*4, index+1 if index<len(IMPORTS) else 0)
    for index, symbol in enumerate(symbols, 1):
        struct.pack_into('<IBBHQQ', image, 0x6400+24*index, offsets[symbol], 0x12, 0, 0, 0, 0)
        struct.pack_into('<QQq', image, 0x6600+24*(index-1), 0x7000+8*(index-1), (index<<32)|6, 0)
    image[0x4000:0x4000+len(body)] = body
    image[0x7800:0x7800+len(code.constants)] = code.constants
    return image, [description for _, description in code.failures], code.constant_manifest


def main():
    if len(sys.argv) != 3 or os.name != 'nt' or platform.machine().lower() not in ('amd64', 'x86_64'):
        raise SystemExit('usage: Windows x86-64 test_converted_wide_contract.py <relinker> <patched-libraries>')
    relinker, libraries = (Path(value).resolve() for value in sys.argv[1:])
    evidence = Path(os.environ.get('ANYPS5_TEST_EVIDENCE', tempfile.gettempdir()))
    evidence.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='anyps5-converted-wide-', dir=evidence))
    (work/'sce_module').mkdir()
    (work/'app0').mkdir()
    runtime = work/'libs'
    runtime.mkdir()
    artifacts = []
    names = ['libc.prx', 'libkernel.prx', 'libgcc_s_seh-1.dll', 'libstdc++-6.dll', 'libwinpthread-1.dll']
    for name in names:
        candidates = [libraries/name, libraries/'unpatched'/name]
        candidates.extend(Path(part)/name for part in os.environ.get('PATH','').split(os.pathsep) if part)
        original = libraries/name if name.endswith('.prx') else next((p for p in candidates if p.is_file()), None)
        if original is not None and not original.is_file():
            raise FileNotFoundError('Requested patched PRX missing: '+str(original))
        if original is None:
            raise FileNotFoundError(name)
        target = runtime/name
        shutil.copy2(original,target)
        if sha256(target) != sha256(original):
            raise AssertionError('Staged artifact hash differs')
        artifacts.append({'source':str(original),'copy':str(target),'sha256':sha256(original),
                          'kind':'patched-prx' if name.endswith('.prx') else 'mingw-runtime'})
    image, expectations, constants = fixture()
    source = work/'input.elf'
    source.write_bytes(image)
    output = work/'output.exe'
    command = [str(relinker),'--registry','--windows',str(source),str(output)]
    manifest = {'platform':platform.platform(),'machine':platform.machine(),'fixture_artifacts':str(work),
                'conversion_command':command,'runtime_command':[str(output)],'cwd':str(work),
                'environment_overrides':{'APS5_TRACE_EXIT':'1'},'artifacts':artifacts,
                'relinker_sha256':sha256(relinker),'fixture_script_sha256':sha256(Path(__file__)),
                'helper_path':str(HELPER),'helper_sha256':sha256(HELPER),'source_sha256':sha256(source),
                'contract':expectations,'payload_manifest':constants,'claim':'bounded Windows UTF-16 C-locale conversion and SysV wide formatting; complete console ABI and locale behavior unverified'}
    manifest_path = work/'manifest.json'
    def save():
        manifest_path.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    save()
    start=time.monotonic()
    converted = subprocess.run(command,cwd=work,capture_output=True,text=True,timeout=10)
    manifest.update(conversion_returncode=converted.returncode,conversion_stdout=converted.stdout,conversion_stderr=converted.stderr)
    (work/'conversion.stdout.txt').write_text(converted.stdout,encoding='utf-8')
    (work/'conversion.stderr.txt').write_text(converted.stderr,encoding='utf-8')
    save()
    if converted.returncode != 0:
        raise AssertionError(('conversion failed',converted.returncode,str(manifest_path)))
    registry_path=output.with_suffix('.registry.json')
    imported={(item['nid'],item['library']) for item in json.loads(registry_path.read_text())}
    required={(nid+'#A#B','libc.prx') for _,nid in IMPORTS}
    if imported != required:
        raise AssertionError(('actual guest NID imports differ',imported,required))
    manifest.update(imports=sorted(imported),registry_sha256=sha256(registry_path),output_sha256=sha256(output))
    save()
    environment=os.environ.copy()
    environment['APS5_TRACE_EXIT']='1'
    executed=subprocess.run([str(output)],cwd=work,env=environment,capture_output=True,text=True,timeout=10)
    manifest.update(returncode=executed.returncode,stdout=executed.stdout,stderr=executed.stderr,duration_seconds=time.monotonic()-start,
                    artifact_hashes_after={item['copy']:sha256(Path(item['copy'])) for item in artifacts})
    (work/'runtime.stdout.txt').write_text(executed.stdout,encoding='utf-8')
    (work/'runtime.stderr.txt').write_text(executed.stderr,encoding='utf-8')
    save()
    if executed.returncode != 0:
        expectation=expectations[executed.returncode-1] if 0<executed.returncode<=len(expectations) else 'loader, ABI or process failure'
        raise AssertionError((expectation,executed.returncode,executed.stderr,str(manifest_path)))
    if '[libc] exit(0) called' not in executed.stderr:
        raise AssertionError(('guest exit evidence missing',str(manifest_path)))
    if any(sha256(Path(item['copy'])) != item['sha256'] for item in artifacts):
        raise AssertionError('Staged runtime artifact changed during execution')
    print('Converted wide guest invoked four actual patched NIDs; all '+str(len(expectations))+' active checks passed')
    print('Evidence: '+str(manifest_path))


if __name__ == '__main__':
    main()
