import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from test_windows_import_modules import executable, exit_code_without_standard_handles


def table(path):
    image = path.read_bytes()
    header = struct.unpack_from('<I', image, 0x3c)[0]
    optional = header + 24
    section_table = optional + struct.unpack_from('<H', image, header + 20)[0]
    sections = []
    for index in range(struct.unpack_from('<H', image, header + 6)[0]):
        position = section_table + index * 40
        size, rva, raw_size, raw = struct.unpack_from('<IIII', image, position + 8)
        sections.append((image[position:position + 8].rstrip(b'\0'), rva, size, raw_size, raw))

    def offset(rva, length):
        for _, start, _, raw_size, raw in sections:
            if start <= rva and rva + length <= start + raw_size:
                return raw + rva - start
        raise AssertionError(f'Unmapped exception data {rva:#x}+{length}')

    rva, size = struct.unpack_from('<II', image, optional + 112 + 3 * 8)
    assert size and size % 12 == 0
    count = size // 12
    assert count <= 32
    start = offset(rva, size)
    entry = next(section for section in sections if section[0] == b'.entry')
    records = []
    previous_end = entry[1]
    for index in range(count):
        begin, end, unwind = struct.unpack_from('<III', image, start + index * 12)
        assert previous_end <= begin < end <= entry[1] + entry[2]
        previous_end = end
        data = image[offset(unwind, 24):offset(unwind, 24) + 24]
        assert data[0] & 7 == 1 and data[1] <= end - begin
        records.append(struct.pack('<III', begin, end, unwind) + data)
    assert records[1][12:20] == bytes((1, 4, 1, 0, 4, 0x42, 0, 0))
    expected = bytes((1, 16, 9, 0, 16, 0x82, 12, 0xf0, 10, 0xe0, 8, 0xd0,
                      6, 0xc0, 4, 0x70, 3, 0x60, 2, 0x50, 1, 0x30, 0, 0))
    assert all(record[12:] == expected for record in records[2:14])
    return records


def main():
    relinker, provider = map(lambda value: Path(value).resolve(), sys.argv[1:3])
    parent = os.environ.get('ANYPS5_STDIO_TEST_ARTIFACTS')
    if parent:
        Path(parent).mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='anyps5-stdio-unwind-', dir=parent))
    completed = False
    try:
        for diagnostics in (False, True):
            case = work / ('diagnostics' if diagnostics else 'default')
            (case / 'libs').mkdir(parents=True)
            (case / 'prx').mkdir()
            source = case / 'input.elf'
            source.write_bytes(executable('a.prx', 'shared'))
            output = case / 'output.exe'
            command = [str(relinker), '--windows', '--windows-gui']
            if diagnostics:
                command.append('--windows-diagnostics')
            command.extend((str(source), str(output)))
            result = subprocess.run(command, cwd=case, capture_output=True, text=True, timeout=30)
            assert result.returncode == 0, result.stderr
            shutil.copyfile(provider, case / 'libs' / 'a.prx')
            records = table(output)
            assert len(records) == (31 if diagnostics else 14)
            witness = case / 'unwind.bin'
            os.environ['ANYPS5_STDIO_UNWIND_WITNESS'] = str(witness)
            result = exit_code_without_standard_handles(output)
            assert result == len(records), (result, case)
            actual = witness.read_bytes()
            expected = b'\xaa' * 32 + struct.pack('<I', len(records)) + b''.join(records)
            expected += b'\xaa' * (36 * (32 - len(records)) + 32)
            assert actual == expected, (case, len(actual), len(expected))
        completed = True
        print('Generated PE: 14 and 31 sorted unwind ranges matched native lookups and guarded witnesses')
    finally:
        os.environ.pop('ANYPS5_STDIO_UNWIND_WITNESS', None)
        if completed and not parent:
            shutil.rmtree(work)


if __name__ == '__main__':
    main()
