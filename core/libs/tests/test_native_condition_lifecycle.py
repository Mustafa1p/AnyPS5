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

from test_converted_library_contract import sha256

HELPER = Path(__file__).resolve().with_name('test_converted_library_contract.py')
ORIGINAL = bytes([0xaa]) * 256
RECORD = struct.pack('<IIIIQQQII', 48, 48, 408, 816, 0x12345678bbcc0045, 0x12345678bbcc0046, 0xc0d1c7105a5af00d, 16, 96)
EXPECTED = ORIGINAL[:32] + RECORD + ORIGINAL[80:]


def main():
    if len(sys.argv) != 3 or os.name != 'nt' or platform.machine().lower() not in ('amd64', 'x86_64'):
        raise SystemExit('usage: Windows x86-64 test_native_condition_lifecycle.py <executable> <patched-libraries>')
    executable, libraries = (Path(value).resolve() for value in sys.argv[1:])
    evidence = Path(os.environ.get('ANYPS5_TEST_EVIDENCE', tempfile.gettempdir()))
    evidence.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='anyps5-native-condition-', dir=evidence))
    runtime = work / 'libs'
    runtime.mkdir()
    (work / 'app0').mkdir()
    artifacts = []
    staged = work / executable.name
    shutil.copyfile(executable, staged)
    artifacts.append({'source': str(executable), 'copy': str(staged), 'sha256': sha256(executable)})
    for name in ('libc.prx', 'libkernel.prx', 'libgcc_s_seh-1.dll', 'libstdc++-6.dll', 'libwinpthread-1.dll'):
        candidates = [libraries / name, executable.parent / name]
        candidates.extend(Path(part) / name for part in os.environ.get('PATH', '').split(os.pathsep) if part)
        original = libraries / name if name.endswith('.prx') else next((path for path in candidates if path.is_file()), None)
        if original is None or not original.is_file():
            raise FileNotFoundError(name)
        target = runtime / name
        shutil.copyfile(original, target)
        artifacts.append({'source': str(original), 'copy': str(target), 'sha256': sha256(original)})
    if any(sha256(Path(item['copy'])) != item['sha256'] for item in artifacts):
        raise AssertionError('Copied native condition artifact hash differs')
    payload = work / 'app0/condition-witness.bin'
    payload.write_bytes(ORIGINAL)
    environment = os.environ.copy()
    environment['PATH'] = str(runtime) + os.pathsep + environment['PATH']
    command = [str(staged), str(runtime)]
    manifest = {'command': command, 'cwd': str(work), 'environment_changes': {'PATH_prefix': str(runtime)}, 'platform': platform.platform(), 'artifacts': artifacts, 'driver_sha256': sha256(Path(__file__)), 'helper_sha256': sha256(HELPER), 'payload_before_hex': ORIGINAL.hex(), 'payload_expected_hex': EXPECTED.hex(), 'claim': 'Existing project condition/mutex ** handle and SysV callback model; nine libc operations and normal lifecycle. Destroy-to-null and relock-busy3 are project-source expectations; spurious wakes/order allowed; no private PS5 object layout or console claim.'}
    manifest_path = work / 'manifest.json'
    def save():
        manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    save()
    started = time.monotonic()
    try:
        result = subprocess.run(command, cwd=work, env=environment, capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired as error:
        manifest.update(timed_out=True, duration_seconds=time.monotonic() - started)
        save()
        raise AssertionError(('native condition lifecycle timed out', str(manifest_path))) from error
    manifest.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr, duration_seconds=time.monotonic() - started, payload_after_hex=payload.read_bytes().hex(), payload_matches_expected=payload.read_bytes() == EXPECTED, artifact_hashes_after={item['copy']: sha256(Path(item['copy'])) for item in artifacts})
    save()
    if result.returncode != 0:
        raise AssertionError(('native condition lifecycle failed', result.returncode, result.stderr, str(manifest_path)))
    if not manifest['payload_matches_expected']:
        raise AssertionError(('independent native condition host file witness mismatch', str(manifest_path)))
    if any(sha256(Path(item['source'])) != item['sha256'] or sha256(Path(item['copy'])) != item['sha256'] for item in artifacts):
        raise AssertionError('Native condition runtime artifact changed')
    print('Native patched condition lifecycle and independent48-byte guarded file witness PASS')
    print('Evidence: ' + str(manifest_path))


if __name__ == '__main__':
    main()
