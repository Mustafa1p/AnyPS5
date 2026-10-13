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

HELPER=Path(__file__).resolve().with_name('test_converted_library_contract.py')
from test_converted_library_contract import Code,configure_fixture_loads,sha256

IMPORTS=[('init','ZsXLFtd2jqQ','libkernel.prx'),('wait','CawZgCYqXWk','libkernel.prx'),
         ('destroy','+Pqub9HZCPo','libkernel.prx'),('create','OxhIB8LB-PQ','libkernel.prx'),
         ('join','h9CcP3J0oVM','libkernel.prx'),('open','wuCroIGjt2g','libkernel.prx'),
         ('lseek','Oy6IpwgtYOk','libkernel.prx'),('write','FN4gaPmuFV8','libkernel.prx'),
         ('close','bY-PO6JhzhQ','libkernel.prx'),('exit','uMei1W9uyNo','libc.prx')]
SLOTS={name:0x7000+index*8 for index,(name,_,_) in enumerate(IMPORTS)}
SHARED=0x7c00
JOIN_VALUES=[0x1234567887654001,0x1234567887654002]
ORIGINAL=bytes([0xaa])*256
EXPECTED=ORIGINAL[:32]+struct.pack('<12I',*([1]*12))+bytes([0xaa])*16+ORIGINAL[96:]


class BarrierCode(Code):
    def address(self,opcode,offset):
        self.emit(opcode)
        self.u32(offset)

    def static(self,opcode,address):
        self.emit(opcode)
        self.u32((address-(0x4000+len(self.data)+4))&0xffffffff)

    def function(self,name):
        self.call(SLOTS[name])

    def store(self,offset,value):
        self.address('c783',offset)
        self.u32(value)

    def expect(self,offset,value,description):
        self.address('81bb',offset)
        self.u32(value)
        self.failure('0f85',description)

    def wait(self,generation,participant):
        unique=participant+'-'+str(generation)
        self.emit('4889df')
        self.function('wait')
        self.emit('83f8ff')
        self.branch('0f85','normal-'+unique)
        self.address('f08383',0x40+generation*4)
        self.emit('01')
        self.branch('e9','waited-'+unique)
        self.labels['normal-'+unique]=len(self.data)
        self.status(0,participant+' generation '+str(generation)+' wait must return zero or SERIAL_THREAD')
        self.labels['waited-'+unique]=len(self.data)

    def guards(self,description):
        for offset,length in ((8,8),(0x30,16),(0x70,0x50),(0xcc,4),(0xd8,0x328)):
            self.sentinel(offset,length,description+' '+hex(offset))

    def finish(self):
        for index,(name,_) in enumerate(self.failures,1):
            self.labels[name]=len(self.data)
            self.emit('bf')
            self.u32(index)
            self.function('exit')
            self.emit('0f0b')
        for position,name in self.branches:
            struct.pack_into('<i',self.data,position,self.labels[name]-position-4)
        if len(self.data)>=0x2000:
            raise AssertionError('Fixture code overlaps dynamic section')
        return self.data


def fixture():
    code=BarrierCode()
    code.emit('5341544883ec08')
    code.static('488d1d',SHARED)
    code.emit('48c703000000004889df31f631d2')
    code.function('init')
    code.status(22,'zero barrier participant count must report EINVAL22')
    code.guards('zero count must preserve storage outside barrier object')
    code.emit('48c703000000004889df31f6ba03000000')
    code.function('init')
    code.status(0,'default private barrier initializes with three participants')
    code.emit('48833b00')
    code.failure('0f84','successful barrier initialization produces a usable opaque handle')
    code.address('488dbb',0x40)
    code.emit('b90600000031c0f348ab')
    for worker,offset in enumerate((0x10,0x18)):
        code.address('488dbb',offset)
        code.emit('31f6')
        code.branch('488d15','worker-'+str(worker))
        code.emit('4889d9')
        code.function('create')
        code.status(0,'create SysV worker '+str(worker)+' succeeds')
    for cycle in range(4):
        code.wait(cycle*3,'main')
        for worker in range(2):
            code.expect(0xc0+worker*4,1000+cycle*10+worker,'main sees worker '+str(worker)+' published marker after generation '+str(cycle*3))
        code.store(0xc8,2000+cycle)
        code.wait(cycle*3+1,'main')
        code.wait(cycle*3+2,'main')
        for worker in range(2):
            code.expect(0xd0+worker*4,3000+cycle*10+worker,'main sees worker '+str(worker)+' acknowledgement after generation '+str(cycle*3+2))
    for worker,thread_offset,result_offset in ((0,0x10,0x20),(1,0x18,0x28)):
        code.address('488bbb',thread_offset)
        code.address('488db3',result_offset)
        code.function('join')
        code.status(0,'join actual worker '+str(worker)+' succeeds')
        code.emit('48b8')
        code.data.extend(struct.pack('<Q',JOIN_VALUES[worker]))
        code.address('483983',result_offset)
        code.failure('0f85','join preserves full64-bit SysV worker '+str(worker)+' return value')
    for generation in range(12):
        code.expect(0x40+generation*4,1,'generation '+str(generation)+' has exactly one serial return across three participants')
    code.guards('joined workers preserve opaque handle and message guards')
    code.emit('4889df')
    code.function('destroy')
    code.status(0,'completed private barrier destroys successfully')
    code.guards('barrier destruction preserves outside-object guards')
    code.static('488d3d',0x7800)
    code.emit('be0200000031d2')
    code.function('open')
    code.emit('85c0')
    code.failure('0f88','open host-created side-effect file succeeds')
    code.emit('4189c44489e7be2000000031d2')
    code.function('lseek')
    code.emit('483d20000000')
    code.failure('0f85','side-effect file cursor moves to guarded payload offset32')
    code.emit('4489e7')
    code.address('488db3',0x40)
    code.emit('ba40000000')
    code.function('write')
    code.emit('483d40000000')
    code.failure('0f85','guest writes64-byte serial-count witness into real host file')
    code.emit('4489e7')
    code.function('close')
    code.status(0,'close side-effect file succeeds')
    code.emit('31ff')
    code.function('exit')
    code.emit('0f0b')
    for worker in range(2):
        code.labels['worker-'+str(worker)]=len(code.data)
        code.emit('534889fb')
        for cycle in range(4):
            code.store(0xc0+worker*4,1000+cycle*10+worker)
            code.wait(cycle*3,'worker'+str(worker))
            code.wait(cycle*3+1,'worker'+str(worker))
            code.expect(0xc8,2000+cycle,'worker '+str(worker)+' sees main broadcast after generation '+str(cycle*3+1))
            code.store(0xd0+worker*4,3000+cycle*10+worker)
            code.wait(cycle*3+2,'worker'+str(worker))
        code.emit('48b8')
        code.data.extend(struct.pack('<Q',JOIN_VALUES[worker]))
        code.emit('5bc3')
    body=code.finish()
    image=bytearray(0xa000)
    image[:16]=b'\x7fELF\x02\x01\x01'+bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH',image,16,3,62,1,0x4000,64,0,0,64,56,5,64,0,0)
    struct.pack_into('<IIQQQQQQ',image,64,1,7,0x4000,0x4000,0x4000,0x6000,0x6000,0x4000)
    for index in range(2,5):
        struct.pack_into('<IIQQQQQQ',image,64+index*56,0x6fffff01,0,0,0,0,0,0,1)
    configure_fixture_loads(image,len(body),0x6000)
    strings=bytearray(b'\0')
    offsets={}
    symbols=[]
    for _,nid,library in IMPORTS:
        symbol=nid+('#A#B' if library=='libkernel.prx' else '#A#C')
        symbols.append(symbol)
        for value in (symbol,library):
            if value not in offsets:
                offsets[value]=len(strings)
                strings.extend(value.encode()+b'\0')
    if len(strings)>0x200:
        raise AssertionError('Fixture string table overlaps hash table')
    image[0x6100:0x6100+len(strings)]=strings
    tags=[(5,0x6100),(10,len(strings)),(6,0x6400),(11,24),(4,0x6300),
          (7,0x6600),(8,len(IMPORTS)*24),(9,24),(1,offsets['libkernel.prx']),(1,offsets['libc.prx']),
          (0x61000045,(1<<48)|offsets['libkernel.prx']),(0x61000045,(2<<48)|offsets['libc.prx']),(0,0)]
    for index,tag in enumerate(tags):
        struct.pack_into('<qQ',image,0x6000+index*16,*tag)
    struct.pack_into('<IIQQQQQQ',image,120,2,6,0x6000,0x6000,0x6000,len(tags)*16,len(tags)*16,8)
    struct.pack_into('<III',image,0x6300,1,len(IMPORTS)+1,1)
    for index in range(1,len(IMPORTS)+1):
        struct.pack_into('<I',image,0x6300+12+index*4,index+1 if index<len(IMPORTS) else 0)
    for index,symbol in enumerate(symbols,1):
        struct.pack_into('<IBBHQQ',image,0x6400+24*index,offsets[symbol],0x12,0,0,0,0)
        struct.pack_into('<QQq',image,0x6600+24*(index-1),0x7000+8*(index-1),(index<<32)|6,0)
    image[0x4000:0x4000+len(body)]=body
    path=b'/app0/barrier-witness.bin\0'
    image[0x7800:0x7800+len(path)]=path
    image[SHARED:SHARED+0x400]=bytes([0xaa])*0x400
    return image,[description for _,description in code.failures]


def main():
    if len(sys.argv)!=3 or os.name!='nt' or platform.machine().lower() not in ('amd64','x86_64'):
        raise SystemExit('usage: Windows x86-64 test_converted_barrier_contract.py <relinker> <patched-libraries>')
    relinker,libraries=(Path(value).resolve() for value in sys.argv[1:])
    evidence=Path(os.environ.get('ANYPS5_TEST_EVIDENCE',tempfile.gettempdir()))
    evidence.mkdir(parents=True,exist_ok=True)
    work=Path(tempfile.mkdtemp(prefix='anyps5-converted-barrier-',dir=evidence))
    (work/'sce_module').mkdir()
    (work/'app0').mkdir()
    runtime=work/'libs'
    runtime.mkdir()
    artifacts=[]
    for name in ('libc.prx','libkernel.prx','libgcc_s_seh-1.dll','libstdc++-6.dll','libwinpthread-1.dll'):
        candidates=[libraries/name,libraries/'unpatched'/name]
        candidates.extend(Path(part)/name for part in os.environ.get('PATH','').split(os.pathsep) if part)
        original=libraries/name if name.endswith('.prx') else next((p for p in candidates if p.is_file()),None)
        if original is None or not original.is_file():
            raise FileNotFoundError(name)
        target=runtime/name
        shutil.copy2(original,target)
        if sha256(target)!=sha256(original):
            raise AssertionError('Copied runtime hash differs')
        artifacts.append({'source':str(original),'copy':str(target),'sha256':sha256(original)})
    payload=work/'app0/barrier-witness.bin'
    payload.write_bytes(ORIGINAL)
    source=work/'input.elf'
    image,expectations=fixture()
    source.write_bytes(image)
    output=work/'output.exe'
    command=[str(relinker),'--registry','--windows',str(source),str(output)]
    manifest={'platform':platform.platform(),'machine':platform.machine(),'fixture_artifacts':str(work),
              'conversion_command':command,'runtime_command':[str(output)],'cwd':str(work),
              'environment_overrides':{'APS5_TRACE_EXIT':'1'},'artifacts':artifacts,
              'relinker_sha256':sha256(relinker),'fixture_script_sha256':sha256(Path(__file__)),
              'helper_path':str(HELPER),'helper_sha256':sha256(HELPER),'source_sha256':sha256(source),
              'contract':expectations,'participants':3,'reused_generations':12,'join_values':JOIN_VALUES,
              'payload_path':str(payload),'payload_before_hex':ORIGINAL.hex(),'payload_before_sha256':sha256(payload),
              'payload_expected_hex':EXPECTED.hex(),'payload_guard_prefix_bytes':32,'payload_guard_suffix_bytes':160,
              'claim':'bounded converted default private barrier rendezvous and SysV thread callbacks; shared-process, cancellation, full thread attrs/console and Linux unverified'}
    manifest_path=work/'manifest.json'
    def save():
        manifest_path.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    save()
    start=time.monotonic()
    converted=subprocess.run(command,cwd=work,capture_output=True,text=True,timeout=10)
    manifest.update(conversion_returncode=converted.returncode,conversion_stdout=converted.stdout,conversion_stderr=converted.stderr)
    (work/'conversion.stdout.txt').write_text(converted.stdout,encoding='utf-8')
    (work/'conversion.stderr.txt').write_text(converted.stderr,encoding='utf-8')
    save()
    if converted.returncode!=0:
        raise AssertionError(('conversion failed',converted.returncode,str(manifest_path)))
    registry_path=output.with_suffix('.registry.json')
    imported={(item['nid'],item['library']) for item in json.loads(registry_path.read_text())}
    required={(nid+('#A#B' if library=='libkernel.prx' else '#A#C'),library) for _,nid,library in IMPORTS}
    if imported!=required:
        raise AssertionError(('actual guest imports differ',imported,required))
    manifest.update(imports=sorted(imported),registry_sha256=sha256(registry_path),output_sha256=sha256(output))
    save()
    environment=os.environ.copy()
    environment['APS5_TRACE_EXIT']='1'
    try:
        executed=subprocess.run([str(output)],cwd=work,env=environment,capture_output=True,text=True,timeout=10)
    except subprocess.TimeoutExpired as error:
        manifest.update(runtime_timeout=True,duration_seconds=time.monotonic()-start,payload_after_sha256=sha256(payload))
        save()
        raise AssertionError(('guest barrier timed out',str(manifest_path))) from error
    manifest.update(returncode=executed.returncode,stdout=executed.stdout,stderr=executed.stderr,duration_seconds=time.monotonic()-start,
                    payload_after_sha256=sha256(payload),payload_after_hex=payload.read_bytes().hex(),payload_matches_expected=payload.read_bytes()==EXPECTED,
                    artifact_hashes_after={item['copy']:sha256(Path(item['copy'])) for item in artifacts})
    (work/'runtime.stdout.txt').write_text(executed.stdout,encoding='utf-8')
    (work/'runtime.stderr.txt').write_text(executed.stderr,encoding='utf-8')
    save()
    if executed.returncode!=0:
        expectation=expectations[executed.returncode-1] if 0<executed.returncode<=len(expectations) else 'loader, ABI or process failure'
        raise AssertionError((expectation,executed.returncode,executed.stderr,str(manifest_path)))
    if not manifest['payload_matches_expected']:
        raise AssertionError(('host independently observed incorrect serial counters or file guards',str(manifest_path)))
    if '[libc] exit(0) called' not in executed.stderr:
        raise AssertionError(('guest exit evidence missing',str(manifest_path)))
    if any(sha256(Path(item['copy']))!=item['sha256'] for item in artifacts):
        raise AssertionError('Runtime artifacts changed')
    print('Converted private barrier: three participants, twelve generations, '+str(len(expectations))+' active guest checks, independent host file witness PASS')
    print('Evidence: '+str(manifest_path))


if __name__=='__main__':
    main()
