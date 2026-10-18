from pathlib import Path
import json,hashlib,struct
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
b=Path('F:/PS5-14.10-Research/docs/dumps_13.60/kernel_text.bin').read_bytes();out=Path(__file__).parent;m=Cs(CS_ARCH_X86,CS_MODE_64)
windows=[('write_enter',0x2c6480,0x2c64e1),('read_enter',0x2c6820,0x2c6863),('upgrade',0x2c6980,0x2c6a97),('map_initializer',0x2c6f80,0x2c70a0),('metric_reader',0xabd4f0,0xabd532)]
r=[]
for name,a,z in windows:
 (out/(name+'.asm.txt')).write_text('\n'.join(f'{i.address:08x}: {i.bytes.hex():28} {i.mnemonic} {i.op_str}' for i in m.disasm(b[a:z],a))+'\n')
 r.append({'name':name,'start':hex(a),'end_exclusive':hex(z),'window_sha256':hashlib.sha256(b[a:z]).hexdigest(),'limitation':'Window boundaries are analytical; includes bytes rather than authenticated symbols.'})
x=[]
for a in range(0x2c6000,0x2d8000):
 if b[a]==0xe8:
  t=a+5+struct.unpack_from('<i',b,a+1)[0]
  if t==0x2c6480:
   st=b.rfind(bytes.fromhex('554889e5'),max(0,a-5000),a)
   ins=list(m.disasm(b[st:a+5],st)) if st>=0 else []
   if ins and ins[-1].address==a:
    x.append({'call':hex(a),'prologue_candidate':hex(st),'context':[f'{i.address:08x}: {i.mnemonic} {i.op_str}' for i in ins[-12:]]})
(out/'DIRECT_CALL_CANDIDATES.json').write_text(json.dumps(x,indent=2));(out/'FOCUSED_WINDOWS.json').write_text(json.dumps(r,indent=2))
print('validated_linear_call_candidates',len(x));print(json.dumps(x[:4],indent=2))
