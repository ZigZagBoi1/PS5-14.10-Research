from pathlib import Path
import json
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM,X86_REG_RIP
p=Path('F:/PS5-14.10-Research/docs/dumps_13.60/kernel_text.bin');b=p.read_bytes();d=Path('F:/PS5-14.10-Research/docs/dumps_13.60/kernel_data.bin').read_bytes();out=Path(__file__).parent
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
records=[];pos=0;starts=set()
while True:
 pos=b.find(bytes.fromhex('c4010000'),pos)
 if pos<0:break
 start=b.rfind(bytes.fromhex('554889e5'),max(0,pos-5000),pos)
 if start>=0:
  ins=list(md.disasm(b[start:pos+20],start))
  for k,i in enumerate(ins):
   if i.address<=pos<i.address+i.size and any(o.type==X86_OP_MEM and o.mem.disp==0x1c4 for o in i.operands):
    records.append({'instruction':hex(i.address),'decode_start':hex(start),'bytes':i.bytes.hex(),'operation':i.mnemonic+' '+i.op_str,'context':[f'{x.address:08x}: {x.mnemonic} {x.op_str}' for x in ins[max(0,k-5):k+3]],'caution':'prologue-pattern linear decode; object identity and reachability unverified'})
    starts.add(start)
 pos+=4
(out/'FIELD_DISPLACEMENT_CANDIDATES.json').write_text(json.dumps(records,indent=2))
for start in starts:
 end=min(start+6000,len(b));lines=[]
 for i in md.disasm(b[start:end],start):
  line=f'{i.address:08x}: {i.bytes.hex():28} {i.mnemonic} {i.op_str}'
  for o in i.operands:
   if o.type==X86_OP_MEM and o.mem.base==X86_REG_RIP:
    off=i.address+i.size+o.mem.disp-0x1000000
    if 0<=off<len(d):
     s=d[off:off+180].split(b'\0')[0]
     if s and all(32<=x<127 or x in (10,13,9) for x in s):line+=' ; DATA '+hex(off)+' '+repr(s.decode())
  lines.append(line)
 (out/(hex(start)+'.asm.txt')).write_text('\n'.join(lines)+'\n')
print(json.dumps(records,indent=2))
