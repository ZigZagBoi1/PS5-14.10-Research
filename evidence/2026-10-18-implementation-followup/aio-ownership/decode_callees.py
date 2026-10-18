from pathlib import Path
import json, hashlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
root=Path('F:/PS5-14.10-Research/docs/dumps_13.60')
out=Path(__file__).parent
code=(root/'kernel_text.bin').read_bytes(); data=(root/'kernel_data.bin').read_bytes()
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
windows=[('lookup_399ee0',0x399ee0,0x39a040),('retain_lock_399e20',0x399e20,0x399eb0),('release_399eb0',0x399eb0,0x399ee0),('finish_3b3f50',0x3b3f50,0x3b42a0),('result_3b3a40',0x3b3a40,0x3b3c00),('object_lock_bf1770',0xbf1770,0xbf1c00),('mutex_init_4c7dd0',0x4c7dd0,0x4c7e50),('mutex_destroy_4c7e50',0x4c7e50,0x4c7f30),('mutex_enter_4c6a00',0x4c6a00,0x4c6c00)]
records=[]
for name,start,end in windows:
    lines=[]; calls=[]; refs=[]
    for i in md.disasm(code[start:end],start):
        lines.append(f'{i.address:08x}: {i.bytes.hex():28} {i.mnemonic} {i.op_str}')
        if i.mnemonic in ('call','jmp'): calls.append({'offset':hex(i.address),'operation':i.mnemonic,'target':i.op_str})
        for op in i.operands:
            if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
                target=i.address+i.size+op.mem.disp; off=target-0x1000000
                if 0<=off<len(data):
                    b=data[off:off+300].split(b'\0')[0]
                    if b and all(32<=c<127 or c in (9,10,13) for c in b): refs.append({'instruction':hex(i.address),'data_file_offset':hex(off),'string':b.decode('ascii')})
    (out/(name+'.asm.txt')).write_text('\n'.join(lines)+'\n')
    records.append({'name':name,'source':str(root/'kernel_text.bin'),'start':hex(start),'end_exclusive':hex(end),'selected_window_sha256':hashlib.sha256(code[start:end]).hexdigest(),'calls_and_jumps':calls,'strings':refs,'limitation':'Decode window may include adjacent functions; names provisional.'})
(out/'CALLEE_WINDOWS.json').write_text(json.dumps(records,indent=2))
