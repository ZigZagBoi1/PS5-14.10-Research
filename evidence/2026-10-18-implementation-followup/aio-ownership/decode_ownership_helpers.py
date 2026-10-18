exec((__import__('pathlib').Path(__file__).parent/'decode_callees.py').read_text().split('windows=')[0])
windows=[('lookup_tail',0x39a095,0x39a100),('aio_helpers',0x3b4440,0x3b6800),('wakeup',0xc06910,0xc06980),('allocation_backend',0x43b880,0x43bc00)]
recs=[]
for name,start,end in windows:
 lines=[];refs=[];calls=[]
 for i in md.disasm(code[start:end],start):
  lines.append(f'{i.address:08x}: {i.bytes.hex():28} {i.mnemonic} {i.op_str}')
  if i.mnemonic=='call': calls.append({'offset':hex(i.address),'target':i.op_str})
  for op in i.operands:
   if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
    off=i.address+i.size+op.mem.disp-0x1000000
    if 0<=off<len(data):
     b=data[off:off+300].split(b'\0')[0]
     if b and all(32<=c<127 or c in (9,10,13) for c in b):refs.append({'instruction':hex(i.address),'data_offset':hex(off),'string':b.decode()})
 (out/(name+'.asm.txt')).write_text('\n'.join(lines)+'\n')
 recs.append({'name':name,'start':hex(start),'end_exclusive':hex(end),'window_sha256':hashlib.sha256(code[start:end]).hexdigest(),'strings':refs,'calls':calls})
(out/'OWNERSHIP_HELPER_WINDOWS.json').write_text(json.dumps(recs,indent=2))
