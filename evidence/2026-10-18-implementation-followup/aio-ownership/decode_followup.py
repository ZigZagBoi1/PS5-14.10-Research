exec((__import__('pathlib').Path(__file__).parent/'decode_callees.py').read_text().split('windows=')[0])
windows=[('lookup_complete',0x399ee0,0x39a09a),('object_lock_dispatch',0xbf1770,0xbf22d0),('wait_primitive',0xc06260,0xc06800),('record_notify_area',0x3af900,0x3b01f0),('aio_following_bodies',0x3b0fb0,0x3b3410),('rwlock_enter',0xc4b350,0xc4b500),('rwlock_leave_A',0xc4c300,0xc4c4b0),('rwlock_leave_B',0xc4c4b0,0xc4c610)]
recs=[]
for name,start,end in windows:
 lines=[];strings=[]
 for i in md.disasm(code[start:end],start):
  lines.append(f'{i.address:08x}: {i.bytes.hex():28} {i.mnemonic} {i.op_str}')
  for op in i.operands:
   if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
    off=i.address+i.size+op.mem.disp-0x1000000
    if 0<=off<len(data):
     b=data[off:off+300].split(b'\0')[0]
     if b and all(32<=c<127 or c in (9,10,13) for c in b): strings.append({'instruction':hex(i.address),'data_offset':hex(off),'string':b.decode()})
 (out/(name+'.asm.txt')).write_text('\n'.join(lines)+'\n')
 recs.append({'name':name,'start':hex(start),'end_exclusive':hex(end),'window_sha256':hashlib.sha256(code[start:end]).hexdigest(),'strings':strings})
(out/'FOLLOWUP_WINDOWS.json').write_text(json.dumps(recs,indent=2))
