exec((__import__('pathlib').Path(__file__).parent/'decode_callees.py').read_text().split('windows=')[0])
windows=[('allocator_zero_path',0x43be15,0x43c080),('descriptor_exclusive_lookup',0x39a2a0,0x39a490),('entry_dispose',0x3b3e90,0x3b3f50),('lockmgr_init',0xbf1690,0xbf1770)]
rs=[]
for name,a,b in windows:
 lines=[f'{i.address:08x}: {i.bytes.hex():28} {i.mnemonic} {i.op_str}' for i in md.disasm(code[a:b],a)]
 (out/(name+'.asm.txt')).write_text('\n'.join(lines)+'\n')
 rs.append({'name':name,'start':hex(a),'end_exclusive':hex(b),'window_sha256':hashlib.sha256(code[a:b]).hexdigest()})
(out/'FINAL_TARGETED_WINDOWS.json').write_text(json.dumps(rs,indent=2))
