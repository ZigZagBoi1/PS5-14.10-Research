exec((__import__('pathlib').Path(__file__).parent/'decode_callees.py').read_text().split('windows=')[0])
windows=[('zero_helper',0x258ff0,0x259050),('exclusive_lock_head',0xc4bb20,0xc4bc20)]
records=[]
for name,a,b in windows:
 (out/(name+'.asm.txt')).write_text('\n'.join(f'{i.address:08x}: {i.bytes.hex():28} {i.mnemonic} {i.op_str}' for i in md.disasm(code[a:b],a))+'\n')
 records.append({'name':name,'start':hex(a),'end_exclusive':hex(b),'window_sha256':hashlib.sha256(code[a:b]).hexdigest()})
(out/'LOCK_ZERO_WINDOWS.json').write_text(json.dumps(records,indent=2))
