from pathlib import Path
import hashlib,json
p=Path(__file__).parent;raw=(p/'response.raw').read_bytes();records=[]
for name in ('syscall.lua','native.lua','uint64.lua'):
 start=b'FILE_BEGIN\t'+name.encode();end=b'FILE_END\t'+name.encode()
 body=raw.split(start,1)[1].split(end,1)[0];lines=body.splitlines();size=[int(l.split(b'\t')[1]) for l in lines if l.startswith(b'FILE_BYTES\t')]
 data=b''.join(bytes.fromhex(l.split(b'\t',1)[1].decode()) for l in lines if l.startswith(b'HEX\t'))
 assert len(size)==1 and len(data)==size[0],(name,size,len(data))
 (p/name).write_bytes(data);records.append({'original_path':'/savedata0/'+name,'bytes':len(data),'sha256_received_now':hashlib.sha256(data).hexdigest(),'custody':'named userland file read -> hex TCP response -> exact byte reconstruction','historical_execution_identity':'not established','current_loaded_chunk_identity':'not established'})
(p/'RECEIVED_FILES.json').write_text(json.dumps(records,indent=2));print(json.dumps(records,indent=2))
