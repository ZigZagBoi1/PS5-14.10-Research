from pathlib import Path
import json,hashlib
p=Path(__file__).parent;r=(p/'response.raw').read_bytes();out=[]
for name in ('ropchain.lua','lua.lua'):
 body=r.split(b'FILE_BEGIN\t'+name.encode(),1)[1].split(b'FILE_END\t'+name.encode(),1)[0];lines=body.splitlines();n=[int(x.split(b'\t')[1]) for x in lines if x.startswith(b'FILE_BYTES\t')];b=b''.join(bytes.fromhex(x.split(b'\t',1)[1].decode()) for x in lines if x.startswith(b'HEX\t'));assert len(n)==1 and n[0]==len(b)
 (p/name).write_bytes(b);out.append({'original_path':'/savedata0/'+name,'bytes':len(b),'sha256_received_now':hashlib.sha256(b).hexdigest(),'loaded_chunk_identity':'not established'})
(p/'RECEIVED_FILES.json').write_text(json.dumps(out,indent=2));print(json.dumps(out,indent=2))
