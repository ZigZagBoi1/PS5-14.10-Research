from pathlib import Path
import json,hashlib
p=Path(__file__).parent;r=(p/'response.raw').read_bytes();items=[]
for name in ('fcall_call','syscall_resolve','native_fcall_with_rax'):
 body=r.split(b'CHUNK_BEGIN\t'+name.encode(),1)[1].split(b'CHUNK_END\t'+name.encode(),1)[0];lines=body.splitlines();n=[int(x.split(b'\t')[1]) for x in lines if x.startswith(b'CHUNK_BYTES\t')]
 if not n:items.append({'function':name,'status':'unavailable'});continue
 b=b''.join(bytes.fromhex(x.split(b'\t',1)[1].decode()) for x in lines if x.startswith(b'HEX\t'));assert len(b)==n[0]
 (p/(name+'.luac.bin')).write_bytes(b);items.append({'function':name,'bytes':len(b),'sha256_serialized_now':hashlib.sha256(b).hexdigest(),'header_hex':b[:12].hex(),'limitation':'serialization from current runtime; not native code or historical identity; not executed offline'})
(p/'LOADED_CHUNKS.json').write_text(json.dumps(items,indent=2));print(json.dumps(items,indent=2))
