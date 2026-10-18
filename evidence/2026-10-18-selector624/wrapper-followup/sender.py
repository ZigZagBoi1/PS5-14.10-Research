from pathlib import Path
import socket,struct,hashlib,json,datetime
p=Path(__file__).parent
now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
b=(p/'baseline.lua').read_bytes();frame=struct.pack('<Q',len(b))+b
(p/'transmitted-frame.bin').write_bytes(frame)
r={'endpoint':'10.0.0.96:9026','start_utc':now(),'script_sha256':hashlib.sha256(b).hexdigest(),'sender_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'protocol_reference':'tools/send_probe.py:30-32','wrapper_reference':'probes/phase12_kernel_analysis/51b_accessible_syscall_deep.lua:20-25,207-212','firmware_identity':'not authenticated','connection':False,'submitted':False}
s=socket.socket();s.settimeout(10);raw=bytearray()
try:
 s.connect(('10.0.0.96',9026));r['connection']=True;r['connected_utc']=now()
 s.sendall(frame);r['submitted']=True;r['submitted_utc']=now()
 while len(raw)<65536:
  x=s.recv(min(4096,65536-len(raw)))
  if not x:r['peer_eof']=True;break
  raw.extend(x)
except Exception as e:r['termination']=type(e).__name__+': '+str(e)
finally:
 s.close();(p/'response.raw').write_bytes(raw);r['end_utc']=now();r['response_sha256']=hashlib.sha256(raw).hexdigest();r['completion_marker_received']=b'SELECTOR624_BASELINE_END_20261018' in raw
 (p/'SESSION.json').write_text(json.dumps(r,indent=2));print(json.dumps(r,indent=2));print(raw.decode(errors='replace'));print('EVIDENCE:',p)
