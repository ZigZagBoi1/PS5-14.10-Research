from pathlib import Path
import hashlib,json
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
p=Path('F:/PS5-14.10-Research/docs/dumps_13.60/kernel_text.bin');b=p.read_bytes();o=Path(__file__).parent;m=Cs(CS_ARCH_X86,CS_MODE_64)
a,z=0x399de0,0x399e20
(o/'descriptor_publish.asm.txt').write_text('\n'.join(f'{i.address:08x}: {i.bytes.hex():28} {i.mnemonic} {i.op_str}' for i in m.disasm(b[a:z],a))+'\n')
(o/'NEW_WINDOW.json').write_text(json.dumps({'source':str(p),'start':hex(a),'end_exclusive':hex(z),'sha256_window':hashlib.sha256(b[a:z]).hexdigest(),'limitation':'new narrow decode; no original full hash comparison'},indent=2))
