"""Run the creator and raider aio-delete probes on two connections to the same process."""
import socket, struct, sys, time, re

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.121"
PORT = 9026

def send(src):
    s = socket.create_connection((HOST, PORT), timeout=10)
    s.settimeout(0.5)
    s.sendall(struct.pack("<Q", len(src)) + src.encode())
    return s

def pump(s, until=None, deadline=None):
    out = b""
    while True:
        if deadline and time.time() > deadline:
            break
        try:
            d = s.recv(65536)
            if not d:
                break
            out += d
            if until and re.search(until, out.decode("utf-8", "replace")):
                break
        except socket.timeout:
            if until is None and deadline is None:
                break
            continue
    return out.decode("utf-8", "replace")

a_src = open("probes/phase17_new_vectors/899a_aio_race_creator.lua", encoding="utf-8").read()
sa = send(a_src)
txt = pump(sa, until=r"IDBUF=0x[0-9A-Fa-f]+", deadline=time.time() + 8)
m = re.search(r"IDBUF=0x([0-9A-Fa-f]+)", txt)
print(txt, end="")
if not m:
    print("[driver] no IDBUF line, aborting")
    sys.exit(1)
addr = int(m.group(1), 16)
print(f"[driver] raider target 0x{addr:X}")
b_src = open("probes/phase17_new_vectors/899b_aio_race_raider.lua", encoding="utf-8").read().replace("__IDBUF__", hex(addr))
sb = send(b_src)
tb = pump(sb, deadline=time.time() + 12)
print(tb, end="")
ta = pump(sa, deadline=time.time() + 10)
print(ta, end="")
