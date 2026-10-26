#!/usr/bin/env python3
"""Shape sweep over the reachable syscall numbers, one connection each.

Every run installs SIG_IGN for SIGSYS first, then calls the number with a
fixed set of argument shapes, printing one line per call. A call that kills
the process is named by the last line that was printed. State is kept in
.local/fuzz_shapes_state.json so the sweep resumes after a relaunch.
"""
import argparse, json, os, socket, sys, time

SHAPES = [
    ("zeros", "(0,0,0,0,0,0)"),
    ("buf", "(BUF,4096,0,0,0,0)"),
    ("three", "(BUF,16,BUF+2048,16,BUF+4096,16)"),
    ("ones", "(0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF)"),
    ("counts", "(BUF,1,2,3,4,5)"),
    ("mixed", "(1,BUF,2,BUF+1024,3,BUF+2048)"),
]

HEAD = r'''
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={{}} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local act=memory.alloc(0x30)
for k=0,0x2F,8 do memory.write_qword(act+k,uint64(0)) end
memory.write_qword(act,uint64(1))
pcall(function() mk(416)(uint64(12),uint64(act),uint64(0),uint64(0),uint64(0),uint64(0)) end)
local BUF=memory.alloc(0x4000)
for k=0,0x3FFF,8 do memory.write_qword(BUF+k,uint64(0)) end
local sc=mk({num})
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function SC(...) local a={{...}} for i=1,6 do a[i]=U(a[i] or 0) end return sc(unpack(a)) end
'''


def send(ip, port, src, timeout=12.0):
    out = b""
    s = socket.create_connection((ip, port), timeout=6)
    s.settimeout(1.0)
    s.sendall(len(src.encode()).to_bytes(8, "little") + src.encode())
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            b = s.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            break
        if not b:
            break
        out += b
    s.close()
    return out.decode("utf-8", "replace")


def build(num):
    parts = [HEAD.format(num=num)]
    for name, args in SHAPES:
        parts.append('local ok,rv=pcall(function() return SC%s end)' % args)
        parts.append('print(string.format("[%d] %s ret=%%s",ok and tostring(N(rv)) or "ERR"))' % (num, name))
    parts.append('print("[%d] SWEEP-OK alive="..tostring(N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))' % num)
    return "\n".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="192.168.1.121")
    ap.add_argument("--port", type=int, default=9026)
    ap.add_argument("--start", type=int, default=532)
    ap.add_argument("--end", type=int, default=676)
    ap.add_argument("--state", default=".local/fuzz_shapes_state.json")
    ap.add_argument("--stop-on-death", action="store_true", default=True)
    a = ap.parse_args()
    st = {"next": a.start, "dead": [], "clean": []}
    if os.path.exists(a.state):
        st = json.load(open(a.state))
    for num in range(st["next"], a.end + 1):
        src = build(num)
        try:
            out = send(a.ip, a.port, src)
        except OSError as e:
            print("[!] connect failed at %d: %s" % (num, e))
            return 1
        if "%d] SWEEP-OK" % num in out:
            rets = {}
            for line in out.splitlines():
                if line.startswith("[%d] " % num) and " ret=" in line:
                    k = line.split("] ", 1)[1].split(" ret=")[0]
                    rets[k] = line.split(" ret=")[1]
            st["clean"].append(num)
            st.setdefault("rets", {})[str(num)] = rets
            zero = [k for k, v in rets.items() if v in ("0", "0x0")]
            print("[%d] clean%s" % (num, (" zero=" + ",".join(zero)) if zero else ""))
        else:
            last = [l for l in out.splitlines() if l.startswith("[%d]" % num)]
            st["dead"].append({"num": num, "last": last[-1] if last else None})
            print("[%d] DIED after %s" % (num, last[-1] if last else "no output"))
            st["next"] = num + 1
            json.dump(st, open(a.state, "w"), indent=1)
            return 2
        st["next"] = num + 1
        json.dump(st, open(a.state, "w"), indent=1)
    print("done, clean=%d dead=%d" % (len(st["clean"]), len(st["dead"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
