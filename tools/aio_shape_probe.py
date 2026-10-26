#!/usr/bin/env python3
"""Send one aio argument shape per connection and survive the lethal ones.

Each shape runs in its own connection: if the console takes the process down
mid-call, the driver waits for the loader to come back before the next shape.
That is the only way to fuzz argument layouts of syscalls that kill.
"""
import argparse
import os
import socket
import struct
import sys
import time
from datetime import datetime

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HEADER = """local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function sgn(v)
    local n = to_num(v)
    if n >= 0x8000000000000000 then return n - 0x10000000000000000 end
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end
local page = memory.alloc(0x1000)
pcall(function() for i = 0, 0xFFF, 4 do memory.write_dword(page + i, 0) end end)
local page2 = memory.alloc(0x1000)
pcall(function() for i = 0, 0xFFF, 4 do memory.write_dword(page2 + i, 0) end end)
print("SHAPE %s")
local ok, rv = pcall(function() return make_syscall(%d)(%s) end)
print(string.format("RESULT ok=%%s ret=%%d", tostring(ok), ok and sgn(rv) or -999))
print("SHAPE-END")
"""


def send(ip, port, source, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((ip, port))
    sock.sendall(struct.pack("<Q", len(source)) + source.encode("utf-8"))
    chunks = []
    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
        if b"SHAPE-END" in b"".join(chunks):
            break
    sock.close()
    return b"".join(chunks)


def wait_loader(ip, port, limit):
    start = time.time()
    while time.time() - start < limit:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            path = os.path.join(HERE, ".local", "ping.lua")
            src = 'print("PING canary")'
            if os.path.exists(path):
                src = open(path, encoding="utf-8").read()
            sock.sendall(struct.pack("<Q", len(src)) + src.encode("utf-8"))
            data = sock.recv(4096)
            sock.close()
            if data:
                return True
        except Exception:
            time.sleep(4)
            continue
        time.sleep(4)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="192.168.1.121")
    ap.add_argument("--port", type=int, default=9026)
    ap.add_argument("--wait", type=int, default=240)
    ap.add_argument("--outdir", default=os.path.join(HERE, "results", "phase17_new_vectors"))
    args = ap.parse_args()

    shapes = [
        ("661_page_0_0",    661, "uint64(page), uint64(0), uint64(0)"),
        ("661_page_1_0",    661, "uint64(page), uint64(1), uint64(0)"),
        ("661_page_4_res",  661, "uint64(page), uint64(4), uint64(page2)"),
        ("661_0_1_res",     661, "uint64(0), uint64(1), uint64(page2)"),
        ("668_page_100_0",  668, "uint64(page), uint64(0x100), uint64(0)"),
        ("668_page_100_1",  668, "uint64(page), uint64(0x100), uint64(1)"),
        ("668_page_40_2",   668, "uint64(page), uint64(0x40), uint64(2)"),
        ("668_page_1000_0", 668, "uint64(page), uint64(0x1000), uint64(0)"),
    ]

    os.makedirs(args.outdir, exist_ok=True)
    for label, num, expr in shapes:
        src = HEADER % (label, num, expr)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        print(f"--- {label} (sys {num}) ---", flush=True)
        try:
            data = send(args.ip, args.port, src, 12)
        except Exception as exc:
            data = b""
            print(f"    connect failed: {exc}", flush=True)
        text = data.decode("latin-1")
        died = "RESULT" not in text
        print(f"    bytes={len(data)} died={died}", flush=True)
        if data:
            for line in text.splitlines():
                if line.startswith(("SHAPE", "RESULT")):
                    print("    " + line, flush=True)
        path = os.path.join(args.outdir, f"487a_{label}_{stamp}.txt")
        with open(path, "wb") as fh:
            fh.write(data)
        if died:
            print("    waiting for the loader...", flush=True)
            if not wait_loader(args.ip, args.port, args.wait):
                print("    loader did not come back; stopping", flush=True)
                return 1
            print("    loader back", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
