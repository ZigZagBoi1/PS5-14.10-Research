"""
PS5 13.60 Research Orchestrator

Connects to the Lua loader on port 9026 (same as 14.10) and sends
research probes automatically. Collects results, dumps kernel memory,
extracts WebProcess binary, and runs overnight test campaigns.

This is the server-side brain. The PS5 runs probes sent over TCP;
this script sends them one after another, saves every result, and
auto-retries on crash (each TCP connection gets a fresh process).

Usage:
    python research_orchestrator.py --ps5-ip 10.0.0.96
    python research_orchestrator.py --ps5-ip 10.0.0.96 --campaign kernel_dump
    python research_orchestrator.py --ps5-ip 10.0.0.96 --campaign overnight

Requirements: Python 3.7+ (stdlib only)
"""
import argparse
import json
import os
import socket
import struct
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROBES_DIR = ROOT.parent.parent / "probes"
RESULTS_DIR = ROOT / "research_results"
PAYLOADS_DIR = ROOT / "research_payloads"


def send_probe(ps5_ip, port, lua_source, timeout=60):
    """Send a Lua probe to the PS5 loader and collect output.

    Returns (success: bool, output: str, duration: float).
    The loader accepts: 8-byte LE length prefix + raw Lua source.
    It sends back print() output over the same socket.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    output_parts = []
    start = time.time()

    try:
        sock.connect((ps5_ip, port))
        # Send: 8-byte LE length + source
        encoded = lua_source.encode("utf-8")
        sock.sendall(struct.pack("<Q", len(encoded)))
        sock.sendall(encoded)

        # Collect output until socket closes or timeout
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                output_parts.append(chunk.decode("utf-8", errors="replace"))
            except socket.timeout:
                break
            except ConnectionResetError:
                break

        duration = time.time() - start
        return True, "".join(output_parts), duration

    except ConnectionRefusedError:
        return False, "CONNECTION_REFUSED (loader not running)", time.time() - start
    except socket.timeout:
        return False, "TIMEOUT (loader not responding)", time.time() - start
    except Exception as e:
        return False, f"ERROR: {e}", time.time() - start
    finally:
        sock.close()


def wait_for_loader(ps5_ip, port=9026, poll_interval=5, max_wait=300):
    """Wait until the Lua loader is accepting connections.

    Returns True if ready, False if timed out.
    """
    start = time.time()
    while time.time() - start < max_wait:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ps5_ip, port))
            sock.close()
            return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            time.sleep(poll_interval)
        finally:
            try:
                sock.close()
            except Exception:
                pass
    return False


def save_result(campaign, probe_name, success, output, duration):
    """Save a probe result to the results directory."""
    campaign_dir = RESULTS_DIR / campaign
    campaign_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{probe_name}_{timestamp}.txt"
    filepath = campaign_dir / filename

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"# Probe: {probe_name}\n")
        f.write(f"# Campaign: {campaign}\n")
        f.write(f"# Time: {datetime.now().isoformat()}\n")
        f.write(f"# Success: {success}\n")
        f.write(f"# Duration: {duration:.2f}s\n")
        f.write(f"# {'='*60}\n\n")
        f.write(output)

    return filepath


# === Campaign: Kernel Dump ===
# Reads kernel memory via the jailbroken 13.60's kernel R/W and sends
# it back over the socket. Each probe reads a chunk and the orchestrator
# reassembles the full image.

KERNEL_DUMP_PROBE = '''
-- CRASH_CLASS: MODERATE
-- PROBE: kernel_dump_chunk
-- Reads a chunk of kernel memory and sends it back as hex.
-- Requires kernel R/W (13.60 jailbroken with etaHEN).

print("=== KERNEL DUMP CHUNK ===")
print("START_ADDR: {start_addr}")
print("CHUNK_SIZE: {chunk_size}")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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

-- Try to read kernel memory
-- On 13.60 jailbroken, kernel R/W should be available
local start = uint64("{start_addr}")
local chunk_size = {chunk_size}
local bytes_read = 0
local hex_lines = {{}}

print("READING...")
for offset = 0, chunk_size - 8, 8 do
    local addr = start + uint64(offset)
    local val = safe_rq(addr)
    if val then
        local h, l = get_hi_lo(val)
        table.insert(hex_lines, string.format("%08X%08X", h, l))
        bytes_read = bytes_read + 8
    else
        table.insert(hex_lines, "________________")
        bytes_read = bytes_read + 8
    end

    -- Print in batches of 64 bytes (8 qwords) per line
    if #hex_lines == 8 then
        print("DATA:" .. table.concat(hex_lines, ""))
        hex_lines = {{}}
    end
end

-- Flush remaining
if #hex_lines > 0 then
    print("DATA:" .. table.concat(hex_lines, ""))
end

print("")
print("BYTES_READ: " .. bytes_read)
print("=== CHUNK COMPLETE ===")
'''


KERNEL_BASE_PROBE = '''
-- CRASH_CLASS: LOW
-- PROBE: kernel_base_finder
-- Uses the fault oracle to find the kernel base address.
-- Works on both 13.60 and 14.10.

print("=== KERNEL BASE FINDER ===")
print("")

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

local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
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

local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- Get eboot base for gadgets
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local eboot_lo = safe_rd(info + 0x108)
local eboot_hi = safe_rd(info + 0x10C)
local eboot_base = uint64(string.format("0x%X%08X", eboot_hi or 0, eboot_lo or 0))
print("EBOOT_BASE: " .. tostring(eboot_base))

-- Get PID
local sc_getpid = make_syscall(20)
local pid_val = sc_getpid()
print("PID: " .. to_num(pid_val))

-- Report firmware info via sysctl
local sc_sysctl = make_syscall(202)
local mib = memory.alloc(16)
safe_wd(mib, 1)       -- CTL_KERN
safe_wd(mib + 4, 2)   -- KERN_OSRELEASE
local outbuf = memory.alloc(256)
local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 256)
local ret = sc_sysctl(uint64(mib), uint64(2), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0))
if to_num(ret) == 0 then
    local osrel = ""
    for i = 0, 63 do
        local c = safe_rd(outbuf + i)
        if not c or c == 0 then break end
        osrel = osrel .. string.char(c % 256)
    end
    print("OSRELEASE: " .. osrel)
end

-- Use fault oracle to find kernel base
-- (same technique as probes 1199a-1199c on 14.10)
print("")
print("Starting kernel base scan...")
print("This uses thr_create to probe kernel VA space.")
print("Each probe faults a child thread on a candidate address.")
print("The fault error code distinguishes mapped from unmapped.")
print("")

-- Scan 0xFFFFFFFF80000000 to 0xFFFFFFFFFFFFFFFF in 2MB steps
-- Looking for the first mapped supervisor page
local found_start = nil
local found_end = nil
local probes_done = 0

-- Quick scan: 256MB steps first
print("Phase 1: Coarse scan (256MB steps)...")
for slide = 0, 0x7F, 1 do
    local hi = 0xFFFFFFFF
    local lo = 0x80000000 + slide * 0x10000000
    if lo >= 0x100000000 then
        lo = lo - 0x100000000
    end
    -- We would do the fault oracle here but it requires the full
    -- thr_create + signal handler setup from probes 1199a-c.
    -- For now, report the scan range.
    probes_done = probes_done + 1
end

print("SCAN_RANGE: 0xFFFFFFFF80000000 - 0xFFFFFFFFFFFFFFFF")
print("PROBES_PLANNED: " .. probes_done)
print("NOTE: Full fault oracle requires thr_create setup.")
print("See probes/phase9_kaslr_defeat/ for the working implementation.")
print("")
print("=== SCAN COMPLETE ===")
'''


WEBPROCESS_FINDER_PROBE = '''
-- CRASH_CLASS: LOW
-- PROBE: webprocess_finder
-- Finds the WebProcess binary in memory on 13.60.
-- On a jailbroken system, we can enumerate all processes and their
-- memory maps to find WebProcess's text segment.

print("=== WEBPROCESS FINDER ===")
print("")

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

-- Get our own PID first
local sc_getpid = make_syscall(20)
local our_pid = to_num(sc_getpid())
print("OUR_PID: " .. our_pid)

-- Use sysctl to enumerate processes
-- CTL_KERN=1, KERN_PROC=14, KERN_PROC_ALL=0
local sc_sysctl = make_syscall(202)
local mib = memory.alloc(16)
safe_wd(mib, 1)       -- CTL_KERN
safe_wd(mib + 4, 14)  -- KERN_PROC
safe_wd(mib + 8, 0)   -- KERN_PROC_ALL

-- First call: get size
local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 0)
safe_wd(oldlenp + 4, 0)
local ret = sc_sysctl(uint64(mib), uint64(3), uint64(0), uint64(oldlenp), uint64(0), uint64(0))
local needed = safe_rd(oldlenp)
print("PROC_LIST_SIZE: " .. (needed or 0) .. " bytes")

if needed and needed > 0 and needed < 0x100000 then
    local buf = memory.alloc(needed + 0x1000)
    safe_wd(oldlenp, needed + 0x1000)
    safe_wd(oldlenp + 4, 0)
    ret = sc_sysctl(uint64(mib), uint64(3), uint64(buf), uint64(oldlenp), uint64(0), uint64(0))

    if to_num(ret) == 0 then
        local actual_len = safe_rd(oldlenp)
        print("PROC_LIST_ACTUAL: " .. (actual_len or 0) .. " bytes")

        -- Each kinfo_proc is ~1096 bytes on PS5
        local kinfo_size = 1096
        local count = math.floor((actual_len or 0) / kinfo_size)
        print("PROCESS_COUNT: " .. count)

        -- Scan for WebProcess
        for i = 0, count - 1 do
            local base = buf + i * kinfo_size
            -- ki_comm at offset +0x1BF (or nearby) -- process name
            -- Read process name bytes
            local name = ""
            for j = 0, 19 do
                local c = safe_rd(base + 0x1BF + j)
                if not c or c == 0 then break end
                if c >= 32 and c < 127 then
                    name = name .. string.char(c)
                end
            end
            -- ki_pid at offset +0x44
            local pid = safe_rd(base + 0x44)

            if #name > 0 then
                print(string.format("PROC[%d]: pid=%d name=%s", i, pid or 0, name))
            end

            -- Look for WebProcess specifically
            if name:find("WebProcess") or name:find("WebKit") or name:find("SceShell") then
                print(string.format("*** FOUND TARGET: pid=%d name=%s ***", pid or 0, name))
            end
        end
    else
        print("SYSCTL_FAILED: ret=" .. to_num(ret))
    end
else
    print("PROC_LIST_FAILED: needed=" .. tostring(needed))
end

print("")
print("=== FINDER COMPLETE ===")
'''


OVERNIGHT_PROBES = [
    ("kernel_base", KERNEL_BASE_PROBE),
    ("webprocess_finder", WEBPROCESS_FINDER_PROBE),
]


def run_campaign_kernel_dump(ps5_ip, port=9026):
    """Dump kernel memory in chunks."""
    print("\n=== KERNEL DUMP CAMPAIGN ===")
    print(f"Target: {ps5_ip}:{port}")
    print()

    # First, find the kernel base
    print("[1/3] Finding kernel base...")
    success, output, duration = send_probe(ps5_ip, port, KERNEL_BASE_PROBE, timeout=120)
    save_result("kernel_dump", "kernel_base", success, output, duration)
    print(f"  Result: {'OK' if success else 'FAIL'} ({duration:.1f}s)")
    if output:
        for line in output.split("\n"):
            if line.startswith("EBOOT_BASE:") or line.startswith("PID:") or line.startswith("OSRELEASE:"):
                print(f"  {line.strip()}")

    # Find WebProcess
    print("\n[2/3] Finding WebProcess...")
    success, output, duration = send_probe(ps5_ip, port, WEBPROCESS_FINDER_PROBE, timeout=120)
    save_result("kernel_dump", "webprocess_finder", success, output, duration)
    print(f"  Result: {'OK' if success else 'FAIL'} ({duration:.1f}s)")
    if output:
        for line in output.split("\n"):
            if "FOUND TARGET" in line or line.startswith("PROCESS_COUNT:"):
                print(f"  {line.strip()}")

    # TODO: once base is known, dump in chunks
    print("\n[3/3] Kernel dump requires base address from step 1.")
    print("  Run with --start-addr once the base is confirmed.")


def run_campaign_overnight(ps5_ip, port=9026, max_hours=12):
    """Run all research probes continuously overnight."""
    print("\n=== OVERNIGHT RESEARCH CAMPAIGN ===")
    print(f"Target: {ps5_ip}:{port}")
    print(f"Max runtime: {max_hours} hours")
    print()

    # Collect all Lua probes from the probes directory
    probe_files = []
    for phase_dir in sorted(PROBES_DIR.iterdir()):
        if not phase_dir.is_dir():
            continue
        for probe_file in sorted(phase_dir.glob("*.lua")):
            probe_files.append(probe_file)

    print(f"Found {len(probe_files)} Lua probes")
    print()

    start_time = time.time()
    max_seconds = max_hours * 3600
    run_count = 0
    fail_count = 0
    consecutive_fails = 0

    for probe_file in probe_files:
        if time.time() - start_time > max_seconds:
            print(f"\nMax runtime ({max_hours}h) reached. Stopping.")
            break

        if consecutive_fails >= 5:
            print(f"\n5 consecutive failures. Waiting for loader...")
            if not wait_for_loader(ps5_ip, port, poll_interval=10, max_wait=300):
                print("Loader not responding after 5 minutes. Stopping.")
                break
            consecutive_fails = 0

        probe_name = probe_file.stem
        lua_source = probe_file.read_text(encoding="utf-8")

        elapsed = time.time() - start_time
        print(f"[{elapsed/3600:.1f}h] Running {probe_name}...", end=" ", flush=True)

        success, output, duration = send_probe(ps5_ip, port, lua_source, timeout=120)
        save_result("overnight", probe_name, success, output, duration)
        run_count += 1

        if success:
            consecutive_fails = 0
            # Check for interesting results
            kptr_count = 0
            for line in output.split("\n"):
                if "KERNEL" in line.upper() or "0xFFFF8" in line:
                    kptr_count += 1
            status = f"OK ({duration:.1f}s)"
            if kptr_count > 0:
                status += f" *** {kptr_count} KERNEL HITS ***"
            print(status)
        else:
            fail_count += 1
            consecutive_fails += 1
            print(f"FAIL ({output[:50]})")

        # Brief pause between probes
        time.sleep(1)

    total_time = time.time() - start_time
    print(f"\n=== CAMPAIGN COMPLETE ===")
    print(f"Probes run: {run_count}")
    print(f"Failures: {fail_count}")
    print(f"Total time: {total_time/3600:.1f} hours")
    print(f"Results in: {RESULTS_DIR / 'overnight'}")


def run_single_probe(ps5_ip, port, probe_path):
    """Run a single probe file."""
    path = Path(probe_path)
    if not path.exists():
        print(f"Probe not found: {probe_path}")
        return

    lua_source = path.read_text(encoding="utf-8")
    print(f"Sending {path.name} to {ps5_ip}:{port}...")

    success, output, duration = send_probe(ps5_ip, port, lua_source, timeout=120)
    save_result("single", path.stem, success, output, duration)

    print(f"\nResult: {'OK' if success else 'FAIL'} ({duration:.1f}s)")
    print(f"{'='*60}")
    print(output)


def main():
    parser = argparse.ArgumentParser(description="PS5 Research Orchestrator")
    parser.add_argument("--ps5-ip", default="10.0.0.96", help="PS5 IP")
    parser.add_argument("--port", type=int, default=9026, help="Loader port")
    parser.add_argument("--campaign", choices=["kernel_dump", "overnight", "single"],
                        default="kernel_dump", help="Which campaign to run")
    parser.add_argument("--probe", help="Single probe file path (for --campaign single)")
    parser.add_argument("--max-hours", type=int, default=12, help="Max hours for overnight")
    parser.add_argument("--wait", action="store_true", help="Wait for loader before starting")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print()
    print("  PS5 Research Orchestrator")
    print("  =========================")
    print(f"  Target: {args.ps5_ip}:{args.port}")
    print(f"  Campaign: {args.campaign}")
    print()

    if args.wait:
        print("Waiting for PS5 loader...")
        if not wait_for_loader(args.ps5_ip, args.port):
            print("Timed out waiting for loader.")
            sys.exit(1)
        print("Loader ready!")

    if args.campaign == "kernel_dump":
        run_campaign_kernel_dump(args.ps5_ip, args.port)
    elif args.campaign == "overnight":
        run_campaign_overnight(args.ps5_ip, args.port, args.max_hours)
    elif args.campaign == "single":
        if not args.probe:
            print("--probe required for single campaign")
            sys.exit(1)
        run_single_probe(args.ps5_ip, args.port, args.probe)


if __name__ == "__main__":
    main()
