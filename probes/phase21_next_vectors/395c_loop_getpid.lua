-- CRASH_CLASS: LOW
-- PROBE 395c: child loop with getpid syscall — isolate syscall corruption
--
-- Like 395a but with getpid(20) via stub in each loop iteration.
-- No socketpair, no write(). If this corrupts, the stub itself is the problem.
-- If clean, write() is the problem.

print("=== PROBE 395c: loop getpid ===")

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
    local lo = eb_lo + off
    local hi = eb_hi
    if lo >= 0x100000000 then
        hi = hi + math.floor(lo / 0x100000000)
        lo = lo % 0x100000000
    end
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

-- Shared memory
local shared = memory.alloc(0x20)
for i = 0, 0x1C, 4 do wd(N(shared) + i, 0) end
local marker_a = N(shared)

-- Fake TCB — 16KB, %fs in the middle
local tcb_buf = memory.alloc(0x4000)
for i = 0, 0x3FFC, 4 do wd(N(tcb_buf) + i, 0) end
local tcb_mid = N(tcb_buf) + 0x2000
wq(tcb_mid, uint64(tcb_mid))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

-- Stack
local BUF_SIZE = 0x10000
local stk = memory.alloc(BUF_SIZE)
for i = 0, BUF_SIZE - 4, 4 do wd(N(stk) + i, 0) end
local stk_base = N(stk)
local NOMINAL_SIZE = 0x100
local rsp = ((stk_base + NOMINAL_SIZE) - ((stk_base + NOMINAL_SIZE) % 16)) - 8

local sp = rsp
local function push(val) wq(sp, val); sp = sp + 8 end

-- Preamble: sysarch(SET_FSBASE)
push(uint64(165))
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

-- getpid(20) — no args, always succeeds, no errno
push(pop_rax_ret)
push(uint64(20))
push(stub)

-- write marker
push(pop_rdi_ret)
push(uint64(marker_a))
push(pop_rax_ret)
push(uint64(0xCAFE))
push(mov_rdi_rax)

-- loop back
push(pop_rsp_ret)
push(uint64(loop_addr))

print(string.format("chain=%d bytes", sp - rsp))

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

print("launch")
local ok_t, rv_t = pcall(function()
    return mk(455)(uint64(N(pa)), uint64(0x38))
end)
local tret = ok_t and N(rv_t) or -999
print(string.format("thr=%d", tret))
if tret ~= 0 then print("FAIL"); return end
if not alive() then print("DEAD"); return end

-- Busy wait
local dummy = 0
for i = 1, 500000 do dummy = dummy + 1 end

local m = rd(marker_a)
print(string.format("marker=%04X (expect CAFE)", m or 0))

local tid_lo = rd(N(ctid))
if tid_lo and tid_lo > 0 then
    local ok_k, rv_k = pcall(function()
        return mk(433)(uint64(tid_lo), uint64(0))
    end)
    print(string.format("thr_kill=%d (0=alive)", ok_k and N(rv_k) or -999))
end

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 395c COMPLETE ===")
