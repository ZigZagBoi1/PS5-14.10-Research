-- CRASH_CLASS: MODERATE
-- PROBE 160a: UMTX op matrix — CORRECTED FreeBSD 9 numbering
--
-- Context: All prior 153x probes had WRONG op numbers (e.g. MUTEX_LOCK=10
-- instead of 5, CV_BROADCAST=15 instead of 10). 153b blocked because it
-- called WAIT_UINT_PRIVATE(15) thinking it was CV_BROADCAST.
--
-- Confirmed working on 14.10: op 5 (MUTEX_LOCK, writes TID), op 21 (NWAKE_PRIVATE, ret=0)
-- Confirmed stub: op 25 (SHM, always ret=0)
-- From 153b (mislabeled): op 3 (WAKE) ret=0, op 14 (RW_UNLOCK) ret=-1
--
-- FreeBSD 9 UMTX ops (CORRECT):
-- 0  LOCK               12 RW_RDLOCK
-- 1  UNLOCK             13 RW_WRLOCK
-- 2  WAIT               14 RW_UNLOCK
-- 3  WAKE               15 WAIT_UINT_PRIVATE
-- 4  MUTEX_TRYLOCK      16 WAKE_PRIVATE
-- 5  MUTEX_LOCK         17 MUTEX_WAIT
-- 6  MUTEX_UNLOCK       18 MUTEX_WAKE
-- 7  SET_CEILING        19 SEM_WAIT
-- 8  CV_WAIT            20 SEM_WAKE
-- 9  CV_SIGNAL          21 NWAKE_PRIVATE    confirmed
-- 10 CV_BROADCAST       22 MUTEX_WAKE2
-- 11 WAIT_UINT          23 SEM2_WAIT
--                       24 SEM2_WAKE
--                       25 SHM              stub
--                       26 ROBUST_LISTS

print("=== PROBE 160a: UMTX OP MATRIX (FIXED) ===")
print("")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end
local function q(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X_%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function rv_str(ok, ret)
    if not ok then return "CRASH" end
    if ret == nil then return "nil" end
    local h, l = get_hi_lo(ret)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    if h == 0xFFFFFFFF and l == 0xFFFFFFFF then return "-1" end
    if h == 0 then return tostring(l) end
    return string.format("0x%X%08X", h, l)
end

collectgarbage("stop")
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local sc_umtx = make_syscall(454)

local OP_NAMES = {
    [0]="LOCK", [1]="UNLOCK", [2]="WAIT", [3]="WAKE",
    [4]="MUTEX_TRYLOCK", [5]="MUTEX_LOCK", [6]="MUTEX_UNLOCK",
    [7]="SET_CEILING", [8]="CV_WAIT", [9]="CV_SIGNAL",
    [10]="CV_BROADCAST", [11]="WAIT_UINT", [12]="RW_RDLOCK",
    [13]="RW_WRLOCK", [14]="RW_UNLOCK", [15]="WAIT_UINT_PRIV",
    [16]="WAKE_PRIVATE", [17]="MUTEX_WAIT", [18]="MUTEX_WAKE",
    [19]="SEM_WAIT", [20]="SEM_WAKE", [21]="NWAKE_PRIVATE",
    [22]="MUTEX_WAKE2", [23]="SEM2_WAIT", [24]="SEM2_WAKE",
    [25]="SHM", [26]="ROBUST_LISTS"
}

-- ============================================================
-- SECTION A: Safe non-blocking ops
-- Wake/signal/broadcast/unlock ops should never block
-- ============================================================
print("")
print("--- SECTION A: NON-BLOCKING OPS ---")

local function test_op(op, val, extra_label)
    local buf = memory.alloc(0x40)
    zero(buf, 0x40)
    local name = OP_NAMES[op] or ("?" .. op)
    local ok, ret = pcall(function()
        return sc_umtx(uint64(to_num(buf)), uint64(op), uint64(val), uint64(0), uint64(0))
    end)
    local after = rq(buf)
    local ah, al = 0, 0
    if after then ah, al = get_hi_lo(after) end
    if ah < 0 then ah = ah + 0x100000000 end
    if al < 0 then al = al + 0x100000000 end
    local tag = extra_label and (" " .. extra_label) or ""
    print(string.format("  op%02d %-16s ret=%-8s word=0x%08X_%08X%s",
        op, name, rv_str(ok, ret), ah, al, tag))
    return ok, ret
end

test_op(3, 1)                  -- WAKE: wake 1 waiter (none → ret 0 or -1)
test_op(9, 0)                  -- CV_SIGNAL: signal condvar (no waiters)
test_op(10, 0)                 -- CV_BROADCAST: broadcast condvar
test_op(16, 1)                 -- WAKE_PRIVATE: wake 1 waiter
test_op(18, 0)                 -- MUTEX_WAKE: wake mutex waiter
test_op(20, 1)                 -- SEM_WAKE: wake semaphore waiter
test_op(21, 1)                 -- NWAKE_PRIVATE: (confirmed ret=0)
test_op(22, 0)                 -- MUTEX_WAKE2
test_op(24, 1)                 -- SEM2_WAKE

-- Unlock ops on unlocked objects (should fail gracefully)
test_op(1, 0)                  -- UNLOCK: old-style
test_op(6, 0)                  -- MUTEX_UNLOCK: unlock unowned mutex
test_op(14, 0)                 -- RW_UNLOCK: unlock unlocked rwlock

-- SHM (known stub)
test_op(25, 1, "(create)")     -- SHM create
test_op(25, 4, "(destroy)")    -- SHM destroy

-- Invalid op (negative control)
test_op(99, 0, "(invalid)")

-- ============================================================
-- SECTION B: Lock ops — uncontested, should return immediately
-- ============================================================
print("")
print("--- SECTION B: LOCK OPS ---")

-- LOCK (0) — old-style simple lock
print("[B1] LOCK(0)...")
local lk0 = memory.alloc(0x40)
zero(lk0, 0x40)
local ok0, r0 = pcall(function()
    return sc_umtx(uint64(to_num(lk0)), uint64(0), uint64(0), uint64(0), uint64(0))
end)
local w0 = rq(lk0)
print("  ret=" .. rv_str(ok0, r0) .. " word=" .. q(w0))

-- MUTEX_TRYLOCK (4)
print("[B2] MUTEX_TRYLOCK(4)...")
local mtry = memory.alloc(0x40)
zero(mtry, 0x40)
local ok4, r4 = pcall(function()
    return sc_umtx(uint64(to_num(mtry)), uint64(4), uint64(0), uint64(0), uint64(0))
end)
local w4 = rq(mtry)
print("  ret=" .. rv_str(ok4, r4) .. " word=" .. q(w4))

-- MUTEX_LOCK (5) — confirmed working (writes TID to m_owner)
print("[B3] MUTEX_LOCK(5) normal (flags=0)...")
local mtx5 = memory.alloc(0x40)
zero(mtx5, 0x40)
local ok5, r5 = pcall(function()
    return sc_umtx(uint64(to_num(mtx5)), uint64(5), uint64(0), uint64(0), uint64(0))
end)
local w5_owner = rd(mtx5)
print("  ret=" .. rv_str(ok5, r5) .. " m_owner=0x" .. string.format("%08X", w5_owner or 0))

-- MUTEX_UNLOCK (6) — release what we just locked
if ok5 and to_num(r5) == 0 then
    print("[B4] MUTEX_UNLOCK(6)...")
    local ok6, r6 = pcall(function()
        return sc_umtx(uint64(to_num(mtx5)), uint64(6), uint64(0), uint64(0), uint64(0))
    end)
    local w6_owner = rd(mtx5)
    print("  ret=" .. rv_str(ok6, r6) .. " m_owner=0x" .. string.format("%08X", w6_owner or 0))
end

-- MUTEX_LOCK (5) with PI flag — CRITICAL TEST for race probe
print("[B5] MUTEX_LOCK(5) PI (flags=0x4)...")
local mtx_pi = memory.alloc(0x40)
zero(mtx_pi, 0x40)
wd(mtx_pi + 4, 4)  -- m_flags = UMUTEX_PRIO_INHERIT
local ok5pi, r5pi = pcall(function()
    return sc_umtx(uint64(to_num(mtx_pi)), uint64(5), uint64(0), uint64(0), uint64(0))
end)
local w5pi_owner = rd(mtx_pi)
local w5pi_flags = rd(mtx_pi + 4)
print("  ret=" .. rv_str(ok5pi, r5pi) ..
    " m_owner=0x" .. string.format("%08X", w5pi_owner or 0) ..
    " m_flags=0x" .. string.format("%X", w5pi_flags or 0))

-- PI MUTEX_UNLOCK (6)
if ok5pi and to_num(r5pi) == 0 then
    print("[B6] MUTEX_UNLOCK(6) PI...")
    local ok6pi, r6pi = pcall(function()
        return sc_umtx(uint64(to_num(mtx_pi)), uint64(6), uint64(0), uint64(0), uint64(0))
    end)
    local w6pi_owner = rd(mtx_pi)
    print("  ret=" .. rv_str(ok6pi, r6pi) .. " m_owner=0x" .. string.format("%08X", w6pi_owner or 0))
end

-- RW_RDLOCK (12)
print("[B7] RW_RDLOCK(12)...")
local rwl = memory.alloc(0x40)
zero(rwl, 0x40)
local ok12, r12 = pcall(function()
    return sc_umtx(uint64(to_num(rwl)), uint64(12), uint64(0), uint64(0), uint64(0))
end)
local w12 = rq(rwl)
print("  ret=" .. rv_str(ok12, r12) .. " word=" .. q(w12))

-- RW_UNLOCK (14) if rdlock succeeded
if ok12 and to_num(r12) == 0 then
    print("[B8] RW_UNLOCK(14)...")
    local ok14, r14 = pcall(function()
        return sc_umtx(uint64(to_num(rwl)), uint64(14), uint64(0), uint64(0), uint64(0))
    end)
    local w14 = rq(rwl)
    print("  ret=" .. rv_str(ok14, r14) .. " word=" .. q(w14))
end

-- RW_WRLOCK (13)
print("[B9] RW_WRLOCK(13)...")
local rwl2 = memory.alloc(0x40)
zero(rwl2, 0x40)
local ok13, r13 = pcall(function()
    return sc_umtx(uint64(to_num(rwl2)), uint64(13), uint64(0), uint64(0), uint64(0))
end)
local w13 = rq(rwl2)
print("  ret=" .. rv_str(ok13, r13) .. " word=" .. q(w13))

-- SET_CEILING (7)
print("[B10] SET_CEILING(7) val=5...")
local ceil = memory.alloc(0x40)
zero(ceil, 0x40)
wd(ceil + 4, 8)  -- m_flags = UMUTEX_PRIO_PROTECT
local ok7, r7 = pcall(function()
    return sc_umtx(uint64(to_num(ceil)), uint64(7), uint64(5), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(ok7, r7))

-- ============================================================
-- SECTION C: WAIT ops with guaranteed mismatch (should NOT block)
-- ============================================================
print("")
print("--- SECTION C: WAIT MISMATCH ---")

-- WAIT (2): buf contains 42, expect 99 → mismatch → immediate EWOULDBLOCK
local wbuf2 = memory.alloc(64)
wd(wbuf2, 42)
print("[C1] WAIT(2) *=42 expect=99...")
local okw2, rw2 = pcall(function()
    return sc_umtx(uint64(to_num(wbuf2)), uint64(2), uint64(99), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(okw2, rw2))

-- WAIT_UINT (11): same pattern
local wbuf11 = memory.alloc(64)
wd(wbuf11, 42)
print("[C2] WAIT_UINT(11) *=42 expect=99...")
local okw11, rw11 = pcall(function()
    return sc_umtx(uint64(to_num(wbuf11)), uint64(11), uint64(99), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(okw11, rw11))

-- WAIT_UINT_PRIVATE (15): same pattern (THIS is what killed 153b!)
local wbuf15 = memory.alloc(64)
wd(wbuf15, 42)
print("[C3] WAIT_UINT_PRIV(15) *=42 expect=99...")
local okw15, rw15 = pcall(function()
    return sc_umtx(uint64(to_num(wbuf15)), uint64(15), uint64(99), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(okw15, rw15))

-- ============================================================
-- SECTION D: ROBUST_LISTS (26)
-- ============================================================
print("")
print("--- SECTION D: ROBUST_LISTS ---")

local rp = memory.alloc(0x40)
zero(rp, 0x40)
print("[D1] ROBUST_LISTS(26) size=24...")
local ok26, r26 = pcall(function()
    return sc_umtx(uint64(0), uint64(26), uint64(24), uint64(to_num(rp)), uint64(0))
end)
print("  ret=" .. rv_str(ok26, r26))

print("[D2] ROBUST_LISTS(26) size=32 (oversized, should fail)...")
local ok26b, r26b = pcall(function()
    return sc_umtx(uint64(0), uint64(26), uint64(32), uint64(to_num(rp)), uint64(0))
end)
print("  ret=" .. rv_str(ok26b, r26b))

-- ============================================================
-- SECTION E: sys 624 VM counter baseline
-- ============================================================
print("")
print("--- SECTION E: VM COUNTER ---")

local sc_624 = make_syscall(624)
local ok624a, cnt_a = pcall(function() return sc_624(uint64(0), uint64(0), uint64(0)) end)
print("vm_counter_before=" .. (ok624a and rv_str(true, cnt_a) or "FAIL"))

-- Do a PI lock/unlock cycle and check if VM counter changes
local mtx_vm = memory.alloc(0x40)
zero(mtx_vm, 0x40)
wd(mtx_vm + 4, 4)  -- PI flag
pcall(function() sc_umtx(uint64(to_num(mtx_vm)), uint64(5), uint64(0), uint64(0), uint64(0)) end)
pcall(function() sc_umtx(uint64(to_num(mtx_vm)), uint64(6), uint64(0), uint64(0), uint64(0)) end)

local ok624b, cnt_b = pcall(function() return sc_624(uint64(0), uint64(0), uint64(0)) end)
print("vm_counter_after_pi=" .. (ok624b and rv_str(true, cnt_b) or "FAIL"))

-- Control: mmap should bump counter
pcall(function()
    local sc_mmap = make_syscall(477)
    sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local ok624c, cnt_c = pcall(function() return sc_624(uint64(0), uint64(0), uint64(0)) end)
print("vm_counter_after_mmap=" .. (ok624c and rv_str(true, cnt_c) or "FAIL"))

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 160a COMPLETE ===")
