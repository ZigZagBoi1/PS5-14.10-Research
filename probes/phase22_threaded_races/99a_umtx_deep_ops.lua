-- CRASH_CLASS: MODERATE
-- PROBE 99a: UMTX deep ops — CV_WAIT, PI mutex, SEM2 with proper setup
--
-- Context: 95a surveyed all 27 UMTX ops with zeros on syscall 454.
-- Ops 8 (CV_WAIT), 7 (SET_CEILING), 22 (MUTEX_WAKE2) returned -1 (need proper setup).
-- Ops 19/23 (SEM_WAIT) were skipped (they block). Op 24 (SEM_WAKE) never tested.
-- This probe exercises them with correct structures and short timeouts.
-- Uses sys 624 VM counter to fingerprint kernel allocations per op.

print("=== PROBE 99a: UMTX DEEP OPS ===")
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local umtx = make_syscall(454)
local sc_624 = make_syscall(624)
local sc_getpid = make_syscall(20)

local pid = to_num(sc_getpid())
print("pid=" .. pid)

local function vm_count()
    local ok, v = pcall(function()
        return sc_624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then return to_num(v) end
    return -1
end

local function fmt_rv(ok, rv)
    if not ok then return "PCALL_FAIL" end
    local h, l = get_hi_lo(rv)
    if h == 0xFFFFFFFF and l == 0xFFFFFFFF then return "-1" end
    return tostring(to_num(rv))
end

-- ================================================================
print("--- SECTION A: CV_WAIT (op 8) with condvar + mutex + timeout ---")
-- FreeBSD ucond: { c_has_waiters(u32), c_flags(u32), c_clockid(u32), spare(u32) } = 16B
-- FreeBSD umutex: { m_owner(u32), m_flags(u32), m_ceilings[2](u32), ... } = 32B
-- CV_WAIT args: obj=cv, op=8, val=flags, uaddr1=mutex, uaddr2=timespec*

local cv = memory.alloc(32)
safe_wd(cv + 0, 0)    -- c_has_waiters = 0
safe_wd(cv + 4, 0)    -- c_flags = 0
safe_wd(cv + 8, 0)    -- c_clockid = CLOCK_REALTIME
safe_wd(cv + 12, 0)

local mtx = memory.alloc(48)
safe_wd(mtx + 0, 0)   -- m_owner = UNOWNED
safe_wd(mtx + 4, 0)   -- m_flags = 0 (normal mutex)
safe_wd(mtx + 8, 0)
safe_wd(mtx + 12, 0)

-- Step 1: lock mutex (required before CV_WAIT)
local vmc1 = vm_count()
local ok1, rv1 = pcall(function()
    return umtx(uint64(mtx), uint64(5), uint64(0), uint64(0), uint64(0))
end)
local vmc2 = vm_count()
print(string.format("  MUTEX_LOCK(5): rv=%s vmd=%d owner=0x%X",
    fmt_rv(ok1, rv1), vmc2 - vmc1, safe_rd(mtx) or 0))

-- Step 2: prepare timeout (struct timespec, 16 bytes) — 10ms relative
local ts = memory.alloc(16)
safe_wq(ts, uint64(0))              -- tv_sec = 0
safe_wq(ts + 8, uint64(10000000))   -- tv_nsec = 10,000,000 = 10ms

-- Step 3: CV_WAIT — should release mutex, sleep 10ms, re-acquire mutex
local vmc3 = vm_count()
local ok2, rv2 = pcall(function()
    return umtx(uint64(cv), uint64(8), uint64(0), uint64(mtx), uint64(ts))
end)
local vmc4 = vm_count()
print(string.format("  CV_WAIT(8): rv=%s vmd=%d c_has_waiters=%d owner_after=0x%X",
    fmt_rv(ok2, rv2), vmc4 - vmc3, safe_rd(cv) or -1, safe_rd(mtx) or 0))

-- Unlock
pcall(function() umtx(uint64(mtx), uint64(6), uint64(0), uint64(0), uint64(0)) end)

-- Also try CV_SIGNAL (op 9) and CV_BROADCAST (op 10) on our condvar
local vmc5 = vm_count()
local ok_sig, rv_sig = pcall(function()
    return umtx(uint64(cv), uint64(9), uint64(0), uint64(0), uint64(0))
end)
local vmc6 = vm_count()
print(string.format("  CV_SIGNAL(9) on cv: rv=%s vmd=%d", fmt_rv(ok_sig, rv_sig), vmc6 - vmc5))

-- ================================================================
print("")
print("--- SECTION B: PI MUTEX (PRIO_INHERIT) — ops 5, 17, 22 ---")
-- umutex with m_flags = UMUTEX_PRIO_INHERIT (0x4)
-- PI lock should allocate umtx_pi kernel object

local pi_mtx = memory.alloc(48)
safe_wd(pi_mtx + 0, 0)    -- m_owner = UNOWNED
safe_wd(pi_mtx + 4, 4)    -- m_flags = UMUTEX_PRIO_INHERIT
safe_wd(pi_mtx + 8, 0)
safe_wd(pi_mtx + 12, 0)

-- PI MUTEX_LOCK (op 5) — allocates umtx_pi
local vmc7 = vm_count()
local ok3, rv3 = pcall(function()
    return umtx(uint64(pi_mtx), uint64(5), uint64(0), uint64(0), uint64(0))
end)
local vmc8 = vm_count()
print(string.format("  PI MUTEX_LOCK(5): rv=%s vmd=%d owner=0x%X",
    fmt_rv(ok3, rv3), vmc8 - vmc7, safe_rd(pi_mtx) or 0))

-- PI MUTEX_UNLOCK (op 6)
local vmc_u1 = vm_count()
local ok_piu, rv_piu = pcall(function()
    return umtx(uint64(pi_mtx), uint64(6), uint64(0), uint64(0), uint64(0))
end)
local vmc_u2 = vm_count()
print(string.format("  PI MUTEX_UNLOCK(6): rv=%s vmd=%d owner_after=0x%X",
    fmt_rv(ok_piu, rv_piu), vmc_u2 - vmc_u1, safe_rd(pi_mtx) or 0))

-- Second PI mutex for MUTEX_WAIT (op 17)
local pi_mtx2 = memory.alloc(48)
safe_wd(pi_mtx2 + 0, 0)
safe_wd(pi_mtx2 + 4, 4)   -- PI

local vmc9 = vm_count()
local ok4, rv4 = pcall(function()
    return umtx(uint64(pi_mtx2), uint64(17), uint64(0), uint64(0), uint64(0))
end)
local vmc10 = vm_count()
print(string.format("  PI MUTEX_WAIT(17): rv=%s vmd=%d owner=0x%X",
    fmt_rv(ok4, rv4), vmc10 - vmc9, safe_rd(pi_mtx2) or 0))

-- Unlock pi_mtx2
pcall(function() umtx(uint64(pi_mtx2), uint64(6), uint64(0), uint64(0), uint64(0)) end)

-- MUTEX_WAKE2 (op 22) on unlocked PI mutex
local vmc11 = vm_count()
local ok5, rv5 = pcall(function()
    return umtx(uint64(pi_mtx), uint64(22), uint64(0), uint64(0), uint64(0))
end)
local vmc12 = vm_count()
print(string.format("  MUTEX_WAKE2(22) on unlocked PI: rv=%s vmd=%d",
    fmt_rv(ok5, rv5), vmc12 - vmc11))

-- Lock then WAKE2
pcall(function() umtx(uint64(pi_mtx), uint64(5), uint64(0), uint64(0), uint64(0)) end)
local vmc13 = vm_count()
local ok5b, rv5b = pcall(function()
    return umtx(uint64(pi_mtx), uint64(22), uint64(0), uint64(0), uint64(0))
end)
local vmc14 = vm_count()
print(string.format("  MUTEX_WAKE2(22) on locked PI: rv=%s vmd=%d",
    fmt_rv(ok5b, rv5b), vmc14 - vmc13))
pcall(function() umtx(uint64(pi_mtx), uint64(6), uint64(0), uint64(0), uint64(0)) end)

-- ================================================================
print("")
print("--- SECTION C: SET_CEILING (op 7) with PRIO_PROTECT mutex ---")
-- m_flags = UMUTEX_PRIO_PROTECT (0x8), m_ceilings[0] = initial ceiling

local pp_mtx = memory.alloc(48)
safe_wd(pp_mtx + 0, 0)     -- m_owner = UNOWNED
safe_wd(pp_mtx + 4, 8)     -- m_flags = UMUTEX_PRIO_PROTECT
safe_wd(pp_mtx + 8, 100)   -- m_ceilings[0] = 100
safe_wd(pp_mtx + 12, 0)    -- m_ceilings[1] = 0

-- SET_CEILING: obj=mutex, op=7, val=new_ceiling, uaddr1=old_ceiling_ptr
local old_ceil = memory.alloc(8)
safe_wd(old_ceil, 0xDEAD)

local vmc15 = vm_count()
local ok6, rv6 = pcall(function()
    return umtx(uint64(pp_mtx), uint64(7), uint64(200), uint64(old_ceil), uint64(0))
end)
local vmc16 = vm_count()
print(string.format("  SET_CEILING(7) 100->200: rv=%s vmd=%d old_ceil=%d new_ceil=%d",
    fmt_rv(ok6, rv6), vmc16 - vmc15, safe_rd(old_ceil) or -1, safe_rd(pp_mtx + 8) or -1))

-- Try locking PRIO_PROTECT mutex
local vmc17 = vm_count()
local ok6b, rv6b = pcall(function()
    return umtx(uint64(pp_mtx), uint64(5), uint64(0), uint64(0), uint64(0))
end)
local vmc18 = vm_count()
print(string.format("  PP MUTEX_LOCK(5): rv=%s vmd=%d owner=0x%X",
    fmt_rv(ok6b, rv6b), vmc18 - vmc17, safe_rd(pp_mtx) or 0))
pcall(function() umtx(uint64(pp_mtx), uint64(6), uint64(0), uint64(0), uint64(0)) end)

-- ================================================================
print("")
print("--- SECTION D: SEM2_WAIT (op 19) with timeout ---")
-- _usem2: { _count(u32), _flags(u32) } = 8 bytes
-- _umtx_time: { timespec(16B), _flags(u32), _clockid(u32) } = 24 bytes
-- SEM2_WAIT: obj=sem, op=19, val=sizeof(_umtx_time), uaddr2=_umtx_time*

local sem = memory.alloc(16)
safe_wd(sem + 0, 0)    -- _count = 0 (will block)
safe_wd(sem + 4, 0)    -- _flags = 0

local ut = memory.alloc(32)
safe_wq(ut, uint64(0))              -- tv_sec = 0
safe_wq(ut + 8, uint64(10000000))   -- tv_nsec = 10ms
safe_wd(ut + 16, 0)                 -- _flags = 0 (relative)
safe_wd(ut + 20, 0)                 -- _clockid = CLOCK_REALTIME

-- Try val=0 first
local vmc19 = vm_count()
local ok7, rv7 = pcall(function()
    return umtx(uint64(sem), uint64(19), uint64(0), uint64(0), uint64(ut))
end)
local vmc20 = vm_count()
print(string.format("  SEM2_WAIT(19) val=0: rv=%s vmd=%d", fmt_rv(ok7, rv7), vmc20 - vmc19))

-- Try val=sizeof(struct _umtx_time)=24
safe_wd(sem, 0)  -- reset count
local vmc21 = vm_count()
local ok7b, rv7b = pcall(function()
    return umtx(uint64(sem), uint64(19), uint64(24), uint64(0), uint64(ut))
end)
local vmc22 = vm_count()
print(string.format("  SEM2_WAIT(19) val=24: rv=%s vmd=%d", fmt_rv(ok7b, rv7b), vmc22 - vmc21))

-- Try val=sizeof(struct timespec)=16
safe_wd(sem, 0)
local vmc23 = vm_count()
local ok7c, rv7c = pcall(function()
    return umtx(uint64(sem), uint64(19), uint64(16), uint64(0), uint64(ut))
end)
local vmc24 = vm_count()
print(string.format("  SEM2_WAIT(19) val=16: rv=%s vmd=%d", fmt_rv(ok7c, rv7c), vmc24 - vmc23))

-- Try with count=1 (token available — should return immediately)
safe_wd(sem, 1)
local vmc25 = vm_count()
local ok7d, rv7d = pcall(function()
    return umtx(uint64(sem), uint64(19), uint64(24), uint64(0), uint64(ut))
end)
local vmc26 = vm_count()
print(string.format("  SEM2_WAIT(19) count=1: rv=%s vmd=%d count_after=%d",
    fmt_rv(ok7d, rv7d), vmc26 - vmc25, safe_rd(sem) or -1))

-- ================================================================
print("")
print("--- SECTION E: SEM_WAKE (op 24) + SEM_WAIT (op 23) deprecated ---")

-- SEM_WAKE (op 24) — COMPLETELY UNTESTED
local old_sem = memory.alloc(16)
safe_wd(old_sem + 0, 0)   -- _has_waiters
safe_wd(old_sem + 4, 1)   -- _count = 1
safe_wd(old_sem + 8, 0)   -- _flags

local vmc27 = vm_count()
local ok8, rv8 = pcall(function()
    return umtx(uint64(old_sem), uint64(24), uint64(0), uint64(0), uint64(0))
end)
local vmc28 = vm_count()
print(string.format("  SEM_WAKE(24): rv=%s vmd=%d", fmt_rv(ok8, rv8), vmc28 - vmc27))

-- SEM_WAIT (op 23) with timeout
safe_wd(old_sem + 4, 0)  -- count = 0 (block)
local ut2 = memory.alloc(32)
safe_wq(ut2, uint64(0))
safe_wq(ut2 + 8, uint64(10000000))
safe_wd(ut2 + 16, 0)
safe_wd(ut2 + 20, 0)

local vmc29 = vm_count()
local ok9, rv9 = pcall(function()
    return umtx(uint64(old_sem), uint64(23), uint64(0), uint64(0), uint64(ut2))
end)
local vmc30 = vm_count()
print(string.format("  SEM_WAIT(23) val=0: rv=%s vmd=%d", fmt_rv(ok9, rv9), vmc30 - vmc29))

safe_wd(old_sem + 4, 0)
local vmc31 = vm_count()
local ok9b, rv9b = pcall(function()
    return umtx(uint64(old_sem), uint64(23), uint64(24), uint64(0), uint64(ut2))
end)
local vmc32 = vm_count()
print(string.format("  SEM_WAIT(23) val=24: rv=%s vmd=%d", fmt_rv(ok9b, rv9b), vmc32 - vmc31))

-- SEM_WAIT with count=1 (immediate)
safe_wd(old_sem + 4, 1)
local vmc33 = vm_count()
local ok9c, rv9c = pcall(function()
    return umtx(uint64(old_sem), uint64(23), uint64(24), uint64(0), uint64(ut2))
end)
local vmc34 = vm_count()
print(string.format("  SEM_WAIT(23) count=1: rv=%s vmd=%d count_after=%d",
    fmt_rv(ok9c, rv9c), vmc34 - vmc33, safe_rd(old_sem + 4) or -1))

-- ================================================================
print("")
print("--- SECTION F: SUMMARY ---")
print(string.format("  Op 5  MUTEX_LOCK (normal): %s", fmt_rv(ok1, rv1)))
print(string.format("  Op 5  MUTEX_LOCK (PI):     %s vmd=%d", fmt_rv(ok3, rv3), vmc8 - vmc7))
print(string.format("  Op 5  MUTEX_LOCK (PP):     %s vmd=%d", fmt_rv(ok6b, rv6b), vmc18 - vmc17))
print(string.format("  Op 6  MUTEX_UNLOCK (PI):   %s vmd=%d", fmt_rv(ok_piu, rv_piu), vmc_u2 - vmc_u1))
print(string.format("  Op 7  SET_CEILING:         %s vmd=%d", fmt_rv(ok6, rv6), vmc16 - vmc15))
print(string.format("  Op 8  CV_WAIT:             %s vmd=%d", fmt_rv(ok2, rv2), vmc4 - vmc3))
print(string.format("  Op 17 MUTEX_WAIT (PI):     %s vmd=%d", fmt_rv(ok4, rv4), vmc10 - vmc9))
print(string.format("  Op 19 SEM2_WAIT:           %s (best of 4 variants)", fmt_rv(ok7b, rv7b)))
print(string.format("  Op 20 SEM2_WAKE:           %s", fmt_rv(ok_sig, rv_sig)))
print(string.format("  Op 22 MUTEX_WAKE2:         %s", fmt_rv(ok5b, rv5b)))
print(string.format("  Op 23 SEM_WAIT:            %s (best of 3 variants)", fmt_rv(ok9b, rv9b)))
print(string.format("  Op 24 SEM_WAKE:            %s", fmt_rv(ok8, rv8)))

print("")
print("=== PROBE 99a COMPLETE ===")
