-- CRASH_CLASS: MODERATE
-- PROBE 99b: UMTX SEM + CV_WAIT investigation
--
-- Context: 99a found PI mutex ops fully functional, CV_WAIT returns -1 but
-- releases the mutex (partial execution), SET_CEILING blocks (kernel deadlock
-- on PP mutex acquire). This probe tests SEM ops and investigates CV_WAIT.

print("=== PROBE 99b: UMTX SEM + CV_WAIT ===")
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
local function fmt_rv(ok, rv)
    if not ok then return "PCALL_FAIL" end
    local h, l = get_hi_lo(rv)
    if h == 0xFFFFFFFF and l == 0xFFFFFFFF then return "-1" end
    return tostring(to_num(rv))
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

-- ================================================================
print("")
print("--- SECTION A: SEM2_WAIT (op 19) / SEM2_WAKE (op 20) ---")
-- _usem2: { _count(u32), _flags(u32) }
-- SEM2_WAIT: obj=sem, op=19, val=sizeof(_umtx_time), uaddr2=_umtx_time*
-- SEM2_WAKE: obj=sem, op=20, val=0

local sem = memory.alloc(16)

-- _umtx_time (24 bytes): timespec(16) + flags(4) + clockid(4)
local ut = memory.alloc(32)
safe_wq(ut, uint64(0))              -- tv_sec = 0
safe_wq(ut + 8, uint64(10000000))   -- tv_nsec = 10ms
safe_wd(ut + 16, 0)                 -- _flags = 0 (relative)
safe_wd(ut + 20, 0)                 -- _clockid = CLOCK_REALTIME

-- Test 1: SEM2_WAKE on semaphore with count=0
safe_wd(sem, 0)
safe_wd(sem + 4, 0)
local vmc1 = vm_count()
local ok1, rv1 = pcall(function()
    return umtx(uint64(sem), uint64(20), uint64(0), uint64(0), uint64(0))
end)
local vmc2 = vm_count()
print(string.format("  SEM2_WAKE(20) count=0: rv=%s vmd=%d count_after=%d",
    fmt_rv(ok1, rv1), vmc2 - vmc1, safe_rd(sem) or -1))

-- Test 2: SEM2_WAIT with count=1 (immediate — should NOT block)
safe_wd(sem, 1)
local vmc3 = vm_count()
local ok2, rv2 = pcall(function()
    return umtx(uint64(sem), uint64(19), uint64(24), uint64(0), uint64(ut))
end)
local vmc4 = vm_count()
print(string.format("  SEM2_WAIT(19) count=1 val=24: rv=%s vmd=%d count_after=%d",
    fmt_rv(ok2, rv2), vmc4 - vmc3, safe_rd(sem) or -1))

-- Test 3: SEM2_WAIT with count=0, 10ms timeout
safe_wd(sem, 0)
local vmc5 = vm_count()
local ok3, rv3 = pcall(function()
    return umtx(uint64(sem), uint64(19), uint64(24), uint64(0), uint64(ut))
end)
local vmc6 = vm_count()
print(string.format("  SEM2_WAIT(19) count=0 timeout: rv=%s vmd=%d",
    fmt_rv(ok3, rv3), vmc6 - vmc5))

-- Test 4: val=16 (timespec only, no _umtx_time header)
safe_wd(sem, 0)
local ok3b, rv3b = pcall(function()
    return umtx(uint64(sem), uint64(19), uint64(16), uint64(0), uint64(ut))
end)
print(string.format("  SEM2_WAIT(19) count=0 val=16: rv=%s", fmt_rv(ok3b, rv3b)))

-- Test 5: val=0 (no timeout info — might block!)
-- Use count=1 to avoid blocking
safe_wd(sem, 1)
local ok3c, rv3c = pcall(function()
    return umtx(uint64(sem), uint64(19), uint64(0), uint64(0), uint64(0))
end)
print(string.format("  SEM2_WAIT(19) count=1 val=0 no_timeout: rv=%s count_after=%d",
    fmt_rv(ok3c, rv3c), safe_rd(sem) or -1))

-- ================================================================
print("")
print("--- SECTION B: SEM_WAKE (op 24) / SEM_WAIT (op 23) deprecated ---")
-- _usem: { _has_waiters(u32), _count(u32), _flags(u32) }

local old_sem = memory.alloc(16)

-- SEM_WAKE (op 24)
safe_wd(old_sem + 0, 0)   -- _has_waiters = 0
safe_wd(old_sem + 4, 0)   -- _count = 0
safe_wd(old_sem + 8, 0)   -- _flags = 0
local vmc7 = vm_count()
local ok4, rv4 = pcall(function()
    return umtx(uint64(old_sem), uint64(24), uint64(0), uint64(0), uint64(0))
end)
local vmc8 = vm_count()
print(string.format("  SEM_WAKE(24) count=0: rv=%s vmd=%d", fmt_rv(ok4, rv4), vmc8 - vmc7))

safe_wd(old_sem + 4, 5)   -- _count = 5
local ok4b, rv4b = pcall(function()
    return umtx(uint64(old_sem), uint64(24), uint64(0), uint64(0), uint64(0))
end)
print(string.format("  SEM_WAKE(24) count=5: rv=%s", fmt_rv(ok4b, rv4b)))

-- SEM_WAIT (op 23) with count=1 (immediate)
safe_wd(old_sem + 0, 0)
safe_wd(old_sem + 4, 1)
safe_wd(old_sem + 8, 0)
local ut2 = memory.alloc(32)
safe_wq(ut2, uint64(0))
safe_wq(ut2 + 8, uint64(10000000))
safe_wd(ut2 + 16, 0)
safe_wd(ut2 + 20, 0)

local ok5, rv5 = pcall(function()
    return umtx(uint64(old_sem), uint64(23), uint64(24), uint64(0), uint64(ut2))
end)
print(string.format("  SEM_WAIT(23) count=1: rv=%s count_after=%d has_waiters=%d",
    fmt_rv(ok5, rv5), safe_rd(old_sem + 4) or -1, safe_rd(old_sem) or -1))

-- SEM_WAIT with count=0, timeout
safe_wd(old_sem + 4, 0)
local ok5b, rv5b = pcall(function()
    return umtx(uint64(old_sem), uint64(23), uint64(24), uint64(0), uint64(ut2))
end)
print(string.format("  SEM_WAIT(23) count=0 timeout: rv=%s", fmt_rv(ok5b, rv5b)))

-- ================================================================
print("")
print("--- SECTION C: CV_WAIT investigation ---")
-- 99a showed CV_WAIT returns -1 but releases the mutex.
-- Investigate: is it the condvar struct? the timeout? the flags?

local cv = memory.alloc(32)
local mtx_cv = memory.alloc(48)

-- Test 1: CV_WAIT without timeout (NULL uaddr2) — should block... use from thread
-- For safety, just test with mutex locked + various flag combos

-- Lock mutex
safe_wd(mtx_cv, 0)
safe_wd(mtx_cv + 4, 0)
pcall(function() umtx(uint64(mtx_cv), uint64(5), uint64(0), uint64(0), uint64(0)) end)
local owner_before = safe_rd(mtx_cv)
print(string.format("  mutex owner before CV_WAIT: 0x%X", owner_before or 0))

-- CV_WAIT with CVWAIT_CLOCKID flag (val=2)
safe_wd(cv, 0)
safe_wd(cv + 4, 0)
safe_wd(cv + 8, 0)  -- CLOCK_REALTIME
local ts1 = memory.alloc(16)
safe_wq(ts1, uint64(0))
safe_wq(ts1 + 8, uint64(5000000))  -- 5ms

local ok6, rv6 = pcall(function()
    return umtx(uint64(cv), uint64(8), uint64(2), uint64(mtx_cv), uint64(ts1))
end)
print(string.format("  CV_WAIT(8) flags=CLOCKID: rv=%s owner_after=0x%X",
    fmt_rv(ok6, rv6), safe_rd(mtx_cv) or 0))

-- Re-lock mutex
safe_wd(mtx_cv, 0)
pcall(function() umtx(uint64(mtx_cv), uint64(5), uint64(0), uint64(0), uint64(0)) end)

-- CV_WAIT with CVWAIT_ABSTIME (val=1) — absolute timeout in the past = immediate return
local ts2 = memory.alloc(16)
safe_wq(ts2, uint64(1))    -- tv_sec = 1 (epoch + 1s = way in the past)
safe_wq(ts2 + 8, uint64(0))

local ok7, rv7 = pcall(function()
    return umtx(uint64(cv), uint64(8), uint64(1), uint64(mtx_cv), uint64(ts2))
end)
print(string.format("  CV_WAIT(8) flags=ABSTIME past: rv=%s owner_after=0x%X",
    fmt_rv(ok7, rv7), safe_rd(mtx_cv) or 0))

-- Re-lock
safe_wd(mtx_cv, 0)
pcall(function() umtx(uint64(mtx_cv), uint64(5), uint64(0), uint64(0), uint64(0)) end)

-- CV_WAIT with c_has_waiters=1 (simulate existing waiter)
safe_wd(cv, 1)  -- c_has_waiters = 1
local ok8, rv8 = pcall(function()
    return umtx(uint64(cv), uint64(8), uint64(0), uint64(mtx_cv), uint64(ts1))
end)
print(string.format("  CV_WAIT(8) has_waiters=1: rv=%s owner_after=0x%X",
    fmt_rv(ok8, rv8), safe_rd(mtx_cv) or 0))

-- Re-lock
safe_wd(mtx_cv, 0)
pcall(function() umtx(uint64(mtx_cv), uint64(5), uint64(0), uint64(0), uint64(0)) end)

-- CV_WAIT with PI mutex
safe_wd(mtx_cv + 4, 4)  -- m_flags = PRIO_INHERIT
safe_wd(cv, 0)
local ok9, rv9 = pcall(function()
    return umtx(uint64(cv), uint64(8), uint64(0), uint64(mtx_cv), uint64(ts1))
end)
print(string.format("  CV_WAIT(8) PI mutex: rv=%s owner_after=0x%X",
    fmt_rv(ok9, rv9), safe_rd(mtx_cv) or 0))

-- ================================================================
print("")
print("--- SECTION D: WAIT_UINT variants to confirm timeout works ---")
-- Op 11 (WAIT_UINT) and 15 (WAIT_UINT_PRIVATE) accept timeout in uaddr2
-- These are known-working — use as control to verify our timeout struct

local wait_addr = memory.alloc(8)
safe_wd(wait_addr, 42)  -- value to match

local ts3 = memory.alloc(16)
safe_wq(ts3, uint64(0))
safe_wq(ts3 + 8, uint64(5000000))  -- 5ms

-- WAIT_UINT with matching value — should block then timeout
local ok10, rv10 = pcall(function()
    return umtx(uint64(wait_addr), uint64(11), uint64(42), uint64(16), uint64(ts3))
end)
print(string.format("  WAIT_UINT(11) match+timeout: rv=%s", fmt_rv(ok10, rv10)))

-- WAIT_UINT with non-matching value — should return immediately (EWOULDBLOCK)
local ok11, rv11 = pcall(function()
    return umtx(uint64(wait_addr), uint64(11), uint64(99), uint64(16), uint64(ts3))
end)
print(string.format("  WAIT_UINT(11) no-match: rv=%s", fmt_rv(ok11, rv11)))

print("")
print("=== PROBE 99b COMPLETE ===")
