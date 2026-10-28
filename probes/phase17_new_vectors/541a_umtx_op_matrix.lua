-- CRASH_CLASS: MODERATE
-- PROBE 541a: reachability of every _umtx_op operation
--
-- Context: only ops 5 (mutex lock) and 21 (nwake private) have captures on
-- 14.10; the PI mutex, rwlock, condition variable, semaphore and robust-list
-- operations have never been called. This matrix calls each op once against a
-- page of ones with a mismatched expected value, so the wait-shaped ops return
-- instead of sleeping.
--
-- Argument order is the FreeBSD one: _umtx_op(obj, op, val, uaddr1, uaddr2),
-- so the umtx word is the first argument, not the second. An earlier version
-- of this probe passed the op first and every call returned -1.

print("=== PROBE 541a: UMTX OP MATRIX ===")
print("")
local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local sc454 = mk(454)
local PAGE = memory.alloc(0x100)

local names = {
 [0]="LOCK",[1]="UNLOCK",[2]="WAIT",[3]="WAKE",[4]="MUTEX_TRYLOCK",
 [5]="MUTEX_LOCK",[6]="MUTEX_UNLOCK",[7]="SET_CEILING",[8]="CV_WAIT",
 [9]="CV_SIGNAL",[10]="CV_BROADCAST",[11]="WAIT_UINT",[12]="RW_RDLOCK",
 [13]="RW_WRLOCK",[14]="RW_UNLOCK",[15]="WAIT_UINT_PRIVATE",[16]="WAKE_PRIVATE",
 [17]="MUTEX_WAIT",[18]="MUTEX_WAKE",[19]="SEM_WAIT",[20]="SEM_WAKE",
 [21]="NWAKE_PRIVATE",[22]="MUTEX_WAKE2",[23]="SEM2_WAIT",[24]="SEM2_WAKE",
 [25]="SHM",[26]="ROBUST_LISTS",
}

for op = 0, 26 do
    wd(N(PAGE), 1)
    wd(N(PAGE) + 4, 1)
    local ret = -999
    pcall(function()
        ret = N(sc454(uint64(N(PAGE)), uint64(op), uint64(0), uint64(0), uint64(N(PAGE) + 8)))
    end)
    print(string.format("op %2d %-18s ret=%d word=%d", op, names[op] or "?", ret, N(memory.read_dword(N(PAGE)))))
end
print("=== DONE ===")
