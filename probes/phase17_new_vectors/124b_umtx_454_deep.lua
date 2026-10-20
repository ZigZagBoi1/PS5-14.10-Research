-- CRASH_CLASS: MODERATE
-- PROBE 124b: Real _umtx_op (syscall 454) deep test
-- Previous "umtx" probes used syscall 557 (namedobj_create), NOT real umtx.
-- Only 56i2 section F tested 454: ops 5/21 ret=0, op 5 wrote TID-shaped owner.
-- UMTX_OP_SHM(25) and UMTX_OP_ROBUST_LISTS(26) were NEVER tested on 454.
-- FreeBSD 11 reads SHM key/params from uaddr1, robust lists from uaddr1 pointer.
-- These ops may leak kernel pointers or provide kernel write primitives.

print("=== PROBE 124b: UMTX 454 DEEP ===")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local sc_umtx = make_syscall(454)

-- _umtx_op(void *obj, int op, u_long val, void *uaddr1, void *uaddr2)
-- FreeBSD ops:
--  0=UMTX_OP_LOCK, 1=UMTX_OP_UNLOCK, 2=UMTX_OP_WAIT, 3=UMTX_OP_WAKE
--  4=UMTX_OP_MUTEX_TRYLOCK, 5=UMTX_OP_MUTEX_LOCK, 6=UMTX_OP_MUTEX_UNLOCK
--  7=UMTX_OP_SET_CEILING, 8=UMTX_OP_CV_WAIT, 9=UMTX_OP_CV_SIGNAL
-- 10=UMTX_OP_CV_BROADCAST, 11=UMTX_OP_WAIT_UINT, 12=UMTX_OP_RW_RDLOCK
-- 13=UMTX_OP_RW_WRLOCK, 14=UMTX_OP_RW_UNLOCK, 15=UMTX_OP_WAIT_UINT_PRIVATE
-- 16=UMTX_OP_WAKE_PRIVATE, 17=UMTX_OP_MUTEX_WAIT
-- 18=UMTX_OP_MUTEX_WAKE, 19=UMTX_OP_SEM_WAIT, 20=UMTX_OP_SEM_WAKE
-- 21=UMTX_OP_NWAKE_PRIVATE, 22=UMTX_OP_MUTEX_WAKE2
-- 23=UMTX_OP_SEM2_WAIT, 24=UMTX_OP_SEM2_WAKE
-- 25=UMTX_OP_SHM, 26=UMTX_OP_ROBUST_LISTS

-- Allocate shared buffers
local obj = memory.alloc(0x200)  -- umtx object
local uaddr1 = memory.alloc(0x200)
local uaddr2 = memory.alloc(0x200)
local outbuf = memory.alloc(0x400)

-- Zero all buffers
for i = 0, 0x1F8, 8 do
    memory.write_qword(obj + i, uint64(0))
    memory.write_qword(uaddr1 + i, uint64(0))
    memory.write_qword(uaddr2 + i, uint64(0))
end
for i = 0, 0x3F8, 8 do
    memory.write_qword(outbuf + i, uint64(0))
end

-- Section A: Sweep all ops 0-26 with basic args
print("")
print("--- SECTION A: OP SWEEP ---")
for op = 0, 26 do
    -- Zero obj
    for i = 0, 0x38, 8 do memory.write_qword(obj + i, uint64(0)) end

    local ok, ret = pcall(function()
        return sc_umtx(uint64(obj), uint64(op), uint64(0),
            uint64(uaddr1), uint64(uaddr2))
    end)
    local rv = ok and to_num(ret) or -999
    -- Check if obj was modified
    local obj_w0 = safe_rd(obj) or 0
    local obj_w1 = safe_rd(obj + 4) or 0
    print(string.format("op=%2d ret=%d obj[0]=0x%08X obj[4]=0x%08X", op, rv, obj_w0, obj_w1))
end

-- Section B: UMTX_OP_SHM (25) detailed test
print("")
print("--- SECTION B: UMTX_OP_SHM ---")
-- FreeBSD: uaddr1 is the key, val encodes sub-operation
-- val: UMTX_SHM_CREAT=1, UMTX_SHM_LOOKUP=2, UMTX_SHM_DESTROY=4, UMTX_SHM_ALIVE=8

-- Fill sentinel pattern in outbuf
for i = 0, 0x100, 4 do memory.write_dword(outbuf + i, 0xDEADBEEF) end

-- Try SHM_CREAT (val=1)
local ok1, ret1 = pcall(function()
    return sc_umtx(uint64(outbuf), uint64(25), uint64(1),
        uint64(0), uint64(0))
end)
print("SHM_CREAT(1): ok=" .. tostring(ok1) .. " ret=" .. tostring(ok1 and to_num(ret1) or "FAIL"))

-- Check what was written to outbuf
local shm_changed = 0
for i = 0, 0x100, 4 do
    local v = safe_rd(outbuf + i)
    if v and v ~= 0xDEADBEEF then
        shm_changed = shm_changed + 1
        if shm_changed <= 10 then
            local h = 0
            if i + 4 <= 0x100 then h = safe_rd(outbuf + i + 4) or 0 end
            print(string.format("  outbuf+0x%03X: 0x%08X (hi=0x%08X)", i, v, h))
        end
    end
end
print("shm_changed_dwords=" .. shm_changed)

-- Try SHM with key values
for _, key in ipairs({0, 1, 0x100, 0x1000, 0xFFFF}) do
    memory.write_dword(uaddr1, key)
    local ok, ret = pcall(function()
        return sc_umtx(uint64(uaddr1), uint64(25), uint64(1),
            uint64(0), uint64(0))
    end)
    local rv = ok and to_num(ret) or -999
    local w0 = safe_rd(uaddr1) or 0
    local w4 = safe_rd(uaddr1 + 4) or 0
    print(string.format("SHM key=0x%X ret=%d w0=0x%08X w4=0x%08X", key, rv, w0, w4))
end

-- SHM_LOOKUP (val=2)
local ok2, ret2 = pcall(function()
    return sc_umtx(uint64(outbuf), uint64(25), uint64(2), uint64(0), uint64(0))
end)
print("SHM_LOOKUP(2): ok=" .. tostring(ok2) .. " ret=" .. tostring(ok2 and to_num(ret2) or "FAIL"))

-- Section C: UMTX_OP_ROBUST_LISTS (26)
print("")
print("--- SECTION C: ROBUST_LISTS ---")
-- FreeBSD: copyin struct umtx_robust_lists_params from uaddr1
-- struct has: robust_list_offset, robust_priv_list_offset, robust_inact_offset
-- Size from uaddr2 (actually val parameter in some versions)

-- Prepare robust_lists_params struct (3 pointers)
local robust = memory.alloc(0x100)
-- Fill with sentinel
for i = 0, 0x60, 8 do memory.write_qword(robust + i, uint64(0)) end

-- Try with size = 24 (3 * sizeof(void*))
local ok3, ret3 = pcall(function()
    return sc_umtx(uint64(0), uint64(26), uint64(24),
        uint64(robust), uint64(0))
end)
print("ROBUST(size=24): ok=" .. tostring(ok3) .. " ret=" .. tostring(ok3 and to_num(ret3) or "FAIL"))

-- Check robust buffer for changes
for i = 0, 0x30, 8 do
    local q = safe_rq(robust + i)
    if q then
        local h, l = get_hi_lo(q)
        if h ~= 0 or l ~= 0 then
            print(string.format("  robust+0x%02X: 0x%08X%08X", i, h, l))
        end
    end
end

-- Try different sizes
for _, sz in ipairs({8, 16, 24, 48, 64}) do
    for i = 0, 0x40, 8 do memory.write_qword(robust + i, uint64(0)) end
    local ok, ret = pcall(function()
        return sc_umtx(uint64(0), uint64(26), uint64(sz),
            uint64(robust), uint64(0))
    end)
    print(string.format("ROBUST(size=%d): ret=%s", sz, ok and tostring(to_num(ret)) or "FAIL"))
end

-- Section D: UMTX_OP_MUTEX_LOCK (5) with PI flag
print("")
print("--- SECTION D: PI MUTEX ---")
-- UMTX_OP_MUTEX_LOCK with UMUTEX_PRIO_INHERIT flag
local mutex = memory.alloc(0x100)
for i = 0, 0x40, 8 do memory.write_qword(mutex + i, uint64(0)) end

-- Set flags for PI: offset 4 = flags, UMUTEX_PRIO_INHERIT = 0x04
memory.write_dword(mutex + 4, 0x04)

-- timespec for immediate timeout
local ts = memory.alloc(16)
memory.write_qword(ts, uint64(0))     -- tv_sec = 0
memory.write_qword(ts + 8, uint64(1)) -- tv_nsec = 1 (immediate)

local ok4, ret4 = pcall(function()
    return sc_umtx(uint64(mutex), uint64(5), uint64(0),
        uint64(0), uint64(ts))
end)
local rv4 = ok4 and to_num(ret4) or -999
print("PI_MUTEX_LOCK: ret=" .. rv4)

-- Check what was written to mutex
for i = 0, 0x30, 4 do
    local v = safe_rd(mutex + i)
    if v and v ~= 0 and (i ~= 4 or v ~= 4) then
        print(string.format("  mutex+0x%02X: 0x%08X", i, v))
    end
end

-- Check for kernel pointer in mutex owner field (offset 0)
local owner = safe_rq(mutex)
if owner then
    local h, l = get_hi_lo(owner)
    if h >= 0xFFFF8000 then
        print(string.format("  *** KERNEL PTR IN OWNER: 0x%08X%08X ***", h, l))
    end
end

-- Section E: Scan heap after umtx operations for leaked kernel ptrs
print("")
print("--- SECTION E: POST-UMTX HEAP SCAN ---")
local sc_mmap = make_syscall(477)
local gpu = sc_mmap(uint64(0), uint64(32*0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local gh, gl = get_hi_lo(gpu)
print(string.format("gpu_scan=0x%X%08X", gh, gl))

local heap_kptrs = 0
for off = 0, 32*0x4000 - 8, 8 do
    local addr = uint64(string.format("0x%X%08X", gh, gl + off))
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok and val then
        local h, l = get_hi_lo(val)
        if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
            heap_kptrs = heap_kptrs + 1
            if heap_kptrs <= 15 then
                print(string.format("  HEAP_KPTR +0x%05X: 0x%08X%08X", off, h, l))
            end
        end
    end
end
print("heap_kptrs=" .. heap_kptrs)

print("=== PROBE 124b COMPLETE ===")
