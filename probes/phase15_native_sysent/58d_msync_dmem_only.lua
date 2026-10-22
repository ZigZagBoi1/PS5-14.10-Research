-- CRASH_CLASS: LOW
-- PROBE 58d: msync on dmem0 device mapping only

print("=== PROBE 58d: MSYNC DMEM ===")

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

local sc_open   = make_syscall(5)
local sc_close  = make_syscall(6)
local sc_mmap   = make_syscall(477)
local sc_msync  = make_syscall(65)
local sc_munmap = make_syscall(73)

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local PAGE = 0x4000
local path_buf = memory.alloc(64)

-- Helper to open a device
local function open_dev(path)
    for i = 1, #path do
        memory.write_byte(path_buf + i - 1, string.byte(path, i))
    end
    memory.write_byte(path_buf + #path, 0)
    for _, mode in ipairs({2, 0}) do
        local ok, fd = pcall(function()
            return sc_open(uint64(path_buf), uint64(mode), uint64(0))
        end)
        if ok then
            local fv = to_num(fd)
            if fv >= 0 and fv < 1000 then return fv end
        end
    end
    return -1
end

-- Helper to test msync on a mapping
local function test_msync(name, mapping)
    local mh, ml = get_hi_lo(mapping)
    if ml == 0 and mh == 0 then
        print(name .. ": MAP_FAILED")
        return
    end
    print(name .. ": map=0x" .. string.format("%X%08X", mh, ml))

    local ok_r, v = pcall(function() return memory.read_dword(mapping) end)
    if ok_r then
        print("  read[0]=0x" .. string.format("%08X", to_num(v)))
    else
        print("  read FAULT")
    end

    -- MS_INVALIDATE = 2
    local ok1, r1 = pcall(function()
        return sc_msync(uint64(mapping), uint64(PAGE), uint64(2))
    end)
    local inv = ok1 and to_num(r1) or -999
    print("  MS_INVALIDATE=" .. inv)

    if inv == 0 then
        print("  *** INVALIDATE SUCCEEDED ***")
    end

    -- MS_SYNC = 0
    local ok2, r2 = pcall(function()
        return sc_msync(uint64(mapping), uint64(PAGE), uint64(0))
    end)
    print("  MS_SYNC=" .. (ok2 and tostring(to_num(r2)) or "FAIL"))

    -- MS_ASYNC = 1
    local ok3, r3 = pcall(function()
        return sc_msync(uint64(mapping), uint64(PAGE), uint64(1))
    end)
    print("  MS_ASYNC=" .. (ok3 and tostring(to_num(r3)) or "FAIL"))

    pcall(function() sc_munmap(uint64(mapping), uint64(PAGE)) end)
end

-- [A] /dev/dmem0 with O_RDWR + PROT_READ|MAP_SHARED
print("--- DMEM0 ---")
local fd0 = open_dev("/dev/dmem0")
print("fd0=" .. fd0)

if fd0 >= 0 then
    local ok, m = pcall(function()
        return sc_mmap(uint64(0), uint64(PAGE), uint64(1),
            uint64(0x0001), uint64(fd0), uint64(0))
    end)
    if ok then test_msync("dmem0_RD_SH", m) end

    local ok2, m2 = pcall(function()
        return sc_mmap(uint64(0), uint64(PAGE), uint64(3),
            uint64(0x0001), uint64(fd0), uint64(0))
    end)
    if ok2 then test_msync("dmem0_RW_SH", m2) end

    pcall(function() sc_close(uint64(fd0)) end)
end

-- [B] /dev/dmem1
print("--- DMEM1 ---")
local fd1 = open_dev("/dev/dmem1")
print("fd1=" .. fd1)

if fd1 >= 0 then
    local ok, m = pcall(function()
        return sc_mmap(uint64(0), uint64(PAGE), uint64(1),
            uint64(0x0001), uint64(fd1), uint64(0))
    end)
    if ok then test_msync("dmem1_RD_SH", m) end
    pcall(function() sc_close(uint64(fd1)) end)
end

-- [C] GPU anonymous (comparison)
print("--- GPU_ANON ---")
local ok_g, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(PAGE), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
if ok_g then test_msync("gpu_anon", gpu) end

-- [D] Regular anonymous
print("--- REG_ANON ---")
local ok_a, anon = pcall(function()
    return sc_mmap(uint64(0), uint64(PAGE), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
if ok_a then test_msync("reg_anon", anon) end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
