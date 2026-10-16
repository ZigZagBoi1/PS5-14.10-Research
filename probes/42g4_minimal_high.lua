-- CRASH_CLASS: SAFE
-- PROBE 42g4: minimal high phys test

print("=== PROBE 42g4 ===")

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
local function qw_hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%X%08X", v.h, v.l), v.h, v.l
    end
    local n = to_num(v)
    return string.format("0x%X", n), 0, n
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)

local function dev_open(path)
    local name_buf = memory.alloc(256)
    for i = 1, #path do
        pcall(function() memory.write_byte(name_buf + i - 1, string.byte(path, i)) end)
    end
    pcall(function() memory.write_byte(name_buf + #path, 0) end)
    local fd = nil
    pcall(function() fd = sc_open(name_buf, uint64(2), uint64(0)) end)
    return fd and to_num(fd) or -1
end

local dmem_fd = dev_open("/dev/dmem0")
print("fd: " .. dmem_fd)

-- Test: just try one high address
print("test 4GB...")
local addr = nil
local ok = pcall(function()
    addr = sc_mmap(uint64(0), uint64(0x4000), uint64(1),
        uint64(1), uint64(dmem_fd),
        uint64("0x100000000"))
end)
print("mmap ok: " .. tostring(ok))
if ok and addr then
    local hex = qw_hex(addr)
    print("addr: " .. hex)
    local _, ah, al = qw_hex(addr)
    print("hi: " .. ah .. " lo: " .. al)
    if ah == 0xFFFFFFFF and al == 0xFFFFFFFF then
        print("MAP_FAILED")
    else
        local d = safe_rd(addr)
        print("data: " .. (d or -1))
        pcall(function() sc_munmap(addr, uint64(0x4000)) end)
    end
end

print("test 4.5GB...")
ok = pcall(function()
    addr = sc_mmap(uint64(0), uint64(0x4000), uint64(1),
        uint64(1), uint64(dmem_fd),
        uint64("0x120000000"))
end)
print("mmap ok: " .. tostring(ok))
if ok and addr then
    local hex = qw_hex(addr)
    print("addr: " .. hex)
end

-- Now the REAL question: try the PS5's GDDR6 physical range
-- PS5 has 16GB GDDR6. Addresses might start at a specific base.
-- Try some PS5-specific ranges
print("")
print("--- PS5-SPECIFIC RANGES ---")

local test_offsets = {
    "0x0",          -- we know this works
    "0x80000000",   -- 2GB
    "0xF8000000",   -- ~4GB minus some (PCI hole?)
    "0xFC000000",   -- near 4GB
    "0x100000000",  -- 4GB
    "0x200000000",  -- 8GB
    "0x300000000",  -- 12GB
    "0x380000000",  -- 14GB
}

for _, off_str in ipairs(test_offsets) do
    local test_addr = nil
    local test_ok = pcall(function()
        test_addr = sc_mmap(uint64(0), uint64(0x4000), uint64(1),
            uint64(1), uint64(dmem_fd), uint64(off_str))
    end)
    local result = "error"
    if test_ok and test_addr then
        local _, ah, al = qw_hex(test_addr)
        if ah == 0xFFFFFFFF and al == 0xFFFFFFFF then
            result = "MAP_FAILED"
        else
            local d = safe_rd(test_addr)
            if d ~= nil then
                result = string.format("data=0x%08X", d)
            else
                result = "mapped but unreadable"
            end
            pcall(function() sc_munmap(test_addr, uint64(0x4000)) end)
        end
    end
    print(string.format("  %s: %s", off_str, result))
end

pcall(function() sc_close(uint64(dmem_fd)) end)
print("")
print("=== PROBE 42g4 COMPLETE ===")
