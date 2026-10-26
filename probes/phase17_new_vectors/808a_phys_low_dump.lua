-- CRASH_CLASS: HIGH
-- PROBE 808a: dump the low-memory structures found at 0x1000000-0x1003000
print("=== PROBE 808a: LOW PHYSICAL STRUCTURE DUMP ===")
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
local function rdq(a)
    local lo, hi = rd(a), rd(a + 4)
    if lo == nil or hi == nil then return nil end
    return hi * 4294967296 + lo
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
print("[0] fd=" .. fd)
local VA = 0x880000000
local function map_page(phys)
    pcall(function() return sc_munmap(uint64(VA), uint64(0x4000)) end)
    local ok, r = pcall(function()
        return sc_mmap(uint64(VA), uint64(0x4000), uint64(0x33), uint64(0x11),
            uint64(fd), u64(math.floor(phys / 4294967296), phys % 4294967296))
    end)
    if not ok then return false end
    return to_num(r) == VA
end
local function dump(phys, nq)
    if not map_page(phys) then print(string.format("  %X map-fail", phys)) return end
    local t = {}
    for i = 0, nq - 1 do
        local v = rdq(VA + i * 8)
        t[#t + 1] = v and string.format("%016X", v) or "????"
    end
    print(string.format("  %08X %s", phys, table.concat(t, " ")))
    pcall(function() return sc_munmap(uint64(VA), uint64(0x4000)) end)
end
print("")
print("[1] pages around the first non-zero cluster")
for _, p in ipairs({0x1000000, 0x1001000, 0x1002000, 0x1003000, 0x10010000, 0x10014000, 0x10018000, 0x1001C000, 0x10020000, 0x10024000, 0x10028000}) do
    dump(p, 12)
end
print("")
print("[2] alive pid=" .. to_num(getpid()))
