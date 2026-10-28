-- CRASH_CLASS: HIGH
-- PROBE 810c: read back the markers planted by the previous process
print("=== PROBE 810c: VERIFY PHYSICAL MARKERS ===")
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
print("[0] pid=" .. to_num(getpid()) .. " fd=" .. fd)
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
local function unmap() pcall(function() return sc_munmap(uint64(VA), uint64(0x4000)) end) end
local EXPECT = {
    {0x100000, 0xA5A5A5A5},
    {0x2000000, 0x11223344},
    {0x3000000, 0x11110001},
    {0x3400000, 0x11110002},
    {0x3800000, 0x11110003},
    {0x3C00000, 0x11110004},
    {0x4000000, 0x11110005},
    {0x8000000, 0x11110006},
}
print("")
print("[1] markers")
local kept = 0
for _, e in ipairs(EXPECT) do
    if map_page(e[1]) then
        local a, b = rd(VA), rd(VA + 4)
        local ok = (a == e[2])
        if ok then kept = kept + 1 end
        print(string.format("  %08X = %08X %08X  expect %08X  %s", e[1], a or 0, b or 0, e[2], ok and "KEPT" or "lost"))
        unmap()
    else
        print(string.format("  %08X map-fail", e[1]))
    end
end
print("")
print("[2] kept " .. kept .. " of " .. #EXPECT)
print("[3] alive pid=" .. to_num(getpid()))
