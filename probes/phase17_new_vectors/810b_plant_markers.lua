-- CRASH_CLASS: HIGH
-- PROBE 810b: verify the 0x2000000 marker and plant several unique ones
--
-- The 0x100000 marker vanishing could mean either (a) the window is per-process, or (b) the page
-- was handed to the new process and zeroed.  Several markers at different physical addresses
-- across the same window separate those: a per-process window loses all of them, a real shared
-- page keeps whichever pages the kernel did not reuse.
print("=== PROBE 810b: PLANT PHYSICAL MARKERS ===")
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
print("")
print("[1] previous markers")
for _, p in ipairs({0x100000, 0x2000000, 0x10014000, 0x10D80000}) do
    if map_page(p) then
        print(string.format("  %08X = %08X %08X %08X %08X", p, rd(VA) or 0, rd(VA + 4) or 0, rd(VA + 8) or 0, rd(VA + 12) or 0))
        unmap()
    else
        print(string.format("  %08X map-fail", p))
    end
end
print("")
print("[2] planting unique markers")
local P = {
    {0x3000000, 0x11110001, 0xAAAA0001},
    {0x3400000, 0x11110002, 0xAAAA0002},
    {0x3800000, 0x11110003, 0xAAAA0003},
    {0x3C00000, 0x11110004, 0xAAAA0004},
    {0x4000000, 0x11110005, 0xAAAA0005},
    {0x8000000, 0x11110006, 0xAAAA0006},
}
for _, m in ipairs(P) do
    if map_page(m[1]) then
        local before = rd(VA)
        wd(VA, m[2]); wd(VA + 4, m[3]); wd(VA + 8, m[2]); wd(VA + 12, m[3])
        print(string.format("  %08X before=%08X wrote=%08X %08X read=%08X %08X",
            m[1], before or 0, m[2], m[3], rd(VA) or 0, rd(VA + 4) or 0))
        unmap()
    else
        print(string.format("  %08X map-fail", m[1]))
    end
end
print("")
print("[3] alive pid=" .. to_num(getpid()))
