-- CRASH_CLASS: HIGH
-- PROBE 809a: is the dmem0 aperture real physical memory, or a per-process window?
--
-- The previous process wrote A5A5A5A5 / 5A5A5A5A at physical 0x100000 (probe 806d) and proved a
-- second mapping of the same phys aliases.  The process that wrote it is gone.  Reading the same
-- physical address from THIS process separates the two models:
--   pattern present  -> a real physical page, shared across processes: arbitrary physical memory.
--   zero             -> the pager hands out a private zero page per process: a GPU/GART view.
print("=== PROBE 809a: PHYSICAL PERSISTENCE ACROSS PROCESSES ===")
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
local pid = to_num(getpid())
print("[0] pid=" .. pid .. " fd=" .. fd)
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
local function show(label, phys)
    if not map_page(phys) then print(string.format("  %-22s map-fail", label)) return end
    local a, b, c, d = rd(VA), rd(VA + 4), rd(VA + 8), rd(VA + 12)
    print(string.format("  %-22s phys %08X = %08X %08X %08X %08X", label, phys, a or 0, b or 0, c or 0, d or 0))
    unmap()
end
print("")
print("[1] the marker the previous process planted")
show("0x100000 (marker)", 0x100000)
show("0x100000+0x4000", 0x104000)
print("")
print("[2] the firmware cluster and the poison pages")
show("0x10014000", 0x10014000)
show("0x10018000", 0x10018000)
show("0x10D80000", 0x10D80000)
print("")
print("[3] plant a fresh marker for the next process")
if map_page(0x2000000) then
    local before = rd(VA)
    wd(VA, 0x11223344)
    wd(VA + 4, 0xAABBCCDD)
    local a, b = rd(VA), rd(VA + 4)
    print(string.format("  phys 0x2000000 before=%08X after-write=%08X %08X", before or 0, a or 0, b or 0))
    unmap()
end
print("")
print("[4] alive pid=" .. to_num(getpid()))
