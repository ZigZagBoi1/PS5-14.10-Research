-- CRASH_CLASS: HIGH
-- PROBE 808c: per-page scan of physical memory above 512 MB for the kernel image
--
-- Per-page mapping is the safe pattern: a hole returns -1 from mmap, whereas a large mapping
-- succeeds and then faults when a hole is read.  Only the first dword of each page is read.
print("=== PROBE 808c: PHYSICAL SCAN 0x20000000-0x80000000 ===")
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
print("[0] fd=" .. fd)
local VA = 0x880000000
local function try(phys)
    pcall(function() return sc_munmap(uint64(VA), uint64(0x4000)) end)
    local ok, r = pcall(function()
        return sc_mmap(uint64(VA), uint64(0x4000), uint64(0x33), uint64(0x11),
            uint64(fd), u64(math.floor(phys / 4294967296), phys % 4294967296))
    end)
    if not ok then return false end
    return to_num(r) == VA
end
print("")
local CH = 0x8000000
local start = 0x20000000
local stop = 0x80000000
local p = start
while p < stop do
    local nz, mapped, holes = 0, 0, 0
    local ex = {}
    local q = p
    local qend = math.min(p + CH, stop)
    while q < qend do
        if try(q) then
            mapped = mapped + 1
            local v = rd(VA)
            if v ~= nil and v ~= 0 then
                nz = nz + 1
                if #ex < 6 then ex[#ex + 1] = string.format("%X=%08X", q, v) end
            end
            pcall(function() return sc_munmap(uint64(VA), uint64(0x4000)) end)
        else
            holes = holes + 1
        end
        q = q + 0x1000
    end
    print(string.format("  [%X,%X) mapped=%d holes=%d nz=%d %s", p, qend, mapped, holes, nz, table.concat(ex, " ")))
    p = qend
end
print("")
print("[2] alive pid=" .. to_num(getpid()))
