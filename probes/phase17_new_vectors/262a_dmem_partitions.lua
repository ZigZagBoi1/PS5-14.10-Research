-- CRASH_CLASS: HIGH
-- PROBE 262a: the three dmem partitions, mapped and read
--
-- 261a showed 34 of the 76 /dev nodes open from this game process, and three of
-- them are dmem0, dmem1 and dmem2. Only dmem0 has ever been tried, and only at
-- a few offsets: the shape that works there is mmap with the physical address as
-- the file offset. A partition that maps anything outside the GPU aperture would
-- be a read of memory this process does not own, so the three are compared side
-- by side at the same offsets.
--
--   A  open each partition, print the fd
--   B  mmap(0x4000, PROT_RW, MAP_SHARED, fd, off) for offsets 0, 0x1000,
--      0x1000000, 0x40000000, 0x100000000, then read a qword at the mapping
--   C  ioctl with the DMA-ish commands 0..4 on dmem1 and dmem2
--
-- A kill names its own row, because every row prints the pid.

print("=== PROBE 262a: dmem partitions ===")
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
local function raw(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", v.h, v.l) end
    return "0x" .. string.format("%X", to_num(v))
end
local function n(v)
    local t = to_num(v)
    if t > 0x7FFFFFFFFFFFFFFF then t = t - 18446744073709551616 end
    return t
end
local function call(num, a, b, c, d, e, f)
    local sc = make_syscall(num)
    local ok, rv = pcall(function()
        return sc(a or uint64(0), b or uint64(0), c or uint64(0), d or uint64(0), e or uint64(0), f or uint64(0))
    end)
    if not ok then return nil end
    return rv
end
local function path(p)
    local b = memory.alloc(0x100)
    pcall(function() memory.write_qword(b, 0) end)
    for i = 1, #p do
        local ch = string.byte(p, i)
        pcall(function() memory.write_byte(b + i - 1, ch) end)
    end
    return b
end
local function pid()
    local ok, v = pcall(function() return make_syscall(20)() end)
    if ok then return to_num(v) end
    return 0
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok and v ~= nil then return string.format("0x%08X_%08X", v.h, v.l) end
    return "?"
end

print("[0] pid=" .. tostring(pid()))

local parts = { "dmem0", "dmem1", "dmem2" }
local fds = {}
print("")
print("[A] open")
for i = 1, #parts do
    local rv = call(5, uint64(path("/dev/" .. parts[i])), uint64(0), uint64(0), uint64(0))
    fds[i] = n(rv)
    print(string.format("    %-6s -> %s", parts[i], raw(rv)))
end

print("")
print("[B] mmap by physical offset, then read a qword")
local offsets = { 0, 0x1000, 0x1000000, 0x40000000, 0x100000000 }
for i = 1, #parts do
    local fd = fds[i]
    if fd ~= nil and fd >= 0 then
        for j = 1, #offsets do
            local off = offsets[j]
            local rv = call(477, uint64(0), uint64(0x4000), uint64(3), uint64(0x1),
                uint64(fd), uint64(off))
            local m = n(rv)
            if m > 0 and m < 0x800000000000 then
                print(string.format("    %-6s off=0x%-10X map=%s  [0]=%s  [0x1000]=%s  pid=%s",
                    parts[i], off, raw(rv), rq(m), rq(m + 0x1000), tostring(pid())))
            else
                print(string.format("    %-6s off=0x%-10X map=%s  pid=%s",
                    parts[i], off, raw(rv), tostring(pid())))
            end
        end
    end
end

print("")
print("[C] ioctl 0..4 on each partition")
local buf = memory.alloc(0x100)
for i = 1, #parts do
    local fd = fds[i]
    if fd ~= nil and fd >= 0 then
        local row = {}
        for cmd = 0, 4 do
            pcall(function() for o = 0, 0xFC, 4 do memory.write_dword(buf + o, 0) end end)
            local rv = call(54, uint64(fd), uint64(cmd), uint64(buf), uint64(0x100))
            row[#row + 1] = raw(rv)
        end
        print(string.format("    %-6s %s", parts[i], table.concat(row, " ")))
    end
end

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 262a COMPLETE ===")
