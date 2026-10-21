-- CRASH_CLASS: HIGH
-- PROBE 263a: the dmem partitions with the protection the old probe used
--
-- 262a mapped every partition with PROT_READ|PROT_WRITE and got -1 everywhere,
-- including dmem0, which is known to map. The older working probe opened with
-- O_RDWR and asked for PROT_READ alone, so that is the shape compared here.
--
--   A  open each partition with O_RDWR, print the fd
--   B  mmap(PAGE, PROT_READ, MAP_SHARED, fd, off) at four offsets, read the page
--   C  the same mapping with PROT_READ|PROT_WRITE on dmem0 for contrast

print("=== PROBE 263a: dmem with PROT_READ ===")
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
local function nonzero_page(a)
    local hits = 0
    for off = 0, 0x4000 - 8, 8 do
        local ok, v = pcall(function() return memory.read_qword(a + off) end)
        if ok and v ~= nil and not (v.h == 0 and v.l == 0) then hits = hits + 1 end
    end
    return hits
end

print("[0] pid=" .. tostring(pid()))

local parts = { "dmem0", "dmem1", "dmem2" }
local fds = {}
print("")
print("[A] open with O_RDWR")
for i = 1, #parts do
    local rv = call(5, uint64(path("/dev/" .. parts[i])), uint64(2), uint64(0), uint64(0))
    fds[i] = n(rv)
    print(string.format("    %-6s -> %s", parts[i], raw(rv)))
end

print("")
print("[B] mmap(PAGE, PROT_READ, MAP_SHARED, fd, off)")
local offsets = { 0, 0x1000, 0x1000000, 0x100000000 }
for i = 1, #parts do
    local fd = fds[i]
    if fd ~= nil and fd >= 0 then
        for j = 1, #offsets do
            local off = offsets[j]
            local rv = call(477, uint64(0), uint64(0x4000), uint64(1), uint64(1),
                uint64(fd), uint64(off))
            local m = n(rv)
            if m > 0 and m < 0x800000000000 then
                print(string.format("    %-6s off=0x%-10X map=%s  live qwords=%d  [0]=%s  pid=%s",
                    parts[i], off, raw(rv), nonzero_page(m), rq(m), tostring(pid())))
            else
                print(string.format("    %-6s off=0x%-10X map=%s  pid=%s",
                    parts[i], off, raw(rv), tostring(pid())))
            end
        end
    end
end

print("")
print("[C] dmem0 with PROT_READ|PROT_WRITE")
local fd0 = fds[1]
if fd0 ~= nil and fd0 >= 0 then
    local rv = call(477, uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd0), uint64(0))
    print("    map=" .. raw(rv) .. "  pid=" .. tostring(pid()))
end

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 263a COMPLETE ===")
