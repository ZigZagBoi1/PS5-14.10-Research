-- CRASH_CLASS: LOW
-- PROBE 475e: what controls the gic write length?
--
-- Context: 475d measured the write as +0x000..+0x46F into the target page, with
-- a fixed 14-byte head ({u32 0x00010002; "CUSA27390\0"}) and 0x462 bytes behind
-- it that differ on every call. The argument block has four dwords; q0 is the
-- address and the second dword echoed the low half of q1. This probe asks
-- whether any of those argument fields set the length: if one of them does, the
-- command stops being a fixed record and becomes a caller-sized kernel write.

print("=== PROBE 475e: what sets the gic write length ===")
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
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    if h % 0x100000000 == 0xFFFFFFFF and l % 0x100000000 == 0xFFFFFFFF then return -1 end
    if h == 0 and l >= 0x80000000 then return l - 0x100000000 end
    return l
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return to_num(v) % 0x100 end
    return -1
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)
local CMD = 0xC0104701

local fd = sgn(sc_open(uint64(put_str("/dev/gic")), uint64(2), uint64(0)))
print("fd=" .. fd)
if fd < 0 then
    print("=== PROBE 475e ABORTED ===")
    return
end

local arg = memory.alloc(0x40)
local target = memory.alloc(0x4000)

local function fill(v)
    for off = 0, 0x3FFC, 4 do wd(target + off, v) end
end
local function set_q0(addr)
    local ok = pcall(function() memory.write_qword(arg, uint64(addr)) end)
    if ok then return true end
    local hi = math.floor(addr / 4294967296)
    local lo = addr % 4294967296
    return pcall(function() memory.write_qword(arg, uint64(string.format("0x%X%08X", hi, lo))) end)
end

-- d2 = arg+0x8, d3 = arg+0xC
local function call(d1, d2, d3)
    set_q0(d1)
    wd(arg + 8, d2 % 0x100000000)
    wd(arg + 12, d3 % 0x100000000)
    return sgn(sc_ioctl(uint64(fd), uint64(CMD), uint64(arg)))
end

local function extent()
    local first, last, n = nil, nil, 0
    for off = 0, 0x3FFF do
        local b = rb(target + off)
        local want = ({[0] = 0x00, [1] = 0xEE, [2] = 0xFF, [3] = 0xC0})[off % 4]
        if b ~= want then
            n = n + 1
            if not first then first = off end
            last = off
        end
    end
    return n, first, last
end

local function row(off)
    local hex = {}
    for i = 0, 15 do hex[#hex + 1] = string.format("%02X", rb(target + off + i)) end
    return table.concat(hex, " ")
end

print(string.format("[0] arg=0x%X target=0x%X", to_num(arg), to_num(target)))

print("")
print("[A] vary the second argument dword (arg+0x8); first dword stays q0")
print("    d2           ret   changed  first   last     head at +0")
for _, d2 in ipairs({0, 1, 4, 0x10, 0x40, 0x100, 0x400, 0x470, 0x1000, 0x4000, 0xFFFFFFFF}) do
    fill(0xC0FFEE00)
    local r = call(target, d2, 0)
    local n, first, last = extent()
    print(string.format("    0x%-10X %4d  %6d  %-6s  %-6s   %s", d2, r, n,
        first and string.format("0x%X", first) or "-",
        last and string.format("0x%X", last) or "-", row(0)))
end

print("")
print("[B] vary the third argument dword (arg+0xC)")
print("    d3           ret   changed  first   last     head at +0")
for _, d3 in ipairs({0, 1, 4, 0x10, 0x100, 0x1000, 0xFFFFFFFF}) do
    fill(0xC0FFEE00)
    local r = call(target, 0, d3)
    local n, first, last = extent()
    print(string.format("    0x%-10X %4d  %6d  %-6s  %-6s   %s", d3, r, n,
        first and string.format("0x%X", first) or "-",
        last and string.format("0x%X", last) or "-", row(0)))
end

print("")
print("[C] repeat the plain call three times to see whether the extent moves")
for k = 1, 3 do
    fill(0xC0FFEE00)
    local r = call(target, 0, 0)
    local n, first, last = extent()
    print(string.format("    call%d ret=%d changed=%d first=%s last=%s", k, r, n,
        first and string.format("0x%X", first) or "-",
        last and string.format("0x%X", last) or "-"))
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 475e COMPLETE ===")
