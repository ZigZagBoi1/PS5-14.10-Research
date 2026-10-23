-- CRASH_CLASS: MODERATE
-- PROBE 482e: is the device vm_map insert well behaved?
--
-- 482d: 0x80108002 accepts a legal range in [0x2500000000, 0x2558000001) and
-- returns 0; the callee walks a vm_map at [ctx+0x48]. This asks whether the
-- insert rejects duplicates and whether 0x80108015 removes what was inserted.
-- No memory in the window is read or written after the call, so a wrong guess
-- shows up as a return code, not as a fault.
print("=== PROBE 482e: device vm_map insert/remove semantics ===")
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

local arg = memory.alloc(0x100)
local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

local function setargs(q0, q1)
    pcall(function() memory.write_qword(arg, cast64(q0)) end)
    pcall(function() memory.write_qword(arg + 8, cast64(q1)) end)
    pcall(function() memory.write_qword(arg + 0x10, uint64(0)) end)
    return arg
end
local function call(fd, cmd, q0, q1)
    local p = setargs(q0, q1)
    local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(cmd), uint64(p)) end)
    if not ok then return "pcall-fail" end
    return tostring(sgn(r))
end

local fd = sgn(sc_open(uint64(put_str("/dev/dmem1")), uint64(2), uint64(0)))
print(string.format("[open] /dev/dmem1 fd=%d", fd))
if fd < 0 then
    print("no handle, stopping")
    print("=== PROBE 482e DONE ===")
    return
end

local INSERT, REMOVE = 0x80108002, 0x80108015
local BASE = 0x2520000000

print("[A] insert the same range twice")
print("    insert base+16K  1 -> " .. call(fd, INSERT, BASE, 0x4000))
print("    insert base+16K  2 -> " .. call(fd, INSERT, BASE, 0x4000))
print("    insert base+16K  3 -> " .. call(fd, INSERT, BASE, 0x4000))

print("[B] remove it, then remove again")
print("    remove base+16K  1 -> " .. call(fd, REMOVE, BASE, 0x4000))
print("    remove base+16K  2 -> " .. call(fd, REMOVE, BASE, 0x4000))

print("[C] insert then remove")
print("    insert base+32K     -> " .. call(fd, INSERT, BASE, 0x8000))
print("    remove base+32K     -> " .. call(fd, REMOVE, BASE, 0x8000))

print("[D] adjacent and overlapping inserts")
print("    insert base+16K     -> " .. call(fd, INSERT, BASE, 0x4000))
print("    insert base+16K+16K -> " .. call(fd, INSERT, BASE + 0x4000, 0x4000))
print("    insert base+32K     -> " .. call(fd, INSERT, BASE, 0x8000))
print("    remove base+32K     -> " .. call(fd, REMOVE, BASE, 0x8000))
print("    remove base+16K     -> " .. call(fd, REMOVE, BASE, 0x4000))

print("[E] a range that was never inserted")
print("    remove base+0x100000 -> " .. call(fd, REMOVE, BASE + 0x100000, 0x4000))

print("[F] slot neighbours, one call each")
for i = 1, 3 do
    local a = BASE + i * 0x8000000
    print(string.format("    insert %08X%08X -> %s", math.floor(a / 4294967296), a % 4294967296,
        call(fd, INSERT, a, 0x4000)))
end

pcall(function() sc_close(uint64(fd)) end)
print("=== PROBE 482e DONE ===")
