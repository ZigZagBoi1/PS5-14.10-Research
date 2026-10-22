-- CRASH_CLASS: LOW
-- PROBE 273a: is the encrypt service reachable from a game process?
--
-- Context: ps5-pup-decrypt (zecoxao/ps5-pup-decrypt-elf) opens
-- /dev/pup_update0 and drives it with ioctl 0xC0104401..0xC0284406 to decrypt
-- a PUP. Its main() also calls kernel_set_ucred_authid(pid, 0x4801...) and
-- kernel_set_proc_rootdir(), i.e. it assumes kernel R/W already exists.
--
-- The question this probe answers: does the device exist for us at all?
-- If open() succeeds, the ioctls are worth trying with no kernel primitive.
-- If it returns -1, the tool is circular for our position and the PUP stays
-- encrypted.

print("=== PROBE 273a: encrypt service reachability ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    if h % 0x100000000 == 0xFFFFFFFF and l % 0x100000000 == 0xFFFFFFFF then return -1 end
    if h == 0 and l >= 0x80000000 then return l - 0x100000000 end
    return l
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do
        pcall(function() memory.write_byte(buf + i - 1, s:byte(i)) end)
    end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end

local names = {
    "/dev/pup_update0",
    "/dev/pup_update",
    "/dev/sbl_srv",
    "/dev/encdec",
    "/dev/uvd_dec",
    "/dev/update",
    "/dev/upd",
}

local opened = {}
print("[A] open O_RDONLY, then O_RDWR")
for _, name in ipairs(names) do
    local p = put_str(name)
    local r1 = sc_open(uint64(p), uint64(0), uint64(0))
    local r2 = sc_open(uint64(p), uint64(2), uint64(0))
    print(string.format("    %-20s rd=%d wr=%d", name, sgn(r1), sgn(r2)))
    if sgn(r1) >= 0 then opened[#opened + 1] = { name = name, fd = sgn(r1) } end
    if sgn(r2) >= 0 then opened[#opened + 1] = { name = name, fd = sgn(r2) } end
end

print("")
print("[B] ioctl 0xC0104401 (verify_blsheader) on whatever opened")
print("    args struct is 24 bytes: buffer, length, unknown")
if #opened == 0 then
    print("    nothing opened - the device is not in this process's namespace")
else
    for _, o in ipairs(opened) do
        local args = memory.alloc(0x40)
        local buf = memory.alloc(0x40)
        for off = 0, 0x3C, 4 do
            pcall(function() memory.write_dword(args + off, 0) end)
            pcall(function() memory.write_dword(buf + off, 0) end)
        end
        pcall(function() memory.write_qword(args + 0x00, uint64(buf)) end)
        pcall(function() memory.write_qword(args + 0x08, uint64(0x40)) end)
        local r = sc_ioctl(uint64(o.fd), uint64(0xC0104401), uint64(args))
        print(string.format("    %-20s fd=%d ioctl=%d", o.name, o.fd, sgn(r)))
        pcall(function() sc_close(uint64(o.fd)) end)
    end
end

print("")
print("[C] control: /dev/zero must open, /dev/nope must not")
local z = sc_open(uint64(put_str("/dev/zero")), uint64(0), uint64(0))
local n = sc_open(uint64(put_str("/dev/nope")), uint64(0), uint64(0))
print("    zero=" .. sgn(z) .. "  nope=" .. sgn(n))
if sgn(z) >= 0 then pcall(function() sc_close(uint64(sgn(z))) end) end

print("=== PROBE 273a COMPLETE ===")
