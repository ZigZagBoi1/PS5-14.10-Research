-- CRASH_CLASS: LOW
-- PROBE 353c: the slots that used to be lethal, called with arguments a real
--             handler would accept
--
-- 353b established that ignoring SIGSYS turns every death-on-touch slot into a
-- return of -1. That proves the deaths were the nosys trampoline's SIGSYS, but
-- not that the handlers are absent: a real handler rejecting six zero arguments
-- also returns -1.
--
-- The separator is the argument shape. A present kldstat fills a stat structure
-- and returns 0; a present fstat does the same for an open descriptor; a present
-- sysctlbyname resolves a name. The nosys trampoline cannot - it reads nothing
-- and returns the same value for every shape.
--
-- SIGSYS stays ignored throughout, so nothing here can terminate the process.

print("=== PROBE 353c: THE FORMERLY LETHAL SLOTS WITH REAL ARGUMENTS ===")
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
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local Z = uint64(0)
local function wd(addr, value)
    pcall(function() memory.write_dword(addr, value) end)
end
local function wq(addr, value)
    pcall(function() memory.write_qword(addr, value) end)
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

-- [A] safety: SIGSYS ignored
local sa = memory.alloc(0x80)
local old = memory.alloc(0x80)
for i = 0, 0x70, 8 do
    wq(sa + i, 0)
    wq(old + i, 0)
end
wq(sa + 0, 1)
wd(sa + 8, 0)
local okA, rvA = pcall(function()
    return make_syscall(416)(uint64(12), uint64(sa), uint64(old))
end)
print(string.format("[A] sigaction(12, SIG_IGN) -> %s", okA and tostring(sgn(rvA)) or "EXC"))
if not (okA and sgn(rvA) == 0) then
    print("    could not ignore SIGSYS; stopping")
    print("=== 353c DONE ===")
    return
end

local buf = memory.alloc(0x800)
for i = 0, 0x1FF do wd(buf + i * 4, 0) end

-- [B] 189 fstat on a descriptor we just opened
print("[B] 189 fstat on a real descriptor")
local fd = -1
do
    local ok, rv = pcall(function()
        return make_syscall(5)(put_str("/app0/eboot.bin"), uint64(0), Z)
    end)
    if ok then fd = sgn(rv) end
end
print(string.format("    open(/app0/eboot.bin) = %d", fd))
if fd >= 0 then
    local ok, rv = pcall(function()
        return make_syscall(189)(uint64(fd), uint64(buf), Z, Z, Z, Z)
    end)
    print(string.format("    fstat(fd=%d, buf) = %s   buf[0..3] = %08X %08X %08X %08X",
        fd, ok and tostring(sgn(rv)) or "EXC", rd(buf), rd(buf + 4), rd(buf + 8), rd(buf + 12)))
    pcall(function() return make_syscall(6)(uint64(fd)) end)
end

-- [C] 308 kldstat and 307 kldnext with a mapped stat buffer
print("[C] 308 kldstat / 307 kldnext with a buffer")
for _, num in ipairs({308, 307}) do
    for i = 0, 0x1FF do wd(buf + i * 4, 0) end
    local ok, rv = pcall(function()
        return make_syscall(num)(Z, uint64(buf), Z, Z, Z, Z)
    end)
    print(string.format("    %d(0, buf) = %s   buf[0..1] = %08X %08X",
        num, ok and tostring(sgn(rv)) or "EXC", rd(buf), rd(buf + 4)))
end

-- [D] 570 sysctlbyname with a real name
print("[D] 570 sysctlbyname(\"kern.ostype\")")
for i = 0, 0x1FF do wd(buf + i * 4, 0) end
local lenp = memory.alloc(8)
wq(lenp, 0x100)
local okD, rvD = pcall(function()
    return make_syscall(570)(put_str("kern.ostype"), uint64(buf), uint64(lenp), Z, Z, Z)
end)
print(string.format("    sysctlbyname = %s   *len = 0x%X   buf = %02X %02X %02X %02X %02X %02X",
    okD and tostring(sgn(rvD)) or "EXC", rd(lenp),
    rd(buf) % 256, math.floor(rd(buf) / 0x100) % 256,
    rd(buf + 1) % 256, math.floor(rd(buf + 1) / 0x100) % 256,
    rd(buf + 2) % 256, math.floor(rd(buf + 2) / 0x100) % 256))

-- [E] the controls: two shapes each, so "always -1" is visible
print("[E] the same slots with six zeros")
for _, num in ipairs({189, 307, 308, 570}) do
    local ok, rv = pcall(function()
        return make_syscall(num)(Z, Z, Z, Z, Z, Z)
    end)
    print(string.format("    %d(0 x6) = %s", num, ok and tostring(sgn(rv)) or "EXC"))
end

-- [F] restore
pcall(function()
    return make_syscall(416)(uint64(12), uint64(old), Z)
end)

print("")
print("=== 353c DONE ===")
