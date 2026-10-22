-- CRASH_CLASS: LOW
-- PROBE 353d: fstat is present; kldstat needs its version field
--
-- 353c with SIGSYS ignored: fstat(22, buf) returned 0 and wrote a stat record
-- (0x2909FFAA 00000017 0000816D ...) - the slot is alive and the earlier
-- "fstat kills" record was the argument shape, not the handler. kldstat(0, buf)
-- still returned -1, but FreeBSD's kld_file_stat begins with a version field that
-- must equal sizeof(struct kld_file_stat) (~0x81C) or the call is EINVAL before
-- anything else happens. 43a never set it either.
--
-- This probe checks both, and then reproduces the old six-zero kill with the
-- default disposition restored, so "the kill was a signal" is measured rather
-- than assumed.

print("=== PROBE 353d: FSTAT PRESENT, KLDSTAT WITH A VERSION ===")
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
local function rdstr(addr, n)
    local s = {}
    for i = 0, n - 1 do
        local c = rd(addr + i) % 256
        if c == 0 then break end
        s[#s + 1] = string.char(c)
    end
    return table.concat(s)
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local sa = memory.alloc(0x80)
local old = memory.alloc(0x80)
for i = 0, 0x70, 8 do
    wq(sa + i, 0)
    wq(old + i, 0)
end
wq(sa + 0, 1)
wd(sa + 8, 0)

local buf = memory.alloc(0x1000)
local function zero(n)
    for i = 0, n / 4 - 1 do wd(buf + i * 4, 0) end
end

-- [A] fstat with the default disposition: is SIG_IGN even needed?
print("[A] fstat with the default SIGSYS disposition")
local fd = -1
do
    local ok, rv = pcall(function()
        return make_syscall(5)(put_str("/app0/eboot.bin"), uint64(0), Z)
    end)
    if ok then fd = sgn(rv) end
end
print(string.format("    open = %d", fd))
zero(0x400)
if fd >= 0 then
    local ok, rv = pcall(function()
        return make_syscall(189)(uint64(fd), uint64(buf), Z, Z, Z, Z)
    end)
    print(string.format("    fstat(fd, buf) = %s   %08X %08X %08X %08X %08X %08X",
        ok and tostring(sgn(rv)) or "EXC", rd(buf), rd(buf + 4), rd(buf + 8),
        rd(buf + 12), rd(buf + 16), rd(buf + 20)))
end

-- [B] ignore SIGSYS from here on
local okI, rvI = pcall(function()
    return make_syscall(416)(uint64(12), uint64(sa), uint64(old))
end)
print(string.format("[B] sigaction(12, SIG_IGN) -> %s", okI and tostring(sgn(rvI)) or "EXC"))

-- [C] kldstat with the version field set
print("[C] kldstat / kldnext with kld_file_stat.version")
for _, ver in ipairs({0x81C, 0x60, 0x1C}) do
    zero(0x400)
    wd(buf, ver)
    local ok, rv = pcall(function()
        return make_syscall(308)(Z, uint64(buf), Z, Z, Z, Z)
    end)
    print(string.format("    kldstat(0, version=0x%X) = %s   name=\"%s\" refs=%d id=%d size=0x%X",
        ver, ok and tostring(sgn(rv)) or "EXC", rdstr(buf + 4, 32),
        rd(buf + 0x404), rd(buf + 0x408), rd(buf + 0x410)))
end
for _, num in ipairs({307, 306}) do
    local ok, rv = pcall(function()
        return make_syscall(num)(Z, Z, Z, Z, Z, Z)
    end)
    print(string.format("    %d(0) = %s", num, ok and tostring(sgn(rv)) or "EXC"))
end

-- [D] sysctlbyname with a name and a length that fits
print("[D] sysctlbyname with a real name")
zero(0x400)
local lenp = memory.alloc(8)
wq(lenp, 0x100)
local okD, rvD = pcall(function()
    return make_syscall(570)(put_str("kern.ostype"), uint64(buf), uint64(lenp), Z, Z, Z)
end)
print(string.format("    \"kern.ostype\" = %s  *len=0x%X  \"%s\"",
    okD and tostring(sgn(rvD)) or "EXC", rd(lenp), rdstr(buf, 32)))
wq(lenp, 0x100)
local okD2, rvD2 = pcall(function()
    return make_syscall(570)(put_str("kern.maxproc"), uint64(buf), uint64(lenp), Z, Z, Z)
end)
print(string.format("    \"kern.maxproc\" = %s  *len=0x%X  value=%d",
    okD2 and tostring(sgn(rvD2)) or "EXC", rd(lenp), rd(buf)))

-- [E] the old shape, with the default disposition restored, LAST
print("[E] restoring SIG_DFL, then fstat with six zeros (the shape that used to kill)")
pcall(function()
    return make_syscall(416)(uint64(12), uint64(old), Z)
end)
print("    calling 189(0,0,0,0,0,0) now")
local okE, rvE = pcall(function()
    return make_syscall(189)(Z, Z, Z, Z, Z, Z)
end)
print(string.format("    returned %s - the process survived", okE and tostring(sgn(rvE)) or "EXC"))

print("")
print("=== 353d DONE ===")
