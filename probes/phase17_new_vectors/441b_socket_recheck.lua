-- CRASH_CLASS: LOW
-- PROBE 441b: are the /system_tmp sockets there in this game session?
--
-- 441a got connect-failed on every attempt. The sockets are per game session (the jail's
-- random directory changes with the game, and 362b showed them back after a relaunch), so the
-- first thing to establish is whether the files exist and whether anything is listening before
-- reading anything into the connect failures.

print("=== PROBE 441b: SOCKET RECHECK ===")

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
local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, rv = pcall(function()
        return sc(uint64(a1 or 0), uint64(a2 or 0), uint64(a3 or 0), uint64(a4 or 0), uint64(a5 or 0), uint64(a6 or 0))
    end)
    if not ok then return -999 end
    if type(rv) == "table" and rv.h then
        local h, l = to_num(rv.h), to_num(rv.l)
        if h >= 2147483648 then h = h - 4294967296 end
        if l >= 2147483648 then l = l - 4294967296 end
        if h == -1 and l == -1 then return -1 end
        return h * 4294967296 + l
    end
    local n = to_num(rv)
    if n >= 9223372036854775808 then n = n - 18446744073709551616 end
    return n
end

-- list /system_tmp with the 32-bit dirent layout from 294a
local function mkpath(s)
    local p = memory.alloc(0x200)
    local j = 1
    while j <= #s do memory.write_byte(p + j - 1, s:byte(j)); j = j + 1 end
    memory.write_byte(p + #s, 0)
    return p
end

local dir = call(5, mkpath("/system_tmp"), 0, 0, 0, 0, 0)
print(string.format("[A] open(/system_tmp)=%d", dir))
if dir >= 0 then
    local buf = memory.alloc(0x2000)
    local n = call(196, dir, buf, 0x2000, 0, 0, 0)
    print(string.format("[B] getdirentries=%d", n))
    if n > 0 then
        local off = 0
        while off < n do
            local reclen = to_num(memory.read_dword(buf + off + 4)) % 65536
            local tp = to_num(memory.read_dword(buf + off + 6)) % 256
            local namlen = math.floor(to_num(memory.read_dword(buf + off + 6)) / 256) % 256
            local nm = ""
            local k = 0
            while k < namlen and k < 40 do
                nm = nm .. string.char(to_num(memory.read_dword(buf + off + 8 + k)) % 256)
                k = k + 1
            end
            print(string.format("    %-28s type=%d", nm, tp))
            if reclen <= 0 then break end
            off = off + reclen
        end
    end
    call(6, dir, 0, 0, 0, 0, 0)
end

-- and try each known name
local names = {"GnmCompositor", "GnmCompositorRestricted", "AgcCompositorSppSocket",
               "VrTracker2DomainSock", "SystemTts", "SceImageUtilAgent", "redis.sock"}
local sa = memory.alloc(0x80)
local function try(path)
    local i = 0
    while i < 0x80 do memory.write_byte(sa + i, 0); i = i + 1 end
    memory.write_byte(sa, 2 + #path)
    memory.write_byte(sa + 1, 1)
    local j = 1
    while j <= #path do memory.write_byte(sa + 1 + j, path:byte(j)); j = j + 1 end
    local fd = call(97, 1, 1, 0, 0, 0, 0)
    if fd < 0 then return -1 end
    local r = call(98, fd, sa, 0, 0, 0, 0)
    call(6, fd, 0, 0, 0, 0, 0)
    return r
end

local k = 1
while k <= #names do
    print(string.format("[C] %-26s connect=%d", names[k], try("/system_tmp/" .. names[k])))
    k = k + 1
end

print("=== 441b DONE ===")
