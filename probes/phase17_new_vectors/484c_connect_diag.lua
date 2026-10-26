-- CRASH_CLASS: LOW
-- PROBE 484c: raw returns for the non-blocking connect path
--
-- 484b reported every port open, including 1 and 9999, so one of the syscalls
-- in the chain lies. This prints the raw return of each step for a port that
-- must be closed (1) and one that must be open (9026, the loader's own port).

print("=== PROBE 484c: connect path diagnostics ===")
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
    local n = to_num(v)
    if n >= 0x8000000000000000 then return n - 0x10000000000000000 end
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rd(a) local v = 0; pcall(function() v = to_num(memory.read_dword(a)) end); return v end

local sc_socket  = make_syscall(97)
local sc_connect = make_syscall(98)
local sc_close   = make_syscall(6)
local sc_fcntl   = make_syscall(92)
local sc_select  = make_syscall(93)
local sc_getsock = make_syscall(118)
local sc_getpeer = make_syscall(32)

local sa   = memory.alloc(0x20)
local wfds = memory.alloc(0x100)
local tv   = memory.alloc(0x20)
local opt  = memory.alloc(0x20)
local optl = memory.alloc(0x20)
local plen = memory.alloc(0x20)

local function run(port)
    print(string.format("[port %d]", port))
    local fd = sgn(sc_socket(uint64(2), uint64(1), uint64(0)))
    print(string.format("  socket   = %d", fd))
    if fd < 0 then return end
    print(string.format("  fcntl    = %d", sgn(sc_fcntl(uint64(fd), uint64(4), uint64(4)))))

    for o = 0, 12, 4 do wd(sa + o, 0) end
    pcall(function() memory.write_byte(sa, 16) end)
    pcall(function() memory.write_byte(sa + 1, 2) end)
    pcall(function() memory.write_byte(sa + 2, math.floor(port / 256)) end)
    pcall(function() memory.write_byte(sa + 3, port % 256) end)
    pcall(function() memory.write_byte(sa + 4, 127) end)
    pcall(function() memory.write_byte(sa + 7, 1) end)

    local cr = sgn(sc_connect(uint64(fd), uint64(sa), uint64(16)))
    print(string.format("  connect  = %d", cr))

    for o = 0, 0x7C, 4 do wd(wfds + o, 0) end
    local byteoff = math.floor(fd / 8)
    pcall(function() memory.write_byte(wfds + byteoff, 2 ^ (fd % 8)) end)
    wd(tv, 0); wd(tv + 4, 0); wd(tv + 8, 50000); wd(tv + 12, 0)
    local sr = sgn(sc_select(uint64(fd + 1), uint64(0), uint64(wfds), uint64(0), uint64(tv)))
    print(string.format("  select   = %d  wfds[%d]=0x%02X", sr, byteoff, (function() local v = 0; pcall(function() v = to_num(memory.read_byte(wfds + byteoff)) end); return v end)()))

    wd(opt, 0xDEAD); wd(optl, 4)
    local gr = sgn(sc_getsock(uint64(fd), uint64(0xFFFF), uint64(0x1007), uint64(opt), uint64(optl)))
    print(string.format("  getsockopt SO_ERROR = %d value=0x%X len=%d", gr, rd(opt), rd(optl)))

    for o = 0, 12, 4 do wd(sa + o, 0) end
    wd(plen, 16)
    local pr = sgn(sc_getpeer(uint64(fd), uint64(sa), uint64(plen)))
    print(string.format("  getpeername = %d len=%d", pr, rd(plen)))

    sc_close(uint64(fd))
end

run(1)
print("")
run(9026)
print("=== PROBE 484c END ===")
