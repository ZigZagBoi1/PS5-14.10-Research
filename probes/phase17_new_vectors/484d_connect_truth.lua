-- CRASH_CLASS: LOW
-- PROBE 484d: loopback connect truth test, known-good syscall form
--
-- 484b's select+SO_ERROR test called every port open. This uses the form that
-- already worked on this console (probes/phase8_live_network/40_tcp_connectback.lua):
-- plain numbers, syscall.sc_socket / syscall.sc_connect, and getpeername as the
-- only real "connected" test.

print("=== PROBE 484d: loopback connect truth ===")
print("")

local function num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local sc_socket  = make_syscall(97)
local sc_connect = make_syscall(98)
local sc_getpeer = make_syscall(32)
local sc_getsock = make_syscall(118)
local sc_close   = make_syscall(6)

local sa   = memory.alloc(16)
local peer = memory.alloc(16)
local plen = memory.alloc(8)
local opt  = memory.alloc(8)
local optl = memory.alloc(8)

local function test(port)
    print(string.format("[port %d]", port))
    print(string.format("  sc_socket type=%s", type(syscall.sc_socket)))
    local ok, rv = pcall(function() return sc_socket(2, 1, 6) end)
    local fd = ok and num(rv) or -1
    print(string.format("  socket=%d", fd))
    if fd < 0 then return end

    for i = 0, 15 do memory.write_byte(sa + i, 0) end
    memory.write_byte(sa + 0, 16)
    memory.write_byte(sa + 1, 2)
    memory.write_byte(sa + 2, math.floor(port / 256))
    memory.write_byte(sa + 3, port % 256)
    memory.write_byte(sa + 4, 127)
    memory.write_byte(sa + 7, 1)

    local okc, rvc = pcall(function() return sc_connect(fd, sa, 16) end)
    print(string.format("  connect=%d (%s)", okc and num(rvc) or -999, okc and "ok" or "pcall-fail"))

    memory.write_dword(plen, 16)
    local okp, rvp = pcall(function() return sc_getpeer(fd, peer, plen) end)
    print(string.format("  getpeername=%d len=%d", okp and num(rvp) or -999, num(memory.read_dword(plen))))

    memory.write_dword(opt, 0xDEAD)
    memory.write_dword(optl, 4)
    local okg, rvg = pcall(function() return sc_getsock(fd, 0xFFFF, 0x1007, opt, optl) end)
    print(string.format("  SO_ERROR=%d value=0x%X", okg and num(rvg) or -999, num(memory.read_dword(opt))))

    pcall(function() sc_close(fd) end)
end

test(1)
print("")
test(80)
print("")
test(9026)
print("=== PROBE 484d END ===")
