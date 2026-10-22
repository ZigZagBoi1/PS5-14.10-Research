-- CRASH_CLASS: LOW
-- PROBE 361b: the same measurement with SIGPIPE ignored
--
-- 361a died at its first sendto: the daemon had already closed the connection and
-- the write raised SIGPIPE, whose default action is to terminate. That is itself
-- the answer to half the question - the service closes immediately - but it cost
-- the process, so this revision installs sigaction(13, SIG_IGN) first and reports
-- the send return instead of dying on it.
--
-- A send that returns -1 on the first chunk means the peer closed. A run that
-- accumulates until EAGAIN means the peer is reading but never replies.

print("=== PROBE 361b: SOCKET CONSUMPTION (SIGPIPE IGNORED) ===")
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

local AF_UNIX, SOCK_STREAM, MSG_DONTWAIT = 1, 1, 0x80
local SIGPIPE, SIG_IGN = 13, 1

local sc_sigaction = make_syscall(416)
local sc_socket = make_syscall(97)
local sc_connect = make_syscall(98)
local sc_sendto = make_syscall(133)
local sc_recvfrom = make_syscall(29)
local sc_close = make_syscall(6)

-- 353a installs SIG_IGN as a struct whose handler field is 1 at +0; passing the
-- integer 1 as the pointer is an EFAULT, which is what the first revision of this
-- probe did (-1) and why it died at the first send all over again.
local sa = memory.alloc(0x100)
local oldsa = memory.alloc(0x100)
for i = 0, 0xFC, 8 do
    pcall(function() memory.write_qword(sa + i, uint64(0)) end)
    pcall(function() memory.write_qword(oldsa + i, uint64(0)) end)
end
pcall(function() memory.write_qword(sa + 0, uint64(SIG_IGN)) end)
print(string.format("sigaction(SIGPIPE, &{SIG_IGN}) = %d",
    sgn(sc_sigaction(uint64(SIGPIPE), uint64(sa), uint64(oldsa)))))
print(string.format("  readback handler word = 0x%X", to_num(memory.read_qword(oldsa + 0))))

-- second route in case the disposition is refused: block the signal instead
local sigset = memory.alloc(0x20)
for i = 0, 0x18, 8 do pcall(function() memory.write_qword(sigset + i, uint64(0)) end) end
pcall(function() memory.write_dword(sigset, 0x1000) end)   -- SIGPIPE is 13 -> bit 12
print(string.format("sigprocmask(SIG_BLOCK, {SIGPIPE}) = %d",
    sgn(make_syscall(340)(uint64(1), uint64(sigset), uint64(0)))))

local CHUNK = 0x4000
local CAP = 4 * 1024 * 1024

local sockaddr = memory.alloc(0x80)
local chunk = memory.alloc(CHUNK)
local rbuf = memory.alloc(0x200)
for i = 0, CHUNK - 1, 8 do pcall(function() memory.write_qword(chunk + i, uint64(0x4141414141414141)) end) end

local function connect_to(path)
    local fd = sgn(sc_socket(uint64(AF_UNIX), uint64(SOCK_STREAM), uint64(0)))
    if fd < 3 then return -1 end
    for i = 0, 0x10, 8 do pcall(function() memory.write_qword(sockaddr + i, uint64(0)) end) end
    pcall(function() memory.write_byte(sockaddr, #path + 2) end)
    pcall(function() memory.write_byte(sockaddr + 1, AF_UNIX) end)
    for i = 1, #path do pcall(function() memory.write_byte(sockaddr + 1 + i, path:byte(i)) end) end
    local r = sgn(sc_connect(uint64(fd), uint64(sockaddr), uint64(#path + 2)))
    if r ~= 0 then pcall(function() sc_close(uint64(fd)) end) return -r end
    return fd
end

local function step(path)
    print("[" .. path .. "]")
    local fd = connect_to(path)
    if fd < 3 then print(string.format("  connect refused (%d)", fd)) return end
    print(string.format("  connect = 0 (fd %d)", fd))
    local sends, total, first, last = 0, 0, nil, nil
    while total < CAP do
        local r = sgn(sc_sendto(uint64(fd), uint64(chunk), uint64(CHUNK), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
        sends = sends + 1
        if sends == 1 then first = r end
        if r <= 0 then last = r break end
        total = total + r
    end
    print(string.format("  %d sends, %d bytes, first=%d last=%d", sends, total, first or 0, last or 0))
    local r = sgn(sc_recvfrom(uint64(fd), uint64(rbuf), uint64(0x200), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
    print(string.format("  recv after sends = %d", r))
    pcall(function() sc_close(uint64(fd)) end)
    local again = connect_to(path)
    if again < 3 then
        print(string.format("  reconnect refused (%d)", again))
    else
        print("  reconnect = 0")
        pcall(function() sc_close(uint64(again)) end)
    end
end

step("/system_tmp/GnmCompositorRestricted")
step("/system_tmp/VrTracker2DomainSock")
step("/system_tmp/AgcCompositorSppSocket")

print("")
print("=== 361b DONE ===")
