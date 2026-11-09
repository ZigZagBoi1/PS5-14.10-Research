-- CRASH_CLASS: LOW
-- PROBE 434a: census the compositor command space
--
-- 373a recovered the framing: a request of 0x30 bytes carries a size at +0 and a command
-- at +4, the daemon answers once and closes, and the reply is {u32 type=1; u32 flags;
-- u32 length; u32 status; payload}. Commands 0-6 are recognised and 0x18 beyond that
-- answered 0x80FF (unimplemented).
--
-- Nothing here malforms a message: every request is a well-formed 0x30-byte header. The
-- point is to find out how many commands exist and which ones return a payload, because a
-- command that returns data is a parser that takes our input, and that is the only path
-- into a process that is not ours.
--
-- A command that kills the daemon shows up as a refused connect on the next one, so the
-- census stops there and names it.

print("=== PROBE 434a: COMPOSITOR CENSUS ===")

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
local sc_socket = make_syscall(97)
local sc_connect = make_syscall(98)
local sc_sendto = make_syscall(133)
local sc_recvfrom = make_syscall(29)
local sc_close = make_syscall(6)

local sa = memory.alloc(0x100)
for i = 0, 0xFC, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa + 0, uint64(1)) end)
pcall(function() make_syscall(416)(uint64(13), uint64(sa), uint64(0)) end)

local PATH = "/system_tmp/GnmCompositorRestricted"
local sockaddr = memory.alloc(0x80)
local msg = memory.alloc(0x400)
local rbuf = memory.alloc(0x4000)

local function connect_to()
    local fd = sgn(sc_socket(uint64(AF_UNIX), uint64(SOCK_STREAM), uint64(0)))
    if fd < 3 then return -1 end
    for i = 0, 0x10, 8 do pcall(function() memory.write_qword(sockaddr + i, uint64(0)) end) end
    pcall(function() memory.write_byte(sockaddr, #PATH + 2) end)
    pcall(function() memory.write_byte(sockaddr + 1, AF_UNIX) end)
    for i = 1, #PATH do pcall(function() memory.write_byte(sockaddr + 1 + i, PATH:byte(i)) end) end
    local r = sgn(sc_connect(uint64(fd), uint64(sockaddr), uint64(#PATH + 2)))
    if r ~= 0 then pcall(function() sc_close(uint64(fd)) end) return -1 end
    return fd
end

local function wait(t)
    local t0 = os.clock()
    while os.clock() - t0 < t do end
end

local function run(cmd)
    local fd = connect_to()
    if fd < 3 then return "connect refused" end
    for i = 0, 0x3FC, 4 do pcall(function() memory.write_dword(msg + i, 0) end) end
    pcall(function() memory.write_dword(msg + 0, 0x30) end)
    pcall(function() memory.write_dword(msg + 4, cmd) end)
    local sent = sgn(sc_sendto(uint64(fd), uint64(msg), uint64(0x30), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
    wait(0.05)
    local total = 0
    local w = {}
    for round = 1, 8 do
        local r = sgn(sc_recvfrom(uint64(fd), uint64(rbuf), uint64(0x4000), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
        if r <= 0 then break end
        if #w == 0 then
            local i = 0
            while i < r and i < 0x20 do
                w[#w + 1] = string.format("%08X", to_num(memory.read_dword(rbuf + i)))
                i = i + 4
            end
        end
        total = total + r
    end
    pcall(function() sc_close(uint64(fd)) end)
    wait(0.05)
    return string.format("send=%d bytes=%d %s", sent, total, table.concat(w, " "))
end

local counts = {}
local cmd = 0
while cmd <= 0xFF do
    local r = run(cmd)
    if r == "connect refused" then
        print(string.format("[X] cmd=0x%02X refused - the daemon is down; census stops", cmd))
        break
    end
    local key = r:match("bytes=(%d+)") or "?"
    counts[key] = (counts[key] or 0) + 1
    if not r:find("bytes=16 ") then
        print(string.format("[A] cmd=0x%02X %s", cmd, r))
    end
    cmd = cmd + 1
end
print("")
for k, v in pairs(counts) do print(string.format("[B] reply size %s: %d commands", k, v)) end
print("=== 434a DONE ===")
