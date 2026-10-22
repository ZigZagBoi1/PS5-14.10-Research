-- CRASH_CLASS: MODERATE
-- PROBE 370a: the compositor's header is {size, command}
--
-- 369a sent {0x30, cmd} and the answer tracked cmd:
--   cmd 0     -> 1024 bytes, 00000001 00008000 00001340 80D40009
--   cmd 1     -> 16 bytes,   00000001 00008100 00000000 00000000
--   cmd 2-5   -> 16 bytes,   00000001 00008100 00000000 80D40009
--   cmd 6     -> 32 bytes,   00000001 00008100 00000010 80D40009
--   cmd 7+    -> 16 bytes,   00000001 000080FF  (unknown command)
-- so the first dword is the message size and the second is a command id, and six
-- commands are recognised. This probe holds {size=0x30, cmd} and varies one later
-- word at a time to see which of them a command actually reads.

print("=== PROBE 370a: COMPOSITOR COMMAND ARGUMENTS ===")
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
local rbuf = memory.alloc(0x500)

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

local function send_words(n, words)
    local fd = connect_to()
    if fd < 3 then return "refused" end
    for i = 0, 0x3FC, 4 do pcall(function() memory.write_dword(msg + i, 0) end) end
    for i = 1, #words do pcall(function() memory.write_dword(msg + (i - 1) * 4, words[i]) end) end
    local sent = sgn(sc_sendto(uint64(fd), uint64(msg), uint64(n), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
    wait(0.12)
    local r = sgn(sc_recvfrom(uint64(fd), uint64(rbuf), uint64(0x400), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
    local out = string.format("send=%d recv=%d", sent, r)
    if r > 0 then
        local p = {}
        for i = 0, math.min(r, 40) - 1, 4 do
            p[#p + 1] = string.format("%08X", to_num(memory.read_dword(rbuf + i)))
        end
        out = out .. "  " .. table.concat(p, " ")
    end
    pcall(function() sc_close(uint64(fd)) end)
    return out
end

local function sig(s)
    -- the reply without the leading send/recv words, for comparison
    return s:gsub("^send=%d+ ", "")
end

for cmd = 1, 6 do
    local n = 0x30
    local base = send_words(n, {n, cmd})
    print(string.format("[cmd %d] baseline %s", cmd, base))
    wait(0.15)
    for pos = 2, 11 do
        local w = {n, cmd}
        w[pos + 1] = 1
        local r = send_words(n, w)
        if sig(r) ~= sig(base) then
            print(string.format("   pos=%d value=1 -> %s", pos, r))
            n = 0x30
        end
        wait(0.12)
    end
end

print("")
print("=== 370a DONE ===")
