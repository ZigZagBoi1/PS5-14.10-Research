-- CRASH_CLASS: MODERATE
-- PROBE 366a: does the compositor read a word out of what we send
--
-- 365a got a real reply: sixteen bytes, 00000001 000080FF 00000000 00000000, and
-- the daemon stayed up. Junk produced that. This probe varies only the first
-- dword of a sixteen-byte message and prints the reply for each value, so if the
-- first word is a command or a type selector the reply changes with it.

print("=== PROBE 366a: COMPOSITOR FIRST WORD ===")
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
local msg = memory.alloc(0x100)
local rbuf = memory.alloc(0x400)

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

local function exchange(word, n)
    local fd = connect_to()
    if fd < 3 then return "refused" end
    for i = 0, 0x3C do pcall(function() memory.write_dword(msg + i, 0) end) end
    pcall(function() memory.write_dword(msg, word) end)
    local sent = sgn(sc_sendto(uint64(fd), uint64(msg), uint64(n), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
    wait(0.15)
    local out = {}
    for round = 1, 4 do
        local r = sgn(sc_recvfrom(uint64(fd), uint64(rbuf), uint64(0x400), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
        if r <= 0 then out[#out + 1] = string.format("recv=%d", r) break end
        local p = {}
        for i = 0, math.min(r, 32) - 1, 4 do
            p[#p + 1] = string.format("%08X", to_num(memory.read_dword(rbuf + i)))
        end
        out[#out + 1] = table.concat(p, " ")
    end
    pcall(function() sc_close(uint64(fd)) end)
    return string.format("send=%d [%s]", sent, table.concat(out, " | "))
end

for _, w in ipairs({0, 1, 2, 3, 4, 5, 6, 7, 8, 0x10, 0x100, 0x1000, 0xFFFFFFFF}) do
    print(string.format("word=0x%-8X len=16  %s", w, exchange(w, 16)))
    wait(0.4)
end

for _, n in ipairs({4, 8, 12, 20, 24, 32}) do
    print(string.format("word=0x%-8X len=%-3d %s", 1, n, exchange(1, n)))
    wait(0.4)
end

print("")
print("=== 366a DONE ===")
