-- CRASH_CLASS: LOW
-- PROBE 362a: what GnmCompositorRestricted sends back
--
-- 361b closed the connection after exactly 8192 bytes and left 16 bytes readable.
-- That is the first byte the three system sockets have ever handed us, so this
-- probe reads it: connect, optionally send a known count of 0x41, then read up to
-- 0x100 bytes and print them as hex. It also runs the no-send case, because a
-- greeting that arrives on connect is a different protocol from a reply.

print("=== PROBE 362a: THE COMPOSITOR REPLY ===")
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

local sockaddr = memory.alloc(0x80)
local chunk = memory.alloc(0x4000)
local rbuf = memory.alloc(0x400)
for i = 0, 0x3FF8, 8 do pcall(function() memory.write_qword(chunk + i, uint64(0x4141414141414141)) end) end

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

local function drain(fd, tag)
    local parts = {}
    for round = 1, 8 do
        local n = sgn(sc_recvfrom(uint64(fd), uint64(rbuf), uint64(0x400), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
        if n <= 0 then break end
        local s = {}
        for i = 0, math.min(n, 64) - 1, 4 do
            s[#s + 1] = string.format("%08X", to_num(memory.read_dword(rbuf + i)))
        end
        parts[#parts + 1] = string.format("n=%d %s", n, table.concat(s, " "))
    end
    if #parts == 0 then print("  " .. tag .. ": nothing") else
        for _, p in ipairs(parts) do print("  " .. tag .. ": " .. p) end end
end

local PATH = "/system_tmp/GnmCompositorRestricted"

-- [A] connect and read without sending anything
print("[A] connect, no send")
do
    local fd = connect_to(PATH)
    if fd >= 3 then drain(fd, "on connect") pcall(function() sc_close(uint64(fd)) end) end
end

-- [B] send a known count, then read
print("[B] send N bytes of 0x41, then read")
for _, n in ipairs({0, 1, 2, 4, 8, 12, 16, 20, 32, 64, 128, 0x100, 0x1000, 0x2000}) do
    local fd = connect_to(PATH)
    if fd < 3 then
        print(string.format("  n=%-5d connect refused", n))
    else
        local sent = 0
        if n > 0 then
            local r = sgn(sc_sendto(uint64(fd), uint64(chunk), uint64(n), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
            sent = r
        end
        print(string.format("  n=%-5d send=%d", n, sent))
        drain(fd, "reply")
        pcall(function() sc_close(uint64(fd)) end)
    end
end

print("")
print("=== 362a DONE ===")
