-- CRASH_CLASS: MODERATE
-- PROBE 373a: read the whole reply, not the first kilobyte
--
-- The reply to command 0 is 00000001 00008000 00001340 80D40009 then zeros, and
-- 0x1340 is 4928 - larger than the 1024 bytes every read so far has taken, because
-- the read buffer was 0x400. If the third word is a length, most of the reply was
-- left in the socket. 372a also showed the daemon closes the connection after one
-- message, so there is exactly one reply to read and the size of it is knowable.

print("=== PROBE 373a: COMPOSITOR FULL REPLY ===")
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

local function run(cmd, n, label)
    local fd = connect_to()
    if fd < 3 then print(string.format("%s: connect refused", label)) return end
    for i = 0, 0x3FC, 4 do pcall(function() memory.write_dword(msg + i, 0) end) end
    pcall(function() memory.write_dword(msg + 0, n) end)
    pcall(function() memory.write_dword(msg + 4, cmd) end)
    local sent = sgn(sc_sendto(uint64(fd), uint64(msg), uint64(n), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
    wait(0.25)
    local total = 0
    local nonzero = {}
    local first = {}
    for round = 1, 16 do
        local r = sgn(sc_recvfrom(uint64(fd), uint64(rbuf), uint64(0x4000), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
        if r <= 0 then
            print(string.format("%s: cmd=%d send=%d total=%d tail=%d", label, cmd, sent, total, r))
            break
        end
        for i = 0, r - 1, 4 do
            local v = to_num(memory.read_dword(rbuf + i))
            if #first < 10 then first[#first + 1] = string.format("%08X", v) end
            if v ~= 0 and #nonzero < 16 then
                nonzero[#nonzero + 1] = string.format("+0x%X=%08X", total + i, v)
            end
        end
        total = total + r
    end
    print(string.format("  first: %s", table.concat(first, " ")))
    print(string.format("  nonzero: %s", (#nonzero > 0) and table.concat(nonzero, " ") or "none"))
    pcall(function() sc_close(uint64(fd)) end)
    wait(0.2)
end

run(0, 0x30, "[A]")
run(6, 0x30, "[B]")
run(1, 0x30, "[C]")
run(2, 0x30, "[D]")

print("")
print("=== 373a DONE ===")
