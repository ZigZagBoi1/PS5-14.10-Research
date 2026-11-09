-- CRASH_CLASS: MODERATE
-- PROBE 367a: when does the compositor answer at all
--
-- 365a sent 8192 bytes of 0x41 and got sixteen bytes back. 366a sent sixteen
-- zero-and-word messages and got nothing at all. So the reply is tied to the size
-- of the write, not to what is in it. This probe sends one size per connection of
-- the same 0x41 fill and prints the reply, then fixes the size that answers and
-- varies the first word inside it.

print("=== PROBE 367a: COMPOSITOR REPLY THRESHOLD ===")
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
local msg = memory.alloc(0x8000)
local rbuf = memory.alloc(0x400)
for i = 0, 0x7FF8, 8 do pcall(function() memory.write_qword(msg + i, uint64(0x4141414141414141)) end) end

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

local function exchange(n, word)
    if word then pcall(function() memory.write_dword(msg, word) end) end
    local fd = connect_to()
    if fd < 3 then return "refused" end
    local sent = sgn(sc_sendto(uint64(fd), uint64(msg), uint64(n), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
    wait(0.2)
    local out = {}
    for round = 1, 4 do
        local r = sgn(sc_recvfrom(uint64(fd), uint64(rbuf), uint64(0x400), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
        if r <= 0 then out[#out + 1] = string.format("%d", r) break end
        local p = {}
        for i = 0, math.min(r, 32) - 1, 4 do
            p[#p + 1] = string.format("%08X", to_num(memory.read_dword(rbuf + i)))
        end
        out[#out + 1] = table.concat(p, " ")
    end
    pcall(function() sc_close(uint64(fd)) end)
    return string.format("send=%d [%s]", sent, table.concat(out, " | "))
end

print("[A] sizes, fill 0x41")
for _, n in ipairs({0x100, 0x200, 0x400, 0x800, 0x1000, 0x1800, 0x2000, 0x2001, 0x3000, 0x4000}) do
    print(string.format("  len=0x%-5X %s", n, exchange(n)))
    wait(0.4)
end

print("[B] 0x2000 with a chosen first word, rest 0x41")
for _, w in ipairs({0, 1, 2, 3, 0x41414141, 0xFFFFFFFF}) do
    pcall(function() memory.write_qword(msg, uint64(0x4141414141414141)) end)
    print(string.format("  word=0x%-9X %s", w, exchange(0x2000, w)))
    wait(0.4)
end

print("")
print("=== 367a DONE ===")
