-- CRASH_CLASS: MODERATE
-- PROBE 368a: the smallest message that gets an answer, and whether any word changes it
--
-- 367a got the same sixteen bytes back for every size from 0x100 to 0x4000 and for
-- every first word, and 366a got nothing at all for messages of 4 to 32 bytes. So
-- there is a size threshold between 32 and 256, and the reply is a fixed status.
-- This probe finds the threshold, then sends one message per value of the first
-- word across the low range to see whether any of them is a request the daemon
-- recognises, which would show up as a different reply.

print("=== PROBE 368a: COMPOSITOR THRESHOLD AND OPCODES ===")
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
local msg = memory.alloc(0x4000)
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

local function exchange(n, word)
    local fd = connect_to()
    if fd < 3 then return "refused" end
    for i = 0, 0x3FFC, 4 do pcall(function() memory.write_dword(msg + i, 0) end) end
    if word then pcall(function() memory.write_dword(msg, word) end) end
    local sent = sgn(sc_sendto(uint64(fd), uint64(msg), uint64(n), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
    wait(0.12)
    local r = sgn(sc_recvfrom(uint64(fd), uint64(rbuf), uint64(0x400), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
    local out = string.format("send=%d recv=%d", sent, r)
    if r > 0 then
        local p = {}
        for i = 0, math.min(r, 32) - 1, 4 do
            p[#p + 1] = string.format("%08X", to_num(memory.read_dword(rbuf + i)))
        end
        out = out .. " " .. table.concat(p, " ")
    end
    pcall(function() sc_close(uint64(fd)) end)
    return out
end

print("[A] threshold, all-zero message")
for _, n in ipairs({0x20, 0x30, 0x40, 0x60, 0x80, 0xC0, 0x100}) do
    print(string.format("  len=0x%-4X %s", n, exchange(n, 0)))
    wait(0.25)
end

print("[B] first word 0..0x3F at len 0x100")
local base = nil
for w = 0, 0x3F do
    local r = exchange(0x100, w)
    if w == 0 then base = r end
    if r ~= base then print(string.format("  word=0x%-4X %s", w, r)) end
    wait(0.12)
end
print("  (only words whose reply differs from word 0 are printed)")

print("")
print("=== 368a DONE ===")
