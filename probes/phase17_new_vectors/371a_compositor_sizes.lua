-- CRASH_CLASS: MODERATE
-- PROBE 371a: does a recognised command want more than its header
--
-- 370a varied every header word of commands 1-6 and no reply moved: with
-- {size=0x30, cmd} the daemon answers {00000001 00008100 00000000 80D40009} for
-- 2-5 and {00000001 00008100 00000010 80D40009} for 6. A command that carries a
-- buffer would need bytes after the header, and the size field is the only thing
-- that says how many there are. This probe keeps the command fixed and grows the
-- message, then fills the bytes after the header with one word.

print("=== PROBE 371a: COMPOSITOR MESSAGE SIZES ===")
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
local msg = memory.alloc(0x800)
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

local function send_msg(len, cmd, size_field, extra_word, extra_pos)
    local fd = connect_to()
    if fd < 3 then return "refused" end
    for i = 0, 0x7FC, 4 do pcall(function() memory.write_dword(msg + i, 0) end) end
    pcall(function() memory.write_dword(msg + 0, size_field) end)
    pcall(function() memory.write_dword(msg + 4, cmd) end)
    if extra_word then pcall(function() memory.write_dword(msg + (extra_pos or 12) * 4, extra_word) end) end
    local sent = sgn(sc_sendto(uint64(fd), uint64(msg), uint64(len), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
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

for cmd = 1, 6 do
    print(string.format("[cmd %d] same size, growing message", cmd))
    for _, len in ipairs({0x30, 0x38, 0x40, 0x80, 0x100}) do
        print(string.format("   len=0x%-4X size=0x%-4X %s", len, len, send_msg(len, cmd, len)))
        wait(0.12)
    end
    -- size field that lies: header says 0x30, message is 0x40
    print(string.format("   len=0x40 size=0x30 %s", send_msg(0x40, cmd, 0x30)))
    wait(0.12)
end

print("")
print("=== 371a DONE ===")
