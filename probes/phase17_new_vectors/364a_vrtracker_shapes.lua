-- CRASH_CLASS: MODERATE
-- PROBE 364a: give VrTracker2DomainSock something with a header on it
--
-- 363a showed the daemon stops accepting for a while after a client closes, and
-- 362b showed it accepting again a minute later, so a refused connect is a
-- transient state, not a dead process. Every byte sent so far has been 0x41 with
-- no structure. This probe sends one shape per connection, waits between them so
-- the daemon recovers, and prints whatever comes back.

print("=== PROBE 364a: VRTRACKER MESSAGE SHAPES ===")
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

local PATH = "/system_tmp/VrTracker2DomainSock"
local sockaddr = memory.alloc(0x80)
local msg = memory.alloc(0x1000)
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

local function wait(seconds)
    local t0 = os.clock()
    while os.clock() - t0 < seconds do end
end

local function build(words, fill)
    for i = 0, 0x100, 4 do pcall(function() memory.write_dword(msg + i, 0) end) end
    for i = 1, #words do
        pcall(function() memory.write_dword(msg + (i - 1) * 4, words[i]) end)
    end
    return #words * 4 + (fill or 0)
end

local shapes = {
    {name = "u32 0",                 words = {0},                              fill = 0},
    {name = "u32 16 + 16 zeros",     words = {16},                             fill = 16},
    {name = "u32 32 + 32 zeros",     words = {32},                             fill = 32},
    {name = "u32 16 + 16 x 41",      words = {16},                             fill = 0x41},
    {name = "size16 type1",          words = {16, 1},                          fill = 8},
    {name = "type1 size16",          words = {1, 16},                          fill = 8},
    {name = "qword 16",              words = {16, 0},                          fill = 16},
    {name = "size16 op1 qpad",       words = {16, 1, 0, 0},                    fill = 4},
    {name = "16 zeros",              words = {},                               fill = 16},
}

for _, s in ipairs(shapes) do
    local len = build(s.words, s.fill)
    if s.fill == 0x41 then
        for i = #s.words * 4, len - 1 do pcall(function() memory.write_byte(msg + i, 0x41) end) end
    end
    local fd = connect_to()
    if fd < 3 then
        print(string.format("%-22s connect refused", s.name))
    else
        local sent = sgn(sc_sendto(uint64(fd), uint64(msg), uint64(len), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
        wait(0.4)
        local n = sgn(sc_recvfrom(uint64(fd), uint64(rbuf), uint64(0x400), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
        local hex = ""
        if n > 0 then
            local parts = {}
            for i = 0, math.min(n, 32) - 1, 4 do
                parts[#parts + 1] = string.format("%08X", to_num(memory.read_dword(rbuf + i)))
            end
            hex = " " .. table.concat(parts, " ")
        end
        local fd2 = connect_to()
        local alive = "gone"
        if fd2 >= 3 then alive = "listening" pcall(function() sc_close(uint64(fd2)) end) end
        print(string.format("%-22s len=%-3d send=%-4d recv=%-4d%s  after: %s", s.name, len, sent, n, hex, alive))
        pcall(function() sc_close(uint64(fd)) end)
    end
    wait(1.5)
end

print("")
print("=== 364a DONE ===")
