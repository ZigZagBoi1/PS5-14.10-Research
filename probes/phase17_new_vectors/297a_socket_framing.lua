-- CRASH_CLASS: MODERATE
-- PROBE 297a: what the three reachable system sockets do with a first message
--
-- Context: 296a showed the game process can connect to GnmCompositorRestricted,
-- VrTracker2DomainSock and AgcCompositorSppSocket, and that none of them sends
-- anything first. Those three are system services outside the jail that we have
-- never probed.
--
-- This probe sends progressively larger runs of zero bytes and records whether
-- the service answers, holds the connection or closes it. A close after a short
-- message means the service validates framing; a hold means it is reading a
-- header we have not matched; no reaction at all means the connection is
-- accepted but ignored.
--
-- Between every step, a fresh connect is attempted on the same socket. If that
-- ever fails after a send, the service stopped accepting and the step is the
-- interesting one.
--
-- Nothing here is a crafted structure: only zero bytes of four lengths.

print("=== PROBE 297a: socket framing ===")
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
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    if h % 0x100000000 == 0xFFFFFFFF and l % 0x100000000 == 0xFFFFFFFF then return -1 end
    if h == 0 and l >= 0x80000000 then return l - 0x100000000 end
    return l
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end

local sc_socket = make_syscall(97)
local sc_connect = make_syscall(98)
local sc_close = make_syscall(6)
local sc_recvfrom = make_syscall(29)
local sc_sendto = make_syscall(133)

local AF_UNIX = 1
local SOCK_STREAM = 1
local MSG_DONTWAIT = 0x80

local sockaddr = memory.alloc(0x80)
local rbuf = memory.alloc(0x200)
local wbuf = memory.alloc(0x200)

local function connect_to(path)
    local fd = sgn(sc_socket(uint64(AF_UNIX), uint64(SOCK_STREAM), uint64(0)))
    if fd < 0 then return -1 end
    for i = 0, 0x7F do pcall(function() memory.write_byte(sockaddr + i, 0) end) end
    pcall(function() memory.write_byte(sockaddr + 0, #path + 2) end)
    pcall(function() memory.write_byte(sockaddr + 1, AF_UNIX) end)
    for i = 1, #path do pcall(function() memory.write_byte(sockaddr + 1 + i, path:byte(i)) end) end
    local r = sgn(sc_connect(uint64(fd), uint64(sockaddr), uint64(#path + 2)))
    if r ~= 0 then sc_close(uint64(fd)); return r end
    return fd
end

local function drain(fd, n)
    local out = {}
    for i = 1, n do
        local r = sgn(sc_recvfrom(uint64(fd), uint64(rbuf), uint64(0x200), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
        out[#out + 1] = r
        if r == 0 or r < 0 then break end
        for k = 0, 0x1FC, 4 do
            pcall(function() if to_num(memory.read_dword(rbuf + k)) ~= 0 then return end end)
        end
    end
    return table.concat(out, ",")
end

local names = { "GnmCompositorRestricted", "VrTracker2DomainSock", "AgcCompositorSppSocket" }

for _, name in ipairs(names) do
    local path = "/system_tmp/" .. name
    print("[" .. name .. "]")
    for _, len in ipairs({ 0, 1, 4, 8, 0x40 }) do
        for i = 0, 0x1FC, 4 do pcall(function() memory.write_dword(wbuf + i, 0) end) end
        local fd = connect_to(path)
        if fd < 0 then
            print(string.format("  len=%3d  CONNECT FAILED (%d)", len, fd))
        else
            local s = 0
            if len > 0 then
                s = sgn(sc_sendto(uint64(fd), uint64(wbuf), uint64(len), uint64(0), uint64(0), uint64(0)))
            end
            local rs = drain(fd, 3)
            sc_close(uint64(fd))
            local again = connect_to(path)
            local alive = again >= 0
            if alive then sc_close(uint64(again)) end
            print(string.format("  len=%3d  send=%d recv=[%s] reconnect=%s", len, s, rs, alive and "ok" or "FAILED"))
        end
    end
end

print("")
print("=== PROBE 297a COMPLETE ===")
