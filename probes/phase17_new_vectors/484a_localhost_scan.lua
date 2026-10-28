-- CRASH_CLASS: LOW
-- PROBE 484a: which TCP ports answer on loopback
--
-- Context: a game process can call socket()/connect(). The PS5 runs system
-- daemons the game cannot signal or inspect; a listener on 127.0.0.1 would be
-- reachable if the sandbox allows it, and whatever parses the connection runs
-- outside the game's sandbox. This has never been scanned: earlier probes use
-- loopback only as a packet playground, never to enumerate listeners.
--
-- Connect failures are immediate on loopback (RST), so 65535 attempts are
-- cheap. Every successful connect is printed with whatever banner arrives
-- under MSG_DONTWAIT; the socket is closed either way.

print("=== PROBE 484a: loopback listener scan ===")
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
    local n = to_num(v)
    if n >= 0x8000000000000000 then return n - 0x10000000000000000 end
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end

local sc_socket   = make_syscall(97)
local sc_connect  = make_syscall(98)
local sc_close    = make_syscall(6)
local sc_recvfrom = make_syscall(29)

local sa = memory.alloc(16)
local function fill_sa(port)
    for i = 0, 15 do pcall(function() memory.write_byte(sa + i, 0) end) end
    pcall(function() memory.write_byte(sa + 0, 16) end)      -- sin_len
    pcall(function() memory.write_byte(sa + 1, 2) end)       -- AF_INET
    pcall(function() memory.write_byte(sa + 2, math.floor(port / 256)) end)
    pcall(function() memory.write_byte(sa + 3, port % 256) end)
    pcall(function() memory.write_byte(sa + 4, 127) end)
    pcall(function() memory.write_byte(sa + 5, 0) end)
    pcall(function() memory.write_byte(sa + 6, 0) end)
    pcall(function() memory.write_byte(sa + 7, 1) end)
end

local rbuf = memory.alloc(128)
local open_ports = {}

for port = 1, 65535 do
    fill_sa(port)
    local fd = sgn(sc_socket(uint64(2), uint64(1), uint64(0)))
    if fd >= 0 then
        local rc = sgn(sc_connect(uint64(fd), uint64(sa), uint64(16)))
        if rc == 0 then
            open_ports[#open_ports + 1] = port
            local n = sgn(sc_recvfrom(uint64(fd), uint64(rbuf), uint64(64),
                      uint64(0x80), uint64(0), uint64(0)))   -- MSG_DONTWAIT
            local banner = ""
            if n > 0 then
                for i = 0, math.min(n, 32) - 1 do
                    local ok, b = pcall(function() return memory.read_byte(rbuf + i) end)
                    local ch = ok and to_num(b) or 0
                    if ch >= 32 and ch < 127 then
                        banner = banner .. string.char(ch)
                    else
                        banner = banner .. string.format("\\x%02X", ch)
                    end
                end
            end
            print(string.format("  OPEN port=%d banner=%q", port, banner))
        end
        sgn(sc_close(uint64(fd)))
    end
    if port % 0x2000 == 0 then
        print(string.format("  .. %d ports, open=%d", port, #open_ports))
    end
end

print("")
print(string.format("open count=%d", #open_ports))
local list = ""
for i, p in ipairs(open_ports) do
    if i > 1 then list = list .. "," end
    list = list .. tostring(p)
end
print("open ports: " .. list)
print("=== PROBE 484a END ===")
