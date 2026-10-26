-- CRASH_CLASS: LOW
-- PROBE 484e: loopback listener scan, connect() return as the only test
--
-- 484d proved the discriminator: connect() returns 0 for the open loader port
-- (9026) and -1 for closed ones (1, 80). getpeername and SO_ERROR both read 0
-- regardless, so neither can be used. This scan trusts only connect().

print("=== PROBE 484e: loopback listeners by connect() ===")
print("")

local function num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local sc_socket  = make_syscall(97)
local sc_connect = make_syscall(98)
local sc_close   = make_syscall(6)

local sa = memory.alloc(16)
local open_ports = {}
local tested = 0
local failures = 0

local function probe_port(port)
    local ok, rv = pcall(function() return sc_socket(2, 1, 6) end)
    if not ok then failures = failures + 1; return end
    local fd = num(rv)
    if fd < 0 then failures = failures + 1; return end

    for i = 0, 15 do memory.write_byte(sa + i, 0) end
    memory.write_byte(sa + 0, 16)
    memory.write_byte(sa + 1, 2)
    memory.write_byte(sa + 2, math.floor(port / 256))
    memory.write_byte(sa + 3, port % 256)
    memory.write_byte(sa + 4, 127)
    memory.write_byte(sa + 7, 1)

    local okc, rvc = pcall(function() return sc_connect(fd, sa, 16) end)
    local cr = okc and num(rvc) or -999
    pcall(function() sc_close(fd) end)

    tested = tested + 1
    if cr == 0 then
        open_ports[#open_ports + 1] = port
        print(string.format("OPEN port=%d", port))
    end
end

for port = 1, 65535 do
    probe_port(port)
    if port % 0x2000 == 0 then
        print(string.format("[progress] port=%d tested=%d open=%d fail=%d",
            port, tested, #open_ports, failures))
    end
end

print("")
print(string.format("[DONE] tested=%d open=%d socket_failures=%d",
    tested, #open_ports, failures))
if #open_ports > 0 then
    local s = ""
    for i = 1, #open_ports do s = s .. open_ports[i] .. " " end
    print("[open] " .. s)
end
print("=== PROBE 484e END ===")
