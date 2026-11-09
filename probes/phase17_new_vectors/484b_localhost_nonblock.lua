-- CRASH_CLASS: LOW
-- PROBE 484b: loopback listener scan with non-blocking connects
--
-- Context: 484a blocked on a connect() to a filtered loopback port and was
-- killed by the 30 s idle timeout after 44 bytes. This version never blocks:
-- the socket is put in O_NONBLOCK, connect() is expected to return -1, and a
-- 50 ms select() decides whether the socket became writable. SO_ERROR == 0
-- after a writable select means something is listening on 127.0.0.1:port.
--
-- A short sanity pass runs first (ports 1,7,22,80,443,9026,9999) so a blocked
-- syscall shows up immediately instead of after a sleep.

print("=== PROBE 484b: loopback scan, non-blocking ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a) local v = 0; pcall(function() v = to_num(memory.read_dword(a)) end); return v end

local sc_socket  = make_syscall(97)
local sc_connect = make_syscall(98)
local sc_close   = make_syscall(6)
local sc_fcntl   = make_syscall(92)
local sc_select  = make_syscall(93)
local sc_getsock = make_syscall(118)

local sa   = memory.alloc(0x20)
local wfds = memory.alloc(0x100)
local tv   = memory.alloc(0x20)
local opt  = memory.alloc(0x20)
local optl = memory.alloc(0x20)

local function zero(a, n) for o = 0, n - 1, 4 do wd(a + o, 0) end end

-- returns 1 open, 0 closed, -1 unknown/blocked
local function probe_port(port)
    local fd = sgn(sc_socket(uint64(2), uint64(1), uint64(0)))
    if fd < 0 then return -1 end
    sc_fcntl(uint64(fd), uint64(4), uint64(4))          -- F_SETFL, O_NONBLOCK
    zero(sa, 16)
    pcall(function() memory.write_byte(sa, 16) end)
    pcall(function() memory.write_byte(sa + 1, 2) end)
    local hi = (port - port % 256) / 256
    pcall(function() memory.write_byte(sa + 2, hi) end)
    pcall(function() memory.write_byte(sa + 3, port % 256) end)
    pcall(function() memory.write_byte(sa + 4, 127) end)
    pcall(function() memory.write_byte(sa + 7, 1) end)
    sc_connect(uint64(fd), uint64(sa), uint64(16))       -- expect -1/EINPROGRESS
    zero(wfds, 0x80)
    local byteoff = math.floor(fd / 8)
    pcall(function() memory.write_byte(wfds + byteoff, 2 ^ (fd % 8)) end)
    wq(tv, 0); wq(tv + 8, 50000)                          -- 50 ms
    local r = sgn(sc_select(uint64(fd + 1), uint64(0), uint64(wfds), uint64(0), uint64(tv)))
    local result = -1
    if r > 0 then
        zero(opt, 4); wd(optl, 4)
        sc_getsock(uint64(fd), uint64(0xFFFF), uint64(0x1007), uint64(opt), uint64(optl))
        if rd(opt) == 0 then result = 1 else result = 0 end
    elseif r == 0 then
        result = -1
    else
        result = 0
    end
    sc_close(uint64(fd))
    return result
end

local test = {1, 7, 22, 80, 443, 9026, 9999}
print("[sanity]")
for _, p in ipairs(test) do
    print(string.format("  port %5d -> %d", p, probe_port(p)))
end
print("")

local open = {}
for port = 1, 65535 do
    local r = probe_port(port)
    if r == 1 then
        open[#open + 1] = port
        print(string.format("  OPEN %d", port))
    end
    if port % 0x2000 == 0 then print(string.format("  .. %d", port)) end
end
print(string.format("DONE open=%d", #open))
print("=== PROBE 484b END ===")
