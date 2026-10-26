-- CRASH_CLASS: LOW
-- PROBE 456a: what is listening on the loopback interface?
--
-- Everything the game process can reach through the syscall table has been
-- measured: no memory-safety bug, no leak, no writable kernel path. The one
-- surface never enumerated is the console's own loopback: services bound to
-- 127.0.0.1 that only trust local peers. A refused connect is immediate on
-- loopback, so a full 1-65535 sweep costs three syscalls per port and no
-- waiting.

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function split(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    local n = tonumber(v) or 0
    if n < 0 then n = n + 4294967296 end
    return math.floor(n / 4294967296), n % 4294967296
end
local function isneg(h, l) return h == 0xFFFFFFFF and l == 0xFFFFFFFF end
local function s32(h, l) if isneg(h, l) then return -1 end return l end

local sc_socket, sc_connect, sc_close = make_syscall(97), make_syscall(98), make_syscall(6)

print("=== PROBE 456a: LOOPBACK LISTENER SWEEP ===")
print("")

local sa = memory.alloc(16)
local function fill_port(p)
    memory.write_byte(sa + 0, 16)
    memory.write_byte(sa + 1, 2)                 -- AF_INET
    memory.write_byte(sa + 2, math.floor(p / 256) % 256)   -- sin_port, big endian
    memory.write_byte(sa + 3, p % 256)
    memory.write_byte(sa + 4, 127)
    memory.write_byte(sa + 5, 0)
    memory.write_byte(sa + 6, 0)
    memory.write_byte(sa + 7, 1)
    local i = 8
    while i < 16 do memory.write_byte(sa + i, 0); i = i + 1 end
end

local open = {}
local errors = {}
local fd_ok = 0
local stopped = nil

local t0 = os.time()
for p = 1, 65535 do
    local okf, fdv = pcall(function() return sc_socket(uint64(2), uint64(1), uint64(0)) end)
    local fh, fl = 0, 0
    if okf then fh, fl = split(fdv) end
    local fd = s32(fh, fl)
    if fd < 0 then
        fd_ok = fd_ok + 1
        if fd_ok > 64 then stopped = p break end
    else
        fill_port(p)
        local okc, rv = pcall(function() return sc_connect(uint64(fd), uint64(sa), uint64(16)) end)
        local rh, rl = 0, 0
        if okc then rh, rl = split(rv) end
        local r = s32(rh, rl)
        if r == 0 then
            open[#open + 1] = p
        elseif r ~= -1 then
            errors[#errors + 1] = string.format("%d:%d", p, r)
        end
        pcall(function() return sc_close(uint64(fd)) end)
    end
end
local dt = os.time() - t0

print(string.format("sweep 1-65535 done in %ds, socket() failures=%d stopped=%s",
    dt, fd_ok, tostring(stopped or "no")))
print(string.format("open ports: %d", #open))
local i = 1
while i <= #open do
    local chunk = {}
    local j = i
    while j <= #open and j < i + 16 do chunk[#chunk + 1] = tostring(open[j]); j = j + 1 end
    print("  " .. table.concat(chunk, " "))
    i = j
end
if #errors > 0 then
    print(string.format("unexpected returns: %d", #errors))
    local j = 1
    while j <= #errors and j <= 8 do print("  " .. errors[j]); j = j + 1 end
end

print("")
print("=== 456a DONE ===")
