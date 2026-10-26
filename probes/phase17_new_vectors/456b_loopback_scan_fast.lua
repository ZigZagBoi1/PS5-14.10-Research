-- CRASH_CLASS: LOW
-- PROBE 456b: loopback sweep, chunked and pcall-free
--
-- 456a died to the client timeout after the banner: 65 535 ports times three
-- syscalls plus three pcalls each is far too slow for one connection. This
-- scans a bounded range with no pcalls and prints every hit the moment it is
-- found, so a partial run still answers the question for the part it reached.

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function lg(v)
    local h, l = 0, 0
    if type(v) == "table" and v.h then h, l = v.h, v.l else l = tonumber(v) or 0 end
    if h == 0xFFFFFFFF and l == 0xFFFFFFFF then return -1 end
    if h == 0xFFFFFFFF then return -1 end
    return l
end

local sc_socket, sc_connect, sc_close = make_syscall(97), make_syscall(98), make_syscall(6)
local LO, HI = 1, 5000

local sa = memory.alloc(16)
local function fill(p)
    memory.write_byte(sa + 0, 16)
    memory.write_byte(sa + 1, 2)
    memory.write_byte(sa + 2, math.floor(p / 256) % 256)
    memory.write_byte(sa + 3, p % 256)
    memory.write_byte(sa + 4, 127)
    memory.write_byte(sa + 5, 0)
    memory.write_byte(sa + 6, 0)
    memory.write_byte(sa + 7, 1)
end

print(string.format("=== PROBE 456b: LOOPBACK %d-%d ===", LO, HI))

local t0 = os.clock()
local hits = 0
for p = LO, HI do
    local fd = lg(sc_socket(uint64(2), uint64(1), uint64(0)))
    if fd > 0 then
        fill(p)
        local r = lg(sc_connect(uint64(fd), uint64(sa), uint64(16)))
        if r == 0 then
            hits = hits + 1
            print(string.format("  OPEN %d", p))
        end
        sc_close(uint64(fd))
    end
    if p % 1000 == 0 then
        print(string.format("  ...%d (%.1fs, hits=%d)", p, os.clock() - t0, hits))
    end
end

print(string.format("=== 456b DONE %d-%d hits=%d (%.1fs) ===", LO, HI, hits, os.clock() - t0))
