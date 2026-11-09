-- CRASH_CLASS: LOW
-- Probe 76a: test a valid 56-byte IPv6 routing header as a small,
-- size-controlled kernel allocation with getsockopt readback.
-- No AIO race, stale pointer access, or malformed header is used.

print("=== PROBE 76a: IPV6_RTHDR 56B ROUND TRIP ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

local function mk(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local function wb(addr, value)
    memory.write_byte(addr, value)
end

local function rb(addr)
    return N(memory.read_byte(addr))
end

local function wd(addr, value)
    memory.write_dword(addr, value)
end

local function rd(addr)
    return N(memory.read_dword(addr))
end

local function call(sc, ...)
    local ok, value = pcall(sc, ...)
    if not ok then return -999 end
    return N(value)
end

local socket = mk(97)
local setsockopt = mk(105)
local getsockopt = mk(118)
local close = mk(6)
local buf = memory.alloc(128)
local out = memory.alloc(128)
local outlen = memory.alloc(8)

local fd4 = call(socket, uint64(2), uint64(2), uint64(0))
print("IPv4 control fd=" .. fd4)
if fd4 >= 0 then
    wb(N(buf), 1); wb(N(buf) + 1, 1)
    wb(N(buf) + 2, 1); wb(N(buf) + 3, 0)
    local setrv = call(setsockopt, uint64(fd4), uint64(0), uint64(1),
        uint64(N(buf)), uint64(4))
    wd(N(outlen), 128)
    local getrv = call(getsockopt, uint64(fd4), uint64(0), uint64(1),
        uint64(N(out)), uint64(N(outlen)))
    print(string.format("IPv4 IP_OPTIONS set=%d get=%d len=%d",
        setrv, getrv, rd(N(outlen))))
    call(close, uint64(fd4))
end

local fd6 = call(socket, uint64(28), uint64(2), uint64(17))
print("IPv6 UDP fd=" .. fd6)
if fd6 >= 0 then
    for _, size in ipairs({24, 40, 56}) do
        for i = 0, size - 1 do wb(N(buf) + i, 0) end
        wb(N(buf), 0)                         -- next header
        wb(N(buf) + 1, size / 8 - 1)          -- extension length
        wb(N(buf) + 2, 0)                     -- type 0
        wb(N(buf) + 3, (size - 8) / 16)       -- segments left
        for i = 0, 127 do wb(N(out) + i, 0xCC) end
        wd(N(outlen), 128)
        local setrv = call(setsockopt, uint64(fd6), uint64(41), uint64(51),
            uint64(N(buf)), uint64(size))
        local getrv = call(getsockopt, uint64(fd6), uint64(41), uint64(51),
            uint64(N(out)), uint64(N(outlen)))
        local bytes = {}
        for i = 0, 15 do bytes[#bytes + 1] = string.format("%02X", rb(N(out) + i)) end
        print(string.format("RTHDR size=%d set=%d get=%d len=%d first16=%s",
            size, setrv, getrv, rd(N(outlen)), table.concat(bytes, " ")))
    end
    call(close, uint64(fd6))
end

print("=== PROBE 76a COMPLETE ===")
