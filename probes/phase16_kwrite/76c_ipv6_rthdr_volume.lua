-- CRASH_CLASS: LOW
-- Probe 76c: retain 64 independent 56-byte IPV6_RTHDR allocations
-- and verify the full per-socket pattern through getsockopt.

print("=== PROBE 76c: IPV6_RTHDR 56B VOLUME ===")

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

local function call(sc, ...)
    local ok, value = pcall(sc, ...)
    return ok and N(value) or -999
end

local function wb(a, v) memory.write_byte(a, v) end
local function rb(a) return N(memory.read_byte(a)) end

local socket = mk(97)
local setsockopt = mk(105)
local getsockopt = mk(118)
local close = mk(6)
local data = memory.alloc(64)
local output = memory.alloc(80)
local output_len = memory.alloc(8)
local fds = {}

local function prepare(index)
    for i = 0, 55 do wb(N(data) + i, 0) end
    wb(N(data), 0)
    wb(N(data) + 1, 6)
    wb(N(data) + 2, 0)
    wb(N(data) + 3, 3)
    for i = 8, 55 do wb(N(data) + i, (i * 37 + index * 13) % 256) end
end

for index = 1, 64 do
    local fd = call(socket, uint64(28), uint64(2), uint64(17))
    if fd < 0 then
        print(string.format("socket failed at index=%d rv=%d", index, fd))
        break
    end
    prepare(index)
    local rv = call(setsockopt, uint64(fd), uint64(41), uint64(51),
        uint64(N(data)), uint64(56))
    if rv ~= 0 then
        print(string.format("set failed at index=%d fd=%d rv=%d", index, fd, rv))
        call(close, uint64(fd))
        break
    end
    fds[#fds + 1] = fd
end

print("retained=" .. #fds)
local matched = 0
local failed = 0
for index, fd in ipairs(fds) do
    prepare(index)
    for i = 0, 79 do wb(N(output) + i, 0xCC) end
    memory.write_dword(N(output_len), 80)
    local rv = call(getsockopt, uint64(fd), uint64(41), uint64(51),
        uint64(N(output)), uint64(N(output_len)))
    local len = N(memory.read_dword(N(output_len)))
    local equal = (rv == 0 and len == 56)
    if equal then
        for i = 0, 55 do
            if rb(N(data) + i) ~= rb(N(output) + i) then equal = false; break end
        end
    end
    if equal then matched = matched + 1
    else
        failed = failed + 1
        if failed <= 5 then
            print(string.format("readback mismatch index=%d fd=%d rv=%d len=%d", index, fd, rv, len))
        end
    end
end
print(string.format("matched=%d failed=%d", matched, failed))

for _, fd in ipairs(fds) do call(close, uint64(fd)) end
print("=== PROBE 76c COMPLETE ===")
