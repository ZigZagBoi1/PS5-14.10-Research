-- CRASH_CLASS: LOW
-- Probe 76b: verify all 56 bytes of a valid type-0 IPV6_RTHDR are
-- caller-controlled and returned by getsockopt on PS5 14.10.

print("=== PROBE 76b: IPV6_RTHDR PATTERN READBACK ===")

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

local fd = call(mk(97), uint64(28), uint64(2), uint64(17))
print("fd=" .. fd)

if fd >= 0 then
    local data = memory.alloc(64)
    local output = memory.alloc(80)
    local output_len = memory.alloc(8)
    local size = 56
    for i = 0, size - 1 do wb(N(data) + i, 0) end
    wb(N(data), 0)                    -- next header
    wb(N(data) + 1, 6)                -- (56 / 8) - 1
    wb(N(data) + 2, 0)                -- type 0
    wb(N(data) + 3, 3)                -- segments left = len / 2
    for i = 8, size - 1 do
        wb(N(data) + i, (i * 37 + 11) % 256)
    end

    for i = 0, 79 do wb(N(output) + i, 0xCC) end
    memory.write_dword(N(output_len), 80)

    local setrv = call(mk(105), uint64(fd), uint64(41), uint64(51),
        uint64(N(data)), uint64(size))
    local getrv = call(mk(118), uint64(fd), uint64(41), uint64(51),
        uint64(N(output)), uint64(N(output_len)))
    local gotlen = N(memory.read_dword(N(output_len)))

    local matching = 0
    local first_diff = -1
    for i = 0, size - 1 do
        if rb(N(data) + i) == rb(N(output) + i) then
            matching = matching + 1
        elseif first_diff < 0 then
            first_diff = i
        end
    end

    local tail_unchanged = true
    for i = size, 79 do
        if rb(N(output) + i) ~= 0xCC then tail_unchanged = false end
    end

    print(string.format("set=%d get=%d len=%d matching=%d/56 first_diff=%d tail_unchanged=%s",
        setrv, getrv, gotlen, matching, first_diff, tostring(tail_unchanged)))
    call(mk(6), uint64(fd))
end

print("=== PROBE 76b COMPLETE ===")
