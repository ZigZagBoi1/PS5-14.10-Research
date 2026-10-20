-- CRASH_CLASS: LOW
-- PROBE 56i5b: Reidentify and inspect the 56i4 RO high-half candidate.
-- The value 0xFFFFFFFE082E0057 at +0x7F8 is not a validated pointer.
-- Match the region's contents, not its VM map index or ASLR address.

print("=== PROBE 56i5b: RO CANDIDATE FINGERPRINT ===")

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
local function rd(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function halves(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, to_num(v)
end
local function fmt(v)
    if not v then return "READ_FAIL" end
    local h, l = halves(v)
    return string.format("0x%08X_%08X", h, l)
end
local function add(v, off)
    local h, l = halves(v)
    l = l + off
    if l >= 0x100000000 then h = h + 1; l = l - 0x100000000 end
    return uint64(string.format("0x%X%08X", h, l))
end

local stride, capacity = 72, 512
local records = memory.alloc(stride * capacity)
local countp = memory.alloc(8)
memory.write_qword(countp, uint64(0))
local ok, rv = pcall(function()
    return make_syscall(674)(uint64(records), uint64(stride),
                             uint64(capacity), uint64(countp), uint64(0x40000000))
end)
local count = rd(countp)
local _, n = halves(count)
print("map_ok=" .. tostring(ok) .. " ret=" .. tostring(rv) .. " count=" .. n)
if not ok then return end
if n > capacity then n = capacity end

local matches = 0
for i = 0, n - 1 do
    local rec = records + i * stride
    local start = rd(rec)
    local finish = rd(rec + 8)
    local protv = rd(rec + 0x18)
    local _, prot = halves(protv)
    local sh, sl = halves(start)
    local eh, el = halves(finish)
    if prot == 1 and eh == sh and el - sl == 0x4000 then
        local first = rd(start)
        local second = rd(add(start, 8))
        local fhi, flo = halves(first)
        local shi, slo = halves(second)
        if fhi == 0 and flo == 0x2018 and
           shi == 0xFFFFFFFF and slo == 0xFFFFFFFF then
            matches = matches + 1
            print(string.format("match=%d region=%d base=%s", matches, i, fmt(start)))
            for off = 0x7D0, 0x820, 8 do
                print(string.format("  +0x%03X %s", off, fmt(rd(add(start, off)))))
            end
            local candidate = rd(add(start, 0x7F8))
            print("candidate=" .. fmt(candidate))
        end
    end
end
print("matches=" .. matches)
print("=== PROBE 56i5b COMPLETE ===")
