-- CRASH_CLASS: LOW
-- PROBE 346b: whether 637's stored value changes the GPU pool ceiling
--
-- 346a measured 6 x 64 MiB before the raise and 0 after, which cannot separate
-- "the write does nothing" from "the pool was already spent when the raise
-- happened". This probe raises the limit while headroom still exists: map three
-- chunks, store the new limit, then keep mapping until the next refusal. If the
-- ceiling moves, later chunks succeed; if it does not, the refusal arrives at
-- 64 MiB exactly as it would have without the write.

print("=== PROBE 346b: FMEM CEILING WITH HEADROOM ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local Z = uint64(0)
local sc477 = make_syscall(477)
local sc637 = make_syscall(637)
local CHUNK = 64

local function chunk()
    local ok, rv = pcall(function()
        return sc477(Z, uint64(CHUNK * 0x100000), uint64(0x33), uint64(0x1002),
            uint64(0xFFFFFFFF), Z)
    end)
    if not ok then return false end
    local h, l = get_hi_lo(rv)
    local probe = to_num(h) * 4294967296 + to_num(l)
    return probe > 0 and probe < 0x800000000000
end

local n = 0
while n < 3 do
    if not chunk() then break end
    n = n + 1
end
print(string.format("  mapped before the raise: %d chunks (%d MiB)", n, n * CHUNK))

local okr, rv = pcall(function() return sc637(Z, uint64(0xFFFFFFFF), Z, Z, Z, Z) end)
print(string.format("  637(0, 0xFFFFFFFF) = %s", okr and tostring(sgn(rv)) or "EXC"))

local more = 0
while more < 40 do
    if not chunk() then break end
    more = more + 1
end
print(string.format("  mapped after the raise:  %d more chunks", more))
print(string.format("  total: %d chunks (%d MiB)", n + more, (n + more) * CHUNK))

print("")
print("=== 346b DONE ===")
