-- CRASH_CLASS: LOW
-- PROBE 438a: can the object slot be predicted before the object exists?
--
-- 437a showed the per-process object handle is `generation << 13 | slot`, that a freed slot
-- is handed to the next allocation, and that reuse is LIFO. If that is the whole rule then
-- the id of an object we have not created yet is computable: free a slot at generation G and
-- the next allocation must return (G+1) << 13 | slot.
--
-- That is the difference between "an object exists" and "an object is at a place I chose",
-- and it is what a reclaim needs. This probe states the prediction first and then checks it.
--
-- [A] create four evf, decode each id into generation and slot
-- [B] free two, predict the next two ids, create, compare
-- [C] free an evf slot and create an *osem* - does a different family take that slot?
-- [D] free a slot twice over (reuse, free, reuse) and check the generation climbs by one each time

print("=== PROBE 438a: SLOT PREDICTION ===")

local GEN_SHIFT = 8192

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
local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, rv = pcall(function()
        return sc(uint64(a1 or 0), uint64(a2 or 0), uint64(a3 or 0), uint64(a4 or 0), uint64(a5 or 0), uint64(a6 or 0))
    end)
    if not ok then return -999 end
    if type(rv) == "table" and rv.h then
        local h, l = to_num(rv.h), to_num(rv.l)
        if h >= 2147483648 then h = h - 4294967296 end
        if l >= 2147483648 then l = l - 4294967296 end
        if h == -1 and l == -1 then return -1 end
        return h * 4294967296 + l
    end
    local n = to_num(rv)
    if n >= 9223372036854775808 then n = n - 18446744073709551616 end
    return n
end

local function slot(h) return h % GEN_SHIFT end
local function gen(h) return math.floor(h / GEN_SHIFT) end

local page = call(477, 0, 0x1000, 7, 0x1002, 0xFFFFFFFF, 0)
if page <= 0 then print("no page") return end
local i = 0
while i < 0x400 do memory.write_qword(page + i, uint64(0)); i = i + 8 end

local name = memory.alloc(0x40)
local NAME = "omp438a"
local j = 1
while j <= #NAME do memory.write_byte(name + j - 1, NAME:byte(j)); j = j + 1 end
memory.write_byte(name + #NAME, 0)

local function evf() return call(538, page, 0, 0, 0, 0, 0) end
local function evfDel(h) return call(539, h, 0, 0, 0, 0, 0) end
local function osem() return call(549, name, 0, 0, 4, 0, 0) end
local function osemDel(h) return call(550, h, 0, 0, 0, 0, 0) end

local a, k = {}, 1
while k <= 4 do a[k] = evf(); k = k + 1 end
print(string.format("[A] %d(g%d/s%d) %d(g%d/s%d) %d(g%d/s%d) %d(g%d/s%d)",
    a[1], gen(a[1]), slot(a[1]), a[2], gen(a[2]), slot(a[2]),
    a[3], gen(a[3]), slot(a[3]), a[4], gen(a[4]), slot(a[4])))

-- free #2 then #1, so #1 is on top of the stack
local d2 = evfDel(a[2])
local d1 = evfDel(a[1])
local p1 = (gen(a[1]) + 1) * GEN_SHIFT + slot(a[1])
local p2 = (gen(a[2]) + 1) * GEN_SHIFT + slot(a[2])
print(string.format("[B] rm(2)=%d rm(1)=%d predict %d then %d", d2, d1, p1, p2))
local b1, b2 = evf(), evf()
print(string.format("[B] got %d then %d -> %s", b1, b2, (b1 == p1 and b2 == p2) and "PREDICTED" or "different"))

-- cross family: free an evf slot, then create an osem
local d3 = evfDel(a[3])
local p3 = (gen(a[3]) + 1) * GEN_SHIFT + slot(a[3])
local s1 = osem()
print(string.format("[C] rm(evf 3)=%d predict %d got osem %d -> %s",
    d3, p3, s1, (s1 == p3) and "same slot" or "different"))

-- generation climb
local g0 = gen(b1)
local r1 = evfDel(b1)
local b3 = evf()
local r2 = evfDel(b3)
local b4 = evf()
print(string.format("[D] g%d -> g%d -> g%d (rm=%d,%d) %s",
    g0, gen(b3), gen(b4), r1, r2,
    (gen(b3) == g0 + 1 and gen(b4) == g0 + 2) and "climbs by one" or "does not climb by one"))

-- clean up
evfDel(b2); evfDel(b3); evfDel(b4); evfDel(a[4]); osemDel(s1)
print("=== 438a DONE ===")
