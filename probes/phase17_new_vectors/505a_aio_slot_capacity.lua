-- CRASH_CLASS: MODERATE
-- PROBE 505a: how many aio objects can exist at once, and does deleting free the
-- slots back?  Single threaded, no helper.
--
-- 502b/502d created 1280 objects across a helper loop and the process died on
-- both runs.  Before blaming the race, measure the table: create count=1 objects
-- until create stops returning an id, then delete everything and create again.

print("=== PROBE 505a: aio slot capacity ===")
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
local OUT  = memory.alloc(0x100)
local IDS  = memory.alloc(0x400)
local RES  = memory.alloc(0x400)
fill(DATA, 0, 0x100)

local MAX = 1100
local ids = {}
local made, firstfail = 0, nil
for i = 1, MAX do
    wr(OUT, 0)
    local ok, r = pcall(function() return sc_c(1, DATA, 1, 1, OUT) end)
    local id = rd(OUT)
    if not ok or to_num(r) ~= 0 or id == 0 then
        firstfail = i
        print(string.format("create #%d failed ok=%s ret=%d id=%d", i, tostring(ok), to_num(r), id))
        break
    end
    ids[i] = id
    made = made + 1
    if i % 100 == 0 then print(string.format("  created %d (last id=%d)", i, id)) end
end
print(string.format("A made=%d firstfail=%s", made, tostring(firstfail)))

-- poll everything, then delete in batches of 64
local polled = 0
for i = 1, made do
    wr(IDS, ids[i]); fill(RES, 0x77777777, 8)
    local ok, r = pcall(function() return sc_p(IDS, 1, RES) end)
    if ok and to_num(r) == 0 then polled = polled + 1 end
end
print(string.format("B polled=%d of %d", polled, made))

local clean, other = 0, 0
for base = 1, made, 64 do
    local n = math.min(64, made - base + 1)
    for i = 0, n - 1 do wr(IDS + i * 4, ids[base + i]) end
    fill(RES, 0x77777777, n * 4)
    local ok, r = pcall(function() return sc_d(IDS, n, RES) end)
    for i = 0, n - 1 do
        local v = rd(RES + i * 4)
        if v == 0 then clean = clean + 1 else other = other + 1 end
    end
end
print(string.format("C deletes clean=%d other=%d", clean, other))

-- can we allocate again after the teardown?
local made2, fail2 = 0, nil
for i = 1, 64 do
    wr(OUT, 0)
    local ok, r = pcall(function() return sc_c(1, DATA, 1, 1, OUT) end)
    local id = rd(OUT)
    if not ok or to_num(r) ~= 0 or id == 0 then fail2 = i; break end
    made2 = made2 + 1
    wr(IDS, id); fill(RES, 0x77777777, 8)
    pcall(function() return sc_p(IDS, 1, RES) end)
    local okd, rd2 = pcall(function() return sc_d(IDS, 1, RES) end)
end
print(string.format("D after teardown made=%d fail=%s", made2, tostring(fail2)))
print("=== DONE ===")
