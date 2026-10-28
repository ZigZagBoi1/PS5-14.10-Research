-- CRASH_CLASS: MODERATE
-- PROBE 826a: osem reference accounting — do the destroy variants balance the opens?
--
-- Facts from 824a/825a:
--   549(name,0x101,0,0x1000) -> id, name registered, refcount [obj+0x54] = 1
--   551(name)                -> a NEW id for the same object each call
--   550(id)                  -> 0 for a live id
--   552(id)                  -> 0 for an id returned by 551, -1 for the create id
--
-- If the refcount tracks live ids exactly, destroying every id must free the
-- object and remove its name, so 551(name) then fails. If any destroy path
-- removes an id without dropping the refcount (or drops it twice), the name
-- lookup keeps answering for a freed 0x60 object: that is a use-after-free with
-- 555/553/554 as the write/read on the freed memory.

print("=== PROBE 826a: osem reference accounting ===")
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

local sc549 = make_syscall(549)
local sc550 = make_syscall(550)
local sc551 = make_syscall(551)
local sc552 = make_syscall(552)
local sc555 = make_syscall(555)

local function call(sc, ...)
    local a = {...}
    local ok, r = pcall(function() return sc(unpack(a)) end)
    return to_num(r or 0)
end

-- Case A: three ids, all destroyed with 550
do
    local n = mkname("casA")
    local id0 = call(sc549, n, uint64(0x101), uint64(0), uint64(0x100))
    local id1 = call(sc551, n)
    local id2 = call(sc551, n)
    local id3 = call(sc551, n)
    print(string.format("[A] create=%s open1=%s open2=%s open3=%s", hx(id0), hx(id1), hx(id2), hx(id3)))
    print(string.format("[A] 550(create)=%s", hx(call(sc550, uint64(id0)))))
    print(string.format("[A] 550(open1)=%s", hx(call(sc550, uint64(id1)))))
    print(string.format("[A] 550(open2)=%s", hx(call(sc550, uint64(id2)))))
    print(string.format("[A] 550(open3)=%s", hx(call(sc550, uint64(id3)))))
    local after = call(sc551, n)
    print(string.format("[A] 551(name) after all four ids destroyed = %s", hx(after)))
    if after > 0 then
        print(string.format("[A] *** name survived the free *** 555(%s,1)=%s", hx(after), hx(call(sc555, uint64(after), uint64(1)))))
    end
end

-- Case B: same shape, destroyed with 552 instead
do
    local n = mkname("casB")
    local id0 = call(sc549, n, uint64(0x101), uint64(0), uint64(0x100))
    local id1 = call(sc551, n)
    print(string.format("[B] create=%s open1=%s", hx(id0), hx(id1)))
    print(string.format("[B] 552(open1)=%s", hx(call(sc552, uint64(id1)))))
    print(string.format("[B] 552(create)=%s", hx(call(sc552, uint64(id0)))))
    local after = call(sc551, n)
    print(string.format("[B] 551(name) after both destroyed = %s", hx(after)))
    if after > 0 then
        print(string.format("[B] *** name survived *** 555(%s,1)=%s", hx(after), hx(call(sc555, uint64(after), uint64(1)))))
    end
end

-- Case C: destroy the same id with both variants back to back
do
    local n = mkname("casC")
    local id0 = call(sc549, n, uint64(0x101), uint64(0), uint64(0x100))
    print(string.format("[C] create=%s", hx(id0)))
    print(string.format("[C] 550(create)=%s", hx(call(sc550, uint64(id0)))))
    print(string.format("[C] 552(create) again =%s", hx(call(sc552, uint64(id0)))))
    print(string.format("[C] 550(create) again =%s", hx(call(sc550, uint64(id0)))))
    local after = call(sc551, n)
    print(string.format("[C] 551(name) = %s", hx(after)))
end

-- Case D: plain create (no name flag) then destroy twice, then reuse the slot
do
    local n = mkname("casD")
    local id0 = call(sc549, n, uint64(1), uint64(0), uint64(0x100))
    local id2 = call(sc549, n, uint64(1), uint64(0), uint64(0x100))
    print(string.format("[D] plain create=%s second=%s", hx(id0), hx(id2)))
    print(string.format("[D] 550 first=%s", hx(call(sc550, uint64(id0)))))
    print(string.format("[D] 550 first again=%s", hx(call(sc550, uint64(id0)))))
    print(string.format("[D] 552 first=%s", hx(call(sc552, uint64(id0)))))
    print(string.format("[D] 550 second=%s", hx(call(sc550, uint64(id2)))))
end

-- [E] health
do
    local n = mkname("casE")
    local id0 = call(sc549, n, uint64(1), uint64(0), uint64(0x100))
    print(string.format("[E] health create=%s, 550=%s alive=true", hx(id0), hx(call(sc550, uint64(id0)))))
end
print("=== PROBE 826a COMPLETE ===")
