-- CRASH_CLASS: MODERATE
-- PROBE 824a: create an osem object (549) and hunt its id
--
-- Context: 13.60 decode of sys 549 (handler offset 0xC16020):
--   flags = uap[1]; reject unless (flags & 0xfffffefc) == 0 and (flags & 3) != 3;
--   flags & 3 == 0 -> flags |= 1
--   a3 = (int)uap[2] must be >= 0; a4 = (int)uap[3] must be > 0 and a3 <= a4
--   uap[0] = name pointer, non-zero, copied with a 0x20-byte bounded string copy
--   object = malloc(0x60), init(obj, flags, a3, a4), id = allocator(table)
--   flags & 0x100 -> [obj+0x54] = 1 and a name-table insert
--   otherwise    -> [obj+0x54] = 0, no name insert
--   [obj+0x58] = pid; register(table, 0x120, obj, name); boot gate; [td+0x408] = id
--   return 0.  The id goes to td_retval[1] (RDX), never through the uap.
--
-- Previous sweeps sent flags 0/1/0x1000 with a name page full of 0x10101010, so
-- the string copy failed and every call looked like -1. This sends a real
-- NUL-terminated name and the accepted flag values, then finds the id by
-- calling the destroy entry (550) over the small id range.

print("=== PROBE 824a: osem create (549) and id hunt ===")
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

local sc549 = make_syscall(549)
local sc550 = make_syscall(550)
local sc551 = make_syscall(551)

-- [A] name page, NUL terminated
local name = memory.alloc(0x40)
for i = 0, 0x3F do memory.write_byte(name + i, 0) end
local s = "probe824"
for i = 1, #s do memory.write_byte(name + i - 1, string.byte(s, i)) end
local rd = 0
for i = 0, 0x10 do
    rd = rd + to_num(memory.read_byte(name + i)) * (i + 1)
end
print(string.format("[A] name page written, checksum=%d", rd))

-- [B] create, flags = 1 (accepted, no name registration)
local ok, ret = pcall(function() return sc549(name, uint64(1), uint64(0), uint64(0x1000)) end)
print(string.format("[B] 549(name,1,0,0x1000) ok=%s ret=%s type=%s",
    tostring(ok), hx(ret), type(ret)))

-- [C] a second create with the name-registration flag
local ok2, ret2 = pcall(function() return sc549(name, uint64(0x101), uint64(0), uint64(0x1000)) end)
print(string.format("[C] 549(name,0x101,0,0x1000) ok=%s ret=%s",
    tostring(ok2), hx(ret2)))

-- [D] open by name, which the decode says allocates a second id for the same object
local ok3, ret3 = pcall(function() return sc551(name) end)
print(string.format("[D] 551(name) ok=%s ret=%s", tostring(ok3), hx(ret3)))

-- [E] hunt the id: 550(id) returns 0 only for a live object of type 0x120.
--     Scan the range the object allocator has been observed to use.
print("[E] hunting id with 550 over 0x100..0x3FF")
local found = 0
for id = 0x100, 0x3FF do
    local okr, r = pcall(function() return sc550(uint64(id)) end)
    local v = to_num(r or 0)
    if not okr then
        print(string.format("  id %04X -> pcall failed", id))
    elseif v == 0 then
        print(string.format("  id %04X -> HIT ret=0", id))
        found = found + 1
        if found >= 4 then break end
    end
end
print(string.format("[E] hits=%d", found))

-- [F] health: still alive, create once more
local ok4, ret4 = pcall(function() return sc549(name, uint64(2), uint64(0x10), uint64(0x20)) end)
print(string.format("[F] 549(name,2,0x10,0x20) ok=%s ret=%s alive=true", tostring(ok4), hx(ret4)))
print("=== PROBE 824a COMPLETE ===")
