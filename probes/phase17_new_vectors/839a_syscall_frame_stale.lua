-- CRASH_CLASS: LOW
-- PROBE 839a: does the loader's syscall stub reuse unset argument slots?
--
-- Every probe builds its syscall object with `for k,v in pairs(syscall.pipe)`,
-- so the C side receives whatever Lua hands it.  If the stub writes only the
-- arguments that were passed, slots the caller omits keep the previous call's
-- values, and any handler that reads a slot beyond its argument count reads a
-- value we set earlier with a different syscall.  Tested with mmap(477), whose
-- prot/flags/fd slots are observable from the return value.

print("=== PROBE 839a: stale syscall argument slots ===")
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

local sc = make_syscall(477)

-- A: the full six-argument shape, to learn the working values
local a = sc(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
print(string.format("[A] mmap(0,4000,3,1002,-1,0) = %s", hx(a)))

-- B: two arguments only.  If the omitted slots default to zero this fails
-- (flags 0 is not MAP_ANON and fd 0 is stdin); if they are stale it succeeds.
local b = sc(uint64(0), uint64(0x4000))
print(string.format("[B] mmap(0,4000)              = %s", hx(b)))

-- C: poison the omitted slots with a full call that must fail, then repeat B
local c = sc(uint64(0), uint64(0x4000), uint64(0xDEAD), uint64(0x1111), uint64(0x2222), uint64(0x3333))
print(string.format("[C] mmap(0,4000,DEAD,1111,2222,3333) = %s", hx(c)))
local d = sc(uint64(0), uint64(0x4000))
print(string.format("[D] mmap(0,4000) after poison  = %s", hx(d)))

-- E: poison with values that would succeed if stale but are wrong as defaults
local e = sc(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
print(string.format("[E] mmap(full, working)        = %s", hx(e)))
local f = sc(uint64(0), uint64(0x4000))
print(string.format("[F] mmap(0,4000) after working = %s", hx(f)))

-- G: same question through a different syscall, 674 (region list), which takes
-- six slots and writes a count through slot 4
local sc674 = make_syscall(674)
local buf = memory.alloc(0x400)
local cnt = memory.alloc(8)
memory.write_dword(cnt, 0x40)
local g = sc674(uint64(to_num(buf)), uint64(72), uint64(0x40), uint64(to_num(cnt)), uint64(0x40000000), uint64(0))
print(string.format("[G] 674(full) ret=%s count=%X", hx(g), to_num(memory.read_dword(cnt))))
local h = sc674(uint64(to_num(buf)), uint64(72))
print(string.format("[H] 674(buf,72) only ret=%s count=%X", hx(h), to_num(memory.read_dword(cnt))))

print("[Z] alive=true")
print("=== PROBE 839a COMPLETE ===")
