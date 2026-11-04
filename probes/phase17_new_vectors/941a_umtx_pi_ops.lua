-- CRASH_CLASS: LOW
-- PROBE 941a: which _umtx_op ops exist on 14.10, uncontended
--
-- Context: 454 is reachable and behaves like _umtx_op (56i2: op 5 writes a
-- TID-shaped owner word, op 21 NWAKE returns 0).  The priority-inheritance ops
-- (32..37 in FreeBSD 11) were never issued.  They are the ones that allocate
-- and free umtx_pi structures, which is where the historical umtx races live.
--
-- Every call here is uncontended, so nothing can block: a free mutex word
-- takes ownership immediately and the trylock/ceiling/PI forms return at once.
-- If op 32..37 answer a real value and write an owner word, a contention race
-- becomes reachable with thr_create.
--
-- A: op 4 (TRYLOCK) / 5 (LOCK) / 6 (UNLOCK) on separate words
-- B: op 7 (SET_CEILING), 21 (NWAKE), 22 (MUTEX_WAKE2)
-- C: op 32..37 with a zeroed object and val=0
-- D: op 32 on an object already owned by this thread (PI re-lock)

print("=== PROBE 941a: UMTX OP SURVEY (UNCONTENDED) ===")
print("")

local function to_num(v)
    if type(v) == "table" then
        if v.tonumber then local n = v:tonumber() if n then return n end end
        if v.h then return v.h * 4294967296 + v.l end
    end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a) local o, v = pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end return nil end
local function rq(a) local o, v = pcall(function() return memory.read_qword(a) end); if o then return v end return nil end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function call(f, ...)
    local ok, rv = pcall(f, ...)
    if not ok then return "PCALL-FAIL" end
    return to_num(rv)
end

local sc = mk(454)
local function obj_word()
    local o = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(o + i, 0) end) end
    return o
end
local function op(o, n, val, u1, u2)
    return call(function() return sc(uint64(o), uint64(n), uint64(val or 0), uint64(u1 or 0), uint64(u2 or 0)) end)
end
local function tid()
    return call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)
end

print("[0] pid=" .. tostring(tid()))

print("[A] classic mutex ops, one fresh object each")
for _, n in ipairs({4, 5, 6}) do
    local o = obj_word()
    local r = op(o, n)
    print(string.format("   op %d -> %s word=0x%X", n, tostring(r), rd(o) or 0))
end

print("[B] ceiling / wake / wake2")
for _, n in ipairs({7, 21, 22}) do
    local o = obj_word()
    local r = op(o, n)
    print(string.format("   op %d -> %s word=0x%X", n, tostring(r), rd(o) or 0))
end

print("[C] PI ops 32..37, zeroed object, val=0")
for n = 32, 37 do
    local o = obj_word()
    local r = op(o, n)
    print(string.format("   op %d -> %s word=0x%X qword=0x%X", n, tostring(r), rd(o) or 0, to_num(rq(o))))
end

print("[D] PI lock twice on one object")
local o = obj_word()
print("   first  op32 -> " .. tostring(op(o, 32)))
print("   second op32 -> " .. tostring(op(o, 32)))
print("   op34 unlock -> " .. tostring(op(o, 34)))

print("")
print("=== PROBE 941a COMPLETE ===")
