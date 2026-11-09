-- CRASH_CLASS: MODERATE
-- PROBE 197a: are the two handle classes distinguishable
--
-- Context: 192a created handles from both 538 (evf) and 557 (namedobj) and they
-- share one table: 538 handed out 518..525 and 557 continued at 526..536. 558
-- deleted some of them and refused others (the ones created with a non-zero
-- third argument). 539 and 558 both return 0 on the first delete and -1 on the
-- second, so a handle carries a generation counter.
--
-- Two questions follow. Does the delete call check the class of the handle it
-- is given, or only the index and generation? And does the use call (543/544)
-- accept a handle that was created by the other subsystem? A table that checks
-- only index and generation, with per-class destructors, is a type-confusion
-- primitive; that is what this probe tests, in both directions, before the
-- byte-level races.

print("=== PROBE 197a: handle class confusion ===")
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
local function u64(v)
    if type(v) == "number" then return uint64(string.format("0x%08X", v)) end
    return v
end
local function show(v)
    if v == nil then return "killed" end
    return tostring(v)
end
local dead = false

local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, ret = pcall(function()
        return sc(u64(a1 or 0), u64(a2 or 0), u64(a3 or 0), u64(a4 or 0), u64(a5 or 0), u64(a6 or 0))
    end)
    if not ok then
        dead = true
        return nil, nil
    end
    return ret, to_num(ret)
end

local NAME = memory.alloc(0x40)
local function put_str(addr, s)
    for i = 1, #s do
        pcall(function() memory.write_byte(addr + i - 1, u64(string.byte(s, i))) end)
    end
    pcall(function() memory.write_byte(addr + #s, u64(0)) end)
end

local _, pid = call(20)
print("[0] getpid " .. show(pid))
print("")

put_str(NAME, "evf_197a")
local _, E = call(538, NAME, 0, 0)
print("[A] evf create        -> " .. show(E))
put_str(NAME, "nobj_197a")
local _, N = call(557, NAME, 0, 0)
print("    namedobj create   -> " .. show(N))
print("")

print("[B] cross deletes")
print("    558(evf handle)    -> " .. show((call(558, E))))
print("    539(namedobj handle)-> " .. show((call(539, N))))
print("")

print("[C] cross use")
put_str(NAME, "nobj_197b")
local _, N2 = call(557, NAME, 0, 0)
print("    namedobj create    -> " .. show(N2))
print("    544 set(N2,1)      -> " .. show((call(544, N2, 1))))
print("    543 trywait(N2,1)  -> " .. show((call(543, N2, 1, 1))))
print("    541 close(N2)      -> " .. show((call(541, N2))))
print("")

print("[D] evf handle through the namedobj delete, then reuse")
put_str(NAME, "evf_197b")
local _, E2 = call(538, NAME, 0, 0)
print("    evf create         -> " .. show(E2))
print("    558(E2)            -> " .. show((call(558, E2))))
print("    544 set(E2,1)      -> " .. show((call(544, E2, 1))))
print("    539(E2)            -> " .. show((call(539, E2))))
print("")

print("[E] survivors")
print("    539(E)             -> " .. show((call(539, E))))
print("    558(N2)            -> " .. show((call(558, N2))))
print("")

print("=== PROBE 197a COMPLETE ===")
