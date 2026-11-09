-- CRASH_CLASS: HIGH
-- PROBE 254a: what a named object is, and whether a name can be duplicated
--
-- 253a showed 557 returns a handle-shaped value (0x4205, then 0x206, 0x207 on
-- later calls with the same name), so 557 namedobj_create really does create an
-- object per call. The question that decides whether this family can hold a
-- lifetime mistake is whether the name is a key: reproducing the same name
-- should either fail or hand back the same object, and delete should remove the
-- name rather than just the handle.
--
--   A  create name N1 four times, then a fresh name N2 - are the handles distinct
--   B  558 delete on a handle, then create the same name again - does the name free up
--   C  delete twice, delete 0xDEAD, delete 0 - argument handling
--
-- Every row prints the pid, so a kill names its own row.

print("=== PROBE 254a: named object identity ===")
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
local function q(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", v.h, v.l) end
    local n = to_num(v)
    if n < 0 then n = n + 18446744073709551616 end
    return string.format("0x%X", n)
end
local function num(v)
    local n = to_num(v)
    if n < 0 then n = n + 18446744073709551616 end
    return n
end
local function pid()
    local ok, v = pcall(function() return make_syscall(20)() end)
    if ok then return to_num(v) end
    return nil
end
local function call(num, a, b, c, d)
    local sc = make_syscall(num)
    local ok, rv = pcall(function() return sc(a or uint64(0), b or uint64(0), c or uint64(0), d or uint64(0)) end)
    if not ok then return nil end
    return rv
end
local function mkname(tag)
    local b = memory.alloc(0x40)
    pcall(function() memory.write_qword(b, 0) end)
    for i = 1, #tag do
        pcall(function() memory.write_byte(b + i - 1, string.byte(tag, i)) end)
    end
    return b
end

local N1 = mkname("objone")
local N2 = mkname("objtwo")
print("[0] pid=" .. tostring(pid()) .. "  N1=" .. q(N1) .. "  N2=" .. q(N2))

print("")
print("[A] 557 on the same name, four times, then a fresh name")
local hs = {}
for i = 1, 4 do
    local rv = call(557, uint64(N1), uint64(0), uint64(0))
    hs[i] = num(rv)
    print(string.format("    557(N1) #%d -> %-20s pid=%s", i, q(rv), tostring(pid())))
end
local fresh = call(557, uint64(N2), uint64(0), uint64(0))
print(string.format("    557(N2)    -> %-20s pid=%s", q(fresh), tostring(pid())))

print("")
print("[B] 558 delete, then the name again")
for i = 1, 4 do
    if hs[i] ~= nil and hs[i] > 0 and hs[i] < 0x100000 then
        local rv = call(558, uint64(hs[i]), uint64(0), uint64(0))
        print(string.format("    558(0x%X) -> %-20s pid=%s", hs[i], q(rv), tostring(pid())))
    end
end
local again = call(557, uint64(N1), uint64(0), uint64(0))
print(string.format("    557(N1) after deletes -> %-20s pid=%s", q(again), tostring(pid())))

print("")
print("[C] argument handling")
print("    558(0xDEAD)        -> " .. q(call(558, uint64(0xDEAD), uint64(0), uint64(0))) .. "  pid=" .. tostring(pid()))
print("    558(0)             -> " .. q(call(558, uint64(0), uint64(0), uint64(0))) .. "  pid=" .. tostring(pid()))
print("    558(0xDEAD) again  -> " .. q(call(558, uint64(0xDEAD), uint64(0), uint64(0))) .. "  pid=" .. tostring(pid()))
print("    557(NULL)          -> " .. q(call(557, uint64(0), uint64(0), uint64(0))) .. "  pid=" .. tostring(pid()))
print("    557(unmapped)      -> " .. q(call(557, uint64(0xFFFF0000), uint64(0), uint64(0))) .. "  pid=" .. tostring(pid()))

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 254a COMPLETE ===")
