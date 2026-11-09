-- CRASH_CLASS: LOW
-- PROBE 341a: register named kernel objects, then leave them behind
--
-- 336a showed 538 with attribute 0x100 registers the object by name in a
-- shared registry, and 540 then resolves that name and returns a fresh handle.
-- A registration is supposed to hold a reference of its own (the object carries a
-- count at +0x50), so the object should outlive the process that created it.
-- This creates evf and namedobj objects under fixed names and records their
-- handles; the follow-up probe runs in a new process and looks the same names up.
-- Nothing here blocks or deletes.

print("=== PROBE 341a: NAMED OBJECTS ===")
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
local function safe_wb(addr, val)
    local ok = pcall(function() memory.write_byte(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function lo_of(v)
    local h, l = get_hi_lo(v)
    return to_num(l), to_num(h)
end
local function call(sc, a, b, c, d, e, f)
    local ok, rv = pcall(function() return sc(a, b, c, d, e, f) end)
    if not ok then return nil end
    return sgn(lo_of(rv))
end
local function fmt(v)
    if v == nil then return "EXC" end
    return tostring(v)
end

local PAGE = memory.alloc(0x1000)
local Z = uint64(0)
local P = uint64(PAGE)
local sc538 = make_syscall(538)
local sc540 = make_syscall(540)
local sc544 = make_syscall(544)
local sc557 = make_syscall(557)

local function put_name(s)
    for i = 1, #s do safe_wb(PAGE + i - 1, string.byte(s, i)) end
    safe_wb(PAGE + #s, 0)
end

print("[A] evf with a registered name")
put_name("omp341a_evf")
safe_wq(PAGE + 0x10, uint64(0x1234))
local h_evf = call(sc538, P, uint64(0x100), Z, Z, Z, Z)
print(string.format("  create(name, attr 0x100) = %s", fmt(h_evf)))
print(string.format("  544 set(handle, 0x40)    = %s",
    h_evf and h_evf > 0 and fmt(call(sc544, uint64(h_evf), uint64(0x40), Z, Z, Z, Z)) or "skip"))

print("[B] second registration, different name")
put_name("omp341a_evf2")
safe_wq(PAGE + 0x10, uint64(0x5678))
local h_evf2 = call(sc538, P, uint64(0x100), Z, Z, Z, Z)
print(string.format("  create(name2, attr 0x100) = %s", fmt(h_evf2)))

print("[C] namedobj with a type and a value")
put_name("omp341a_named")
local h_named = call(sc557, P, uint64(0x1000), uint64(0x77), Z, Z, Z)
print(string.format("  557 create(named, 0x1000, 0x77) = %s", fmt(h_named)))
put_name("omp341a_named2")
local h_named2 = call(sc557, P, uint64(0x1000), uint64(0x78), Z, Z, Z)
print(string.format("  557 create(named2, 0x1000, 0x78) = %s", fmt(h_named2)))

print("[D] in-process lookup control")
for _, name in ipairs({ "omp341a_evf", "omp341a_evf2", "omp341a_absent" }) do
    put_name(name)
    print(string.format("  540 lookup(%s) = %s", name, fmt(call(sc540, P, Z, Z, Z, Z, Z))))
end

print("")
print("=== 341a DONE ===")
