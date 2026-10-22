-- CRASH_CLASS: LOW
-- PROBE 342a: do the objects registered by 341a still resolve in a new process?
--
-- 341a registered three kernel objects by name in the shared registry (evf
-- "omp341a_evf", evf "omp341a_evf2", namedobj "omp341a_named"/"omp341a_named2")
-- and then the process was relaunched without deleting them (541 refuses).
-- A registration holds its own reference, so if the registry is global these
-- names resolve here and hand out a handle to an object created by a process
-- that no longer exists. This looks the names up and, if one resolves, drives
-- 544 set against it.

print("=== PROBE 342a: NAMED OBJECTS ACROSS A RELAUNCH ===")
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
local sc540 = make_syscall(540)
local sc544 = make_syscall(544)
local sc557 = make_syscall(557)

local function put_name(s)
    for i = 1, #s do safe_wb(PAGE + i - 1, string.byte(s, i)) end
    safe_wb(PAGE + #s, 0)
end

print("[A] lookup names registered by the previous process")
local NAMES = { "omp341a_evf", "omp341a_evf2", "omp341a_named", "omp341a_named2" }
for _, name in ipairs(NAMES) do
    put_name(name)
    local h = call(sc540, P, Z, Z, Z, Z, Z)
    print(string.format("  540 lookup(%-16s) = %s", name, fmt(h)))
    if h and h > 0 then
        print(string.format("      544 set(%-6d, 0x80) = %s", h,
            fmt(call(sc544, uint64(h), uint64(0x80), Z, Z, Z, Z))))
    end
end

print("[B] control: a name nobody registered")
put_name("omp342a_absent")
print(string.format("  540 lookup(omp342a_absent) = %s", fmt(call(sc540, P, Z, Z, Z, Z, Z))))

print("[C] second lookup of the same name (refcount)")
put_name("omp341a_evf")
print(string.format("  540 lookup(omp341a_evf) #1 = %s", fmt(call(sc540, P, Z, Z, Z, Z, Z))))
put_name("omp341a_evf")
print(string.format("  540 lookup(omp341a_evf) #2 = %s", fmt(call(sc540, P, Z, Z, Z, Z, Z))))

print("")
print("=== 342a DONE ===")
