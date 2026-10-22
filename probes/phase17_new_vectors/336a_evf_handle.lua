-- CRASH_CLASS: LOW
-- PROBE 336a: the evf family driven with the handle 538 returns
--
-- 334a showed evf_create (538) answers 16901 when arg0 is a real page, while
-- six zeros return -1. The rest of the family (541 delete, 543 poll, 544 set,
-- 545 clear, 546 cancel) returned -1 to every pointer shape because it needs a
-- live handle, not a page. This creates one object and drives the family with
-- it. 542 evf_wait is deliberately not called: it blocks the caller until the
-- pattern matches, and a blocked main thread wedges the loader.

print("=== PROBE 336a: EVF FAMILY ===")
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
for i = 0, 0x1000 - 8, 8 do safe_wq(PAGE + i, Z) end
-- name at +0x00, NUL terminated
local NAME = "omp336a"
for i = 1, #NAME do
    pcall(function() memory.write_byte(PAGE + i - 1, string.byte(NAME, i)) end)
end
pcall(function() memory.write_byte(PAGE + #NAME, 0) end)

local sc538 = make_syscall(538)
local sc540 = make_syscall(540)
local sc541 = make_syscall(541)
local sc543 = make_syscall(543)
local sc544 = make_syscall(544)
local sc545 = make_syscall(545)
local sc546 = make_syscall(546)
local P = uint64(PAGE)

print("[A] create")
local h = call(sc538, P, Z, Z, Z, Z, Z)
print(string.format("  evf_create(page)      = %s", fmt(h)))

print("[B] second create, same page")
local h2 = call(sc538, P, Z, Z, Z, Z, Z)
print(string.format("  evf_create(page)      = %s", fmt(h2)))

print("[C] family with the first handle")
if h and h > 0 then
    local H = uint64(h)
    print(string.format("  544 set(h, 0x1)       = %s", fmt(call(sc544, H, uint64(1), Z, Z, Z, Z))))
    print(string.format("  543 poll(h, 0x1, OR)  = %s", fmt(call(sc543, H, uint64(1), Z, P, Z, Z))))
    print(string.format("  543 poll(h, 0x2, OR)  = %s", fmt(call(sc543, H, uint64(2), Z, P, Z, Z))))
    print(string.format("  545 clear(h, 0x0)     = %s", fmt(call(sc545, H, Z, Z, Z, Z, Z))))
    print(string.format("  546 cancel(h, nil)    = %s", fmt(call(sc546, H, Z, Z, P, Z, Z))))
    print(string.format("  541 delete(h)         = %s", fmt(call(sc541, H, Z, Z, Z, Z, Z))))
    print(string.format("  541 delete(h) again   = %s", fmt(call(sc541, H, Z, Z, Z, Z, Z))))
    print(string.format("  544 set(h, 0x1) dead  = %s", fmt(call(sc544, H, uint64(1), Z, Z, Z, Z))))
end

print("[D] family with the raw 16901 / 0x4205 value")
for _, v in ipairs({ 16901, 0x4205 }) do
    print(string.format("  544 set(%d)        = %s", v, fmt(call(sc544, uint64(v), uint64(1), Z, Z, Z, Z))))
end

print("[E] lookup by name (540) with and without registration")
for _, attr in ipairs({ 0, 0x100 }) do
    print(string.format("  create(attr=0x%X)    = %s", attr, fmt(call(sc538, P, uint64(attr), Z, Z, Z, Z))))
    print(string.format("  lookup(540)          = %s", fmt(call(sc540, P, Z, Z, Z, Z, Z))))
end

print("")
print("=== 336a DONE ===")
