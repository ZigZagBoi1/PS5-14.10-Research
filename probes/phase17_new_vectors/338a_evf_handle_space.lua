-- CRASH_CLASS: LOW
-- PROBE 338a: does the evf family validate the handle it is given?
--
-- 336a created evf objects (handles 518-521 and a first-call 16901) and 544
-- set / 545 clear / 546 cancel all returned 0 for one of them, so the handle is
-- real and the family acts on it. The handles are small integers in a
-- process-local namespace (process+0xc48). This walks a range of candidate
-- values through 544 (OR bits into the object pattern) and 545 (AND the
-- pattern) and prints every answer, to see whether a value the caller never
-- received is rejected (missing handle returns 3 per the dossier) or acted on.
-- A value that answers 0 without ever being created is a handle the caller does
-- not own.

print("=== PROBE 338a: EVF HANDLE SPACE ===")
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
local sc538 = make_syscall(538)
local sc544 = make_syscall(544)
local sc545 = make_syscall(545)
local sc546 = make_syscall(546)
local P = uint64(PAGE)

print("[A] create one real handle")
local mine = call(sc538, P, Z, Z, Z, Z, Z)
print(string.format("  create = %s", fmt(mine)))

print("[B] 544 set / 545 clear against candidate handles")
local CAND = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64, 128, 255, 256, 511, 512,
               516, 517, 518, 519, 520, 521, 522, 0x4205, 0x10000, 0x7FFFFFFF }
for _, v in ipairs(CAND) do
    local set = call(sc544, uint64(v), uint64(1), Z, Z, Z, Z)
    local clr = call(sc545, uint64(v), Z, Z, Z, Z, Z)
    local can = call(sc546, uint64(v), Z, Z, Z, Z, Z)
    local mark = ""
    if mine and v == mine then mark = "  <- mine" end
    print(string.format("  h=%-10d set=%-4s clear=%-4s cancel=%-4s%s",
        v, fmt(set), fmt(clr), fmt(can), mark))
end

print("")
print("=== 338a DONE ===")
