-- CRASH_CLASS: MODERATE
-- PROBE 891a: gate-free and self-scoped branches found in the 13.60 bodies
--
-- Context: a full inventory of every credential check in the 13.60 decompiles
-- found three argument shapes that reach a handler body with no gate or with
-- the gate skipped:
--   * 586 (narg=1, budget id) returns 0 for arg0 = 0xffffffff with no 0x2ad
--     gate, and pre-loads its retval with `(budget_id - 1) < 3`, i.e. a 0/1
--     oracle on a kernel proc field (sys_586.c:150-170).
--   * 559 (narg=1, scheduler class) likewise skips the gate for 0xffffffff and
--     returns 0 without writing (sys_559.c:577-620).
--   * 616 (narg=2) looks the passed pid up scoped to the caller FIRST and only
--     runs the cred+0x60 bit-62 capability test when that scoped lookup fails
--     (sys_616.c:32-53, :95-99) -- a self-scoped pid short-circuits the check.
--
-- What we measure: does the 14.10 handler behave like the 13.60 body, and does
-- the 586 oracle answer. A 0/1 that tracks a value we cannot otherwise read is
-- a one-bit kernel oracle; a skipped gate is only interesting if the body then
-- does something observable, so each call is followed by a state check.

print("=== PROBE 891a: GATE-FREE BRANCHES (586/559/616) ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function show(tag, ok, rv)
    if not ok then
        print(string.format("  [%s] PCALL-FAIL", tag))
        return
    end
    local h, l = get_hi_lo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X", tag, h, l))
end

local sc20 = make_syscall(20)
local pid = 0
repeat
    local ok, rv = pcall(function() return sc20() end)
    if ok then pid = to_num(rv) end
until true
print(string.format("[A] self pid = %u", pid))

-- B. 586: budget id setter with a 0/1 retval oracle
local sc586 = make_syscall(586)
print("[B] 586 budget-id oracle:")
for _, v in ipairs({ 0xFFFFFFFF, 0, 1, 2, 3, 4 }) do
    local ok, rv = pcall(function() return sc586(uint64(v)) end)
    show(string.format("586(0x%X)", v), ok, rv)
end

-- C. 559: scheduler class setter, same shape
local sc559 = make_syscall(559)
print("[C] 559 scheduler class:")
for _, v in ipairs({ 0xFFFFFFFF, 0, 1, 2, 3 }) do
    local ok, rv = pcall(function() return sc559(uint64(v)) end)
    show(string.format("559(0x%X)", v), ok, rv)
end

-- D. 616: the capability test is skipped for a self-scoped pid. Last because
-- the body's effect is unknown.
local sc616 = make_syscall(616)
print("[D] 616 self-scoped pid vs foreign pid:")
for _, pair in ipairs({ { pid, 0 }, { pid, 1 }, { pid, 0x40000000 }, { pid + 1, 0 } }) do
    local ok, rv = pcall(function()
        return sc616(uint64(pair[1]), uint64(pair[2]))
    end)
    show(string.format("616(%d, 0x%X)", pair[1], pair[2]), ok, rv)
end

print("")
print("=== PROBE 891a DONE ===")
