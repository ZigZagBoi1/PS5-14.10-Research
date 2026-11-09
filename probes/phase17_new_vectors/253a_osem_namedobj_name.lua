-- CRASH_CLASS: MODERATE
-- PROBE 253a: osem and namedobj with a name pointer
--
-- 252a gave -1 for every scalar shape of 549, so the create call is probably
-- taking a name. Two name-taking creators exist in this range: 549 osem_create
-- and 557 namedobj_create. Both are called here with a NUL-terminated string in
-- the first slot and then with the string in the second, so the two ABIs are
-- told apart by which one returns a handle.

print("=== PROBE 253a: name-taking creators ===")
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

local NAME = memory.alloc(0x40)
pcall(function() memory.write_qword(NAME, 0) end)
local tag = "sema"
for i = 1, #tag do
    pcall(function() memory.write_byte(NAME + i - 1, string.byte(tag, i)) end)
end
print("[0] name at " .. q(NAME) .. " pid=" .. tostring(pid()))

local rows = {
    { "549(name)",         549, uint64(NAME), uint64(0), uint64(0) },
    { "549(name,1)",       549, uint64(NAME), uint64(1), uint64(0) },
    { "549(1,name)",       549, uint64(1), uint64(NAME), uint64(0) },
    { "549(name,1,0)",     549, uint64(NAME), uint64(1), uint64(0x10) },
    { "557(name)",         557, uint64(NAME), uint64(0), uint64(0) },
    { "557(name,0,0)",     557, uint64(NAME), uint64(0), uint64(0) },
    { "557(0,name)",       557, uint64(0), uint64(NAME), uint64(0) },
    { "557(NAME,0x10)",    557, uint64(NAME), uint64(0x10), uint64(0) },
}
for i = 1, #rows do
    local r = rows[i]
    print(string.format("    %-16s -> %-24s pid=%s", r[1], q(call(r[2], r[3], r[4], r[5])), tostring(pid())))
end

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 253a COMPLETE ===")
