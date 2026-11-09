-- CRASH_CLASS: LOW
-- Bounded 14.10 gate for the five IDs compared by the retained 13.60
-- syscall 605 handler. No pointers or writes are supplied by this probe.

print("=== PROBE 112b: syscall 605 whitelist gate ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function u64(n)
    return uint64(string.format("0x%08X", n))
end
local s = make_syscall(605)
local gp = make_syscall(20)
print("pid=" .. tostring(to_num(gp(u64(0)))))
local cases = {
    {0x00000000, "invalid_zero"},
    {0x19810000, "id_19810000"},
    {0x3CC80700, "id_3CC80700"},
    {0x78026400, "id_78026400"},
    {0x78028300, "id_78028300"},
    {0x78028A00, "id_78028A00"},
    {0x78028A01, "invalid_neighbor"},
}
for _, item in ipairs(cases) do
    local ok, rv = pcall(function() return s(u64(item[1])) end)
    print(string.format("%s arg=0x%08X ok=%s rv=%s", item[2], item[1], tostring(ok), ok and tostring(to_num(rv)) or tostring(rv)))
end
print("canary_pid=" .. tostring(to_num(gp(u64(0)))))
print("=== PROBE 112b COMPLETE ===")
