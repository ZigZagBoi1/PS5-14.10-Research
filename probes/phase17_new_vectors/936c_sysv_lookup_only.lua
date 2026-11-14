-- CRASH_CLASS: RISKY
-- PROBE 936c: does the SysV kill depend on the creator path?
--
-- 936a: 221 semget(IPC_PRIVATE, 1, CREAT|0600) killed the process.
-- 936b: 225 msgget(IPC_PRIVATE, CREAT|0600) killed it before any other call.
-- Both were creators. A plain lookup - nonzero key, no IPC_CREAT - should
-- return ENOENT in a working implementation and never allocate anything, so
-- it separates "these handlers fault unconditionally" from "the creation
-- path is what faults".

print("=== PROBE 936c: SYSV LOOKUP ONLY, NO CREATE ===")
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
local function safe_call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, rv = pcall(function() return sc(a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0) end)
    if not ok then return "PCALL-FAIL" end
    return to_num(rv)
end

print("[0] pid=" .. safe_call(20, 0, 0, 0, 0, 0, 0))
print("")

print("[A] msgget(0x1234, 0)      -- lookup, no IPC_CREAT")
print("    -> " .. tostring(safe_call(225, 0x1234, 0, 0, 0, 0, 0)))
print("")

print("[B] semget(0x1234, 1, 0)   -- lookup, no IPC_CREAT")
print("    -> " .. tostring(safe_call(221, 0x1234, 1, 0, 0, 0, 0)))
print("")

print("[C] shmget(0x1234, 0x1000, 0) -- lookup, no IPC_CREAT")
print("    -> " .. tostring(safe_call(231, 0x1234, 0x1000, 0, 0, 0, 0)))
print("")

print("=== COMPLETE ===")
