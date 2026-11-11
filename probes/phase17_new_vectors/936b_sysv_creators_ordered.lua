-- CRASH_CLASS: RISKY
-- PROBE 936b: the SysV creators one at a time, simplest first
--
-- 936a proved that 221 semget dies even with a valid shape
-- (IPC_PRIVATE, 1, IPC_CREAT|0600) - the process stopped on the [A] line.
-- Ordering here is deliberate: the two-argument creator first, then shmget,
-- then semget last, so a kill still buys information about the earlier ones.
--
-- 624 is the VM-operation counter (probe 52b); it shows whether an object was
-- really allocated even when the call returns an error.

print("=== PROBE 936b: SYSV CREATORS, ONE AT A TIME ===")
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
local function vm()
    local rv = safe_call(624, 0, 0, 0, 0, 0, 0)
    if rv == "PCALL-FAIL" then return -1 end
    return rv
end

local FLAGS = 0x380

print("[0] pid=" .. safe_call(20, 0, 0, 0, 0, 0, 0) .. " vm=" .. vm())
print("")

print("[A] msgget(IPC_PRIVATE, 0x380)")
local v0 = vm()
local msg = safe_call(225, 0, FLAGS, 0, 0, 0, 0)
print("    -> " .. tostring(msg) .. "  vm " .. v0 .. " -> " .. vm())
print("")

print("[B] shmget(IPC_PRIVATE, 0x1000, 0x380)")
local v1 = vm()
local shm = safe_call(231, 0, 0x1000, FLAGS, 0, 0, 0)
print("    -> " .. tostring(shm) .. "  vm " .. v1 .. " -> " .. vm())
print("")

if type(shm) == "number" and shm >= 0 then
    print("[C] shmat(" .. shm .. ", NULL, 0)")
    local addr = safe_call(228, shm, 0, 0, 0, 0, 0)
    print("    -> " .. tostring(addr))
    print("")
end

print("[D] semget(IPC_PRIVATE, 1, 0x380)   [936a died here]")
local sem = safe_call(221, 0, 1, FLAGS, 0, 0, 0)
print("    -> " .. tostring(sem))
print("")

print("=== COMPLETE ===")
