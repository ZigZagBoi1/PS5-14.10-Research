-- CRASH_CLASS: RISKY
-- PROBE 936a: can the SysV IPC creators be reached with valid arguments?
--
-- The isolation sweep (results/phase15_native_sysent/syscall_isolation_sweep_20261029_233635.txt)
-- killed the process on 221 semget, 222 semop, 225 msgget, 226 msgsnd, 227 msgrcv,
-- 228 shmat, 230 shmdt and 231 shmget when every register held zero, while
-- 220/223/224/229 (the compat entry points) returned -1. Six zeros are not a
-- valid shape for any of them, so this probe sends the real shape: key
-- IPC_PRIVATE, one object, flags IPC_CREAT|0600 = 0x380.
--
-- 13.60 names, for reference (docs/sysent-names-13.60.csv):
--   220 compat7.__semctl  221 semget    222 semop   223 (unnamed)
--   224 compat7.msgctl    225 msgget    226 msgsnd  227 msgrcv
--   228 shmat              229 compat7.shmctl  230 shmdt  231 shmget
--   510 __semctl           511 msgctl   512 shmctl

print("=== PROBE 936a: SYSV IPC CREATORS ===")
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
local function vm_count()
    local rv = safe_call(624, 0, 0, 0, 0, 0, 0)
    if rv == "PCALL-FAIL" then return -1 end
    return rv
end

local IPC_PRIVATE = 0
local FLAGS       = 0x380   -- IPC_CREAT (0x200) | 0600 (0x180)

print("[0] pid=" .. safe_call(20, 0, 0, 0, 0, 0, 0) .. " vm=" .. vm_count())
print("")

print("[A] semget(IPC_PRIVATE, 1, 0x380) ...")
local sem = safe_call(221, IPC_PRIVATE, 1, FLAGS, 0, 0, 0)
print("    semget -> " .. tostring(sem))
print("")

print("[B] msgget(IPC_PRIVATE, 0x380) ...")
local msg = safe_call(225, IPC_PRIVATE, FLAGS, 0, 0, 0, 0)
print("    msgget -> " .. tostring(msg))
print("")

print("[C] shmget(IPC_PRIVATE, 0x1000, 0x380) ...")
local before = vm_count()
local shm = safe_call(231, IPC_PRIVATE, 0x1000, FLAGS, 0, 0, 0)
local after = vm_count()
print("    shmget -> " .. tostring(shm) .. "  vm " .. before .. " -> " .. after)

if type(shm) == "number" and shm >= 0 then
    print("")
    print("[D] shmat(shm, NULL, 0) ...")
    local addr = safe_call(228, shm, 0, 0, 0, 0, 0)
    print("    shmat -> " .. tostring(addr))
end

print("")
print("=== COMPLETE ===")
