-- CRASH_CLASS: LOW
-- PROBE 353a: the lethal syscalls are the nosys trampoline delivering SIGSYS
--
-- Five slots whose dossiers all decode to the same body - 561, 562, 631, 650,
-- 651 - are the shared nosys trampoline: lock the process, build a signal
-- record with number 12 (SIGSYS) and code 0x10006, deliver it, return 78
-- (ENOSYS). Every one of them terminates the process when called, which is what
-- an uncaught SIGSYS does by default.
--
-- If that reading is right, ignoring SIGSYS makes them return 78 instead of
-- dying, and the same test says whether 665/668 and 661 - the AIO single submit -
-- are the same trampoline or real handlers that fault.
--
-- sigaction is 416 on this kernel (probe 22). SIG_IGN is the value 1.

print("=== PROBE 353a: SIGSYS AND THE LETHAL SLOTS ===")
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
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local Z = uint64(0)
local function wd(addr, value)
    pcall(function() memory.write_dword(addr, value) end)
end
local function wq(addr, value)
    pcall(function() memory.write_qword(addr, value) end)
end
local function rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return -999
end

local SIGSYS = 12
local new_sa = memory.alloc(0x80)

-- [] sigaction(12, NULL, old) first, to see what is there
local before = memory.alloc(0x80)
for i = 0, 0x70, 8 do wq(before + i, 0xDEADDEADDEADDEAD) end
local ok0, rv0 = pcall(function()
    return make_syscall(416)(uint64(SIGSYS), uint64(0), uint64(before))
end)
print(string.format("[A] sigaction(12, NULL, old) -> %s", ok0 and tostring(sgn(rv0)) or "EXC"))
print(string.format("    old handler = %08X %08X  flags = %08X",
    rd(before + 4), rd(before), rd(before + 8)))

-- [B] install SIG_IGN for SIGSYS
for i = 0, 0x70, 8 do wq(new_sa + i, 0) end
wq(new_sa + 0, 1)          -- SIG_IGN
wd(new_sa + 8, 0)          -- no flags
local old_keep = memory.alloc(0x80)
local okB, rvB = pcall(function()
    return make_syscall(416)(uint64(SIGSYS), uint64(new_sa), uint64(old_keep))
end)
print(string.format("[B] sigaction(12, SIG_IGN, old) -> %s", okB and tostring(sgn(rvB)) or "EXC"))
print(string.format("    the handler that was there: %08X %08X", rd(old_keep + 4), rd(old_keep)))

-- [C] the slots that used to be lethal, one call each, all zero arguments
local function try(num)
    local ok, rv = pcall(function()
        return make_syscall(num)(Z, Z, Z, Z, Z, Z)
    end)
    if ok then
        print(string.format("  sys %d(0 x6) = %d", num, sgn(rv)))
    else
        print(string.format("  sys %d(0 x6) = EXC", num))
    end
end

print("[C] with SIGSYS ignored")
try(562)
print("    -- 562 returned, so the process is still here --")
try(650)
try(651)
try(665)
try(668)
print("[D] 631, a fifth slot with the same body")
try(631)
print("[E] 661, the AIO single submit")
try(661)

print("[F] restoring the previous disposition")
local okF, rvF = pcall(function()
    return make_syscall(416)(uint64(SIGSYS), uint64(old_keep), Z)
end)
print(string.format("    sigaction(12, previous, NULL) -> %s", okF and tostring(sgn(rvF)) or "EXC"))

print("")
print("=== 353a DONE ===")
