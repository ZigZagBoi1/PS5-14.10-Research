-- CRASH_CLASS: MODERATE
-- PROBE 354f: the tail of the table, 523-676, under SIG_IGN
--
-- Every "lethal" syscall measured so far turned out to be the shared nosys
-- trampoline raising SIGSYS: 561, 562, 568, 569, 570, 571, 573, 621, 631, 650,
-- 651, 661, 665, 668 (353a/353b/354a). With SIGSYS ignored, an absent slot
-- returns -1 and the process lives.
--
-- That makes a single ascending walk over 400-676 decisive: the first number
-- that still terminates the process is a real handler that faults on six zero
-- arguments, and there is no other explanation left. If the walk completes, the
-- table holds no handler that dies on zeros, and the presence map's "kills"
-- column becomes "absent".
--
-- 450-676 by six zeros, starting after the threading range: 430 (thr_create)
-- with a zero context parks the caller for good, which is how the first run of
-- this probe ended. 400-449 was covered separately (probe 354c).

print("=== PROBE 354f: THE TAIL 523-676 ===")
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

local sa = memory.alloc(0x80)
local old = memory.alloc(0x80)
for i = 0, 0x70, 8 do
    wq(sa + i, 0)
    wq(old + i, 0)
end
wq(sa + 0, 1)
wd(sa + 8, 0)
local okI, rvI = pcall(function()
    return make_syscall(416)(uint64(12), uint64(sa), uint64(old))
end)
print(string.format("[A] sigaction(12, SIG_IGN) -> %s", okI and tostring(sgn(rvI)) or "EXC"))
if not (okI and sgn(rvI) == 0) then
    print("    cannot ignore SIGSYS; stopping")
    print("=== 354f DONE ===")
    return
end

print("[B] 523..676, the number is printed BEFORE the call so a death or a block names it")
print("    522 pselect is excluded: it is the slot that blocked the 456-500 walk")
local counts = {neg1 = 0, other = 0}
local interesting = {}
for num = 523, 676 do
    do
        if num % 20 == 0 then print(string.format("  trying %d", num)) end
        local ok, rv = pcall(function()
            return make_syscall(num)(Z, Z, Z, Z, Z, Z)
        end)
        if ok then
            local v = sgn(rv)
            if v == -1 then
                counts.neg1 = counts.neg1 + 1
            else
                counts.other = counts.other + 1
                interesting[#interesting + 1] = string.format("%d=%d", num, v)
                print(string.format("  sys %d = %d  (returned)", num, v))
            end
        else
            print(string.format("  sys %d = EXC", num))
        end
    end
end

print(string.format("[C] -1: %d   other: %d", counts.neg1, counts.other))
if #interesting > 0 then
    print("    non -1: " .. table.concat(interesting, " "))
end

print("[D] restoring the disposition")
pcall(function()
    return make_syscall(416)(uint64(12), uint64(old), Z)
end)

print("")
print("=== 354f DONE ===")
