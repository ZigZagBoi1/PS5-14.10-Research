-- CRASH_CLASS: MODERATE -- out-of-range syscall numbers, 677..750, with SIGSYS ignored.
-- PROBE 1378a: does SIG_IGN turn the "past the end" kills into ENOSYS?
--
-- The presence sweep that produced docs/SYSENT_PRESENCE_14_10.md called 677..707 with six
-- zeros and every one of them killed the process, which was read as "the table ends at 676".
-- That sweep did NOT install SIG_IGN for SIGSYS, so a kill there proves the caller died on
-- the signal -- the same signal an absent slot raises. The 13.60 CSV, however, resolves
-- 677..694 and 700..734 to real code (53 real, 695-699 nosys), and slot 728 is
-- `virtual_query_by_pid`, which on a system pid would be a VM-map reader we have never
-- been able to reach.
--
-- With SIG_IGN installed, an absent slot returns -1/ENOSYS instead of dying (353a/353b),
-- so this run can tell the two cases apart:
--
--   4095 is the control. It cannot have a handler (the loader's own resolver kills on it),
--   so if 4095 answers -1 here the test is valid.
--
--   any number that answers something ELSE is a real handler the sweep never measured.
--
-- Every number is printed before its call, so a kill names itself in the capture.
--
-- -- prior art:
--   results/phase15_native_sent/syscall_isolation_sweep_20261020_*.txt (677-707 kills, no SIG_IGN)
--   results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101254.txt (SIG_IGN method)
--   docs/SYSENT_PRESENCE_14_10.md ("The table ends at 676"), docs/sysent-names-13.60.csv
--   docs/SYSCALL_ABSENT_VS_LETHAL.md (a kill is a result about the call)

print("=== PROBE 1378a: SYSCALLS 677-750 WITH SIGSYS IGNORED ===")

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
local function U(hi, lo) return uint64(string.format("0x%X%08X", hi, lo)) end
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "?"
end
local mk = make_syscall

local SIG = {5, 6, 7, 8, 12, 24, 25, 26, 30, 31}
local sa = memory.alloc(0x80)
for i = 0, 0x7C, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
local ign = 0
for i = 1, #SIG do
    local ok, rv = pcall(function() return mk(416)(uint64(SIG[i]), uint64(sa), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok and to_num(rv) == 0 then ign = ign + 1 end
end
print(string.format("[0] pid=%d sigign=%d/%d", to_num(mk(20)(U(0,0),U(0,0),U(0,0),U(0,0),U(0,0),U(0,0))), ign, #SIG))

local BUF = memory.alloc(0x4000)
local B1 = to_num(BUF)
pcall(function() memory.write_buffer(BUF, string.rep(string.char(0xA5), 0x1000)) end)

local function call(n, a1)
    local sc = make_syscall(n)
    local ok, rv = pcall(function() return sc(a1, U(0,0), U(0,0), U(0,0), U(0,0), U(0,0)) end)
    if not ok then return "EXC" end
    return to_num(rv)
end
local function line(n, a1, tag)
    local rv = call(n, a1)
    if rv == "EXC" then
        print(string.format("  %s n=%d EXC", tag, n))
        return "EXC"
    elseif rv == -1 then
        print(string.format("  %s n=%d rv=-1 errno=%s", tag, n, es()))
        return "ENOSYS"
    else
        local changed = 0
        local ok, s = pcall(function() return memory.read_buffer(BUF, 0x1000) end)
        if ok and type(s) == "string" and #s == 0x1000 then
            for i = 1, 0xFFD, 4 do
                local a, b, c, d = string.byte(s, i, i + 3)
                if not (a == 0xA5 and b == 0xA5 and c == 0xA5 and d == 0xA5) then changed = changed + 1 end
            end
        end
        print(string.format("  %s n=%d rv=%d wrote=%d", tag, n, rv, changed))
        return "OK"
    end
end

print("[A] control: 4095 has no handler")
print("c4095")
line(4095, U(0, 0), "C")

print("[B] 677-750 with six zeros")
local real = {}
for n = 677, 750 do
    print("s" .. n)
    local r = line(n, U(0, 0), "Z")
    if r ~= "ENOSYS" then real[#real + 1] = n end
end

if #real > 0 then
    print("[C] the non-ENOSYS numbers, arg1 = mapped page")
    for i = 1, #real do
        print("t" .. real[i])
        line(real[i], U(0, B1), "P")
    end
else
    print("[C] nothing outside ENOSYS")
end

print("=== PROBE 1378a COMPLETE ===")
