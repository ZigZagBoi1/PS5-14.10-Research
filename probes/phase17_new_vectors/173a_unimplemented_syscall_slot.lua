-- CRASH_CLASS: HIGH (expected to kill the process if the hypothesis holds)
-- PROBE 173a: what does an unimplemented syscall number do?
--
-- Seven numbers now terminate the process on 14.10: 307, 308, 337, 570, 661,
-- 665 and 668. Two of those (665, 668) are nosys stubs in the 13.60 capture and
-- the rest are FreeBSD facilities a game console has no reason to implement
-- (kldnext, kldstat, kldsym, sysctlbyname). A stub that returns ENOSYS cannot
-- terminate its caller, so the deaths do not look like seven hostile handlers;
-- they look like one shared response to an unimplemented slot.
--
-- This probe calls numbers that are almost certainly past the end of the table
-- (1000, 1500, 4095) with six zero arguments. If those kill too, the rule is
-- "unimplemented slot terminates the caller", which also explains 665 and 668
-- without any 13.60/14.10 divergence.
--
-- The first kill ends the connection, so the numbers are ordered with the
-- least plausible one first and a canary printed between each.

print("=== PROBE 173a: UNIMPLEMENTED SYSCALL SLOT ===")

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

local sc20 = make_syscall(20)
print("[0] canary pid=" .. tostring(to_num(sc20())))

local function call(num)
    local sc = make_syscall(num)
    print("[*] BEFORE sys " .. tostring(num))
    local ok, rv = pcall(function()
        return sc(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    local hi, lo = 0, 0
    if ok then hi, lo = get_hi_lo(rv) end
    print(string.format("[*] AFTER  sys %d ok=%s ret=0x%08X%08X", num, tostring(ok), hi, lo))
end

call(4095)
call(1500)
call(1000)

print("[3] canary after: ok=true pid=" .. tostring(to_num(sc20())))
print("=== PROBE 173a DONE ===")
