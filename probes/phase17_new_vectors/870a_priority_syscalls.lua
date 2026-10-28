-- CRASH_CLASS: MODERATE
-- PROBE 870a: can this process raise a thread's scheduling priority?
--
-- The aio delete window (unlock 0x3afe67 -> re-lookup 0x3afe7c) only opens if the
-- winner is descheduled inside it.  A real-time or higher-priority waiter woken
-- by the unlock preempts the winner immediately, which is the one mechanism the
-- 16-thread barrier could not produce.  That needs a schedulable priority:
-- setpriority (146), rtprio (166) or sched_setscheduler-shaped numbers.
--
-- Every candidate runs under a SIGSYS-ignoring shield, so an absent handler
-- returns -1 instead of killing the process.
print("=== PROBE 870a: priority syscalls ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=to_num(a) return uint64(string.format("0x%08X%08X", math.floor(a/4294967296), a%4294967296)) end
local function sgn(v) v=to_num(v); if v >= 0x80000000 and v <= 0xFFFFFFFF then return v-0x100000000 end
    if v >= 0x8000000000000000 then return v - 18446744073709551616 end return v end
local pid = to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
print("[0] pid=" .. tostring(pid) .. " cpu_count=16")
-- shield
local sa = memory.alloc(0x40)
for i=0,0x3F do memory.write_byte(sa+i,0) end
memory.write_dword(sa, 1)            -- SIG_IGN
pcall(function() mk(416)(U(12), U(sa), U(0), U(0)) end)  -- sigaction(SIGSYS, ign)
print("[A] shield set")
local tids = {0, -1, 1, pid}
local cases = {
    {146, "setpriority(PRIO_PROCESS, who, -20)"},
    {166, "rtprio(RTP_SET, who, rtprio)"},
    {167, "rtprio_thread(RTP_SET, lwpid, rtprio)"},
    {346, "sched_setscheduler?"},
    {351, "sched_setscheduler?"},
    {352, "sched_setparam?"},
}
for _, c in ipairs(cases) do
    local n, label = c[1], c[2]
    local row = {}
    for _, who in ipairs(tids) do
        local ok, r = pcall(function() return mk(n)(U(0), U(who), U(0xFFFFFFFF), U(0), U(0), U(0)) end)
        row[#row+1] = string.format("who=%s:%s", tostring(who), ok and tostring(sgn(r)) or "THROW")
    end
    print(string.format("[%d] %s  %s", n, label, table.concat(row, " ")))
end
print("[Z] alive pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
