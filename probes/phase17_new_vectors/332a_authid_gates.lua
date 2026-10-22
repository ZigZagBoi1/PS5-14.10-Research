-- CRASH_CLASS: LOW
-- PROBE 332a: the authid gates, called with this process's own pid
--
-- Six handlers check cred+0x58 against identity values before doing work:
-- 535 and 536 (dynamic-linker list by pid) and 563-566 (performance counters).
-- The dossier says the failed check answers 3 (ESRCH) so the call looks like a
-- missing process. Probes so far used selector 0, which skips the check, so the
-- gate itself has never been tested from a game process. This calls each one
-- with our own pid and records the answer, plus 587 with the same pid.

print("=== PROBE 332a: AUTHID GATES ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then return l - 0x100000000 end
    return l
end
local function lo_of(v)
    local h, l = get_hi_lo(v)
    return to_num(l), to_num(h)
end
local function call(sc, a, b, c, d)
    local ok, rv = pcall(function() return sc(a, b, c, d) end)
    if not ok then return "RAISED" end
    return tostring(sgn(lo_of(rv)))
end

local pid = -1
do
    local ok, rv = pcall(function() return make_syscall(20)(uint64(0)) end)
    if ok then pid = sgn(lo_of(rv)) end
    print(string.format("[A] getpid(20) = %d", pid))
end

local BUF = memory.alloc(0x400)
local CNT = memory.alloc(8)
safe_wq(CNT, uint64(0))
for i = 0, 0x400 - 8, 8 do safe_wq(BUF + i, uint64(0)) end

print("")
print("[B] performance counters with a process selector")
print(string.format("  563(pid)          = %s", call(make_syscall(563), uint64(pid), uint64(0), uint64(0), uint64(0))))
print(string.format("  564(pid)          = %s", call(make_syscall(564), uint64(pid), uint64(0), uint64(0), uint64(0))))
print(string.format("  565(pid,0,0x11)   = %s", call(make_syscall(565), uint64(pid), uint64(0), uint64(0x11), uint64(0))))
print(string.format("  566(pid,0,0x1234) = %s", call(make_syscall(566), uint64(pid), uint64(0), uint64(0x1234), uint64(0))))

print("")
print("[C] dynamic-linker list by pid")
print(string.format("  535(pid,buf,0x80,count) = %s count=%s",
    call(make_syscall(535), uint64(pid), uint64(BUF), uint64(0x80), uint64(CNT)),
    tostring(safe_rd(CNT))))
safe_wq(CNT, uint64(0))
print(string.format("  536(pid,buf,0x80,count) = %s count=%s",
    call(make_syscall(536), uint64(pid), uint64(BUF), uint64(0x80), uint64(CNT)),
    tostring(safe_rd(CNT))))

print("")
print("[D] credential dump for our own pid")
for i = 0, 0x400 - 8, 8 do safe_wq(BUF + i, uint64(0)) end
print(string.format("  587(pid,buf) = %s", call(make_syscall(587), uint64(pid), uint64(BUF), uint64(0), uint64(0))))
for i = 0, 0x80 - 4, 4 do
    local v = safe_rd(BUF + i)
    if v and v ~= 0 then
        print(string.format("    +0x%02X = 0x%08X", i, v))
    end
end

print("")
print("=== 332a DONE ===")
