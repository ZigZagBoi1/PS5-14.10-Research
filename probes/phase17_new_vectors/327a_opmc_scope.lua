-- CRASH_CLASS: LOW
-- PROBE 327a: sys 563-567 (opmc) on the caller's own threads
--
-- Context: sys_563.md..sys_567.md describe a performance-counter subsystem.
-- The selector is interpreted as: 0 = every thread of the current process,
-- 1..99999 = a process id, anything else = a thread id within the current pid.
-- The process-selector path first checks cred+0x58 == 0x4800000000010003 and
-- returns 3 (ESRCH) when it does not match; the zero-selector path has no such
-- check but is scoped to the current pid. 566 writes a caller-supplied u64 to
-- PCB+0x190+8*index (all six for index 0xffffffff) and programs the fixed PMC
-- MSRs; 565 writes an event-select word with reserved bits rejected.
--
-- This measures the paths that need no credential: enable, set, read back, and
-- a nonexistent process id (which must fail at lookup, not at the gate).

print("=== PROBE 327a: OPMC SCOPE ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
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

local sc_432 = make_syscall(432)
local sc_563 = make_syscall(563)
local sc_564 = make_syscall(564)
local sc_565 = make_syscall(565)
local sc_566 = make_syscall(566)
local sc_567 = make_syscall(567)
local Z = uint64(0)

-- [A] the caller's own thread id
local tbuf = memory.alloc(8)
safe_wq(tbuf, Z)
pcall(function() sc_432(uint64(tbuf)) end)
local tid = safe_rd(tbuf) or 0
print(string.format("[A] thr_self = 0x%X", tid))

-- [B] enable on every thread of this process
print(string.format("[B] 563(sel=0)  = %s", call(sc_563, Z, Z, Z, Z)))
print(string.format("[B] 564(sel=0)  = %s", call(sc_564, Z, Z, Z, Z)))

-- [C] set counter and control words for our own thread
print(string.format("[C] 566(tid,0,0x1234) = %s",
    call(sc_566, uint64(tid), uint64(0), uint64(0x1234), Z)))
print(string.format("[C] 566(tid,1,0x5678) = %s",
    call(sc_566, uint64(tid), uint64(1), uint64(0x5678), Z)))
print(string.format("[C] 566(tid,6,...)    = %s",
    call(sc_566, uint64(tid), uint64(6), uint64(0), Z)))
print(string.format("[C] 565(tid,0,0x11)  = %s",
    call(sc_565, uint64(tid), uint64(0), uint64(0x11), Z)))
print(string.format("[C] 565(tid,0,0x10000)= %s (reserved bit)",
    call(sc_565, uint64(tid), uint64(0), uint64(0x10000), Z)))

-- [D] read back
local out = memory.alloc(8)
safe_wq(out, Z)
print(string.format("[D] 567(tid,0) = %s value=0x%016X", call(sc_567, uint64(tid), uint64(0), uint64(out)),
    to_num(safe_rq(out) or 0)))

-- [E] a process id that cannot exist: must fail at lookup
print(string.format("[E] 563(sel=0x7FFFFFFF) = %s", call(sc_563, uint64(0x7FFFFFFF), Z, Z, Z)))
print(string.format("[E] 566(sel=0x7FFFFFFF,0,0) = %s",
    call(sc_566, uint64(0x7FFFFFFF), uint64(0), uint64(0), Z)))
print(string.format("[E] 560 exists after the calls: %s", call(make_syscall(560), Z, Z, Z, Z)))

-- [F] disable again
print(string.format("[F] 564(sel=0)  = %s", call(sc_564, Z, Z, Z, Z)))

print("")
print("=== 327a DONE ===")
