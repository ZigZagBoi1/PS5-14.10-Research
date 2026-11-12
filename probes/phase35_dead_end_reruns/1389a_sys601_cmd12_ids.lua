-- CRASH_CLASS: MODERATE -- 0x12 is non-lethal in all eight shapes measured so far; the struct
-- values below are identifiers, not pointers, so the worst expected outcome is another ENOENT.
-- PROBE 1389a: 601 cmd 0x12 - the copyin succeeds and then a LOOKUP fails, so feed it identifiers.
--
-- 1388a (results/phase35_dead_end_reruns/1388a_sys601_cmd12_consumer_20261109_140806.txt) walked
-- the arg1 x arg2 x arg3 = {0,page} cube for 0x10/0x12/0x13/0x14/0x15 and produced a clean map:
--
--   0x12 arg2=0                       -> EFAULT(14)   the copyin source must be a pointer
--   0x12 arg2=page, arg1=page         -> EINVAL(22)   arg1 must be zero
--   0x12 arg2=page, arg1=0, arg3=0|p  -> ENOENT(2)    copyin succeeded, then a lookup failed
--
-- ENOENT is new. Every earlier 0x12 attempt either had no pointer in arg2 (1355a sent arg1=0,
-- arg2=struct - that is the shape that now returns ENOENT) or put a pointer in arg1 (1348a/1384a
-- -> EINVAL). The 13.60 body copies 0x20 bytes in from arg2 and then stores two qwords from that
-- block into [proc+0x578]/[proc+0x580]; a name/id lookup between the copyin and the store would
-- explain why a block of 0x5A bytes answers ENOENT rather than storing garbage.
--
-- So this probe feeds the 0x20-byte block identifiers instead of paint: our pid, our thread id,
-- zeros, 1, small integers, and the same values in the second qword and in the dword slots, plus
-- two shapes where a qword is a mapped user pointer. Any rv=0 is followed by the consumer sweep:
-- every non-lethal 601 command with arg1 = a 0x800 output page, looking for the 0x480-byte
-- copyout of [proc+0x578] (results/kernel_handlers/asm/sys_601_deep.asm, ca1b8b).
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1388a_sys601_cmd12_consumer_20261109_140806.txt
--   results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt
--   results/kernel_handlers/asm/sys_601_deep.asm (ca0de6 store block, ca1b8b copyout + kfree)

print("=== PROBE 1389a: 601 cmd 0x12 IDENTIFIER FEED ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hex(v) v = v % 4294967296 return string.format("%08X", v) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
local TID = N(mk(432)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d tid=0x%08X", PID, TID))

-- SIG_IGN so an absent slot answers ENOSYS instead of raising SIGSYS
local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
local ign = 0
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    local ok, rv = pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
    if ok and N(rv) == 0 then ign = ign + 1 end
end
print(string.format("[0] SIG_IGN installed on %d/10 signals", ign))

local S = memory.alloc(0x40)
local SP = N(S)
local PAGE = memory.alloc(0x800)
local PP = N(PAGE)
local OUT = memory.alloc(0x800)
local OP = N(OUT)
local PAINT_OUT = string.rep(string.char(0xA5), 0x800)

local sc = mk(601)

local function paint_struct()
    for i = 0, 0x1F, 4 do wd(S + i, 0) end
end

local function scan_changed(base, words, sentinel)
    local n, acc = 0, {}
    for i = 0, words - 1 do
        local v = rd(base + i * 4)
        if v and v ~= sentinel then
            n = n + 1
            if #acc < 8 then acc[#acc + 1] = hex(v) end
        end
    end
    return n, table.concat(acc, " ")
end

local function call6(cmd, a1, a2, a3)
    local ok, rv = pcall(function()
        return sc(uint64(cmd), uint64(a1), uint64(a2), uint64(a3), uint64(0), uint64(0))
    end)
    return ok and N(rv) or -99999
end

-- every shape writes the 0x20-byte block, then calls 0x12 with arg1=0 and arg2=the block
local SHAPES = {
    {"q0=pid",            PID, 0, 0, 0},
    {"q1=pid",            0, PID, 0, 0},
    {"q0=tid",            TID, 0, 0, 0},
    {"q1=tid",            0, TID, 0, 0},
    {"all zero",          0, 0, 0, 0},
    {"q0=1",              1, 0, 0, 0},
    {"q0=2",              2, 0, 0, 0},
    {"q0=pid q1=1",       PID, 1, 0, 0},
    {"q0=pid q1=pid",     PID, PID, 0, 0},
    {"q0=pid q1=0x1000",  PID, 0x1000, 0, 0},
    {"q0=pid ptr@q1",     PID, 0, 0, 0},
    {"q0=0x20 q1=ptr",    0x20, 0, 0, 0},
}

print("")
print("[A] 601(0x12, 0, block) with identifiers in the 0x20-byte block")
for _, t in ipairs(SHAPES) do
    paint_struct()
    wd(S + 0, t[2])
    wd(S + 4, 0)
    wd(S + 8, t[3])
    wd(S + 12, 0)
    wd(S + 16, t[4])
    wd(S + 20, 0)
    wd(S + 24, t[5])
    wd(S + 28, 0)
    local rv = call6(0x12, 0, SP, 0)
    local e = es()
    print(string.format("  %-18s rv=%-8d %s", t[1], rv, e))
    if rv == -99999 then print("  [FATAL] did not return"); return end
end

-- two shapes where a qword is a real user pointer, in case the block is {id, pointer}
print("")
print("[B] 601(0x12, 0, block) with a user pointer inside the block")
local PTR_SHAPES = {
    {"q0=pid q1=pq0",  PID, PP, 0},
    {"q0=pid q2=ptr",  PID, 0, PP},
    {"q0=size q1=ptr", 0x20, PP, 0},
    {"q0=ptr",         PP, 0, 0},
}
for _, t in ipairs(PTR_SHAPES) do
    paint_struct()
    wd(S + 0, t[2])
    wd(S + 4, 0)
    wd(S + 8, t[3])
    wd(S + 12, 0)
    wd(S + 16, t[4])
    wd(S + 20, 0)
    local rv = call6(0x12, 0, SP, 0)
    local e = es()
    print(string.format("  %-18s rv=%-8d %s", t[1], rv, e))
    if rv == -99999 then print("  [FATAL] did not return"); return end
end

-- retry the two ENOENT shapes with the block in the other two slots, in case arg2 is not the
-- copyin source on 14.10 (the errno map says it is, but the check is free)
print("")
print("[C] slot check: identical block in arg1 and in arg3")
paint_struct()
wd(S + 0, PID)
local rvC = call6(0x12, SP, 0, SP)
print(string.format("  0x12 a1=S a3=S      rv=%-8d %s", rvC, es()))
if rvC == -99999 then print("  [FATAL] did not return"); return end

-- if anything returned 0 there may now be a planted pointer at [proc+0x578]; find its consumer
print("")
print("[D] consumer sweep (runs regardless; prints every non-lethal command with an output page)")
local SKIP = {[0x03]=true, [0x04]=true, [0x08]=true, [0x0C]=true, [0x11]=true, [0x1B]=true, [0x27]=true}
for cmd = 0x00, 0x1A do
    if not SKIP[cmd] then
        pcall(function() memory.write_buffer(OUT, PAINT_OUT) end)
        local rv = call6(cmd, OP, 0, 0)
        local e = es()
        local n, first = scan_changed(OP, 0x120, 0xA5A5A5A5)
        print(string.format("  0x%02X a1  rv=%-8d %-26s changed=%-4d %s", cmd, rv, e, n, first))
        if rv == -99999 then print("  [FATAL] did not return"); return end
    end
end

print("=== PROBE 1389a COMPLETE ===")
