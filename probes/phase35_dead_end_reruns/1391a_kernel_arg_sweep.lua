-- CRASH_CLASS: MODERATE -- kernel addresses are only ever copied from; every lethal number from
-- 1342a stays on the skip list, and the probe stops at the first call that does not return.
-- PROBE 1391a: the K-class argument sweep - a MAPPED kernel address in every pointer slot.
--
-- 1342a (docs/ARG1_CLASSES_14_10.md) swept arg1 over 131 of the 145 numbers in 532..676 with two
-- classes: N (null) and U (a mapped user page). The K class - a mapped supervisor page - was only
-- ever tried on eleven numbers, all of which refused it with EFAULT/EINVAL/ESRCH. That is the
-- weakest coverage in the argument-class matrix, and it is the one that matters: a handler that
-- copies OUT of a kernel address instead of out of a kernel buffer is an instant kernel read.
--
-- The presence oracle (results/1331a_20261109_141053.txt) puts this boot's image at
-- 0xFFFFFFFFC1000000, present samples through 0xFFFFFFFFC6C00000, and the stub page at
-- 0xFFFFFFFFC0000000; 0xFFFFFFFFD0000000 is absent. Three mapped pages and one absent page go into
-- every pointer slot, and any number whose answer differs between a mapped and an absent kernel
-- address is flagged - that difference is the signature of a dereference.
--
-- Kernel addresses are carried as STRINGS and converted with uint64("0x...") at the call site.
-- Converting 0xFFFFFFFFC1000000 to a Lua number loses precision (it is above 2^53), which would
-- silently probe the wrong page.
--
-- Phase B repeats the idea for the command dispatchers, whose pointer slots are not arg1:
--   532(cmd, arg1, out_ptr, in_ptr, size, 0)   with out_ptr / in_ptr = kernel pages
--   601(cmd, arg1, arg2, arg3, 0, 0)           with arg1 / arg2 = kernel pages
--
-- -- prior art:
--   docs/ARG1_CLASSES_14_10.md (the N/U matrix and the eleven-number K pass)
--   results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101254.txt (skip list)
--   results/1331a_20261109_141053.txt (this boot's present/absent map)
--   docs/FAULT_CODE_ORACLE_14_10.md (the oracle itself)

print("=== PROBE 1391a: KERNEL-ADDRESS ARGUMENT SWEEP ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hex(v) v = v % 4294967296 return string.format("%08X", v) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function UA(v) if type(v) == "string" then return uint64(v) end return uint64(v) end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

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

local BUF = memory.alloc(0x1000)
local BA = N(BUF)
local PAINT = string.rep(string.char(0xA5), 0x1000)
local function paint() pcall(function() memory.write_buffer(BUF, PAINT) end) end

local K1  = "0xFFFFFFFFC1000000"   -- image base, present
local K3  = "0xFFFFFFFFC0000000"   -- stub page, present
local ABS = "0xFFFFFFFFD0000000"   -- absent
local function short(a)
    if a == K1 then return "K1" elseif a == K3 then return "K3"
    elseif a == ABS then return "ABS" elseif a == BA then return "U"
    elseif a == 0 then return "0" end
    return tostring(a)
end

local function changed()
    local n, acc = 0, {}
    for i = 0, 0xFF do
        local v = rd(BA + i * 4)
        if v and v ~= 0xA5A5A5A5 then
            n = n + 1
            if #acc < 6 then acc[#acc + 1] = hex(v) end
        end
    end
    return n, table.concat(acc, " ")
end

local function call(num, a1, a2, a3, a4, a5, a6)
    local ok, rv = pcall(function()
        return mk(num)(UA(a1), UA(a2), UA(a3), UA(a4 or 0), UA(a5 or 0), UA(a6 or 0))
    end)
    if not ok then return -99999, "EXC" end
    return N(rv), es()
end

-- 1342a's skip list: lethal, wedging or known-destructive numbers
local SKIP = {[561]=1,[562]=1,[570]=1,[571]=1,[573]=1,[622]=1,[609]=1,[614]=1,[621]=1,
              [631]=1,[650]=1,[651]=1,[668]=1,[673]=1}
-- command dispatchers: arg1 is a command word, so phase A teaches nothing about them
local DISPATCH = {[532]=1, [601]=1, [649]=1, [669]=1, [662]=1, [663]=1, [664]=1, [666]=1,
                  [667]=1, [670]=1, [671]=1, [657]=1}

print("")
print("[A] num(K1) vs num(K3) vs num(absent); a difference between a mapped and an absent")
print("    kernel address is the signature of a dereference")
local diffs = {}
for num = 532, 676 do
    if not SKIP[num] and not DISPATCH[num] then
        paint()
        local rv1, e1 = call(num, K1, BA, 0x800)
        local c1 = changed()
        paint()
        local rv3, e3 = call(num, K3, BA, 0x800)
        local c3 = changed()
        paint()
        local rvu, eu = call(num, ABS, BA, 0x800)
        local cu = changed()
        local mark = ""
        if rv1 ~= rvu or rv3 ~= rvu or c1 ~= cu or c3 ~= cu then
            mark = "  ***DIFF"
            diffs[#diffs + 1] = string.format("%d K1[%d %s chg=%d] K3[%d %s chg=%d] ABS[%d %s chg=%d]",
                num, rv1, e1, c1, rv3, e3, c3, rvu, eu, cu)
        end
        print(string.format("  %d K1=%d/%-8s/%-3d  K3=%d/%-8s/%-3d  ABS=%d/%-8s/%-3d%s",
            num, rv1, e1, c1, rv3, e3, c3, rvu, eu, cu, mark))
        if rv1 == -99999 or rv3 == -99999 or rvu == -99999 then
            print("  [FATAL] a class did not return; stopping phase A")
            break
        end
    end
end

print("")
if #diffs == 0 then
    print("[A] no number answered a mapped kernel address differently from an absent one")
else
    print("[A] DIFFERENCES:")
    for _, d in ipairs(diffs) do print("   " .. d) end
end

print("")
print("[B] command dispatchers with kernel addresses in their pointer slots")
local function p532(cmd, outp, inp, size)
    paint()
    local rv, e = call(532, cmd, 0, outp, inp, size)
    local n, first = changed()
    print(string.format("  532(0x%02X, 0, out=%-3s, in=%-3s, 0x%X) rv=%-8d %-22s changed=%d %s",
        cmd, short(outp), short(inp), size, rv, e, n, first))
    return rv
end
for _, cmd in ipairs({0x18, 0x19, 0x1E, 0x1F, 0x20, 0x2F}) do
    if p532(cmd, K1, K1, 0x40) == -99999 then print("  [FATAL] stopping"); return end
end
p532(0x2F, ABS, ABS, 0x40)
p532(0x2F, K1, BA, 0x40)
p532(0x2F, BA, K1, 0x40)

local function p601(cmd, a1, a2)
    paint()
    local rv, e = call(601, cmd, a1, a2)
    local n, first = changed()
    print(string.format("  601(0x%02X, %-3s, %-3s) rv=%-8d %-22s changed=%d %s",
        cmd, short(a1), short(a2), rv, e, n, first))
    return rv
end
for _, cmd in ipairs({0x00, 0x07, 0x09, 0x0B, 0x0D, 0x0E, 0x13, 0x14, 0x19, 0x1A}) do
    if p601(cmd, K1, K1) == -99999 then print("  [FATAL] stopping"); return end
end
for _, cmd in ipairs({0x00, 0x0D, 0x0E}) do
    if p601(cmd, ABS, ABS) == -99999 then print("  [FATAL] stopping"); return end
end

print("=== PROBE 1391a COMPLETE ===")
