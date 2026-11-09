-- CRASH_CLASS: MODERATE (one supervisor address in arg2 / arg3 of calls whose
--               arg1 class was already measured; the mapped page is the same
--               one 1343a used)
-- PROBE 1344a: arg2 / arg3 given a supervisor address instead of an absent one
--
-- prior art:
--   probes/phase35_dead_end_reruns/1343a_arg23_classes.lua
--   results/phase35_dead_end_reruns/1343a_arg23_classes_20261109_101720.txt
--       20 numbers read arg2, 10 read arg3, measured against mapped and absent
--   probes/phase35_dead_end_reruns/1343b_outpage_scorer.lua
--   results/phase35_dead_end_reruns/1343b_outpage_scorer_20261109_101855.txt
--       seven of them write into the destination, and every one refuses an
--       absent destination with EFAULT -- which is what a copyout check looks like
--   probes/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus.lua
--       the same trick for arg1: all 11 handlers tested reject a supervisor
--       pointer with EFAULT / EINVAL / ESRCH
--   docs/ARG23_CLASSES_14_10.md   the arg2 / arg3 table in doc form
--
-- 1343a compared arg2/arg3 mapped against absent, so a difference proves the
-- handler dereferences that pointer. It cannot tell "the pointer is checked"
-- from "the pointer class is not checked but the address happens to be empty".
-- This probe passes the boot's kernel image base instead: a handler that skips
-- the class check and treats it as a user address reaches the supervisor page,
-- and the fault it takes is the result. A `0` return would mean the write went
-- through with no check at all.
--
-- Phases, every number called three times with arg1 always mapped:
--   [A] (U1, U2, U3)  baseline, same as 1343a's phase A
--   [B] (U1, K,  U3)  arg2 is the kernel image base
--   [C] (U1, U2, K )  arg3 is the kernel image base
--
-- K is this boot's image base, 0xFFFFFFFFC1000000, measured by 1331a at
-- 2026-11-09 10:05 UTC. A reboot changes it; STATE.md carries the current value
-- and a stale K only makes the phase read as absent, never as a write.

print("=== PROBE 1344a: ARG2 / ARG3 KERNEL POINTER CLASS ===")

local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local o,e=pcall(function() return get_error_string() end) if o then return tostring(e) end return "?" end
local function page(n)
    local o,a=pcall(function() return mk(477)(uint64(0), uint64(n), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    if not o then return 0 end
    local v=to_num(a)
    if v==0 or v>=0x800000000000 then return 0 end
    for x=0,n-8,8 do pcall(function() memory.write_qword(uint64(v+x), uint64(0x4141414141414141)) end) end
    return v
end

local U1, U2, U3 = page(0x4000), page(0x4000), page(0x4000)
if U1==0 or U2==0 or U3==0 then print("[!] mmap failed"); return end
local K = 0xFFFFFFFFC1000000
print(string.format("[0] U1=0x%X U2=0x%X U3=0x%X K=0x%X", U1, U2, U3, K))

local sa = memory.alloc(0x80)
for i = 0, 0x70, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa + 0, uint64(1)) end)
local okI, rvI = pcall(function() return mk(416)(uint64(12), uint64(sa), uint64(0)) end)
if not (okI and to_num(rvI) == 0) then
    print("[!] SIGSYS could not be ignored; not spending the console")
    print("=== PROBE 1344a STOPPED ===")
    return
end
print("[0] sigaction(12, SIG_IGN) -> 0")

-- same skip list as 1342a/1343a: 561, 562, 570, 571, 573, 609, 614, 621, 622,
-- 631, 650, 651, 668, 673 (622 is the one real handler that dies on a bad arg)
local SKIP = {[561]=1,[562]=1,[570]=1,[571]=1,[573]=1,[609]=1,[614]=1,[621]=1,[622]=1,[631]=1,[650]=1,[651]=1,[668]=1,[673]=1}

local function q(v) return uint64(string.format("%d", v)) end
local function call(n, a2, a3, tag)
    local ok, rv = pcall(function() return mk(n)(q(U1), q(a2), q(a3), uint64(0), uint64(0), uint64(0)) end)
    if ok then
        print(string.format("%d %s %d %s", n, tag, to_num(rv), ES()))
    else
        print(string.format("%d %s EXC", n, tag))
    end
end

print("")
print("[A] all mapped")
for n = 532, 676 do
    if not SKIP[n] then call(n, U2, U3, "A") end
end
print("[A] canary " .. tostring(to_num(mk(20)())))

print("")
print("[B] arg2 = kernel image base")
for n = 532, 676 do
    if not SKIP[n] then call(n, K, U3, "B") end
end
print("[B] canary " .. tostring(to_num(mk(20)())))

print("")
print("[C] arg3 = kernel image base")
for n = 532, 676 do
    if not SKIP[n] then call(n, U2, K, "C") end
end
print("[C] canary " .. tostring(to_num(mk(20)())))

print("")
print("[E] alive pid=" .. tostring(to_num(mk(20)())))
print("=== PROBE 1344a COMPLETE ===")
