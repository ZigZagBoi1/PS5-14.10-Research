-- CRASH_CLASS: MODERATE (the same 131 numbers, now with mapped pages in the
--               argument positions that every sweep so far left at zero)
-- PROBE 1345a: arg4 / arg5 / arg6 pointer classes with args1-3 mapped
--
-- prior art:
--   probes/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus.lua
--   results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101254.txt
--       arg1 mapped vs absent: 8 numbers branch, 11 reject a supervisor pointer
--   probes/phase35_dead_end_reruns/1343a_arg23_classes.lua
--   results/phase35_dead_end_reruns/1343a_arg23_classes_20261109_101720.txt
--       arg2/arg3 mapped vs absent: 20 and 10 numbers branch
--   probes/phase35_dead_end_reruns/1344a_arg23_kernel_class.lua
--   results/phase35_dead_end_reruns/1344a_arg23_kernel_class_20261109_102818.txt
--       arg2/arg3 = kernel image base: every handler that touches them answers EFAULT
--   docs/SYSENT_PRESENCE_14_10.md   "the -1 column is not a verdict" -- every sweep
--       in this project passed zeros for args 4-6, so a handler that needs a
--       fourth pointer looks exactly like a credential gate
--   docs/ARG23_CLASSES_14_10.md     the arg2/arg3 table
--
-- Every class sweep so far varied args 1-3 and left args 4-6 at zero. Calls whose
-- recovered contract names four or five arguments -- 548's operation array, 663's
-- wait mode and timeout, 669's class and id array -- were therefore only ever
-- measured in a shape their handler must reject. This probe holds args 1-3 mapped
-- and compares each of arg4, arg5 and arg6 mapped against zero, so a number that
-- only answers with a fourth pointer shows up as a phase difference.
--
-- Phases, every number called four times:
--   [A] (U1, U2, U3, P4, P5, P6)   all six mapped
--   [B] (U1, U2, U3, 0,  P5, P6)   arg4 zero (the shape every earlier sweep used)
--   [C] (U1, U2, U3, P4, 0,  P6)   arg5 zero
--   [D] (U1, U2, U3, P4, P5, 0 )   arg6 zero
-- B/C/D differing from A is a handler that dereferences that argument. B is the
-- control: it is the exact shape the presence table and the ARG1 page measured.
--
-- SIGSYS is ignored first (1342a run 3): without it the nosys trampoline kills the
-- caller and a stub is indistinguishable from a hostile handler.

print("=== PROBE 1345a: ARG4 / ARG5 / ARG6 POINTER CLASSES ===")

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
local P4, P5, P6 = page(0x4000), page(0x4000), page(0x4000)
if U1==0 or U2==0 or U3==0 or P4==0 or P5==0 or P6==0 then print("[!] mmap failed"); return end
print(string.format("[0] U1=0x%X U2=0x%X U3=0x%X P4=0x%X P5=0x%X P6=0x%X", U1, U2, U3, P4, P5, P6))

local sa = memory.alloc(0x80)
for i = 0, 0x70, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa + 0, uint64(1)) end)
local okI, rvI = pcall(function() return mk(416)(uint64(12), uint64(sa), uint64(0)) end)
if not (okI and to_num(rvI) == 0) then
    print("[!] SIGSYS could not be ignored; not spending the console")
    print("=== PROBE 1345a STOPPED ===")
    return
end
print("[0] sigaction(12, SIG_IGN) -> 0")

-- 622 kills on a bad argument rather than rejecting it (1342a run 3); the
-- nosys numbers are harmless but answer ENOSYS in every phase, so they are left
-- in the loop: they double as a canary that the harness still works.
local SKIP = {[561]=1,[562]=1,[570]=1,[571]=1,[573]=1,[609]=1,[614]=1,[621]=1,[622]=1,[631]=1,[650]=1,[651]=1,[668]=1,[673]=1}

local function q(v) return uint64(string.format("%d", v)) end
local function call(n, a4, a5, a6, tag)
    local ok, rv = pcall(function() return mk(n)(q(U1), q(U2), q(U3), q(a4), q(a5), q(a6)) end)
    if ok then
        print(string.format("%d %s %d %s", n, tag, to_num(rv), ES()))
    else
        print(string.format("%d %s EXC", n, tag))
    end
end

print("")
print("[A] args 1-6 mapped")
for n = 532, 676 do
    if not SKIP[n] then call(n, P4, P5, P6, "A") end
end
print("[A] canary " .. tostring(to_num(mk(20)())))

print("")
print("[B] arg4 zero -- the shape every earlier sweep used")
for n = 532, 676 do
    if not SKIP[n] then call(n, 0, P5, P6, "B") end
end
print("[B] canary " .. tostring(to_num(mk(20)())))

print("")
print("[C] arg5 zero")
for n = 532, 676 do
    if not SKIP[n] then call(n, P4, 0, P6, "C") end
end
print("[C] canary " .. tostring(to_num(mk(20)())))

print("")
print("[D] arg6 zero")
for n = 532, 676 do
    if not SKIP[n] then call(n, P4, P5, 0, "D") end
end
print("[D] canary " .. tostring(to_num(mk(20)())))

print("")
print("[E] alive pid=" .. tostring(to_num(mk(20)())))
print("=== PROBE 1345a COMPLETE ===")
