-- CRASH_CLASS: MODERATE (same call shapes the arg1 sweep already exercised, plus
--               an absent arg2/arg3; no supervisor address is used at all)
-- PROBE 1343a: arg2 / arg3 pointer classes with arg1 mapped
--
-- prior art:
--   probes/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus.lua
--   results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101254.txt
--       the arg1 class map for 532-676: 131 numbers measured, only 8 branch on
--       arg1, none copies anything back from a supervisor pointer
--   docs/ARG1_CLASSES_14_10.md   the same result in table form
--   probes/phase17_new_vectors/1194b_601_arg2_write_leak.lua, 1194d_601_arg2_struct_consumers.lua
--       601's arg2 as a write destination and as a struct pointer -- specific
--       to one syscall, not a range sweep
--   docs/SYSENT_PRESENCE_14_10.md  a -1 is not a verdict: the handler may only
--       reject because a later argument was never reached
--
-- The arg1 sweep answered "does the handler read its first argument". It cannot
-- answer "does the handler read its second", because every one of those calls
-- passed five zeros. A handler that validates arg1 and then dereferences arg2 --
-- the normal shape for (buffer, length, out) calls -- looks identical to a gate
-- in that data. This probe holds arg1 mapped and compares arg2 and arg3 mapped
-- against absent, so a difference is a handler that dereferences that pointer.
--
-- Phases, every number called three times:
--   [A] (U1, U2, U3)  all three pointers mapped
--   [B] (U1, N,  U3)  arg2 absent
--   [C] (U1, U2, N )  arg3 absent
-- B or C differing from A is the finding. U1/U2/U3 are separate pages, each
-- filled with 0x41, so a handler that reads a length out of arg1 sees a huge
-- value and rejects before touching anything -- which is why this probe cannot
-- find a length-confused write, only which pointer argument is dereferenced.
--
-- SIGSYS is ignored first: without it the nosys trampoline terminates the caller
-- and a stub looks like a hostile handler (1342a run 3).

print("=== PROBE 1343a: ARG2 / ARG3 POINTER CLASSES ===")

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
local N = 0x00007FFF00000000
print(string.format("[0] U1=0x%X U2=0x%X U3=0x%X absent=0x%X", U1, U2, U3, N))

local sa = memory.alloc(0x80)
for i = 0, 0x70, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa + 0, uint64(1)) end)
local okI, rvI = pcall(function() return mk(416)(uint64(12), uint64(sa), uint64(0)) end)
if not (okI and to_num(rvI) == 0) then
    print("[!] SIGSYS could not be ignored; not spending the console")
    print("=== PROBE 1343a STOPPED ===")
    return
end
print("[0] sigaction(12, SIG_IGN) -> 0")

-- 622 kills on a bad argument rather than rejecting it (1342a run 3); the
-- nosys numbers are harmless but answer ENOSYS in every phase, so they are left
-- in the loop: they double as a canary that the harness still works.
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
print("[B] arg2 absent")
for n = 532, 676 do
    if not SKIP[n] then call(n, N, U3, "B") end
end
print("[B] canary " .. tostring(to_num(mk(20)())))

print("")
print("[C] arg3 absent")
for n = 532, 676 do
    if not SKIP[n] then call(n, U2, N, "C") end
end
print("[C] canary " .. tostring(to_num(mk(20)())))

print("")
print("[E] alive pid=" .. tostring(to_num(mk(20)())))
print("=== PROBE 1343a COMPLETE ===")
