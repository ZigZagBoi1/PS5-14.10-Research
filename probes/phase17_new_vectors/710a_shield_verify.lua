-- CRASH_CLASS: MODERATE
-- PROBE 710a: establish the SIGSYS shield properly, then use 4095 as the control.
--
-- Context: two different sigaction(416) shapes have been used in this repo -
-- a direct value (416(12, 1, 0, 0)) and a struct pointer (416(12, act, old))
-- - and the direct form's return value was never printed, so it is unknown
-- whether the shield was ever active. 353a's struct form returned 0.
--
-- 4095 has no handler in any version and kills the caller. With a working
-- SIG_IGN on SIGSYS it must return -1 instead. That makes it the control that
-- proves the shield, before any conclusion is drawn from a "-1" on a real
-- number.
--
-- Order matters: the control runs last, so a dead end still leaves the shape
-- comparisons on disk.

print("=== PROBE 710a: shield shapes and the 4095 control ===")
print("")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n
    setmetatable(t,getmetatable(syscall.pipe))
    return t
end
local function U(a)
    a=N(a)
    return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296))
end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a)
    local o,v=pcall(function() memory.read_dword(a) end)
    if o then return N(v) end
    return nil
end
local function safe(f)
    local ok,rv=pcall(f)
    if not ok then return "EXC" end
    return N(rv)
end

local sigact=mk(416)
local sa=memory.alloc(0x80)
local oldsa=memory.alloc(0x80)
for i=0,0x78,8 do wq(N(sa)+i,0) end
wq(N(sa)+0,1)
print(string.format("[A] direct shape 416(12,1,0,0) -> %s", tostring(safe(function() return sigact(uint64(12),uint64(1),uint64(0),uint64(0)) end))))
print(string.format("[B] struct shape 416(12,act,old) -> %s", tostring(safe(function() return sigact(uint64(12),U(N(sa)),U(N(oldsa))) end))))
print(string.format("    old handler low dword = %s", tostring(rd(N(oldsa)))))

local function call(n)
    local sc=mk(n)
    return safe(function() return sc(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
end

print("[C] control 4095 with the struct shield installed")
print("    before")
local r=call(4095)
print(string.format("    after -> %s", tostring(r)))

print(string.format("[Z] alive=%d", N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
