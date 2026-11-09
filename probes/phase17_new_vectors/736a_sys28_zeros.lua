-- CRASH_CLASS: HIGH
-- PROBE 736a: is syscall 28 lethal on its own, and are 27/29/30/133?
--
-- 733a and 734a both died inside the first mk(28) call, one with a NULL msghdr
-- and one with a valid one. Everything before it (shield, socketpair, write,
-- read, three 0x4000 allocations) is proven good in 734a/735a. This probe calls
-- each number with zeros first, printing before and after so the last line
-- names the call that ended the process.

print("=== PROBE 736a: SYS 28 ZEROS ===")
print("")
local function to_num(v)
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
local U = function(a) a=to_num(a); return uint64(string.format("0x%08X%08X", math.floor(a/4294967296), a%4294967296)) end
local Z = uint64(0)
local function wd(a,v) memory.write_dword(a,v) end
local function wq(a,v) memory.write_qword(a,v) end
local function live(tag)
    local ok, v = pcall(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)
    print(string.format("    (%s) alive=%s", tag, tostring(ok and to_num(v) or "NO")))
end

local act = to_num(memory.alloc(64)); local old = to_num(memory.alloc(64))
for k=0,15 do wq(act+k*8, Z) end
wd(act, 1)
pcall(function() return mk(416)(U(12), U(act), U(old), Z, Z, Z) end)
local okc, ctl = pcall(function() return mk(4095)(Z,Z,Z,Z,Z,Z) end)
print(string.format("[0] shield: 4095 -> %s", tostring(okc and to_num(ctl) or "DEAD")))
live("shield")

local function zero_call(nr, args)
    print(string.format("[c] calling %d with %d args (all zero)", nr, args))
    local ok, rv = pcall(function() return mk(nr)(Z,Z,Z,Z,Z,Z) end)
    print(string.format("[c] %d -> %s", nr, tostring(ok and to_num(rv) or "DEAD")))
    if ok then live(nr) end
    return ok
end

if not zero_call(28, 6) then return end
if not zero_call(27, 6) then return end
if not zero_call(29, 6) then return end
if not zero_call(30, 6) then return end
if not zero_call(133, 6) then return end
print("=== 736a DONE ===")
