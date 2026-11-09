-- CRASH_CLASS: LOW
-- PROBE 740a: do mmap pages survive the SIGSYS shield?
--
-- 738a/739a: after the shield is installed, memory.alloc + fill dies (and
-- restoring the old action does not undo it). The whole sendmsg test needs a
-- shield for possibly-absent numbers, so it needs memory that survives it.
-- mmap (477) pages are kernel-backed, unlike the loader's bump allocator.

print("=== PROBE 740a: MMAP UNDER SHIELD ===")
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
local sc_mmap = mk(477)
local U = function(a) a=to_num(a); return uint64(string.format("0x%08X%08X", math.floor(a/4294967296), a%4294967296)) end
local Z = uint64(0)
local function wd(a,v) memory.write_dword(a,v) end
local function wq(a,v) memory.write_qword(a,v) end
local n=0
local function say(t) n=n+1; print(string.format("[%02d] %s", n, t)) end
local function map(px)
    local ok, a = pcall(function() return sc_mmap(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = ok and to_num(a) or 0
    if v ~= 0 and v < 0x8000000000000000 then
        for k=0,(px/4)-1 do wd(v+k*4, 0) end
    else
        v = 0
    end
    return v
end

local p1 = map(0x4000)
say(string.format("mmap page1=%X", p1))
for k=0,0xFFF do wd(p1+k*4, 0x11111111) end
say("fill page1 ok")

local act = map(0x4000); local old = map(0x4000)
wd(act, 1)
say(string.format("act=%X old=%X", act, old))
pcall(function() return mk(416)(U(12), U(act), U(old), Z, Z, Z) end)
local okc, ctl = pcall(function() return mk(4095)(Z,Z,Z,Z,Z,Z) end)
say("4095 under shield -> "..tostring(okc and to_num(ctl) or "DEAD"))

say("mmap page2 under shield")
local p2 = map(0x4000)
say(string.format("page2=%X", p2))
say("fill page2 start")
for k=0,0xFFF do wd(p2+k*4, 0x22222222) end
say("fill page2 ok")
say("health="..tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("=== 740a DONE ===")
