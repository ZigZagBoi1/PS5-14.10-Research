-- CRASH_CLASS: LOW
-- PROBE 739a: does restoring the old sigaction fix the post-shield death?
--
-- 738a ran the whole alloc/fill/msghdr sequence with no shield (all 16 steps
-- printed), installed SIG_IGN for SIGSYS, and then died inside the next fill
-- loop. So the shield itself breaks later memory writes. This tests the obvious
-- workaround: install it, use it for one call, restore the old action.

print("=== PROBE 739a: SHIELD SCOPE ===")
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
local n=0
local function say(t) n=n+1; print(string.format("[%02d] %s", n, t)) end

say("alloc before shield")
local p1 = to_num(memory.alloc(0x1000))
for k=0,0x3FF do wd(p1+k*4, 0x11111111) end
say("fill before shield ok")

local act = to_num(memory.alloc(64)); local old = to_num(memory.alloc(64))
for k=0,15 do wq(act+k*8, Z); wq(old+k*8, Z) end
wd(act, 1)
say("install shield")
pcall(function() return mk(416)(U(12), U(act), U(old), Z, Z, Z) end)
local okc, ctl = pcall(function() return mk(4095)(Z,Z,Z,Z,Z,Z) end)
say("4095 under shield -> "..tostring(okc and to_num(ctl) or "DEAD"))

say("restore old sigaction")
local okr, rr = pcall(function() return mk(416)(U(12), U(old), U(0), Z, Z, Z) end)
say("restore ret="..tostring(okr and to_num(rr) or "DEAD"))

say("alloc after restore")
local p2 = to_num(memory.alloc(0x1000))
say("fill after restore start")
for k=0,0x3FF do wd(p2+k*4, 0x22222222) end
say("fill after restore ok")
say("alloc second page")
local p3 = to_num(memory.alloc(0x4000))
for k=0,0xFFF do wd(p3+k*4, 0x33333333) end
say("second fill ok")
say("health="..tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("=== 739a DONE ===")
