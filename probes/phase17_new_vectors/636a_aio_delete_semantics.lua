-- CRASH_CLASS: LOW
-- PROBE 636a: block vs non-block object: what does a second delete return?
print("=== PROBE 636a: AIO DELETE SEMANTICS ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local sc669=mk(669) local sc664=mk(664) local sc662=mk(662)
local data=memory.alloc(0x1000) local out=memory.alloc(0x40) local st=memory.alloc(0x40) local st2=memory.alloc(0x40)
for i=0,0xFFC,4 do wd(N(data)+i,0) end
local function create(flags,cnt)
    wd(N(out),0)
    local o,r=pcall(function() return sc669(uint64(flags),uint64(N(data)),uint64(cnt),uint64(1),uint64(N(out))) end)
    return o and N(r) or -99, rd(N(out))
end
local function del(id,stp)
    wd(N(stp),0x77777777)
    local o,r=pcall(function() return sc662(U(id),uint64(1),uint64(N(stp))) end)
    return (o and N(r) or -99), rd(N(stp))
end
local function poll(id,stp)
    wd(N(stp),0x77777777)
    local o,r=pcall(function() return sc664(U(id),uint64(1),uint64(N(stp))) end)
    return (o and N(r) or -99), rd(N(stp))
end
-- block of 4
local rb,b4=create(0x1001,4)
print(string.format("[A] block4 ret=%d base=%s",rb,tostring(b4)))
local id0=b4
print(string.format("[B] poll id0 %d/%s",poll(id0,st)))
local r1,s1=del(id0,st)
local r2,s2=del(id0,st)
print(string.format("[C] block id0 del1 ret=%d st=%s  del2 ret=%d st=%s",r1,tostring(s1),r2,tostring(s2)))
local id3=b4+3*0x10000
print(string.format("[D] poll id3 %d/%s",poll(id3,st)))
local r3,s3=del(id3,st)
local r4,s4=del(id3,st)
print(string.format("[E] block id3 del1 ret=%d st=%s  del2 ret=%d st=%s",r3,tostring(s3),r4,tostring(s4)))
-- non-block single
local rn,b1=create(1,1)
print(string.format("[F] single ret=%d base=%s",rn,tostring(b1)))
print(string.format("[G] poll %d/%s",poll(b1,st)))
local r5,s5=del(b1,st)
local r6,s6=del(b1,st)
print(string.format("[H] single del1 ret=%d st=%s  del2 ret=%d st=%s",r5,tostring(s5),r6,tostring(s6)))
local r7,s7=del(b1,st2)
print(string.format("[I] single del3 ret=%d st=%s",r7,tostring(s7)))
-- a fresh single after the deletes
local rn2,b2=create(1,1)
print(string.format("[J] single2 ret=%d base=%s",rn2,tostring(b2)))
print(string.format("[K] poll %d/%s",poll(b2,st)))
local r8,s8=del(b2,st)
print(string.format("[L] single2 del1 ret=%d st=%s",r8,tostring(s8)))
print(string.format("[M] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
print("[Z] alive")
