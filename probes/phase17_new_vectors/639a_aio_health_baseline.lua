-- CRASH_CLASS: LOW
-- PROBE 639a: aio health baseline (create, poll, delete) - run before and after a race
print("=== PROBE 639a: AIO HEALTH BASELINE ===")
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
local data=memory.alloc(0x1000) local out=memory.alloc(0x40) local st=memory.alloc(0x40)
for i=0,0xFFC,4 do wd(N(data)+i,0) end
local function create(flags,cnt)
    wd(N(out),0)
    local o,r=pcall(function() return sc669(uint64(flags),uint64(N(data)),uint64(cnt),uint64(1),uint64(N(out))) end)
    return (o and N(r) or -99), rd(N(out))
end
local idbuf=memory.alloc(0x10)
local function del(id,stp)
    wd(N(stp),0x77777777) wd(N(idbuf),id)
    local o,r=pcall(function() return sc662(U(N(idbuf)),uint64(1),uint64(N(stp))) end)
    return (o and N(r) or -99), rd(N(stp))
end
local function poll(id,stp)
    wd(N(stp),0x77777777) wd(N(idbuf),id)
    local o,r=pcall(function() return sc664(U(N(idbuf)),uint64(1),uint64(N(stp))) end)
    return (o and N(r) or -99), rd(N(stp))
end
local rb,b4=create(0x1001,4)
print(string.format("[A] block4 ret=%d base=%s",rb,tostring(b4)))
if rb==0 and b4 and b4>0 then
    local pr,ps=poll(b4,st)
    print(string.format("[B] poll ret=%d st=%s",pr,tostring(ps)))
    local dr,ds=del(b4,st)
    print(string.format("[C] del ret=%d st=%s",dr,tostring(ds)))
    local dr2,ds2=del(b4,st)
    print(string.format("[D] del2 ret=%d st=%s",dr2,tostring(ds2)))
end
local rn,b1=create(1,1)
print(string.format("[E] single ret=%d base=%s",rn,tostring(b1)))
if rn==0 and b1 and b1>0 then
    local pr,ps=poll(b1,st)
    print(string.format("[F] poll ret=%d st=%s",pr,tostring(ps)))
    local dr,ds=del(b1,st)
    print(string.format("[G] del ret=%d st=%s",dr,tostring(ds)))
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
