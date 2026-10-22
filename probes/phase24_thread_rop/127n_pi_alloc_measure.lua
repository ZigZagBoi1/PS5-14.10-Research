-- CRASH_CLASS: LOW
-- PROBE 127n: Measure kernel allocations during UMTX PI mutex ops
--
-- Key insight from 127l: TRYLOCK on 0x80000000 (CONTESTED, no owner)
-- succeeds and enters the kernel slow path which allocates umtx_pi.
-- If the subsequent UNLOCK fails (child corrupts word), the umtx_pi leaks.
--
-- Use sys 624 (VM op counter, confirmed 52b) as side channel to detect
-- kernel allocations. Compare:
-- A) TRYLOCK on word=0 (fast path, no kernel object)
-- B) TRYLOCK on word=0x80000000 (slow path, possible umtx_pi alloc)
-- C) Successful LOCK+UNLOCK cycle (alloc + free)
-- D) TRYLOCK(0x80000000) + failed UNLOCK (alloc without free = leak)

print("=== PROBE 127n: PI ALLOC MEASUREMENT ===")
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

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid
end

-- sys 624 = VM op counter (+5 per mmap, stable monotonic, narg=0)
local sc_624 = mk(624)
local function vmd()
    local ok, r = pcall(function() return sc_624() end)
    if ok and r then return N(r) end
    return -1
end

local sc_umtx = mk(454)

-- Shared mutex word
local shared = memory.alloc(0x1000)
local S = N(shared)

print(string.format("  initial vmd=%d", vmd()))

-- [A] Baseline: measure VM ops for fast-path TRYLOCK (word=0)
print("")
print("[A] Fast-path TRYLOCK (word=0)")
local results_a = {}
for i = 1, 20 do
    wd(S, 0); wd(S + 4, 0)
    local v0 = vmd()

    -- TRYLOCK on word=0 → fast CAS(0→main_tid)
    pcall(function()
        sc_umtx(shared, uint64(4), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    local v1 = vmd()

    -- UNLOCK
    pcall(function()
        sc_umtx(shared, uint64(6), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    local v2 = vmd()

    results_a[i] = {trylock = v1 - v0, unlock = v2 - v1, total = v2 - v0}
end

local sum_a = 0
for _, r in ipairs(results_a) do sum_a = sum_a + r.total end
print(string.format("  20 fast TRYLOCK+UNLOCK cycles"))
print(string.format("  sample: trylock_delta=%d unlock_delta=%d total=%d",
    results_a[1].trylock, results_a[1].unlock, results_a[1].total))
print(string.format("  avg total delta: %.1f", sum_a / 20))

if not alive() then print("DIED!") return end

-- [B] Slow-path TRYLOCK (word=0x80000000, CONTESTED no owner)
print("")
print("[B] Slow-path TRYLOCK (word=0x80000000)")
local results_b = {}
for i = 1, 20 do
    -- Set word to CONTESTED with no owner
    wd(S, 0x80000000); wd(S + 4, 0)
    local v0 = vmd()

    -- TRYLOCK → enters slow path (CONTESTED bit set)
    pcall(function()
        sc_umtx(shared, uint64(4), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    local v1 = vmd()

    -- UNLOCK (should succeed since we own it now)
    pcall(function()
        sc_umtx(shared, uint64(6), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    local v2 = vmd()

    results_b[i] = {trylock = v1 - v0, unlock = v2 - v1, total = v2 - v0}
end

local sum_b = 0
for _, r in ipairs(results_b) do sum_b = sum_b + r.total end
print(string.format("  20 slow TRYLOCK+UNLOCK cycles"))
print(string.format("  sample: trylock_delta=%d unlock_delta=%d total=%d",
    results_b[1].trylock, results_b[1].unlock, results_b[1].total))
print(string.format("  avg total delta: %.1f", sum_b / 20))

if not alive() then print("DIED!") return end

-- [C] TRYLOCK(0x80000000) + corrupted UNLOCK (potential leak)
print("")
print("[C] Slow TRYLOCK + corrupted UNLOCK (leak test)")
local results_c = {}
for i = 1, 20 do
    wd(S, 0x80000000); wd(S + 4, 0)
    local v0 = vmd()

    -- TRYLOCK slow path
    pcall(function()
        sc_umtx(shared, uint64(4), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    local v1 = vmd()

    -- Corrupt the word BEFORE unlock (simulate child writer)
    wd(S, 0xDEAD); wd(S + 4, 0)

    -- UNLOCK with corrupted word → should fail, umtx_pi leaked
    local ul_ret = nil
    pcall(function()
        ul_ret = sc_umtx(shared, uint64(6), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    local v2 = vmd()

    results_c[i] = {
        trylock = v1 - v0,
        unlock = v2 - v1,
        total = v2 - v0,
        ul_ret = ul_ret and N(ul_ret) or -999
    }
end

local sum_c = 0
for _, r in ipairs(results_c) do sum_c = sum_c + r.total end
print(string.format("  20 slow TRYLOCK + corrupt UNLOCK cycles"))
print(string.format("  sample: trylock_delta=%d unlock_delta=%d total=%d ul_ret=%s",
    results_c[1].trylock, results_c[1].unlock, results_c[1].total, fmt(results_c[1].ul_ret)))
print(string.format("  avg total delta: %.1f", sum_c / 20))

-- Check unlock return values
local ul_zero = 0
local ul_fail = 0
for _, r in ipairs(results_c) do
    if r.ul_ret == 0 then ul_zero = ul_zero + 1
    else ul_fail = ul_fail + 1 end
end
print(string.format("  unlock results: ok=%d fail=%d", ul_zero, ul_fail))

if not alive() then print("DIED!") return end

-- [D] Normal LOCK+UNLOCK for comparison
print("")
print("[D] Normal LOCK+UNLOCK baseline")
local results_d = {}
for i = 1, 20 do
    wd(S, 0); wd(S + 4, 0)
    local v0 = vmd()

    pcall(function()
        sc_umtx(shared, uint64(5), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    local v1 = vmd()

    pcall(function()
        sc_umtx(shared, uint64(6), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    local v2 = vmd()

    results_d[i] = {lock = v1 - v0, unlock = v2 - v1, total = v2 - v0}
end

local sum_d = 0
for _, r in ipairs(results_d) do sum_d = sum_d + r.total end
print(string.format("  20 LOCK+UNLOCK cycles"))
print(string.format("  sample: lock_delta=%d unlock_delta=%d total=%d",
    results_d[1].lock, results_d[1].unlock, results_d[1].total))
print(string.format("  avg total delta: %.1f", sum_d / 20))

-- [E] Mass leak test: 200 TRYLOCK(0x80000000) + corrupt UNLOCK
print("")
print("[E] Mass leak: 200 contested TRYLOCK + corrupt UNLOCK")
local v_before = vmd()

for i = 1, 200 do
    wd(S, 0x80000000); wd(S + 4, 0)

    pcall(function()
        sc_umtx(shared, uint64(4), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    -- Corrupt before unlock
    wd(S, 0xDEAD); wd(S + 4, 0)

    pcall(function()
        sc_umtx(shared, uint64(6), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    if not alive() then
        print(string.format("  *** DIED at iter %d ***", i))
        return
    end
end

local v_after = vmd()
print(string.format("  vmd before=%d after=%d delta=%d", v_before, v_after, v_after - v_before))
print(string.format("  delta per cycle: %.1f", (v_after - v_before) / 200))

-- [F] Summary
print("")
print("[F] Summary")
print(string.format("  fast trylock+unlock avg: %.1f vmd/cycle", sum_a / 20))
print(string.format("  slow trylock+unlock avg: %.1f vmd/cycle", sum_b / 20))
print(string.format("  slow trylock+corrupt avg: %.1f vmd/cycle", sum_c / 20))
print(string.format("  normal lock+unlock avg: %.1f vmd/cycle", sum_d / 20))
print(string.format("  mass leak total: %d vmd over 200 cycles (%.1f/cycle)",
    v_after - v_before, (v_after - v_before) / 200))

if sum_c / 20 > sum_b / 20 + 0.5 then
    print("  *** LEAK SIGNAL: corrupt unlock uses MORE vm ops than clean unlock ***")
elseif sum_b / 20 > sum_a / 20 + 0.5 then
    print("  *** ALLOC SIGNAL: slow path uses MORE vm ops than fast path ***")
else
    print("  no significant difference detected")
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 127n COMPLETE ===")
