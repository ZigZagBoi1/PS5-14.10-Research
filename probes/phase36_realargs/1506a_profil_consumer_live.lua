-- CRASH_CLASS: LOW -- user buffer only, no kernel address is ever passed.
-- PROBE 1506a: does syscall 44 (profil) actually deliver ticks on 14.10?
--
-- StaticHunt found that the 13.60 body stores pr_base/pr_size/pr_off/pr_scale from the caller
-- into [proc+0x58]+0xf0/+0xf8/+0x100/+0x108 with NO user-range test on pr_base, and that
-- 1377a measured 44(arg1 = kernel image base) -> rv=0 with the process surviving. If the
-- statclock consumer does a raw store, that is a kernel write at an attacker-chosen address.
--
-- A linear scan of all 5,343,048 instructions in the 13.60 text dump for the addupc shape
-- (imul by pr_scale, shr 16, then an indexed store through pr_base) returns ZERO hits, so the
-- consumer is either outside the dumped text or absent. Before spending a relaunch on a kernel
-- arm, this probe establishes the cheap precondition: with a correctly shaped USER buffer, does
-- a tick ever land?
--
-- Prior probes (389d, 392f) reported zero samples, but they used size 0x1000 with scale
-- 0x10000, and i = (pc - pr_off) * pr_scale >> 16 means scale 0x10000 makes i = pc, which is
-- ~0x522000000 and therefore always >= size. The shape has to be: scale 1 (1/65536), pr_off 0,
-- pr_size large enough to cover pc/65536. This probe uses pr_size = 0x200000 (2,097,152 u_short
-- = 4 MiB of buffer) which covers any pc below 0x8000000000.
--
-- [A] disable, map an 8 MiB zeroed buffer
-- [B] arm with scale 1, pr_off 0, pr_size 0x200000, busy loop ~1 s, disable
-- [C] scan every u_short: count nonzero, print the first indices and the implied pc range
-- [D] re-arm with pr_off = 0x10000000 to confirm the arithmetic actually subtracts
-- [E] control: arm with scale 0, busy loop, confirm it produces nothing
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1377a_arg1_kernel_class_bsd_20261109_132333.txt (44 with a
--     kernel base returned 0, process survived)
--   results/389d_* / results/392f_* (profil rv=0 with no samples; wrong shape per above)

print("=== PROBE 1506a: IS profil LIVE ON 14.10? ===")

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
-- one C-side copy, then C-side searching: 4 MiB of per-word Lua calls would exceed the idle timeout
local function scan_nonzero(base, nbytes)
    local ok, s = pcall(function() return memory.read_buffer(base, nbytes) end)
    if not ok or type(s) ~= "string" then return nil, {} end
    local hits, firsts, pos = 0, {}, 1
    while true do
        local p = s:find("[^%z]", pos)
        if not p then break end
        hits = hits + 1
        if #firsts < 12 then
            -- a nonzero byte at p means the u_short at (p-1)/2 is nonzero
            firsts[#firsts + 1] = math.floor((p - 1) / 2)
        end
        pos = p + 1
    end
    return hits, firsts
end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local function profil(base, size, off, scale)
    local ok, rv = pcall(function()
        return mk(44)(uint64(base), uint64(size), uint64(off), uint64(scale), uint64(0), uint64(0))
    end)
    if not ok then return -999 end
    return sgn(rv)
end

local function spin(n)
    local x = 1
    for i = 1, n do x = x + i end
    return x
end

-- ---------------------------------------------------------------- [A] buffer
print("")
print("--- [A] buffer ---")
local d0 = profil(0, 0, 0, 0)
print(string.format("  disable first: rv=%d %s", d0, d0 < 0 and es() or ""))

local LEN = 0x800000
local BUF = sgn(mk(477)(uint64(0), uint64(LEN), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
print(string.format("  mmap(0x%X) -> 0x%X %s", LEN, BUF, BUF < 0 and es() or ""))
if BUF < 0 then print("=== PROBE 1506a VOID ===") return end
for off = 0, LEN - 1, 0x1000 do
    local ok = pcall(function() memory.write_word(BUF + off, uint64(0)) end)
    if not ok then print(string.format("  zero failed at +0x%X", off)) break end
end
print("  buffer zeroed")

-- ---------------------------------------------------------------- [B] arm
print("")
print("--- [B] arm: scale 1, off 0, size 0x200000 ---")
local SIZE = 0x200000
local a = profil(BUF, SIZE, 0, 1)
print(string.format("  profil arm: rv=%d %s", a, a < 0 and es() or ""))
if a < 0 then print("=== PROBE 1506a INCOMPLETE: arm refused ===") return end
print("  spinning...")
local sink = spin(30000000)
print(string.format("  spin done (sink=%d)", sink))
local off_ok = profil(0, 0, 0, 0)
print(string.format("  disable: rv=%d %s", off_ok, off_ok < 0 and es() or ""))

-- ---------------------------------------------------------------- [C] scan
print("")
print("--- [C] scan 0x%X u_shorts at 0x%X ---", SIZE, BUF)
local hits, idxs = scan_nonzero(BUF, SIZE * 2)
if hits == nil then
    print("  read_buffer failed - buffer lost")
    hits = 0
end
print(string.format("  nonzero u_shorts: %d of %d", hits, SIZE))
for _, i in ipairs(idxs) do
    print(string.format("    i=0x%X  pc~0x%X", i, i * 65536))
end
print(string.format("  VERDICT: profil sampling %s", (hits > 0) and "IS LIVE" or "DELIVERS NOTHING"))

if hits == 0 then
    print("")
    print("=== PROBE 1506a COMPLETE: profil is inert on 14.10 (user buffer got no ticks) ===")
    print(string.format("final canary pid %d", N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
    return
end

-- ---------------------------------------------------------------- [D] arithmetic check
print("")
print("--- [D] re-arm with pr_off = 0x10000000 (index must drop by 0x10000000/0x10000 = 0x1000) ---")
for off = 0, LEN - 1, 0x1000 do
    pcall(function() memory.write_word(BUF + off, uint64(0)) end)
end
local b = profil(BUF, SIZE, 0x10000000, 1)
print(string.format("  profil arm2: rv=%d %s", b, b < 0 and es() or ""))
spin(20000000)
profil(0, 0, 0, 0)
local hits2, idxs2 = scan_nonzero(BUF, SIZE * 2)
local first2 = (idxs2 and #idxs2 > 0) and idxs2[1] or -1
print(string.format("  nonzero: %s  first index: %s", tostring(hits2),
      first2 >= 0 and string.format("0x%X", first2) or "none"))
print("  a subtractive offset is confirmed if first index moved DOWN by 0x1000")

-- ---------------------------------------------------------------- [E] scale 0 control
print("")
print("--- [E] control: scale 0 ---")
for off = 0, LEN - 1, 0x1000 do
    pcall(function() memory.write_word(BUF + off, uint64(0)) end)
end
local c = profil(BUF, SIZE, 0, 0)
print(string.format("  profil scale=0: rv=%d %s", c, c < 0 and es() or ""))
spin(20000000)
profil(0, 0, 0, 0)
local hits3 = scan_nonzero(BUF, SIZE * 2)
print(string.format("  nonzero with scale 0: %s (expected 0: scale 0 disables)", tostring(hits3)))

print("")
print(string.format("final canary pid %d", N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
print("=== PROBE 1506a COMPLETE ===")
