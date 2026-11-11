-- CRASH_CLASS: LOW -- user buffer only; no kernel address is ever passed.
-- PROBE 1506b: clean-baseline profil tick test (fixes 1506a's stale readout)
--
-- 1506a armed profil(BUF, 0x200000, 0, 1) and then found exactly one nonzero u_short at
-- byte 0x9B2 - but the same index survived a re-zero and a re-arm with pr_off = 0x10000000 and
-- also appeared in the scale-0 control, so the readout was stale, not a measurement: the zeroing
-- loop stepped 0x1000 and wrote 2 bytes, leaving every other byte of each page untouched.
--
-- This probe establishes the baseline properly and only then arms.
-- [A] zero the whole 8 MiB with write_buffer, scan -> must report 0
-- [B] arm scale 1, pr_off 0, pr_size 0x200000, spin, disable, scan -> hits, first index, value
-- [C] zero, scan -> must report 0 again
-- [D] arm scale 1, pr_off 0x10000000, spin, disable, scan -> the index must move DOWN by 0x1000
--     (i = (pc - pr_off) * scale >> 16), which is the only way to prove the writes are ticks
-- [E] print every nonzero index with its value in both arms
--
-- -- prior art:
--   results/phase36_realargs/1506a_profil_consumer_live_20261109_222347.txt (2 nonzero bytes
--     survived re-zero: stale)
--   results/phase35_dead_end_reruns/1377a_arg1_kernel_class_bsd_20261109_132333.txt (44 with a
--     kernel base returned 0, process survived)

print("=== PROBE 1506b: CLEAN profil TICK TEST ===")

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

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local function profil(base, size, off, scale)
    local ok, rv = pcall(function()
        return mk(44)(uint64(base), uint64(size), uint64(off), uint64(scale), uint64(0), uint64(0))
    end)
    if not ok then return -999 end
    return sgn(rv)
end
local function spin(n) local x = 1 for i = 1, n do x = x + i end return x end

local LEN = 0x800000
local BUF = sgn(mk(477)(uint64(0), uint64(LEN), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
print(string.format("  mmap(0x%X) -> 0x%X %s", LEN, BUF, BUF < 0 and es() or ""))
if BUF < 0 then print("=== PROBE 1506b VOID ===") return end

local ZCH = string.rep("\0", 0x4000)
local function zero_all()
    for off = 0, LEN - 1, 0x4000 do
        pcall(function() memory.write_buffer(BUF + off, ZCH) end)
    end
end

local function scan(tag)
    local ok, s = pcall(function() return memory.read_buffer(BUF, LEN) end)
    if not ok or type(s) ~= "string" then
        print(string.format("  [%s] read_buffer FAILED", tag))
        return -1, {}
    end
    local hits, list, pos = 0, {}, 1
    while true do
        local p = s:find("[^%z]", pos)
        if not p then break end
        hits = hits + 1
        if #list < 16 then
            local bi = p - 1
            local idx = math.floor(bi / 2)
            local lo = string.byte(s, idx * 2 + 1) or 0
            local hi = string.byte(s, idx * 2 + 2) or 0
            list[#list + 1] = string.format("byte=0x%X idx=0x%X val=0x%04X", bi, idx, hi * 256 + lo)
        end
        pos = p + 1
    end
    print(string.format("  [%s] nonzero bytes: %d", tag, hits))
    for _, v in ipairs(list) do print("      " .. v) end
    return hits, list
end

-- ---------------------------------------------------------------- [A] baseline
print("")
print("--- [A] baseline: zero everything, expect 0 ---")
profil(0, 0, 0, 0)
zero_all()
local hA = scan("A")

-- ---------------------------------------------------------------- [B] arm, off 0
print("")
print("--- [B] arm scale 1, pr_off 0, pr_size 0x200000 ---")
local SIZE = 0x200000
local a = profil(BUF, SIZE, 0, 1)
print(string.format("  arm rv=%d %s", a, a < 0 and es() or ""))
local sink = spin(30000000)
print(string.format("  spin done (sink=%d)", sink))
print(string.format("  disable rv=%d %s", profil(0, 0, 0, 0), ""))
local hB = scan("B")

-- ---------------------------------------------------------------- [C] re-zero
print("")
print("--- [C] re-zero, expect 0 ---")
zero_all()
local hC = scan("C")

-- ---------------------------------------------------------------- [D] shifted offset
print("")
print("--- [D] arm pr_off 0x10000000, same size/scale ---")
local b = profil(BUF, SIZE, 0x10000000, 1)
print(string.format("  arm rv=%d %s", b, b < 0 and es() or ""))
spin(30000000)
profil(0, 0, 0, 0)
local hD, lD = scan("D")
print("  the tick index must be 0x1000 LOWER than in [B]; identical indices mean no new ticks")

print("")
print(string.format("SUMMARY  baseline=%s  armB=%d  rezero=%s  armD=%d", tostring(hA), hB, tostring(hC), hD))
print(string.format("final canary pid %d", N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
print("=== PROBE 1506b COMPLETE ===")
