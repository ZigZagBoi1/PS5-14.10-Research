-- CRASH_CLASS: MODERATE
-- PROBE 392f: BSD last batch — ktimer, profil, fcntl, stat enumeration
--
-- Final sweep of BSD-native range before concluding exploration

print("=== PROBE 392f: BSD last batch ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end
local function write_str(buf, s)
    zero_buf(buf, (#s + 8) - ((#s + 8) % 4))
    for i = 0, #s - 1, 4 do
        local dw = 0
        for j = 0, 3 do
            local idx = i + j + 1
            if idx <= #s then dw = dw + string.byte(s, idx) * (256 ^ j) end
        end
        wd(N(buf) + i, dw)
    end
end

-- Ignore SIGSYS
local act = memory.alloc(0x40)
zero_buf(act, 0x40)
wq(N(act), uint64(1))
pcall(function() mk(416)(uint64(12), act, uint64(0)) end)

-- ===================================================================
-- [A] ktimer lifecycle
-- ===================================================================
print("[A] ktimer")

-- ktimer_create(235): (clockid, evp, timerid_out)
local tid_buf = memory.alloc(8)
zero_buf(tid_buf, 8)
-- CLOCK_REALTIME=0, no sigevent (NULL)
local ok_kc, rv_kc = pcall(function()
    return mk(235)(uint64(0), uint64(0), tid_buf)
end)
local ret_kc = ok_kc and N(rv_kc) or -999
local timer_id = rd(N(tid_buf)) or -1
print(string.format("  ktimer_create(REALTIME): ret=%d id=%d", ret_kc, timer_id))

if ret_kc == 0 and timer_id >= 0 then
    -- ktimer_settime(236): (id, flags, value, ovalue)
    -- struct itimerspec: 2x struct timespec (tv_sec + tv_nsec = 16 bytes each)
    local its = memory.alloc(32)
    zero_buf(its, 32)
    -- interval: 0 (one-shot)
    -- value: 1 nanosecond (fire immediately)
    wd(N(its) + 16, 0)    -- tv_sec = 0
    wd(N(its) + 24, 1)    -- tv_nsec = 1

    local oits = memory.alloc(32)
    zero_buf(oits, 32)

    local ok_ks, rv_ks = pcall(function()
        return mk(236)(uint64(timer_id), uint64(0), its, oits)
    end)
    print(string.format("  ktimer_settime(1ns): ret=%d", ok_ks and N(rv_ks) or -999))

    -- ktimer_gettime(237)
    local gits = memory.alloc(32)
    zero_buf(gits, 32)
    local ok_kg, rv_kg = pcall(function()
        return mk(237)(uint64(timer_id), gits)
    end)
    local ret_kg = ok_kg and N(rv_kg) or -999
    print(string.format("  ktimer_gettime: ret=%d", ret_kg))
    if ret_kg == 0 then
        local rem_sec = rd(N(gits) + 16) or 0
        local rem_ns = rd(N(gits) + 24) or 0
        print(string.format("    remaining: %d.%09d", rem_sec, rem_ns))
    end

    -- ktimer_getoverrun(238)
    local ok_ko, rv_ko = pcall(function()
        return mk(238)(uint64(timer_id))
    end)
    print(string.format("  ktimer_getoverrun: ret=%d", ok_ko and N(rv_ko) or -999))

    -- ktimer_delete(239)
    local ok_kd, rv_kd = pcall(function()
        return mk(239)(uint64(timer_id))
    end)
    print(string.format("  ktimer_delete: ret=%d", ok_kd and N(rv_kd) or -999))

    -- Create a second timer to test CLOCK_MONOTONIC
    zero_buf(tid_buf, 8)
    local ok_km, rv_km = pcall(function()
        return mk(235)(uint64(4), uint64(0), tid_buf)  -- CLOCK_MONOTONIC=4
    end)
    print(string.format("  ktimer(MONOTONIC): ret=%d id=%d",
        ok_km and N(rv_km) or -999, rd(N(tid_buf)) or -1))
    if (ok_km and N(rv_km) or -1) == 0 then
        pcall(function() mk(239)(uint64(rd(N(tid_buf)) or 0)) end)
    end
else
    print("  ktimer_create failed, skip rest")
end

if not alive() then print("DEAD [A]"); return end
print("")

-- ===================================================================
-- [B] profil(44) — statistical profiling
-- ===================================================================
print("[B] profil(44)")

-- profil(samples, size, offset, scale)
-- scale=0 disables, scale=0x10000 = 1:1 mapping
local prof_buf = memory.alloc(0x1000)
zero_buf(prof_buf, 0x1000)

local ok_p, rv_p = pcall(function()
    return mk(44)(prof_buf, uint64(0x1000), uint64(0), uint64(0x10000))
end)
print(string.format("  profil(enable): ret=%d", ok_p and N(rv_p) or -999))

-- Disable profiling
local ok_pd, rv_pd = pcall(function()
    return mk(44)(uint64(0), uint64(0), uint64(0), uint64(0))
end)
print(string.format("  profil(disable): ret=%d", ok_pd and N(rv_pd) or -999))

-- Check if any samples were written
local samples = 0
for off = 0, 0xFC, 4 do
    local d = rd(N(prof_buf) + off)
    if d and d ~= 0 then samples = samples + 1 end
end
print(string.format("  samples written: %d/64", samples))

if not alive() then print("DEAD [B]"); return end
print("")

-- ===================================================================
-- [C] fcntl(92) on various fds
-- ===================================================================
print("[C] fcntl(92)")

-- Create test fds
local sock = -1
local ok_sf, rv_sf = pcall(function()
    return mk(97)(uint64(2), uint64(1), uint64(0))
end)
if ok_sf then sock = N(rv_sf) end

-- F_GETFL=3, F_GETFD=1, F_GETLK=11, F_GETOWN=5
-- F_GETPATH_MTMINFO = 47 (macOS), try anyway
-- F_GET_SEALS = 1034 (Linux, might exist on FreeBSD)

local fcntl_cmds = {
    {1, "F_GETFD"},
    {3, "F_GETFL"},
    {5, "F_GETOWN"},
    {14, "F_ISUNIONSTACK"},
    {15, "F_KINFO"},  -- FreeBSD: get file descriptor info
}

if sock >= 0 then
    for _, cmd in ipairs(fcntl_cmds) do
        if not alive() then break end
        local ok_fc, rv_fc = pcall(function()
            return mk(92)(uint64(sock), uint64(cmd[1]))
        end)
        local ret = ok_fc and N(rv_fc) or -999
        print(string.format("  fcntl(sock, %s=%d): ret=%d", cmd[2], cmd[1], ret))
    end

    -- F_KINFO (15) with buffer — might return struct kinfo_file with kernel addresses!
    local kinfo_buf = memory.alloc(0x400)
    zero_buf(kinfo_buf, 0x400)
    -- kf_structsize at +0
    wd(N(kinfo_buf), 0x400)
    local ok_ki, rv_ki = pcall(function()
        return mk(92)(uint64(sock), uint64(15), kinfo_buf)
    end)
    local ret_ki = ok_ki and N(rv_ki) or -999
    print(string.format("  fcntl(sock, F_KINFO, buf): ret=%d", ret_ki))
    if ret_ki == 0 then
        -- Scan first 128 bytes for interesting data
        local nonzero = 0
        for off = 0, 124, 4 do
            local d = rd(N(kinfo_buf) + off)
            if d and d ~= 0 then
                nonzero = nonzero + 1
                if nonzero <= 8 then
                    print(string.format("    +%02X: 0x%08X", off, d))
                end
            end
        end
        -- Check for kptrs (two adjacent dwords)
        for off = 0, 0x3F0, 8 do
            local lo = rd(N(kinfo_buf) + off)
            local hi = rd(N(kinfo_buf) + off + 4)
            if hi and hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                print(string.format("    +%03X: KPTR hi=%08X lo=%08X", off, hi, lo or 0))
            end
        end
    end

    pcall(function() mk(6)(uint64(sock)) end)
end

if not alive() then print("DEAD [C]"); return end
print("")

-- ===================================================================
-- [D] stat enumeration — what paths can we stat?
-- ===================================================================
print("[D] stat")

local path_buf = memory.alloc(64)
local stat_buf = memory.alloc(0x100)

local paths = {
    "/", "/dev", "/dev/null", "/dev/dce", "/dev/gc",
    "/app0", "/app0/eboot.bin", "/app0/sce_sys",
    "/system", "/system/common", "/system/common/lib",
    "/data", "/user", "/mnt", "/hostapp",
    "/proc", "/proc/curproc", "/tmp", "/system_tmp",
    "/dev/hid", "/dev/rng", "/dev/urandom",
    "/sandbox", "/usb", "/savedata",
}

for _, p in ipairs(paths) do
    if not alive() then break end
    write_str(path_buf, p)
    zero_buf(stat_buf, 0x100)
    local ok_st, rv_st = pcall(function()
        return mk(188)(path_buf, stat_buf)
    end)
    local ret = ok_st and N(rv_st) or -999
    if ret == 0 then
        local ino = rd(N(stat_buf) + 8) or 0
        local mode = rd(N(stat_buf) + 4) or 0
        local size_lo = rd(N(stat_buf) + 0x60) or 0
        print(string.format("  stat(%s): ino=%d mode=0x%04X size=%d",
            p, ino, mode % 0x10000, size_lo))
    end
end

if not alive() then print("DEAD [D]"); return end
print("")

-- ===================================================================
-- [E] Misc remaining
-- ===================================================================
print("[E] misc")

-- ptrace(26) — probably blocked
local ok_pt, rv_pt = pcall(function()
    return mk(26)(uint64(0), uint64(0), uint64(0), uint64(0))  -- PT_TRACE_ME
end)
print(string.format("  ptrace: %d", ok_pt and N(rv_pt) or -999))

-- minherit(250) on heap
local heap = memory.alloc(0x4000)
local ok_mi, rv_mi = pcall(function()
    return mk(250)(uint64(N(heap)), uint64(0x4000), uint64(2))  -- INHERIT_NONE
end)
print(string.format("  minherit(heap, NONE): %d", ok_mi and N(rv_mi) or -999))

-- INHERIT_SHARE
local ok_mi2, rv_mi2 = pcall(function()
    return mk(250)(uint64(N(heap)), uint64(0x4000), uint64(0))  -- INHERIT_SHARE
end)
print(string.format("  minherit(heap, SHARE): %d", ok_mi2 and N(rv_mi2) or -999))

-- rfork(251) — probably blocked
local ok_rf, rv_rf = pcall(function()
    return mk(251)(uint64(0x80000))  -- RFTHREAD
end)
print(string.format("  rfork(RFTHREAD): %d", ok_rf and N(rv_rf) or -999))

-- yield(321)
local ok_y, rv_y = pcall(function() return mk(321)() end)
print(string.format("  yield: %d", ok_y and N(rv_y) or -999))

-- cpuset_getid(486)
local cpuset_id = memory.alloc(8)
zero_buf(cpuset_id, 8)
local ok_ci, rv_ci = pcall(function()
    return mk(486)(uint64(0), uint64(0), uint64(pid_val), cpuset_id)
end)
print(string.format("  cpuset_getid: %d", ok_ci and N(rv_ci) or -999))
if (ok_ci and N(rv_ci) or -1) == 0 then
    print(string.format("    cpuset=%d", rd(N(cpuset_id)) or -1))
end

-- cpuset_getaffinity(487)
local mask = memory.alloc(0x80)
zero_buf(mask, 0x80)
local ok_ca, rv_ca = pcall(function()
    return mk(487)(uint64(0), uint64(0), uint64(pid_val), uint64(0x80), mask)
end)
print(string.format("  cpuset_getaffinity: %d", ok_ca and N(rv_ca) or -999))
if (ok_ca and N(rv_ca) or -1) == 0 then
    local m0 = rd(N(mask)) or 0
    print(string.format("    mask=0x%08X", m0))
end

-- audit(445) — BSM audit
local ok_au, rv_au = pcall(function()
    return mk(445)(uint64(0), uint64(0))
end)
print(string.format("  audit: %d", ok_au and N(rv_au) or -999))

-- getaudit_addr(451) — audit info with potential addresses
local auinfo = memory.alloc(0x100)
zero_buf(auinfo, 0x100)
local ok_ga, rv_ga = pcall(function()
    return mk(451)(auinfo, uint64(0x100))
end)
print(string.format("  getaudit_addr: %d", ok_ga and N(rv_ga) or -999))

if not alive() then print("DEAD"); return end
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 392f COMPLETE ===")
