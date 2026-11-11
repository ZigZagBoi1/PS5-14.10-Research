-- CRASH_CLASS: MODERATE -- 532 unknown handlers, each called once with a real file descriptor and a
-- mapped output buffer. A handler that kills still kills; the skip list covers only the numbers that
-- ended a previous segment.
-- PROBE 1387a: the BSD range with a real file descriptor and a real output buffer
--
-- Every BSD sweep so far passed arg1 = a page pointer and arg2..6 = 0. For a handler whose first
-- argument is a descriptor that is EBADF, and for a handler that copies out to arg2 it is a null
-- destination - so both classes of answer were invisible. The five segments 1376a-1376e measured
-- "does the number return a value", not "does it write anything".
--
-- This probe calls each number 0..531 as n(fd, buf, 0x800, 0, 0, 0) with fd = an open
-- /app0/eboot.bin and buf = a 0x800-byte page painted 0xAA, then reports every changed dword and
-- every qword whose high 16 bits are >= 0xFFFF8000 (the kernel-pointer band used by this project:
-- real kernel pointers look like 0xFFFF8xxx_xxxxxxxx; 0xFFFFFFFF_* sentinels do not match the test
-- because the test is h >= 0xFFFF8000 and h == 0xFFFFFFFF does match it, so the sentinel values are
-- also printed and can be discarded by eye).
--
-- Rationale: the only two kernel-pointer disclosures found in the whole 13.60 corpus are sys 397
-- (behind priv_check(td,0x2ab) - measured EPERM on 14.10) and sys 607 (behind the cred+0x58 tag
-- compare - measured EACCES), plus two functions with no sysent entry. A *different* 14.10 handler
-- with a copyout that the corpus did not flag is exactly what a real-argument pass would find.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1376a..1376e (arg1 = page, arg2 = 0: returns only)
--   results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101254.txt (532-676)
--   results/phase35_dead_end_reruns/1343b_arg23_writers_20261109_101855.txt (7 writers, no kptr)
--   docs/KERNEL_POINTER_LEAK_CENSUS_14_10.md (4 static candidates, all gated or unreferenced)
--   docs/ARG1_CLASSES_BSD_14_10.md (the 531-row table this probe complements)

print("=== PROBE 1387a: BSD REAL-ARGUMENT LEAK SWEEP ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t = {} for k, v in pairs(syscall.pipe) do t[k] = v end t.syscall_no = n setmetatable(t, getmetatable(syscall.pipe)) return t end
local function es() local ok, s = pcall(function() return get_error_string() end) if ok and type(s) == "string" then return s end return "errno?" end
local function spin(n) local x = 0 for i = 1, n do x = x + i end return x end

-- SIG_IGN for the signals a nosys slot can raise, so an absent slot answers -1 instead of dying.
do
    local SA = memory.alloc(0x80)
    for i = 0, 15 do pcall(function() memory.write_qword(SA + i * 8, uint64(0)) end) end
    pcall(function() memory.write_qword(SA, uint64(1)) end)
    local sigs = {5, 6, 7, 8, 12, 24, 25, 26, 30, 31}
    local okd = 0
    for i = 1, #sigs do
        local ok, rv = pcall(function() return mk(416)(uint64(sigs[i]), uint64(SA), uint64(0)) end)
        if ok and N(rv) == 0 then okd = okd + 1 end
    end
    print(string.format("[0] SIG_IGN installed on %d/10 signals", okd))
end

-- one descriptor we can hand to anything that wants one
local FD = -1
do
    local path = memory.alloc(0x80)
    pcall(function()
        memory.write_buffer(path, "/app0/eboot.bin\0")
        local ok, rv = pcall(function() return mk(5)(uint64(N(path)), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
        if ok then FD = N(rv) end
    end)
    print(string.format("[0] open(/app0/eboot.bin) = %d", FD))
end

local BUF = memory.alloc(0x800 + 0x40)
local BU = N(BUF)
local LP = memory.alloc(0x80)
local LPU = N(LP)
pcall(function() memory.write_buffer(LP, "/app0/eboot.bin\0") end)
local CANARY_A, CANARY_B = 0x5A5AA5A5, 0xC3C33C3C

local function paint()
    pcall(function()
        memory.write_buffer(BUF, string.rep("\xAA", 0x800))
        memory.write_dword(BUF + 0x800, CANARY_A)
        memory.write_dword(BUF + 0x804, CANARY_B)
    end)
end

local function scan(tag, rv)
    local changed = 0
    local kp = 0
    local head = ""
    for j = 0, 0x7FF, 4 do
        local ok, v = pcall(function() return N(memory.read_dword(BU + j)) end)
        if ok and v ~= 0xAAAAAAAA then
            changed = changed + 1
            if #head < 80 then head = head .. string.format(" %03X:%08X", j, v) end
        end
    end
    for j = 0, 0x7F8, 8 do
        local okh, hi = pcall(function() return N(memory.read_dword(BU + j + 4)) end)
        if okh and hi >= 0xFF800000 then
            local okl, lo = pcall(function() return N(memory.read_dword(BU + j)) end)
            kp = kp + 1
            if #head < 200 then head = head .. string.format(" KP[%03X]=%08X%08X", j, hi, okl and lo or 0) end
        end
    end
    local cr = -1
    local okc, c = pcall(function() return N(memory.read_dword(BUF + 0x800)) end)
    if okc then cr = c end
    return changed, kp, cr, head
end

-- union of every skip the 1376a-1376e segments had to add: 1 is exit (it ended run 1 of this
-- probe, at n=1, before any output), the rest killed or wedged in the earlier page-argument sweep.
local SKIP = {[0] = "indirect syscall dispatcher - recurses and kills", [1] = "exit - 1387a run 1 died here", [2] = "fork - 1387a run 2 died here",
    [59] = "1376a", [74] = "mprotect 1376a", [93] = "1376a", [95] = "1376a",
    [341] = "sigsuspend 1376c", [345] = "sigtimedwait 1376c", [346] = "1376d", [359] = "1376d",
    [363] = "1376d", [402] = "1376d", [417] = "1376d", [429] = "1376d",
    [431] = "thr_exit 1376d", [432] = "1376a", [441] = "1376d", [442] = "1376e",
    [455] = "thr_new 1376e", [460] = "1376e", [461] = "1376e", [462] = "1376e", [465] = "1376e",
    [522] = "1376d", [530] = "1376a"}
local START, STOP = 0, 531
print(string.format("[A] n(fd=%d, buf, 0x800, 0, 0, 0) for n = %d..%d", FD, START, STOP))

local findings = 0
for n = START, STOP do
    if SKIP[n] then
        print(string.format("  n=%-3d SKIP  %s", n, SKIP[n]))
    else
        paint()
        -- a fresh descriptor per call: a handler that consumes it (close, fstat, revoke) must not
        -- leave the rest of the sweep with a dead fd.
        local fd = FD
        do
            local okf, rvf = pcall(function() return mk(5)(uint64(LPU), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
            if okf and N(rvf) >= 0 then fd = N(rvf) end
        end
        local ok, rv = pcall(function()
            return mk(n)(uint64(fd), uint64(BU), uint64(0x800), uint64(0), uint64(0), uint64(0))
        end)
        local r = ok and N(rv) or -99999
        local changed, kp, cr, head = scan(n, r)
        if changed > 0 or kp > 0 or (ok and r >= 0) then
            findings = findings + 1
            print(string.format("  n=%-3d rv=%-8s %-20s changed=%-4d kptr=%-2d canary=%08X%s",
                n, tostring(r), ok and es() or "EXC", changed, kp, cr, head))
        end
    end
    if n % 64 == 63 then spin(200000) end
end
print(string.format("[A] done, %d numbers produced a non-default answer", findings))

-- B: the descriptor call again, but with the length in arg3 as well (sysctl/getdirentries shape)
print("[B] curated descriptor calls with a 4 KiB output buffer")
local BIG = memory.alloc(0x1000 + 0x40)
local BGU = N(BIG)
local LIST = {189, 272, 393, 397, 30, 92, 95, 116, 344, 340, 421, 404, 405}
for i = 1, #LIST do
    local n = LIST[i]
    pcall(function()
        memory.write_buffer(BIG, string.rep("\xAA", 0x1000))
        memory.write_dword(BIG + 0x1000, CANARY_A)
    end)
    local ok, rv = pcall(function()
        return mk(n)(uint64(FD), uint64(BGU), uint64(0x1000), uint64(0), uint64(0), uint64(0))
    end)
    local r = ok and N(rv) or -99999
    local changed, kp = 0, 0
    local head = ""
    for j = 0, 0xFFF, 4 do
        local ok2, v = pcall(function() return N(memory.read_dword(BGU + j)) end)
        if ok2 and v ~= 0xAAAAAAAA then changed = changed + 1 if #head < 60 then head = head .. string.format(" %03X:%08X", j, v) end end
    end
    for j = 0, 0xFF8, 8 do
        local ok2, hi = pcall(function() return N(memory.read_dword(BGU + j + 4)) end)
        if ok2 and hi >= 0xFF800000 then kp = kp + 1 end
    end
    local okc, c = pcall(function() return N(memory.read_dword(BIG + 0x1000)) end)
    print(string.format("  n=%-3d rv=%-8s %-20s changed=%-4d kptr=%-2d canary=%08X%s",
        n, tostring(r), ok and es() or "EXC", changed, kp, okc and c or -1, head))
end

print(string.format("[C] alive pid=%d", N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
print("=== PROBE 1387a COMPLETE ===")
