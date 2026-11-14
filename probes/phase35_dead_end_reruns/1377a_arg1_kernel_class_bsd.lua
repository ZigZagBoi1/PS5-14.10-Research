-- CRASH_CLASS: LOW -- 24 known-good syscall numbers, called with a supervisor pointer.
-- PROBE 1377a: arg1 pointer class for the 24 non-negative rows of the 1-531 sweep
--
-- 1376a-1376e measured 507 of the 531 BSD slots with arg1 = a mapped user page
-- (docs/SYSENT_PRESENCE_14_10.md carries the per-number zero-argument rows; the pointer-class
-- captures are results/phase35_dead_end_reruns/1376a..1376e_*.txt). 346 of those 507 are the
-- shared nosys stub (errno 78) and 161 are real handlers. Exactly 24 answered with a
-- non-negative return value:
--
--   20 getpid 278 · 24 getuid 1 · 25 geteuid 1 · 36 sync 0 · 39 getppid 54 · 42 compat10.pipe 22
--   43 getegid 1 · 44 profil 0 · 47 getgid 1 · 65 msync 0 · 75 madvise 0 · 78 mincore 0
--   116 gettimeofday 0 (wrote 4) · 203 mlock 0 · 209 poll 0 · 234 clock_getres 0
--   253 issetugid 0 · 331 sched_yield 0 · 340 sigprocmask 0 · 343 sigpending 0 (wrote 4)
--   362 kqueue 22 · 404 ksem_init 0 (wrote 2) · 405 ksem_open 0 (wrote 2) · 421 getcontext 0 (wrote 280)
--
-- The kernel pass of 1376a-1376e never ran (each segment ended on a hang or a kill before its
-- tail), so the class test that found 538/557/563-566/572/653 inside 532-676 has not been
-- applied to these 24. This probe does exactly that: same 24 numbers, arg1 = the kernel image
-- base for this boot, plus a second user-class call for the four writers so the byte counts sit
-- in one capture.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1376a_arg1_user_sweep_20261109_130223.txt
--   results/phase35_dead_end_reruns/1376b_arg1_user_sweep_75_20261109_130404.txt
--   results/phase35_dead_end_reruns/1376c_arg1_user_sweep_342_20261109_130627.txt
--   results/phase35_dead_end_reruns/1376d_arg1_user_sweep_346_20261109_130840.txt
--   results/phase35_dead_end_reruns/1376e_arg1_user_sweep_433_20261109_132246.txt
--   results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101254.txt (the method)

print("=== PROBE 1377a: ARG1 CLASS, THE 24 LIVE BSD SLOTS ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function U(hi, lo) return uint64(string.format("0x%X%08X", hi, lo)) end
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "?"
end

local mk = make_syscall
local SIG = {5, 6, 7, 8, 12, 24, 25, 26, 30, 31}
local sa = memory.alloc(0x80)
for i = 0, 0x7C, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
local ign = 0
for i = 1, #SIG do
    local ok, rv = pcall(function() return mk(416)(uint64(SIG[i]), uint64(sa), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok and to_num(rv) == 0 then ign = ign + 1 end
end
print(string.format("[0] pid=%d sigign=%d/%d", to_num(mk(20)(U(0,0),U(0,0),U(0,0),U(0,0),U(0,0),U(0,0))), ign, #SIG))

local BUF = memory.alloc(0x4000)
local B1 = to_num(BUF)
local PAINT_BYTES = string.rep(string.char(0xA5), 0x1000)
pcall(function() memory.write_buffer(BUF, PAINT_BYTES) end)

local function survey()
    local changed, first = 0, ""
    local ok, s = pcall(function() return memory.read_buffer(BUF, 0x1000) end)
    if not (ok and type(s) == "string" and #s == 0x1000) then return 0, "" end
    for i = 1, 0xFFD, 4 do
        local a, b, c, d = string.byte(s, i, i + 3)
        if not (a == 0xA5 and b == 0xA5 and c == 0xA5 and d == 0xA5) then
            changed = changed + 1
            if #first < 60 then first = first .. string.format(" %02X%02X%02X%02X", d, c, b, a) end
        end
    end
    return changed, first
end
local function repaint() pcall(function() memory.write_buffer(BUF, PAINT_BYTES) end) end

local NUMBERS = {20, 24, 25, 36, 39, 42, 43, 44, 47, 65, 75, 78, 116, 203, 209, 234,
                 253, 331, 340, 343, 362, 404, 405, 421}
local WRITERS = {[116]=true, [343]=true, [404]=true, [405]=true, [421]=true}

local function call(n, a1)
    local sc = make_syscall(n)
    local ok, rv = pcall(function() return sc(a1, U(0, 0), U(0, 0), U(0, 0), U(0, 0), U(0, 0)) end)
    if not ok then return "EXC" end
    return to_num(rv)
end

local KB = U(0xFFFFFFFF, 0xC1000000)
print("[K] arg1 = kernel image base 0xFFFFFFFFC1000000")
for i = 1, #NUMBERS do
    local n = NUMBERS[i]
    print("k" .. n)
    repaint()
    local rv = call(n, KB)
    local extra = ""
    if WRITERS[n] then
        local changed, first = survey()
        extra = string.format("  wrote=%d%s", changed, first ~= "" and (" [" .. first .. "]") or "")
    end
    if rv == "EXC" then
        print(string.format("  n=%d EXC", n))
    elseif rv == -1 then
        print(string.format("  n=%d rv=-1 errno=%s%s", n, es(), extra))
    else
        print(string.format("  n=%d rv=%d%s", n, rv, extra))
    end
end

print("[U] the five writers with arg1 = user page, for the byte counts in one capture")
for i = 1, #NUMBERS do
    local n = NUMBERS[i]
    if WRITERS[n] then
        print("u" .. n)
        repaint()
        local rv = call(n, U(0, B1))
        local changed, first = survey()
        if rv == "EXC" then
            print(string.format("  n=%d EXC", n))
        else
            print(string.format("  n=%d rv=%d wrote=%d%s", n, rv, changed,
                first ~= "" and (" [" .. first .. "]") or ""))
        end
    end
end

print("=== PROBE 1377a COMPLETE ===")
