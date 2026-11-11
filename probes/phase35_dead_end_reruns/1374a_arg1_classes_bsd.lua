-- CRASH_CLASS: HIGH -- 531 unknown handlers called with a real pointer. SIGSYS is
-- ignored first so nosys slots answer instead of dying; exit/execve are skipped.
-- PROBE 1374a: arg1 pointer classes over 1-531 (the BSD range was never swept)
--
-- The arg1-class method (1342a/1343a) found eight Sony handler numbers whose return
-- value changes with the class of the first argument -- 538, 557, 563-566, 572, 653 --
-- and that sweep covered only 532-676. Numbers 1-531 have been called exactly once,
-- with six zeros (docs/SYSENT_PRESENCE_14_10.md), and 161 of them are recorded there as
-- "kills", a mark that mostly predates the SIGSYS correction (probes/phase17_new_vectors/
-- 353b_lethal_reclassify.lua:41-57): the reserved nosys trampoline raises signal 12, so a
-- stub looks hostile until SIG_IGN is installed.
--
-- Three passes, all on one connection, everything printed only where it differs:
--   [Z] baseline, six zeros, to re-classify the 161 kill marks without the signal
--   [U] arg1 = a mapped 0x4000 user page, surveyed for writes and for kernel-shaped qwords
--   [K] arg1 = the kernel image base (present supervisor page per 1331a), for the rows
--       that answered differently in [U] -- the class test that found the eight above
--
-- exit (1) and execve (59) are skipped: the first ends the connection, the second would
-- replace the process under us. 95 (fsync), 432 (thr_self) and 530 are skipped too: the
-- per-connection presence sweep recorded NO_OUTPUT for all three (docs/SYSENT_PRESENCE_14_10.md),
-- i.e. a call that never returns, and 1374a's first attempt hung inside the baseline pass
-- before n=100 -- 95 is the only one of them below that mark and the only candidate.
-- Every number prints "Z<n>"/"U<n>" before its call, so a hang names its own culprit.
-- First attempt: results/phase35_dead_end_reruns/1374a_arg1_classes_bsd_20261109_124849.txt
-- (89 bytes: pid, sigign=10/10, then nothing).
--
-- -- prior art:
--   docs/SYSENT_PRESENCE_14_10.md (per-number zero-arg results, 161 kill marks)
--   results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101254.txt
--   results/phase35_dead_end_reruns/1343a_arg23_classes_20261109_101720.txt
--   probes/phase17_new_vectors/353b_lethal_reclassify.lua:41-57 (the SIG_IGN idiom)

print("=== PROBE 1374a: ARG1 CLASSES 1-531 ===")

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
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "?"
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok and v ~= nil then return to_num(v) end
    return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then
        local h, l = 0, 0
        if type(v) == "table" and v.h then h, l = to_num(v.h), to_num(v.l)
        else h = math.floor(to_num(v) / 4294967296); l = to_num(v) % 4294967296 end
        return h, l
    end
    return nil, nil
end
local function wd(addr, val) pcall(function() memory.write_dword(addr, val) end) end
local function U(hi, lo) return uint64(string.format("0x%X%08X", hi, lo)) end

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
if ign == 0 then print("=== PROBE 1374a ABORT: no SIG_IGN ===") return end

local BUF  = memory.alloc(0x4000)
local B1 = to_num(BUF)
local KB = U(0xFFFFFFFF, 0xC1000000)
local PAINT = 0xA5A5A5A5
local SKIP = {[1] = true, [59] = true, [95] = true, [432] = true, [530] = true}

local function call(n, a1)
    local sc = make_syscall(n)
    local ok, rv = pcall(function() return sc(a1, U(0,0), U(0,0), U(0,0), U(0,0), U(0,0)) end)
    if not ok then return -999, "EXC" end
    return to_num(rv), es()
end


-- Bulk paint and survey: 0x4000 bytes through memory.write_buffer/read_buffer is one
-- C call per direction, where a per-dword pcall loop is 4096 Lua calls and takes long
-- enough to turn the sweep into a timeout. The dword loop stays as a fallback.
local BULK = 0x1000
local PAINT_BYTES = string.rep(string.char(0xA5), BULK)
local BULK_OK = pcall(function() memory.write_buffer(BUF, PAINT_BYTES) end)
local function paint()
    if BULK_OK then
        local ok = pcall(function() memory.write_buffer(BUF, PAINT_BYTES) end)
        if ok then return end
    end
    for i = 0, BULK - 4, 4 do wd(BUF + i, PAINT) end
end
local function survey()
    local changed, first, kq = 0, "", -1
    local s = nil
    if BULK_OK then
        local ok, v = pcall(function() return memory.read_buffer(BUF, BULK) end)
        if ok and type(v) == "string" and #v == BULK then s = v end
    end
    if s then
        for i = 1, BULK - 3, 4 do
            local a, b, c, d = string.byte(s, i, i + 3)
            if not (a == 0xA5 and b == 0xA5 and c == 0xA5 and d == 0xA5) then
                changed = changed + 1
                if #first < 40 then first = first .. string.format(" %02X%02X%02X%02X", d, c, b, a) end
            end
        end
        if changed > 0 then
            for i = 1, BULK - 7, 8 do
                local h1, h2, h3, h4 = string.byte(s, i + 4, i + 7)
                local h = h4 * 16777216 + h3 * 65536 + h2 * 256 + h1
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then kq = i - 1; break end
            end
        end
        return changed, first, kq
    end
    for i = 0, BULK - 4, 4 do
        local v = rd(BUF + i)
        if v ~= nil and v ~= PAINT then
            changed = changed + 1
            if #first < 40 then first = first .. string.format(" %08X", v) end
        end
    end
    if changed > 0 then
        for i = 0, BULK - 8, 8 do
            local h = rq(BUF + i)
            if h and h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then kq = i; break end
        end
    end
    return changed, first, kq
end

local base, bu, bk = {}, {}, {}
local interesting = {}

print("[Z] baseline, six zeros")
for n = 1, 531 do
    if not SKIP[n] then
        print("Z" .. n)
        local rv, e = call(n, U(0, 0))
        base[n] = rv .. "|" .. e
        if n % 100 == 0 then print(string.format("    ... n=%d", n)) end
    end
end
print("[Z] done")

print("[U] arg1 = mapped user page")
for n = 1, 531 do
    if not SKIP[n] then
        print("U" .. n)
        paint()
        local rv, e = call(n, U(0, B1))
        bu[n] = rv .. "|" .. e
        local changed, first, kq = survey()
        if bu[n] ~= base[n] or changed > 0 then
            interesting[#interesting + 1] = n
            print(string.format("  n=%d  base=%s  user=%d/%s  wrote=%d%s%s",
                n, base[n], rv, e, changed, first ~= "" and ("  [" .. first .. "]") or "",
                kq >= 0 and ("  KERNEL-QWORD at +0x" .. string.format("%X", kq)) or ""))
        end
        if n % 100 == 0 then print(string.format("    ... n=%d", n)) end
    end
end
print(string.format("[U] done, %d interesting", #interesting))

print("[K] arg1 = kernel image base, for the interesting rows")
for i = 1, #interesting do
    local n = interesting[i]
    local rv, e = call(n, KB)
    bk[n] = rv .. "|" .. e
    local mark = ""
    if bu[n] ~= bk[n] then mark = "  <-- CLASS-DEPENDENT" end
    print(string.format("  n=%d  user=%s  kaddr=%d/%s%s", n, bu[n], rv, e, mark))
end

print("=== PROBE 1374a COMPLETE ===")
