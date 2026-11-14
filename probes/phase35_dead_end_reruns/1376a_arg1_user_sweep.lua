-- CRASH_CLASS: HIGH -- 525 unknown handlers called with a real pointer, in one thread.
-- A blocking handler ends the connection; every later number is lost and the capture names
-- the culprit. 1376a: arg1 = mapped user page over 1-531 (plain loop, no threads).
--
-- 1374a's two attempts hung at sys 95 and then at sys 93; the three NO_OUTPUT rows in
-- docs/SYSENT_PRESENCE_14_10.md (95 fsync, 432 thr_self, 530) are skipped from the start.
-- 1375a tried to make the sweep hang-tolerant with ten numbers per loader thread and every
-- child call came back EXC -- a fresh luaL_newstate has `syscall.pipe` without the metatable
-- that makes it callable (results/phase35_dead_end_reruns/1375a_arg1_sweep_threaded_20261109_130102.txt,
-- plus a child fault at slice 71-80 matching the loader's own warning about an unfixed native
-- race in .local/loader_payload/thread.lua:113). So: one thread, explicit skip list.
--
-- Method: the arg1 pointer-class sweep that found 538/557/563-566/572/653 inside 532-676,
-- applied to 1-531. The zero-argument baseline is not re-measured -- every number already has
-- a measured row in docs/SYSENT_PRESENCE_14_10.md -- and rv is printed for every number so
-- the two tables can be compared offline. SIG_IGN is installed for the ten ignorable signals
-- first, so a nosys slot answers -1 instead of raising SIGSYS (353a/353b).
--
-- -- prior art:
--   docs/SYSENT_PRESENCE_14_10.md (per-number zero-arg rows, 161 kill marks, 3 NO_OUTPUT)
--   results/phase35_dead_end_reruns/1374a_arg1_classes_bsd_20261109_124849.txt (hung at 95)
--   results/phase35_dead_end_reruns/1374a_arg1_classes_bsd_20261109_125432.txt (hung at 93)
--   results/phase35_dead_end_reruns/1375a_arg1_sweep_threaded_20261109_130102.txt (all EXC)
--   results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101254.txt

print("=== PROBE 1376a: ARG1 = USER PAGE, 1-531 ===")

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
if ign == 0 then print("=== PROBE 1376a ABORT: no SIG_IGN ===") return end

local BUF = memory.alloc(0x4000)
local B1 = to_num(BUF)
local PAINT_BYTES = string.rep(string.char(0xA5), 0x1000)
local BULK = pcall(function() memory.write_buffer(BUF, PAINT_BYTES) end)
local SKIP = {[1]=true, [59]=true, [93]=true, [95]=true, [432]=true, [530]=true}

local function paint()
    if BULK and pcall(function() memory.write_buffer(BUF, PAINT_BYTES) end) then return end
    for i = 0, 0xFFC, 4 do pcall(function() memory.write_dword(BUF + i, 0xA5A5A5A5) end) end
end
local function survey()
    local changed, first = 0, ""
    local s = nil
    if BULK then
        local ok, v = pcall(function() return memory.read_buffer(BUF, 0x1000) end)
        if ok and type(v) == "string" and #v == 0x1000 then s = v end
    end
    if not s then return 0, "" end
    for i = 1, 0xFFD, 4 do
        local a, b, c, d = string.byte(s, i, i + 3)
        if not (a == 0xA5 and b == 0xA5 and c == 0xA5 and d == 0xA5) then
            changed = changed + 1
            if #first < 48 then first = first .. string.format(" %02X%02X%02X%02X", d, c, b, a) end
        end
    end
    return changed, first
end

local function call(n, a1)
    local sc = make_syscall(n)
    local ok, rv = pcall(function() return sc(a1, U(0, 0), U(0, 0), U(0, 0), U(0, 0), U(0, 0)) end)
    if not ok then return nil end
    return to_num(rv)
end

paint()
local success = {}
print("[U] arg1 = mapped user page")
for n = 1, 531 do
    if not SKIP[n] then
        print("n" .. n)
        local rv = call(n, U(0, B1))
        if rv == nil then
            print(string.format("  n=%d EXC", n))
        elseif rv == -1 then
            print(string.format("  n=%d rv=-1 errno=%s", n, es()))
        else
            local changed, first = survey()
            print(string.format("  n=%d rv=%d%s", n, rv, changed > 0 and ("  wrote=" .. changed .. " [" .. first .. "]") or ""))
            success[#success + 1] = n
            if changed > 0 then paint() end
        end
    end
end

print(string.format("[U] done: %d non-negative", #success))
print("[K] arg1 = kernel image base, for the non-negative rows")
for i = 1, #success do
    local n = success[i]
    print("k" .. n)
    local rv = call(n, U(0xFFFFFFFF, 0xC1000000))
    local mark = ""
    if rv == nil then mark = "  EXC"
    elseif rv ~= 0 then mark = "  (user rv=0)" end
    print(string.format("  n=%d kaddr_rv=%s%s", n, tostring(rv), mark))
end

print("=== PROBE 1376a COMPLETE ===")
