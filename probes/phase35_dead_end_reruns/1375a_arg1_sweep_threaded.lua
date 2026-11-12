-- CRASH_CLASS: HIGH -- 529 unknown handlers called with a real pointer. Ten numbers per
-- loader thread, so a blocking call costs ten numbers and one relaunch, not the connection.
-- PROBE 1375a: arg1 = mapped user page, 1-531, threaded slices
--
-- 1374a proved the BSD range cannot be swept in one thread: syscall 95 (fsync) with six zeros
-- never returns -- the plain loop died at Z93 in
-- results/phase35_dead_end_reruns/1374a_arg1_classes_bsd_20261109_125432.txt, with SIG_IGN
-- installed for 5/6/7/8/12/24-26/30/31, so a block is not a signal. Signals 5, 6, 7, 8, 12,
-- 24, 25, 26, 30 and 31 are still ignored here so that the reserved nosys trampoline answers
-- -1 instead of raising SIGSYS (353a/353b).
--
-- Method: the arg1 pointer-class sweep that found 538/557/563-566/572/653 inside 532-676,
-- applied to the BSD range. The zero-argument baseline is not re-measured: every number
-- already has a measured row in docs/SYSENT_PRESENCE_14_10.md (one connection per number),
-- and this pass prints rv for every number so the two tables can be compared offline.
--
-- Each slice of ten numbers runs inside run_lua_code_in_new_thread, which gives the child its
-- own Lua state (memory, syscall, uint64 all available; probes/phase35_dead_end_reruns/
-- 1350b_sys622_kill_containment.lua:62-84 is the idiom). The child writes one result slot per
-- number, so a slice that blocks still leaves the results of the numbers before the block,
-- and the slot that never fills names the culprit. exit (1), execve (59) and the doc's three
-- NO_OUTPUT rows (95, 432, 530) are skipped.
--
-- -- prior art:
--   docs/SYSENT_PRESENCE_14_10.md (per-number zero-arg rows, 161 kill marks, 3 NO_OUTPUT)
--   results/phase35_dead_end_reruns/1374a_arg1_classes_bsd_20261109_125432.txt (hung at 93)
--   results/phase35_dead_end_reruns/1374a_arg1_classes_bsd_20261109_124849.txt (hung at 95)
--   results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101254.txt
--   probes/phase17_new_vectors/1177a_mdbg_sweep_high.lua:53-61 (threaded command sweep)

print("=== PROBE 1375a: THREADED ARG1 SWEEP 1-531 ===")

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
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rqh(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if not ok then return nil end
    if type(v) == "table" and v.h then return to_num(v.h), to_num(v.l) end
    local n = to_num(v)
    return math.floor(n / 4294967296), n % 4294967296
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
local pid = to_num(mk(20)(U(0,0),U(0,0),U(0,0),U(0,0),U(0,0),U(0,0)))
print(string.format("[0] pid=%d sigign=%d/%d", pid, ign, #SIG))
if ign == 0 then print("=== PROBE 1375a ABORT: no SIG_IGN ===") return end

local SLOT = memory.alloc(0x2000)
local BUF  = memory.alloc(0x4000)
local B1 = to_num(BUF)
for i = 0, 0xFFC, 4 do pcall(function() memory.write_dword(BUF + i, 0xA5A5A5A5) end) end
local SKIP = {[1]=true, [59]=true, [95]=true, [432]=true, [530]=true}
local SLICE = 10
local SLOTBASE = to_num(SLOT)
local SENT = 0x5A5A5A5A

local function slot(n) return SLOT + n * 8 end
local function is_sentinel(n)
    local h, l = rqh(slot(n))
    return h == 0 and l == SENT
end
local function rv_of(n)
    local h, l = rqh(slot(n))
    if h == nil or (h == 0 and l == SENT) then return nil end
    if h == 0x1111 then
        local v = l
        if v >= 2147483648 then v = v - 4294967296 end
        return v
    end
    return "EXC"
end

local function spin(k) local x = 0 for i = 1, k do x = x + i end return x end
local LIM = 25                                  -- per slice, a few tens of ms

local hung, hcount = {}, 0
local results = {}

local function run_slice(n0, n1)
    for n = n0, n1 do
        if not SKIP[n] and not hung[n] then wq(slot(n), U(0, SENT)) end
    end
    local first = nil
    for n = n0, n1 do
        if not SKIP[n] and not hung[n] then first = n; break end
    end
    if not first then return end
    local src = string.format([[
local S, A = 0x%X, 0x%X
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
for n = %d, %d do
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    local okc, rv = pcall(function() return t(uint64(A), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    local slot = uint64(S + n * 8)
    if okc then
        memory.write_qword(slot, uint64("0x1111000000000000") + (N(rv) %% 4294967296))
    else
        memory.write_qword(slot, uint64("0x2222000000000000"))
    end
end
]], SLOTBASE, B1, n0, n1)
    local ok, res = pcall(run_lua_code_in_new_thread, src, { async = true })
    if not ok then
        print(string.format("[slice %d-%d] spawn FAILED %s", n0, n1, tostring(res)))
        return
    end
    local pending = 0
    for n = n0, n1 do
        if not SKIP[n] and not hung[n] then pending = pending + 1 end
    end
    for i = 1, LIM do
        local done = 0
        for n = n0, n1 do
            if not SKIP[n] and not hung[n] then
                if rv_of(n) ~= nil then done = done + 1 end
            end
        end
        if done >= pending then return end
        spin(1000000)
    end
    -- budget expired: name the first slot that never filled
    local stuck = nil
    for n = n0, n1 do
        if not SKIP[n] and not hung[n] and rv_of(n) == nil then stuck = n; break end
    end
    if stuck then
        hung[stuck] = true
        hcount = hcount + 1
        print(string.format("  n=%d HANG (slice %d-%d stopped here)", stuck, n0, n1))
    end
end

print("[U] arg1 = mapped user page, slices of " .. SLICE)
for n0 = 1, 531, SLICE do
    local n1 = n0 + SLICE - 1
    if n1 > 531 then n1 = 531 end
    print(string.format("slice %d-%d", n0, n1))
    run_slice(n0, n1)
    for n = n0, n1 do
        if not SKIP[n] then
            local v = rv_of(n)
            if v ~= nil then
                results[n] = v
                print(string.format("  n=%d rv=%s", n, tostring(v)))
            end
        end
    end
end

local nres, nneg, npos, nexc = 0, 0, 0, 0
for n, v in pairs(results) do
    nres = nres + 1
    if v == "EXC" then nexc = nexc + 1
    elseif v >= 0 then npos = npos + 1
    else nneg = nneg + 1 end
end
print(string.format("[U] done: %d answered, %d non-negative, %d -1/other, %d EXC, %d hung",
    nres, npos, nneg, nexc, hcount))
print("=== PROBE 1375a COMPLETE ===")
