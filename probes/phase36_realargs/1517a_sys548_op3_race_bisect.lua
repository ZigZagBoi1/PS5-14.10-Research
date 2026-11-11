-- CRASH_CLASS: HIGH -- races 548 op 3 against a page fault taken inside copyin. If the vm layer
--   drops the entry under the fault handler, the console may panic.
-- PROBE 1517a: bisect the op 3 / copyin-fault race -- how far does it get, and which part kills it?
--
-- 1516a established the important part: the racing thread faults the page INSIDE write(), and an
-- unmapped source there returns EFAULT(14) instead of delivering a signal (measured, [A]). The
-- process still died during the racing phase. This probe separates the three ways that can happen:
--   1. the child thread alone is unstable          -> [C] fails with no op 3 running
--   2. main's own write/replace loop is unstable   -> [B] fails with no child running
--   3. only the combination dies                   -> [D] fails, and the round number says when
-- Every phase prints before it runs, so the capture truncates exactly where the death happened.
--
-- [A] socketpair, page V, counter page SH; prove an unmapped source returns EFAULT
-- [B] CONTROL 1: main alone, 300 rounds of write / op3 replace. No second thread.
-- [C] CONTROL 2: the writer thread alone for 200000 writes, no op 3 at all
-- [D] RACE: writer thread running, then main does 400 rounds, printing every 25
-- [E] afterwards: drain the socket, read the page, confirm the descriptor still works
--
-- -- prior art:
--   results/phase36_realargs/1516a_sys548_op3_kernel_fault_race_20261109_231009.txt (spawn OK, then
--     the capture ends; [A] had already proved EFAULT from an unmapped source)
--   results/phase36_realargs/1515a_sys548_op3_fault_race_20261109_230554.txt (the user-read version,
--     ambiguous because a user read in the delete-to-insert window is an honest SIGSEGV)
--   results/phase36_realargs/1512a_sys548_op3_split_20261109_230244.txt (op 3 splits an entry)
--   results/phase36_realargs/1514a_sys548_op3_shm_clip_20261109_230444.txt (a quiescent clip is clean)
--   results/phase36_realargs/1381a_store_to_unmapped_kills_or_silent.txt (a store to an unmapped
--     address is swallowed by the loader's write path, so a write cannot be assumed to fault loudly)

print("=== PROBE 1517a: BISECT THE op 3 / copyin-FAULT RACE ===")

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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end
    return nil
end
local function wr(a, v) pcall(function() memory.write_dword(a, uint64(v)) end) end
local function wrq(a, v) pcall(function() memory.write_qword(a, uint64(v)) end) end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return N(v) end
    return nil
end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local ent  = memory.alloc(0x40)
local done = memory.alloc(0x10)
local function batch(flags, start, len, prot, op)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent, uint64(start)) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(len)) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, op) end)
    pcall(function() memory.write_dword(done, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return mk(548)(uint64(0), uint64(flags), uint64(ent), uint64(1), uint64(done), uint64(0))
    end)
    if not ok then return -999, 0 end
    return sgn(rv), N(memory.read_dword(done))
end
local function mmap_page()
    local ok, v = pcall(function() return mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    if not ok then return -1 end
    return sgn(v)
end

--============================================================== [A] setup
print("")
print("[A] socketpair and pages")
local pair = memory.alloc(0x10)
wrq(pair, 0); wrq(pair + 8, 0)
local oks, sr = pcall(function() return mk(135)(uint64(1), uint64(1), uint64(0), uint64(pair), uint64(0), uint64(0)) end)
print(string.format("   socketpair = %s %s", oks and tostring(sgn(sr)) or "EXC", (not oks or sgn(sr) ~= 0) and es() or ""))
local FDR, FDW = rd(pair), rd(pair + 4)
print(string.format("   fds = %s / %s", tostring(FDR), tostring(FDW)))
if not FDR or not FDW or FDR <= 0 or FDW <= 0 then print("   VERDICT: VOID -- no socketpair") return end

local V, SH = mmap_page(), mmap_page()
print(string.format("   V = %s   SH = %s", V > 0x10000 and string.format("0x%X", V) or "FAILED",
    SH > 0x10000 and string.format("0x%X", SH) or "FAILED"))
if V <= 0x10000 or SH <= 0x10000 then print("   VERDICT: VOID -- mmap failed") return end
for i = 0, 0x38, 8 do wrq(SH + i, 0) end

local SENTINEL = 0xDEADBEEF
local WRITE = mk(4)
local function kern_write()
    local ok, rv = pcall(function()
        return WRITE(uint64(FDW), uint64(V + 0x1000), uint64(4), uint64(0), uint64(0), uint64(0))
    end)
    if not ok then return -999 end
    return sgn(rv)
end
wr(V + 0x1000, SENTINEL)
print(string.format("   write from the mapped page = %d", kern_write()))
local okf, rv_f = pcall(function() return WRITE(uint64(FDW), uint64(0x400000000), uint64(4), uint64(0), uint64(0), uint64(0)) end)
local fault_rv = okf and sgn(rv_f) or -999
print(string.format("   write from an unmapped user address = %d %s", fault_rv, fault_rv == -1 and es() or ""))
if fault_rv ~= -1 then print("   VERDICT: VOID -- an unmapped source does not return EFAULT") return end

--============================================================== [B] control 1
print("")
print("[B] CONTROL 1: main alone, 300 rounds of write then op3 replace")
local bfail = 0
for i = 1, 300 do
    wr(V + 0x1000, SENTINEL)
    local rv, proc = batch(0x10, V, 0x4000, 3, 3)
    if proc ~= 1 or rv ~= V then bfail = bfail + 1 end
end
print(string.format("   done, replacement_failures=%d, pid alive", bfail))
if bfail > 30 then print("   VERDICT: VOID -- replacement is unreliable without a race") return end

local fd = rq(signal.fd_addr)
local function spawn(limit)
    local src = string.format([[
local V, SH, FD, LIMIT = 0x%X, 0x%X, %d, %d
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wq(a,v) pcall(function() memory.write_qword(a, uint64(v)) end) end
local function rq(a) local ok,v = pcall(function() return memory.read_qword(a) end) if ok then return tonumber(v) or 0 end return nil end
local W = mk(4)
local n, faults = 0, 0
while n < LIMIT do
    if rq(SH) == 1 then break end
    local ok, rv = pcall(function() return W(uint64(FD), uint64(V + 0x1000), uint64(4), uint64(0), uint64(0), uint64(0)) end)
    n = n + 1
    if not ok then faults = faults + 1
    else
        local v = tonumber(rv) or 0
        if v < 0 then faults = faults + 1 end
    end
end
wq(SH + 0x10, n)
wq(SH + 0x18, faults)
]], V, SH, FDW, limit)
    local ok = pcall(function() return run_lua_code_in_new_thread(src, {async = true, client_fd = fd}) end)
    return ok
end

--============================================================== [C] control 2
print("")
print("[C] CONTROL 2: the writer thread alone, 200000 writes, no op 3 at all")
if not fd or fd <= 0 then
    print("   SKIPPED -- no client fd, cannot spawn")
else
    wrq(SH, 0); wrq(SH + 0x10, 0); wrq(SH + 0x18, 0)
    print(string.format("   spawn = %s", spawn(200000) and "OK" or "FAILED"))
    local spin = 0
    while spin < 8000000 and rq(SH + 0x10) == 0 do spin = spin + 1 end
    local cn, cf = rq(SH + 0x10) or 0, rq(SH + 0x18) or 0
    print(string.format("   child finished: %s writes, %s faulted, main still alive", tostring(cn), tostring(cf)))
    if cn == 0 then print("   NOTE: the child never reported; it may still be running") end
end

--============================================================== [D] the race
print("")
print("[D] RACE: writer thread running, main does 400 rounds, reporting every 25")
wrq(SH, 0); wrq(SH + 0x10, 0); wrq(SH + 0x18, 0)
wr(V + 0x1000, SENTINEL)
print(string.format("   spawn = %s", spawn(20000000) and "OK" or "FAILED"))
print("   starting rounds")
local rfail = 0
for i = 1, 400 do
    if i % 25 == 1 then print(string.format("   round %d ... (child writes=%s faults=%s)", i, tostring(rq(SH + 0x10) or 0), tostring(rq(SH + 0x18) or 0))) end
    wr(V + 0x1000, SENTINEL)
    local rv, proc = batch(0x10, V, 0x4000, 3, 3)
    if proc ~= 1 or rv ~= V then rfail = rfail + 1 end
end
wrq(SH, 1)
print(string.format("   finished 400 rounds, replacement_failures=%d", rfail))
print("   SURVIVED THE RACE")

--============================================================== [E] after
print("")
print("[E] after the race")
local spin = 0
while spin < 3000000 and rq(SH + 0x10) == 0 do spin = spin + 1 end
print(string.format("   child reported writes=%s faults=%s", tostring(rq(SH + 0x10) or 0), tostring(rq(SH + 0x18) or 0)))
local buf = memory.alloc(0x100)
for i = 0, 0xFC, 4 do pcall(function() memory.write_dword(buf + i, uint64(0)) end) end
local okt, tr = pcall(function() return mk(3)(uint64(FDR), uint64(buf), uint64(0x100), uint64(0), uint64(0), uint64(0)) end)
print(string.format("   socket read = %s %s", okt and tostring(sgn(tr)) or "EXC", (not okt or sgn(tr) < 0) and es() or ""))
print(string.format("   V+0x1000 now = 0x%08X", rd(V + 0x1000) or 0xDEAD))

print("")
local final_pid = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[Z] alive pid=%d (was %d)", final_pid, PID))
print("=== PROBE 1517a COMPLETE ===")
