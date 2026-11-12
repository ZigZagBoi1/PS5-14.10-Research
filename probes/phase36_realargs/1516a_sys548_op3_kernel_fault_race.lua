-- CRASH_CLASS: HIGH -- this races 548 op 3 against a page fault taken inside the kernel. If the
--   entry is freed under the fault handler the console may panic, not just the loader.
-- PROBE 1516a: 548 op 3 vs a KERNEL-driven fault on the same page.
--
-- 1515a raced op 3 against a Lua thread reading the page, and the process died -- but op 3 is
-- vm_map_delete followed by vm_map_insert, so between the two the address is genuinely unmapped and
-- a user read there takes an honest SIGSEGV. That design cannot tell a signal from a kernel bug.
--
-- This probe removes the ambiguity: the racing thread never touches V from userland. It calls
-- write(fd, V+0x1000, 4) on a socketpair, so the page is faulted in by copyin inside the kernel.
-- An unmapped source there returns EFAULT to the caller; it cannot deliver a signal. Therefore:
--   * process survives  -> the clip tolerated a concurrent kernel fault
--   * process dies      -> a fault taken inside the kernel did not tolerate the clip
-- and the loader's own capture ending mid-run is the only signal needed.
--
-- [A] socketpair, a 16 KiB page V with a marker, a 16 KiB counter page SH
-- [B] CONTROL: 200 serial rounds of write / replace / write with no second thread
-- [C] START the writer thread and run 400 racing rounds; a death here is the result
-- [D] drain the socket and prove it is still a working descriptor
--
-- -- prior art:
--   results/phase36_realargs/1515a_sys548_op3_fault_race_20261109_230554.txt (the user-read
--     version: control clean in 200 rounds, then the process died during the racing phase)
--   results/phase36_realargs/1512a_sys548_op3_split_20261109_230244.txt (op 3 splits an entry and
--     the carve page reads zero)
--   results/phase36_realargs/1514a_sys548_op3_shm_clip_20261109_230444.txt (quiescent clip clean)
--   probes/phase17_new_vectors/465a_aio_complete_then_delete.lua (the socketpair shape used here:
--     mk(135)(1, 1, 0, &pair, 0, 0))
--   probes/phase35_dead_end_reruns/1350b_sys622_kill_containment.lua (thread spawn convention; the
--     child gets its own globals, so everything it needs is formatted into its source)

print("=== PROBE 1516a: 548 op 3 VS A KERNEL-DRIVEN FAULT ===")

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
local function rdq(a)
    local lo, hi = rd(a), rd(a + 4)
    if lo == nil or hi == nil then return nil end
    return lo + hi * 4294967296
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

--============================================================== [A] setup
print("")
print("[A] socketpair and pages")
local pair = memory.alloc(0x10)
wrq(pair, 0); wrq(pair + 8, 0)
local oks, sr = pcall(function() return mk(135)(uint64(1), uint64(1), uint64(0), uint64(pair), uint64(0), uint64(0)) end)
print(string.format("   socketpair = %s %s", oks and tostring(sgn(sr)) or "EXC", (not oks or sgn(sr) ~= 0) and es() or ""))
local FDR = rd(pair)
local FDW = rd(pair + 4)
print(string.format("   fds = %s / %s", tostring(FDR), tostring(FDW)))
if not FDR or not FDW or FDR <= 0 or FDW <= 0 then
    print("   VERDICT: VOID -- no socketpair")
    return
end

local function mmap_page()
    local ok, v = pcall(function() return mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    if not ok then return -1 end
    return sgn(v)
end
local V  = mmap_page()
local SH = mmap_page()
print(string.format("   V = %s   SH = %s", V > 0x10000 and string.format("0x%X", V) or "FAILED",
    SH > 0x10000 and string.format("0x%X", SH) or "FAILED"))
if V <= 0x10000 or SH <= 0x10000 then
    print("   VERDICT: VOID -- mmap failed")
    return
end
for i = 0, 0x38, 8 do wrq(SH + i, 0) end

local SENTINEL = 0xDEADBEEF
wr(V + 0x1000, SENTINEL)
local WRITE = mk(4)
local function kwrite(len)
    local ok, rv = pcall(function() return WRITE(uint64(FDW), uint64(V + 0x1000), uint64(len), uint64(0), uint64(0), uint64(0)) end)
    if not ok then return -999 end
    return sgn(rv)
end
local r0 = kwrite(4)
print(string.format("   write from a mapped page = %d", r0))
if r0 ~= 4 then
    print(string.format("   VERDICT: VOID -- the control write failed (%s)", es()))
    return
end
-- the kernel faults the page away and puts it back; prove the EFAULT path really returns instead of
-- killing, by unmapping nothing and instead pointing at an address that is definitely not mapped
local r1 = -999
do
    local ok, rv = pcall(function() return WRITE(uint64(FDW), uint64(0x400000000), uint64(4), uint64(0), uint64(0), uint64(0)) end)
    r1 = ok and sgn(rv) or -999
end
print(string.format("   write from an unmapped user address = %d %s", r1, r1 == -1 and es() or ""))
if r1 ~= -1 then
    print("   VERDICT: VOID -- an unmapped source does not return EFAULT, so a death is ambiguous")
    return
end
print("   an unmapped source returns EFAULT -- a death during the race is therefore a kernel fault")

local function one_round()
    wr(V + 0x1000, SENTINEL)
    local rv, proc = batch(0x10, V, 0x4000, 3, 3)
    if proc ~= 1 or rv ~= V then return -1 end
    return 0
end

--============================================================== [B] control
print("")
print("[B] CONTROL: 200 serial rounds, no second thread")
local cfail = 0
for i = 1, 200 do if one_round() ~= 0 then cfail = cfail + 1 end end
print(string.format("   rounds=200 replacement_failures=%d", cfail))
if cfail > 20 then print("   VERDICT: VOID -- replacement is unreliable without a race") return end

--============================================================== [C] the race
print("")
print("[C] START the kernel-side writer, then 400 racing rounds")
local fd = rq(signal.fd_addr)
print(string.format("   client fd = %s", fd and tostring(fd) or "unreadable"))

local src = string.format([[
local V, SH, FD = 0x%X, 0x%X, %d
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wq(a,v) pcall(function() memory.write_qword(a, uint64(v)) end) end
local function rq(a) local ok,v = pcall(function() return memory.read_qword(a) end) if ok then return tonumber(v) or 0 end return nil end
local W = mk(4)
local n, faults = 0, 0
while true do
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
]], V, SH, FDW)

local spawned = false
if fd and fd > 0 then
    local ok = pcall(function() return run_lua_code_in_new_thread(src, {async = true, client_fd = fd}) end)
    spawned = ok
end
print(string.format("   spawn = %s", spawned and "OK" or "FAILED"))

if not spawned then
    print("   VERDICT: no writer thread, [C] did not run")
else
    local rfail = 0
    for i = 1, 400 do if one_round() ~= 0 then rfail = rfail + 1 end end
    print(string.format("   rounds=400 replacement_failures=%d", rfail))
    print("   SURVIVED the racing phase")
    wrq(SH, 1)
    local spin = 0
    while spin < 3000000 and rq(SH + 0x10) == 0 do spin = spin + 1 end
    local cn = rq(SH + 0x10) or 0
    local cbad = rq(SH + 0x18) or 0
    print(string.format("   writer thread: %s writes, %s of them faulted", tostring(cn), tostring(cbad)))
end

--============================================================== [D] the socket still works
print("")
print("[D] drain the socket")
local buf = memory.alloc(0x100)
for i = 0, 0xFC, 4 do pcall(function() memory.write_dword(buf + i, uint64(0)) end) end
local okt, tr = pcall(function() return mk(3)(uint64(FDR), uint64(buf), uint64(0x100), uint64(0), uint64(0), uint64(0)) end)
print(string.format("   read = %s %s", okt and tostring(sgn(tr)) or "EXC", (not okt or sgn(tr) < 0) and es() or ""))
if okt and sgn(tr) > 0 then
    print(string.format("   first dword back = 0x%08X (the page's sentinel is 0x%08X)", rd(buf) or 0, SENTINEL))
end

print("")
local final_pid = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[Z] alive pid=%d (was %d)", final_pid, PID))
print("=== PROBE 1516a COMPLETE ===")
