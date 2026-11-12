-- CRASH_CLASS: MODERATE -- one 16 KiB anonymous page is replaced under a faulting reader thread.
--   Nothing here touches memory the process does not own.
-- PROBE 1515a: race 548 op 3 against a concurrent fault on the SAME page.
--
-- Why: 1512a/1513a/1514a show op 3 is vm_map_delete(range) + vm_map_insert(anon) and that the
-- clippers handle a quiescent object correctly. A page fault in progress is not quiescent: the
-- faulting thread resolves the entry, holds the vm_object and a vm_page, and only later installs
-- the PTE. FreeBSD serialises that with MAP_ENTRY_IN_TRANSITION and a per-entry lock, and munmap
-- waits for it. If this port's op 3 does not, one of two things happens and both are useful:
--   (a) the racing fault installs the OLD page's contents into the NEW entry -- a stale page, i.e.
--       a physical page still mapped after its object was replaced;
--   (b) the entry or object is freed under the fault handler -- a use-after-free in the kernel.
--
-- Discriminator: write a sentinel into the live page, immediately replace the entry (the new page
-- must be zeros), then read the sentinel back. A non-zero read after a successful replacement is a
-- stale page, and no amount of correct bookkeeping produces it.
--
-- [A] map a 16 KiB anon page V and a separate 16 KiB counter page SH
-- [B] CONTROL: 200 rounds of write / replace / read with no other thread running. Must be all zero.
-- [C] START a loader thread that reads V+0x1000 in a tight loop, and run 400 rounds of the same
--     write / replace / read. Any non-zero read here is a race artifact, because [B] proved the
--     serial sequence always reads zero.
-- [D] stop the thread, read its counters, and 547 the page.
--
-- -- prior art:
--   results/phase36_realargs/1512a_sys548_op3_split_20261109_230244.txt (op 3 splits an entry;
--     rv equals the requested address; the carved page reads zero)
--   results/phase36_realargs/1514a_sys548_op3_shm_clip_20261109_230444.txt (the clip is clean when
--     the object is quiescent -- that is exactly what this probe removes)
--   results/phase36_realargs/1508a_sys548_map_fixed_20261109_224934.txt (MAP_FIXED bit 0x10)
--   results/phase36_realargs/1450a_munmap_semantics_20261109_172529.txt (munmap is entry-scoped,
--     so this VM layer is already known to deviate from stock)
--   probes/phase35_dead_end_reruns/1350b_sys622_kill_containment.lua (the run_lua_code_in_new_thread
--     convention: the child gets its own globals, so addresses are formatted into its source)
--   probe 1175a (a loader thread printing to the same socket while main kept printing)

print("=== PROBE 1515a: 548 op 3 VS A CONCURRENT FAULT ===")

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

local rec = memory.alloc(0x30)
local function show547(tag, a)
    for i = 0, 0x2C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
    local ok, rv = pcall(function() return mk(547)(uint64(a), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if not ok or sgn(rv) ~= 0 then print(string.format("   %-10s 547(0x%X): no entry", tag, a)) return end
    local s, e = rdq(rec), rdq(rec + 8)
    if s == nil or e == nil then print(string.format("   %-10s 547(0x%X): unreadable", tag, a)) return end
    print(string.format("   %-10s 547(0x%X): start=0x%X end=0x%X len=0x%X prot=0x%X", tag, a, s, e, e - s, rd(rec + 0x10) or 0))
end

--============================================================== [A] pages
print("")
print("[A] one page to race on, one page of counters")
local okv, vv = pcall(function() return mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
local V = okv and sgn(vv) or -1
local oks, sv = pcall(function() return mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
local SH = oks and sgn(sv) or -1
print(string.format("   V = %s   SH = %s", V > 0x10000 and string.format("0x%X", V) or "FAILED",
    SH > 0x10000 and string.format("0x%X", SH) or "FAILED"))
if V <= 0x10000 or SH <= 0x10000 then
    print(string.format("   mmap failed: %s -- VERDICT VOID", es()))
    return
end
for i = 0, 0x38, 8 do wrq(SH + i, 0) end
wr(V + 0x1000, 0x12345678)
local base_v = rd(V + 0x1000)
print(string.format("   baseline marker at V+0x1000 = 0x%08X", base_v or 0))
if base_v ~= 0x12345678 then print("   VERDICT: VOID -- the page is not writable") return end
show547("V", V)

local SENTINEL = 0xDEADBEEF
local function one_round()
    wr(V + 0x1000, SENTINEL)
    local rv, proc = batch(0x10, V, 0x4000, 3, 3)
    if proc ~= 1 or rv ~= V then return -1, nil end
    local v = rd(V + 0x1000)
    if v == nil then return -2, nil end
    return 0, v
end

--============================================================== [B] control, single threaded
print("")
print("[B] CONTROL: 200 serial rounds with no other thread")
local ctrl_bad, ctrl_fail, ctrl_first = 0, 0, -1
for i = 1, 200 do
    local rc, v = one_round()
    if rc ~= 0 then
        ctrl_fail = ctrl_fail + 1
    elseif v ~= 0 then
        ctrl_bad = ctrl_bad + 1
        if ctrl_first < 0 then ctrl_first = v end
    end
end
print(string.format("   rounds=200 replaced_failures=%d non-zero reads=%d first=0x%08X",
    ctrl_fail, ctrl_bad, ctrl_first < 0 and 0 or ctrl_first))
if ctrl_fail > 20 then
    print("   VERDICT: VOID -- replacement is unreliable even without a race")
    return
end
if ctrl_bad > 0 then
    print("   NOTE: the serial sequence itself reads non-zero -- the discriminator is unsound")
end

--============================================================== [C] the race
print("")
print("[C] START a reader thread on V+0x1000, then 400 racing rounds")
local fd = rq(signal.fd_addr)
print(string.format("   client fd = %s", fd and tostring(fd) or "unreadable"))

local src = string.format([[
local V, SH = 0x%X, 0x%X
local function rd(a) local ok,v = pcall(function() return memory.read_dword(a) end) if ok then return tonumber(v) or 0 end return nil end
local function wq(a,v) pcall(function() memory.write_qword(a, uint64(v)) end) end
local function rq(a) local ok,v = pcall(function() return memory.read_qword(a) end) if ok then return tonumber(v) or 0 end return nil end
local n, bad, first = 0, 0, 0
while true do
    if rq(SH) == 1 then break end
    local v = rd(V + 0x1000)
    n = n + 1
    if v ~= nil and v ~= 0 then
        bad = bad + 1
        if bad == 1 then first = v end
    end
end
wq(SH + 0x10, n)
wq(SH + 0x18, bad)
wq(SH + 0x20, first)
]], V, SH)

local spawned = false
if fd and fd > 0 then
    local ok, e = pcall(function() return run_lua_code_in_new_thread(src, {async = true, client_fd = fd}) end)
    spawned = ok
    print(string.format("   spawn = %s %s", ok and "OK" or "FAILED", ok and "" or tostring(e)))
else
    print("   spawn = SKIPPED (no client fd)")
end

if not spawned then
    print("   VERDICT: no reader thread, [C] did not run")
else
    local raced_bad, raced_fail, raced_first = 0, 0, -1
    for i = 1, 400 do
        local rc, v = one_round()
        if rc ~= 0 then
            raced_fail = raced_fail + 1
        elseif v ~= 0 then
            raced_bad = raced_bad + 1
            if raced_first < 0 then raced_first = v end
        end
    end
    wrq(SH, 1)
    local spin = 0
    while spin < 2000000 and rq(SH + 0x10) == 0 do spin = spin + 1 end
    local cn, cb, cf = rq(SH + 0x10) or 0, rq(SH + 0x18) or 0, rq(SH + 0x20) or 0
    print(string.format("   rounds=400 replaced_failures=%d non-zero reads=%d first=0x%08X", raced_fail, raced_bad, raced_first < 0 and 0 or raced_first))
    print(string.format("   reader thread: reads=%s non-zero=%s first=0x%08X", tostring(cn), tostring(cb), cf))
    print("")
    if raced_bad > 0 or cb > 0 then
        print("   *** STALE PAGE: a replaced entry still exposed the old contents ***")
    elseif ctrl_bad == 0 then
        print("   no stale read in 400 racing rounds (control was clean in 200 serial rounds)")
    end
end

--============================================================== [D] state afterwards
print("")
print("[D] page state after the race")
show547("V", V)
local v1 = rd(V + 0x1000)
print(string.format("   V+0x1000 now = 0x%08X", v1 or 0xDEAD))

print("")
local final_pid = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[Z] alive pid=%d (was %d)", final_pid, PID))
print("=== PROBE 1515a COMPLETE ===")
