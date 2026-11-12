-- CRASH_CLASS: MODERATE
-- PROBE 1518a: what actually kills a spawned Lua thread -- the write() call, the socket buffer, or
--   the per-iteration closure?
--
-- 1517a's [C] ran 200000 child writes against a SOCK_DGRAM socketpair with NO 548 op 3 call in the
-- process at all, and the loader died at spawn+7 s. That killed the op 3 race instrument before it
-- ever ran. Three explanations survive:
--   (1) the socketpair's receive queue fills and the child blocks in write() -- test by writing to
--       /dev/zero instead, where nothing queues
--   (2) 200000 iterations each creating a fresh pcall closure exhaust the loader's Lua heap -- test
--       by wrapping the WHOLE loop in one pcall so exactly one closure exists
--   (3) a long-running Lua thread is simply unstable -- then this probe dies too, at any count
--
-- [A] open /dev/zero O_WRONLY, mmap V, prove write(V+0x1000)=4 and write(unmapped)=EFAULT
-- [B] CONTROL: no thread at all, 200000 serial writes from MAIN to /dev/zero. If main dies the
--     count itself is the problem, not threading.
-- [C] CHILD: 200000 writes to /dev/zero, one closure total, reporting progress through SH
-- [D] only if [C] reports: 200000 writes to the SOCKETPAIR, same one-closure form -- separates
--     "blocking on a full socket buffer" from "the loop is unstable"
--
-- -- prior art:
--   results/phase36_realargs/1517a_sys548_op3_race_bisect_20261109_231611.txt ([C] spawn=OK then the
--     connection ended with no op 3 in the process -- the death this probe explains)
--   results/phase36_realargs/1516a_sys548_op3_kernel_fault_race_20261109_231009.txt
--   results/phase17_new_vectors/1175a_loader_thread_api_20261104_160547.txt (a Lua thread printing to
--     the same socket while main printed -- concurrent Lua threads CAN work)
--   results/phase35_dead_end_reruns/1350b_sys622_kill_containment_20261109_105*.txt (spawned thread,
--     process ended)
--   docs/THREADING_ALIVE_14_10.md

print("=== PROBE 1518a: WHAT KILLS A SPAWNED LUA THREAD ===")

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
local function str_addr(s, n)
    local b = memory.alloc(n or 0x40)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(b + #s, 0) end)
    return b
end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

--============================================================== [A]
print("")
print("[A] /dev/zero destination and the fault page")
local zpath = str_addr("/dev/zero")
local okz, rvz = pcall(function() return mk(5)(uint64(zpath), uint64(1), uint64(0), uint64(0), uint64(0), uint64(0)) end)
local ZFD = okz and sgn(rvz) or -1
print(string.format("   /dev/zero fd = %d %s", ZFD, ZFD < 0 and es() or ""))

local pair = memory.alloc(0x10)
wrq(pair, 0); wrq(pair + 8, 0)
local oks, sr = pcall(function() return mk(135)(uint64(1), uint64(1), uint64(0), uint64(pair), uint64(0), uint64(0)) end)
print(string.format("   socketpair = %s %s", oks and tostring(sgn(sr)) or "EXC", (not oks or sgn(sr) ~= 0) and es() or ""))
local FDR, FDW = rd(pair), rd(pair + 4)
print(string.format("   socket fds = %s / %s", tostring(FDR), tostring(FDW)))
if ZFD < 0 or not FDR or not FDW then print("   VERDICT: VOID -- no descriptors") return end

local okv, vv = pcall(function() return mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
local V = okv and sgn(vv) or -1
local oksh, vsh = pcall(function() return mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
local SH = oksh and sgn(vsh) or -1
print(string.format("   V = %s   SH = %s", V > 0x10000 and string.format("0x%X", V) or "FAILED",
    SH > 0x10000 and string.format("0x%X", SH) or "FAILED"))
if V <= 0x10000 or SH <= 0x10000 then print("   VERDICT: VOID -- mmap failed") return end
for i = 0, 0x38, 8 do wrq(SH + i, 0) end

local SENTINEL = 0xDEADBEEF
local WRITE = mk(4)
local function w_to(fd)
    local ok, rv = pcall(function()
        return WRITE(uint64(fd), uint64(V + 0x1000), uint64(4), uint64(0), uint64(0), uint64(0))
    end)
    if not ok then return -999 end
    return sgn(rv)
end
wr(V + 0x1000, SENTINEL)
print(string.format("   write(V+0x1000) -> /dev/zero = %d", w_to(ZFD)))
print(string.format("   write(unmapped)  -> /dev/zero = %d %s", (function()
    local ok, rv = pcall(function() return WRITE(uint64(ZFD), uint64(0x400000000), uint64(4), uint64(0), uint64(0), uint64(0)) end)
    return ok and sgn(rv) or -999 end)(), es()))

--============================================================== [B]
print("")
print("[B] CONTROL: main alone, 200000 writes to /dev/zero, no thread")
local t0 = 0
for i = 1, 200000 do t0 = t0 + w_to(ZFD) end
print(string.format("   finished 200000 serial writes (sum=%d), still alive", t0))

--============================================================== [C]
print("")
print("[C] CHILD: 200000 writes to /dev/zero, one closure total")
local fd = rq(signal.fd_addr)
print(string.format("   client fd = %s", tostring(fd)))
if not fd or fd <= 0 then print("   VERDICT: VOID -- no client fd") return end

local function spawn(dest_fd, limit)
    local src = string.format([[
local V, SH, FD, LIMIT = 0x%X, 0x%X, %d, %d
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wq(a,v) pcall(function() memory.write_qword(a, uint64(v)) end) end
local function rq(a) local ok,v = pcall(function() return memory.read_qword(a) end) if ok then return tonumber(v) or 0 end return nil end
local W = mk(4)
local n, bad = 0, 0
pcall(function()
    while n < LIMIT do
        if rq(SH) == 1 then break end
        W(uint64(FD), uint64(V + 0x1000), uint64(4), uint64(0), uint64(0), uint64(0))
        n = n + 1
    end
end)
wq(SH + 0x10, n)
wq(SH + 0x18, bad)
]], V, SH, dest_fd, limit)
    return pcall(function() return run_lua_code_in_new_thread(src, {async = true, client_fd = fd}) end)
end

wrq(SH, 0); wrq(SH + 0x10, 0); wrq(SH + 0x18, 0)
local okc, cr = spawn(ZFD, 200000)
print(string.format("   spawn = %s%s", okc and "OK" or "EXC", okc and "" or (" " .. tostring(cr))))
local spins = 0
while spins < 40000000 and rq(SH + 0x10) == 0 do
    spins = spins + 1
    if spins % 3000000 == 0 then print(string.format("   still waiting, %d spins", spins)) end
end
local cn = rq(SH + 0x10) or 0
print(string.format("   child reported %s writes after %d spins", tostring(cn), spins))
if cn == 0 then
    print("   VERDICT: the child never reported -- a long Lua thread does not survive [C]")
    print("=== PROBE 1518a COMPLETE ===")
    return
end
print("   CHILD SURVIVED /dev/zero -- the 1517a death was the socket buffer or the closures")

--============================================================== [D]
print("")
print("[D] the same loop with the SOCKETPAIR destination, which fills and blocks")
wrq(SH, 0); wrq(SH + 0x10, 0); wrq(SH + 0x18, 0)
local okd, dr = spawn(FDW, 200000)
print(string.format("   spawn = %s%s", okd and "OK" or "EXC", okd and "" or (" " .. tostring(dr))))
local spins2 = 0
while spins2 < 20000000 and rq(SH + 0x10) == 0 do
    spins2 = spins2 + 1
    if spins2 % 5000000 == 0 then print(string.format("   still waiting, %d spins", spins2)) end
end
local dn = rq(SH + 0x10) or 0
print(string.format("   child reported %s writes after %d spins", tostring(dn), spins2))
if dn == 0 then
    print("   VERDICT: the socket destination is what stops the child (blocks or dies)")
else
    print("   VERDICT: both destinations complete -- 1517a's death was the per-iteration closures")
end

print("")
print(string.format("[Z] alive pid=%d (was %d)", N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))), PID))
print("=== PROBE 1518a COMPLETE ===")
