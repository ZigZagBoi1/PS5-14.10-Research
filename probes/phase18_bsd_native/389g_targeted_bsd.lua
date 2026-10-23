-- CRASH_CLASS: LOW
-- PROBE 389g: Targeted BSD sweep — skip ALL blocking syscalls
--
-- Context: 389f hung on a blocking syscall (likely select(93) with NULL timeout).
-- This tests only non-blocking BSD calls. Known blockers avoided:
-- read(3), accept(30), select(93), poll(209), recvfrom(29), recvmsg(27),
-- readv(120), sigwait(410), sigsuspend(111), __sigwaitinfo(340), ppoll(458)

print("=== PROBE 389g: targeted BSD sweep ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
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

local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

-- Ignore SIGSYS first
local sa = memory.alloc(32)
zero_buf(sa, 32)
wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
print("SIGSYS ignored")

-- Blocking syscalls to NEVER call with zero args:
-- 3(read), 4(write on stdin), 27(recvmsg), 29(recvfrom), 30(accept),
-- 93(select), 104(connect?), 111(sigsuspend), 120(readv), 209(poll),
-- 340(__sigwaitinfo), 345(acl), 410(sigwait), 415(cap_enter!!),
-- 458(ppoll), 459(pselect), 471(pdfork-dangerous)

local SKIP = {}
for _, n in ipairs({
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20, -- basic I/O + process
    21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,
    40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,
    61,62,63,64,65,66,67,68,69, -- up to 69 all well-known
    73, -- munmap (dangerous)
    74, -- mprotect (tested)
    78, -- mincore (tested dead)
    85, -- swapon
    92, -- fcntl (tested)
    93, -- select (BLOCKS!)
    97, -- socket (tested)
    98, -- connect (blocks/tested)
    99, -- netcontrol (tested dead)
    100, 101, 102, -- net stuff (tested)
    104, -- accept4? might block
    105, 106, 107, -- socket ops
    108, -- shutdown
    109, 110, 111, -- sigsuspend blocks!
    114, -- writev
    120, -- readv (BLOCKS on fd 0!)
    125, -- netgetiflist (CRASHES!)
    131, -- flock (might block)
    165, -- sysarch (tested)
    173, -- pread
    174, -- pwrite
    189, -- fstat (tested)
    197, -- mmap (tested extensively)
    202, -- sysctl (tested)
    209, -- poll (BLOCKS!)
    226, -- msync nosys
    232, -- clock_settime (dangerous)
    235, -- timer_create (tested)
    236, 237, 238, 239, -- timer ops (tested)
    240, -- nanosleep (blocks!)
    247, -- clock_getcpuclockid (tested)
    253, -- issetugid (tested ret=0)
    272, -- getdirentries (tested)
    328, 329, 330, -- sched (tested)
    340, -- sigwaitinfo (BLOCKS!)
    362, 363, -- kqueue/kevent (tested)
    392, -- uuidgen (tested)
    394, -- getfsstat (tested -1)
    397, -- fstatfs (tested)
    400,401,402,403,404,405,406,407,408, -- ksem (tested)
    410, -- sigwait (BLOCKS!)
    415, -- cap_enter (DANGEROUS! one-way gate!)
    416, -- sigaction (tested)
    421, -- thr_exit (kills thread!)
    430, -- thr_create (tested)
    432, -- thr_self (tested)
    441, -- ksem_timedwait (might block)
    442, -- thr_suspend (tested)
    445, -- audit (might kill)
    454, 455, 456, -- umtx/thr_new (tested)
    458, -- ppoll (BLOCKS!)
    459, -- pselect (BLOCKS!)
    466, -- openat (tested)
    471, -- pdfork (dangerous)
    477, -- mmap variant (tested)
    487, -- cpuset_getaffinity (tested -1)
    515, -- cap_rights_get
}) do SKIP[n] = true end

-- Test remaining BSD range, print ALL results including -1
local results = {}
local tested = 0
local interesting = {}

for num = 70, 530 do
    if not alive() then
        results[#results + 1] = "DEAD at " .. num
        break
    end
    if not SKIP[num] then
        local sc = mk(num)
        local ok, rv = pcall(function() return sc(uint64(0)) end)
        local r = ok and N(rv) or -999
        tested = tested + 1
        if r ~= -1 and r ~= -999 then
            interesting[#interesting + 1] = string.format("%d:ret=%d", num, r)
        end
    end
end

print("tested: " .. tested .. " syscalls")
print("interesting (non -1/-999): " .. #interesting)
for _, s in ipairs(interesting) do print("  " .. s) end

if not alive() then print("DEAD after sweep"); return end
print("")

-- ===================================================================
-- [B] Deep-test interesting finds: SysV IPC
-- ===================================================================
print("[B] SysV IPC")

local buf = memory.alloc(0x200)

-- shmget(231) — SysV shared memory
zero_buf(buf, 16)
local ok, rv = pcall(function() return mk(231)(uint64(0x12345), uint64(0x4000), uint64(0x3FF)) end)
print("  shmget(key=0x12345, 16K, 0x3FF): ret=" .. (ok and N(rv) or -999))

-- shmat(228) — attach
if ok and N(rv) >= 0 then
    local shmid = N(rv)
    local ok2, rv2 = pcall(function() return mk(228)(uint64(shmid), uint64(0), uint64(0)) end)
    print("  shmat(id=" .. shmid .. "): ret=" .. (ok2 and N(rv2) or -999))
    -- shmdt(230)
    if ok2 and N(rv2) ~= 0 then
        pcall(function() mk(230)(rv2) end)
    end
    -- shmctl(229) IPC_RMID=0
    pcall(function() mk(229)(uint64(shmid), uint64(0), uint64(0)) end)
end

-- msgget(225)
ok, rv = pcall(function() return mk(225)(uint64(0x12345), uint64(0x3FF)) end)
print("  msgget(key=0x12345, 0x3FF): ret=" .. (ok and N(rv) or -999))

-- semget(221)
ok, rv = pcall(function() return mk(221)(uint64(0x12345), uint64(1), uint64(0x3FF)) end)
print("  semget(key=0x12345, 1, 0x3FF): ret=" .. (ok and N(rv) or -999))

if not alive() then print("DEAD after [B]"); return end
print("")

-- ===================================================================
-- [C] getdtablesize(89) and rlimit exploration
-- ===================================================================
print("[C] dtablesize + misc")

ok, rv = pcall(function() return mk(89)() end)
print("  getdtablesize(89): ret=" .. (ok and N(rv) or -999))

-- getlogin(49) — returns pointer to username
ok, rv = pcall(function() return mk(49)() end)
print("  getlogin(49): ret=" .. (ok and N(rv) or -999))

-- umask(60) — returns old mask
ok, rv = pcall(function() return mk(60)(uint64(0x22)) end)
local old_mask = ok and N(rv) or -999
print("  umask(60, 0x22): ret=" .. old_mask)
-- restore
if old_mask >= 0 then pcall(function() mk(60)(uint64(old_mask)) end) end

-- getpgrp(81)
ok, rv = pcall(function() return mk(81)() end)
print("  getpgrp(81): ret=" .. (ok and N(rv) or -999))

-- getegid(43)
ok, rv = pcall(function() return mk(43)() end)
print("  getegid(43): ret=" .. (ok and N(rv) or -999))

-- geteuid(25)
ok, rv = pcall(function() return mk(25)() end)
print("  geteuid(25): ret=" .. (ok and N(rv) or -999))

-- getuid(24)
ok, rv = pcall(function() return mk(24)() end)
print("  getuid(24): ret=" .. (ok and N(rv) or -999))

-- getgid(47)
ok, rv = pcall(function() return mk(47)() end)
print("  getgid(47): ret=" .. (ok and N(rv) or -999))

-- getgroups(79) — group list
zero_buf(buf, 128)
ok, rv = pcall(function() return mk(79)(uint64(16), buf) end)
local r = ok and N(rv) or -999
print(string.format("  getgroups(79): ret=%d", r))
if r > 0 then
    local gs = {}
    for i = 0, r - 1 do gs[#gs + 1] = tostring(rd(N(buf) + i * 4) or "?") end
    print("    groups: " .. table.concat(gs, ", "))
end

-- pathconf(191) — /app0 path limits
local pbuf = memory.alloc(64)
zero_buf(pbuf, 64)
local p = "/app0"
for i = 0, #p - 1, 4 do
    local d = 0
    for j = 0, 3 do
        if i + j < #p then d = d + string.byte(p, i + j + 1) * (256 ^ j) end
    end
    wd(N(pbuf) + i, d)
end

-- _PC_LINK_MAX=1, _PC_NAME_MAX=4, _PC_PATH_MAX=5
for _, pc in ipairs({{1, "LINK_MAX"}, {4, "NAME_MAX"}, {5, "PATH_MAX"}}) do
    ok, rv = pcall(function() return mk(191)(pbuf, uint64(pc[1])) end)
    print(string.format("  pathconf(%s): %d", pc[2], ok and N(rv) or -999))
end

if not alive() then print("DEAD after [C]"); return end
print("")

-- ===================================================================
-- [D] SysV shared memory deep test
-- ===================================================================
print("[D] shm deep test")

-- Try IPC_PRIVATE=0 key
ok, rv = pcall(function() return mk(231)(uint64(0), uint64(0x4000), uint64(0x1FF + 0x200)) end)
-- IPC_CREAT=0x200, perms=0x1FF
local r = ok and N(rv) or -999
print("  shmget(IPC_PRIVATE, 16K, IPC_CREAT|0777): ret=" .. r)

if r >= 0 then
    local shmid = r
    -- Try to get info via shmctl IPC_STAT=2
    zero_buf(buf, 0x200)
    ok, rv = pcall(function() return mk(229)(uint64(shmid), uint64(2), buf) end)
    print("  shmctl(IPC_STAT): ret=" .. (ok and N(rv) or -999))

    -- Check first 64 bytes for kernel pointers
    local has_data = false
    for i = 0, 15 do
        local v = rd(N(buf) + i * 4)
        if v and v ~= 0 then has_data = true; break end
    end
    if has_data then
        for line = 0, 0x60, 32 do
            local parts = {}
            for i = line, line + 28, 4 do
                local v = rd(N(buf) + i)
                if v then parts[#parts + 1] = string.format("%08X", v) end
            end
            print("  +" .. string.format("%03X", line) .. ": " .. table.concat(parts, " "))
        end
        -- Scan for kernel pointers
        for i = 0, 24 do
            local v = rq(N(buf) + i * 8)
            if v then
                local h, l = get_hi_lo(v)
                if h >= 0xFFFF8000 then
                    print(string.format("  *** KPTR +0x%X: 0x%X%08X ***", i * 8, h, l))
                end
            end
        end
    end

    -- Attach it
    ok, rv = pcall(function() return mk(228)(uint64(shmid), uint64(0), uint64(0)) end)
    print("  shmat: ret=" .. (ok and N(rv) or -999))
    if ok and N(rv) ~= 0 and N(rv) ~= 0xFFFFFFFF then
        local addr = rv
        local h, l = get_hi_lo(addr)
        print(string.format("  shm addr: 0x%X%08X", h, l))
        -- Try to read/write
        local rval = rd(l)
        print("  shm read: " .. (rval or "FAIL"))
        -- Detach
        pcall(function() mk(230)(addr) end)
    end

    -- Cleanup
    pcall(function() mk(229)(uint64(shmid), uint64(0), uint64(0)) end)
end

if not alive() then print("DEAD after [D]"); return end
print("")

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 389g COMPLETE ===")
