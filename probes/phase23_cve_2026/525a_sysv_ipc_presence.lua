-- CRASH_CLASS: MODERATE
-- PROBE 525a: SysV IPC presence test (semaphores, shared memory, messages)
--
-- CVE-2026-58087 describes a heap OOB via semctl(GETALL/SETALL)
-- race condition. The race needs:
--   semget(221): create semaphore set
--   __semctl(220): get/set semaphore values (vulnerable path)
--   semop(222): semaphore operations
--
-- Before attempting the race, we must verify the SysV IPC
-- subsystem is even compiled into the PS5 kernel. Sony may
-- have disabled it (NOSTD = conditionally compiled).
--
-- BSD-native sweep (388a-392f) tested ~400 syscalls but with
-- zero/generic args only — SysV IPC needs real struct arguments.
--
-- FreeBSD 11 syscall numbers:
--   220: __semctl(semid, semnum, cmd, union semun *arg)
--   221: semget(key, nsems, semflg)
--   222: semop(semid, struct sembuf *sops, size_t nsops)
--   224: msgctl(msqid, cmd, struct msqid_ds *buf)
--   225: msgget(key, msgflg)
--   226: msgsnd(msqid, msgp, msgsz, msgflg)
--   227: msgrcv(msqid, msgp, msgsz, msgtyp, msgflg)
--   228: shmat(shmid, shmaddr, shmflg)
--   229: shmctl(shmid, cmd, struct shmid_ds *buf)
--   230: shmdt(shmaddr)
--   231: shmget(key, size, shmflg)
--   510: __semctl (FREEBSD7 compat)

print("=== PROBE 525a: SysV IPC presence test ===")
print("")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt_hex(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

local sc20 = make_syscall(20)
local pid = to_num(sc20())
print("pid: " .. pid)

local buf = memory.alloc(0x2000)

local function zero_buf(addr, sz)
    for j = 0, sz - 1, 4 do safe_wd(addr + j, 0) end
end

-- Constants
local IPC_PRIVATE = 0
local IPC_CREAT   = 0x200  -- 01000 octal
local IPC_EXCL    = 0x400  -- 02000 octal
local IPC_RMID    = 0
local IPC_SET     = 1
local IPC_STAT    = 2
local GETVAL      = 12
local GETALL      = 13
local GETNCNT     = 14
local GETZCNT     = 15
local SETVAL      = 16
local SETALL      = 17

-- Ignore SIGSYS so nosys stubs return -1 instead of killing
local sc416 = make_syscall(416) -- sigaction
local sa = memory.alloc(0x20)
safe_wq(sa, uint64(1)) -- SIG_IGN handler = 1
safe_wd(sa + 8, 0)
safe_wd(sa + 12, 0)
safe_wd(sa + 16, 0)
pcall(function() sc416(uint64(12), sa, uint64(0)) end) -- SIGSYS=12
print("SIGSYS ignored")
print("")

-- ============================================================
-- [A] semget(221): create a semaphore set
-- semget(key, nsems, semflg)
-- IPC_PRIVATE=0, nsems=4, IPC_CREAT|0666 = 0x3B6
-- ============================================================
print("[A] semget(221) — create semaphore set")
local sc221 = make_syscall(221)

-- First, test with zeros (what the sweep did)
local ok, ret = pcall(function() return sc221(uint64(0), uint64(0), uint64(0)) end)
local rv = ok and to_num(ret) or -999
print(string.format("  semget(0,0,0): ret=%d%s", rv, ok and "" or " [PCALL-FAIL]"))

-- Now with real args: IPC_PRIVATE, 4 semaphores, IPC_CREAT|0666
ok, ret = pcall(function() return sc221(uint64(IPC_PRIVATE), uint64(4), uint64(IPC_CREAT + 0x1B6)) end)
rv = ok and to_num(ret) or -999
print(string.format("  semget(IPC_PRIVATE, 4, IPC_CREAT|0666): ret=%d%s", rv, ok and "" or " [PCALL-FAIL]"))

local semid = nil
if rv >= 0 and rv ~= -999 then
    semid = rv
    print("  *** SEMAPHORE SET CREATED: semid=" .. semid .. " ***")
end

-- Also try with a named key
ok, ret = pcall(function() return sc221(uint64(0x12345), uint64(2), uint64(IPC_CREAT + 0x1B6)) end)
rv = ok and to_num(ret) or -999
print(string.format("  semget(0x12345, 2, IPC_CREAT|0666): ret=%d%s", rv, ok and "" or " [PCALL-FAIL]"))
local semid2 = nil
if rv >= 0 and rv ~= -999 then
    semid2 = rv
    print("  *** NAMED SEMAPHORE SET CREATED: semid=" .. semid2 .. " ***")
end

-- Try with 1 semaphore (minimal)
ok, ret = pcall(function() return sc221(uint64(IPC_PRIVATE), uint64(1), uint64(IPC_CREAT + 0x1B6)) end)
rv = ok and to_num(ret) or -999
print(string.format("  semget(IPC_PRIVATE, 1, IPC_CREAT|0666): ret=%d%s", rv, ok and "" or " [PCALL-FAIL]"))
local semid3 = nil
if rv >= 0 and rv ~= -999 then
    semid3 = rv
    print("  *** MINIMAL SET CREATED: semid=" .. semid3 .. " ***")
end
print("")

-- ============================================================
-- [B] __semctl(220): get/set semaphore values
-- __semctl(semid, semnum, cmd, union semun *arg)
-- union semun { int val; struct semid_ds *buf; unsigned short *array; }
-- ============================================================
print("[B] __semctl(220) — control operations")
local sc220 = make_syscall(220)

if semid then
    -- GETVAL: get value of semaphore 0
    zero_buf(buf, 0x200)
    -- For GETVAL, the return value IS the semaphore value
    ok, ret = pcall(function() return sc220(uint64(semid), uint64(0), uint64(GETVAL), uint64(0)) end)
    rv = ok and to_num(ret) or -999
    print(string.format("  semctl(semid=%d, 0, GETVAL): ret=%d%s", semid, rv, ok and "" or " [PCALL-FAIL]"))

    -- SETVAL: set semaphore 0 to value 42
    -- For SETVAL, arg.val is the value (passed as the 4th arg pointer, but it's the value)
    -- Actually, union semun's val member — we need to pass a pointer to the union
    local semun = memory.alloc(16)
    safe_wd(semun, 42)
    ok, ret = pcall(function() return sc220(uint64(semid), uint64(0), uint64(SETVAL), uint64(to_num(semun))) end)
    rv = ok and to_num(ret) or -999
    print(string.format("  semctl(semid=%d, 0, SETVAL, 42): ret=%d%s", semid, rv, ok and "" or " [PCALL-FAIL]"))

    -- Read it back with GETVAL
    ok, ret = pcall(function() return sc220(uint64(semid), uint64(0), uint64(GETVAL), uint64(0)) end)
    rv = ok and to_num(ret) or -999
    print(string.format("  semctl(semid=%d, 0, GETVAL): ret=%d%s", semid, rv, ok and "" or " [PCALL-FAIL]"))
    if rv == 42 then
        print("  *** SEMAPHORE VALUE CONFIRMED: 42 ***")
    end

    -- GETALL: get all semaphore values into array
    -- arg.array = pointer to unsigned short[nsems]
    local sem_array = memory.alloc(64)
    zero_buf(sem_array, 64)
    local semun_ga = memory.alloc(16)
    safe_wq(semun_ga, uint64(to_num(sem_array)))
    ok, ret = pcall(function() return sc220(uint64(semid), uint64(0), uint64(GETALL), uint64(to_num(semun_ga))) end)
    rv = ok and to_num(ret) or -999
    print(string.format("  semctl(semid=%d, 0, GETALL, array): ret=%d%s", semid, rv, ok and "" or " [PCALL-FAIL]"))
    if rv == 0 then
        -- Read the array values (unsigned short = 2 bytes each, 4 semaphores)
        for i = 0, 3 do
            local v = safe_rd(sem_array + i * 2)
            if v then
                v = v % 65536 -- mask to 16 bits
                print(string.format("    sem[%d] = %d", i, v))
            end
        end
        print("  *** GETALL WORKS — CVE-2026-58087 RACE PATH IS LIVE ***")
    end

    -- SETALL: set all values
    safe_wd(sem_array, 0x000A0005) -- sem[0]=5, sem[1]=10
    safe_wd(sem_array + 4, 0x00140000) -- sem[2]=0, sem[3]=20 (but only 4 sems)
    local semun_sa = memory.alloc(16)
    safe_wq(semun_sa, uint64(to_num(sem_array)))
    ok, ret = pcall(function() return sc220(uint64(semid), uint64(0), uint64(SETALL), uint64(to_num(semun_sa))) end)
    rv = ok and to_num(ret) or -999
    print(string.format("  semctl(semid=%d, 0, SETALL, [5,10,0,20]): ret=%d%s", semid, rv, ok and "" or " [PCALL-FAIL]"))

    -- Verify with GETALL
    if rv == 0 then
        zero_buf(sem_array, 64)
        safe_wq(semun_ga, uint64(to_num(sem_array)))
        ok, ret = pcall(function() return sc220(uint64(semid), uint64(0), uint64(GETALL), uint64(to_num(semun_ga))) end)
        rv = ok and to_num(ret) or -999
        if rv == 0 then
            for i = 0, 3 do
                local raw = safe_rd(sem_array + i * 2)
                if raw then
                    local v = raw % 65536
                    print(string.format("    verify sem[%d] = %d", i, v))
                end
            end
        end
    end

    -- IPC_STAT: get semid_ds structure (might contain kernel info)
    local sem_ds = memory.alloc(0x100)
    zero_buf(sem_ds, 0x100)
    local semun_stat = memory.alloc(16)
    safe_wq(semun_stat, uint64(to_num(sem_ds)))
    ok, ret = pcall(function() return sc220(uint64(semid), uint64(0), uint64(IPC_STAT), uint64(to_num(semun_stat))) end)
    rv = ok and to_num(ret) or -999
    print(string.format("  semctl(semid=%d, 0, IPC_STAT, buf): ret=%d%s", semid, rv, ok and "" or " [PCALL-FAIL]"))
    if rv == 0 then
        print("  IPC_STAT output:")
        for off = 0, 0x80 - 8, 8 do
            local q = safe_rq(sem_ds + off)
            if q then
                local qh, ql = get_hi_lo(q)
                if qh ~= 0 or ql ~= 0 then
                    local tag = ""
                    local exponent = math.floor((qh % 0x80000000) / 0x100000)
                    if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF and exponent ~= 0x7FF then
                        tag = " *** KPTR ***"
                    end
                    print(string.format("    +0x%02X: 0x%08X_%08X%s", off, qh, ql, tag))
                end
            end
        end
    end

    -- IPC_RMID: remove
    ok, ret = pcall(function() return sc220(uint64(semid), uint64(0), uint64(IPC_RMID), uint64(0)) end)
    rv = ok and to_num(ret) or -999
    print(string.format("  semctl(semid=%d, 0, IPC_RMID): ret=%d%s", semid, rv, ok and "" or " [PCALL-FAIL]"))
else
    print("  (skipped — no semid)")
end

-- also try compat 510
print("  __semctl compat (510):")
ok, ret = pcall(function() return make_syscall(510)(uint64(0), uint64(0), uint64(GETVAL), uint64(0)) end)
rv = ok and to_num(ret) or -999
print(string.format("  510(0, 0, GETVAL): ret=%d%s", rv, ok and "" or " [PCALL-FAIL]"))
print("")

-- ============================================================
-- [C] semop(222): semaphore operations
-- ============================================================
print("[C] semop(222) — semaphore operations")
local sc222 = make_syscall(222)

if semid3 then
    -- Set sem[0] = 1 first
    local semun_sv = memory.alloc(16)
    safe_wd(semun_sv, 1) -- val = 1
    pcall(function() sc220(uint64(semid3), uint64(0), uint64(SETVAL), uint64(to_num(semun_sv))) end)

    -- struct sembuf { unsigned short sem_num; short sem_op; short sem_flg; }
    -- 6 bytes per entry, but aligned to 8 on some systems
    local sops = memory.alloc(16)
    -- sem_num=0, sem_op=-1, sem_flg=IPC_NOWAIT(0x800)
    safe_wd(sops, 0xFFFF0000)  -- sem_num=0, sem_op=-1 (0xFFFF in unsigned short)
    safe_wd(sops + 4, 0x0800)   -- sem_flg=IPC_NOWAIT

    ok, ret = pcall(function() return sc222(uint64(semid3), uint64(to_num(sops)), uint64(1)) end)
    rv = ok and to_num(ret) or -999
    print(string.format("  semop(semid3, wait-1, 1): ret=%d%s", rv, ok and "" or " [PCALL-FAIL]"))

    -- Read the value back — should be 0 now
    ok, ret = pcall(function() return sc220(uint64(semid3), uint64(0), uint64(GETVAL), uint64(0)) end)
    rv = ok and to_num(ret) or -999
    print(string.format("  semctl GETVAL after op: ret=%d%s", rv, ok and "" or " [PCALL-FAIL]"))
    if rv == 0 then
        print("  *** SEMOP DECREMENTED VALUE: 1 -> 0 ***")
    end

    -- Clean up
    pcall(function() sc220(uint64(semid3), uint64(0), uint64(IPC_RMID), uint64(0)) end)
else
    print("  (skipped — no semid3)")
end

-- Clean up semid2
if semid2 then
    pcall(function() sc220(uint64(semid2), uint64(0), uint64(IPC_RMID), uint64(0)) end)
end
print("")

-- ============================================================
-- [D] shmget(231)/shmat(228): SysV shared memory
-- ============================================================
print("[D] shmget(231) / shmat(228) — SysV shared memory")
local sc231 = make_syscall(231)
local sc228 = make_syscall(228)

-- shmget(IPC_PRIVATE, 4096, IPC_CREAT|0666)
ok, ret = pcall(function() return sc231(uint64(IPC_PRIVATE), uint64(0x1000), uint64(IPC_CREAT + 0x1B6)) end)
rv = ok and to_num(ret) or -999
print(string.format("  shmget(IPC_PRIVATE, 4K, IPC_CREAT|0666): ret=%d%s", rv, ok and "" or " [PCALL-FAIL]"))

local shmid = nil
if rv >= 0 and rv ~= -999 then
    shmid = rv
    print("  *** SHM SEGMENT CREATED: shmid=" .. shmid .. " ***")

    -- shmat(shmid, NULL, 0)
    ok, ret = pcall(function() return sc228(uint64(shmid), uint64(0), uint64(0)) end)
    local att_h, att_l = 0, 0
    if ok and ret then
        att_h, att_l = get_hi_lo(ret)
    end
    local att_rv = ok and to_num(ret) or -999
    if att_h > 0 or att_l > 0x1000 then
        print(string.format("  shmat: addr=0x%08X_%08X", att_h, att_l))
        -- Try to write to it
        local wr_ok = safe_wd(ret, 0xDEADBEEF)
        local rd_back = safe_rd(ret)
        print(string.format("  write 0xDEADBEEF: ok=%s, read=0x%X", tostring(wr_ok), rd_back or 0))
        if wr_ok and rd_back == 0xDEADBEEF then
            print("  *** SHM R/W CONFIRMED ***")
        end
        -- shmdt
        pcall(function() make_syscall(230)(ret) end)
    else
        print(string.format("  shmat: ret=%d%s", att_rv, ok and "" or " [PCALL-FAIL]"))
    end

    -- shmctl IPC_STAT
    local shm_ds = memory.alloc(0x100)
    zero_buf(shm_ds, 0x100)
    ok, ret = pcall(function() return make_syscall(229)(uint64(shmid), uint64(IPC_STAT), uint64(to_num(shm_ds))) end)
    rv = ok and to_num(ret) or -999
    print(string.format("  shmctl(IPC_STAT): ret=%d", rv))
    if rv == 0 then
        for off = 0, 0x60 - 8, 8 do
            local q = safe_rq(shm_ds + off)
            if q then
                local qh, ql = get_hi_lo(q)
                if qh ~= 0 or ql ~= 0 then
                    print(string.format("    +0x%02X: 0x%08X_%08X", off, qh, ql))
                end
            end
        end
    end

    -- IPC_RMID
    pcall(function() make_syscall(229)(uint64(shmid), uint64(IPC_RMID), uint64(0)) end)
end
print("")

-- ============================================================
-- [E] msgget(225)/msgsnd(226)/msgrcv(227): SysV message queues
-- ============================================================
print("[E] msgget(225) — SysV message queues")
local sc225 = make_syscall(225)

ok, ret = pcall(function() return sc225(uint64(IPC_PRIVATE), uint64(IPC_CREAT + 0x1B6)) end)
rv = ok and to_num(ret) or -999
print(string.format("  msgget(IPC_PRIVATE, IPC_CREAT|0666): ret=%d%s", rv, ok and "" or " [PCALL-FAIL]"))

local msqid = nil
if rv >= 0 and rv ~= -999 then
    msqid = rv
    print("  *** MESSAGE QUEUE CREATED: msqid=" .. msqid .. " ***")

    -- msgsnd: struct { long mtype; char mtext[]; }
    local msg = memory.alloc(64)
    safe_wq(msg, uint64(1))        -- mtype = 1
    safe_wd(msg + 8, 0x41424344)   -- mtext = "ABCD"
    safe_wd(msg + 12, 0)

    ok, ret = pcall(function() return make_syscall(226)(uint64(msqid), uint64(to_num(msg)), uint64(4), uint64(0)) end)
    rv = ok and to_num(ret) or -999
    print(string.format("  msgsnd(msqid, msg, 4, 0): ret=%d%s", rv, ok and "" or " [PCALL-FAIL]"))

    if rv == 0 then
        -- msgrcv
        local rcv = memory.alloc(64)
        zero_buf(rcv, 64)
        ok, ret = pcall(function() return make_syscall(227)(uint64(msqid), uint64(to_num(rcv)), uint64(32), uint64(0), uint64(0x800)) end)
        rv = ok and to_num(ret) or -999
        print(string.format("  msgrcv: ret=%d%s", rv, ok and "" or " [PCALL-FAIL]"))
        if rv > 0 then
            local mtype = safe_rd(rcv)
            local mtext = safe_rd(rcv + 8)
            print(string.format("    mtype=%d, mtext=0x%08X", mtype or 0, mtext or 0))
            if mtext == 0x41424344 then
                print("  *** MESSAGE QUEUE SEND/RECV CONFIRMED ***")
            end
        end
    end

    -- Clean up
    pcall(function() make_syscall(224)(uint64(msqid), uint64(IPC_RMID), uint64(0)) end)
end
print("")

-- ============================================================
-- [F] Rapid create/destroy cycle count (CVE-2026-58087 setup)
-- If semget works, test how fast we can cycle create/destroy
-- The CVE needs 0x8000 (32768) cycles to wrap the counter
-- ============================================================
print("[F] Rapid create/destroy cycle test")

if semid ~= nil or semid3 ~= nil then
    -- semget works! Test rapid cycling
    local cycle_count = 0
    local start_time = os.clock()
    local errors = 0

    for i = 1, 200 do
        local cok, cret = pcall(function()
            return sc221(uint64(IPC_PRIVATE), uint64(1), uint64(IPC_CREAT + 0x1B6))
        end)
        if cok then
            local csemid = to_num(cret)
            if csemid >= 0 then
                cycle_count = cycle_count + 1
                -- immediate destroy
                pcall(function() sc220(uint64(csemid), uint64(0), uint64(IPC_RMID), uint64(0)) end)
            else
                errors = errors + 1
            end
        else
            errors = errors + 1
        end
    end

    local elapsed = os.clock() - start_time
    print(string.format("  200 create/destroy cycles: %d ok, %d err, %.3fs",
        cycle_count, errors, elapsed))
    if cycle_count > 0 then
        local rate = cycle_count / elapsed
        local time_32k = 32768 / rate
        print(string.format("  rate: %.0f cycles/sec", rate))
        print(string.format("  estimated time for 32768 cycles: %.1fs", time_32k))
        if time_32k < 300 then
            print("  *** CVE-2026-58087 RACE IS FEASIBLE ***")
        end
    end
else
    print("  (skipped — semget not working)")
end
print("")

-- ============================================================
-- [G] Sentinel: process alive?
-- ============================================================
local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("")
print("=== PROBE 525a COMPLETE ===")
