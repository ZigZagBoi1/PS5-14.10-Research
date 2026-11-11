-- CRASH_CLASS: MODERATE
-- PROBE 1408a: SA-26:54 SysV semaphore sequence wrap OOB
--
-- Context: FreeBSD SA-26:54 (2026-07-29) — semctl GETALL/SETALL heap OOB R/W.
-- The sequence number wraps after 0x8000 create/destroy cycles, allowing
-- a stale semid to resolve to the wrong semaphore set's memory.
--
-- Also SA-26:64 (2026-09-29) — semop(2) similar 15-bit sequence wrap OOB.
--
-- FreeBSD syscalls: semget=221, semop=222, __semctl=510
-- Older: semget=221, semctl=220 (4-arg form)
--
-- PS5 14.10 build: Sep 28 2026. SA-26:54 announced Jul 29 2026.
--
-- This probe first tests if SysV semaphores are available, then
-- measures sequence behavior.
--
-- prior art: no prior SysV semaphore probes in this repository

print("=== PROBE 1408a: SysV semaphore availability + sequence test ===")
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
local function hex64(val)
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end

local sc_semget = make_syscall(221)
local sc_semop = make_syscall(222)
local sc_semctl = make_syscall(510)  -- __semctl (FreeBSD)

-- IPC_PRIVATE = 0, IPC_CREAT = 0x200, IPC_EXCL = 0x400, IPC_RMID = 0
-- sem permissions: 0666 = 0x1B6

print("== Section A: semget availability ==")

-- Try creating a semaphore set with IPC_PRIVATE
local IPC_PRIVATE = 0
local IPC_CREAT = 0x200
local IPC_RMID = 0

local ret1
pcall(function()
    ret1 = sc_semget(uint64(IPC_PRIVATE), uint64(1), uint64(IPC_CREAT + 0x1B6))
end)
print(string.format("semget(IPC_PRIVATE, 1, IPC_CREAT|0666): ret=%s", tostring(ret1)))

if ret1 then
    local h, l = get_hi_lo(ret1)
    if h == 0xFFFFFFFF then
        print("  semget returned -1 — SysV semaphores NOT available")
        print("  SA-26:54 and SA-26:64 are DEAD on this system")
        print("")
        print("=== PROBE 1408a COMPLETE (DEAD) ===")
        return
    end
    print(string.format("  semid = %d (0x%X)", l, l))
end

print("")
print("== Section B: semctl IPC_RMID ==")

-- Remove the semaphore set
local ret_rm
pcall(function()
    ret_rm = sc_semctl(uint64(to_num(ret1)), uint64(0), uint64(IPC_RMID), uint64(0))
end)
print(string.format("semctl(semid, 0, IPC_RMID): ret=%s", tostring(ret_rm)))

print("")
print("== Section C: Sequence number measurement ==")
print("Creating and destroying semaphore sets to observe sequence increments...")

-- Create/destroy a few sets and observe the semid pattern
-- FreeBSD semid = (slot_index) | (sequence << 16) or similar
-- The vulnerability wraps at 0x8000 (32768) cycles

local semids = {}
for i = 1, 20 do
    local sid
    pcall(function()
        sid = sc_semget(uint64(IPC_PRIVATE), uint64(1), uint64(IPC_CREAT + 0x1B6))
    end)
    if sid then
        local h, l = get_hi_lo(sid)
        if h ~= 0xFFFFFFFF then
            table.insert(semids, l)
            print(string.format("  cycle %2d: semid = 0x%08X (slot=%d, seq=%d)",
                i, l, l % 65536, math.floor(l / 65536)))
            -- Immediately destroy
            pcall(function()
                sc_semctl(uint64(l), uint64(0), uint64(IPC_RMID), uint64(0))
            end)
        else
            print(string.format("  cycle %2d: semget returned -1", i))
            break
        end
    else
        print(string.format("  cycle %2d: pcall failed", i))
        break
    end
end

print("")
print("== Section D: semctl GETALL/SETALL test ==")

-- Create a set with 4 semaphores
local sid4
pcall(function()
    sid4 = sc_semget(uint64(IPC_PRIVATE), uint64(4), uint64(IPC_CREAT + 0x1B6))
end)
print(string.format("semget(IPC_PRIVATE, 4, IPC_CREAT|0666): ret=%s", tostring(sid4)))

if sid4 then
    local h4, l4 = get_hi_lo(sid4)
    if h4 ~= 0xFFFFFFFF then
        -- SETALL (cmd=17) — set all semaphore values
        local vals = memory.alloc(16)  -- 4 x unsigned short = 8 bytes, padded
        safe_wd(vals, 0x00020001)  -- sem[0]=1, sem[1]=2
        safe_wd(vals + 4, 0x00040003)  -- sem[2]=3, sem[3]=4

        -- semctl(semid, 0, SETALL, &vals)
        -- On FreeBSD, __semctl takes a union semun* as 4th arg
        local semun = memory.alloc(8)
        safe_wq(semun, uint64(vals))

        local ret_sa
        pcall(function()
            ret_sa = sc_semctl(uint64(l4), uint64(0), uint64(17), uint64(semun))
        end)
        print(string.format("  semctl(SETALL): ret=%s", tostring(ret_sa)))

        -- GETALL (cmd=13) — read all values back
        local out = memory.alloc(16)
        for i = 0, 12, 4 do safe_wd(out + i, 0xCCCCCCCC) end

        local semun2 = memory.alloc(8)
        safe_wq(semun2, uint64(out))

        local ret_ga
        pcall(function()
            ret_ga = sc_semctl(uint64(l4), uint64(0), uint64(13), uint64(semun2))
        end)
        print(string.format("  semctl(GETALL): ret=%s", tostring(ret_ga)))

        -- Read back values
        local v0 = safe_rd(out) or 0
        local v1 = safe_rd(out + 4) or 0
        print(string.format("  values: [%d, %d, %d, %d]",
            v0 % 65536, math.floor(v0 / 65536),
            v1 % 65536, math.floor(v1 / 65536)))

        -- Clean up
        pcall(function()
            sc_semctl(uint64(l4), uint64(0), uint64(IPC_RMID), uint64(0))
        end)
    end
end

print("")
print("== Section E: semop test ==")

-- Create a fresh set for semop
local sid5
pcall(function()
    sid5 = sc_semget(uint64(IPC_PRIVATE), uint64(2), uint64(IPC_CREAT + 0x1B6))
end)

if sid5 then
    local h5, l5 = get_hi_lo(sid5)
    if h5 ~= 0xFFFFFFFF then
        -- struct sembuf = { unsigned short sem_num; short sem_op; short sem_flg; }
        -- sizeof(sembuf) = 6 bytes
        local sops = memory.alloc(16)
        -- sem_num=0, sem_op=1 (increment), sem_flg=0x1000 (IPC_NOWAIT)
        safe_wd(sops, 0x00010000)      -- sem_num=0, sem_op=1
        safe_wd(sops + 4, 0x00001000)  -- sem_flg=IPC_NOWAIT, padding

        local ret_op
        pcall(function()
            ret_op = sc_semop(uint64(l5), uint64(sops), uint64(1))
        end)
        print(string.format("semop(semid=%d, V(0), 1): ret=%s", l5, tostring(ret_op)))

        -- Read value back with GETVAL (cmd=12)
        local semun3 = memory.alloc(8)
        local ret_gv
        pcall(function()
            ret_gv = sc_semctl(uint64(l5), uint64(0), uint64(12), uint64(semun3))
        end)
        print(string.format("semctl(GETVAL, sem 0): ret=%s", tostring(ret_gv)))
        if ret_gv then
            local hv, lv = get_hi_lo(ret_gv)
            if hv ~= 0xFFFFFFFF then
                print(string.format("  sem[0] value = %d (expect 1)", lv))
            end
        end

        pcall(function()
            sc_semctl(uint64(l5), uint64(0), uint64(IPC_RMID), uint64(0))
        end)
    end
end

print("")
print("=== PROBE 1408a COMPLETE ===")
