-- CRASH_CLASS: MODERATE
-- PROBE 58d: shm_open via make_syscall + sendfile reachability
--
-- Context: CVE-2026-49427 and CVE-2026-49428 target POSIX shared memory
-- largepage objects. shm_open (syscall 482) crashes the Lua loader via
-- resolve(), but make_syscall(482) has never been tested. If it works,
-- sendfile (syscall 393) and fspacectl (syscall 580) become testable.
--
-- This probe tests:
--   A) shm_open via make_syscall (does it bypass the loader crash?)
--   B) sendfile via make_syscall (never tested at all)
--   C) SHM_LARGEPAGE flag support (does the kernel know largepages?)
--
-- This probe does NOT attempt CVE triggers. It only tests reachability.

print("=== PROBE 58d: SHM_OPEN + SENDFILE REACHABILITY ===")
print("")

-- Standard helpers (same pattern as probe 58a)
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function hex(n)
    if type(n) == "table" and n.h then
        return string.format("0x%08X%08X", n.h, n.l)
    end
    return string.format("0x%X", tonumber(n) or 0)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local sc_getpid    = make_syscall(20)   -- canary
local sc_shm_open  = make_syscall(482)  -- shm_open
local sc_shm_unlink = make_syscall(483) -- shm_unlink
local sc_ftruncate = make_syscall(480)  -- ftruncate
local sc_sendfile  = make_syscall(393)  -- sendfile
local sc_fspacectl = make_syscall(580)  -- fspacectl
local sc_close     = make_syscall(6)    -- close
local sc_mmap      = make_syscall(477)  -- mmap
local sc_munmap    = make_syscall(73)   -- munmap
local sc_socket    = make_syscall(97)   -- socket
local sc_connect   = make_syscall(98)   -- connect
local sc_bind      = make_syscall(104)  -- bind
local sc_listen    = make_syscall(106)  -- listen
local sc_accept    = make_syscall(30)   -- accept

local PAGE = 0x4000  -- 16 KB

-- Flags
local O_RDWR   = 0x0002
local O_CREAT  = 0x0200
local O_TRUNC  = 0x0400
local SHM_LARGEPAGE = 0x0040  -- FreeBSD SHM_LARGEPAGE flag (may not exist on PS5)

--------------------------------------------------------------------
-- CANARY
--------------------------------------------------------------------
print("--- CANARY: getpid ---")
local ok_pid, pid = pcall(function() return sc_getpid() end)
if ok_pid then
    print("  getpid: " .. tostring(to_num(pid)))
else
    print("  getpid FAILED — loader broken")
    print("=== PROBE 58d COMPLETE ===")
    return
end

--------------------------------------------------------------------
-- SECTION A: shm_open via make_syscall
--------------------------------------------------------------------
print("")
print("--- SECTION A: SHM_OPEN VIA MAKE_SYSCALL ---")
print("  Testing make_syscall(482) — shm_open")
print("  (resolve() crashes loader; does make_syscall bypass?)")

local shm_fd = nil
local shm_name = "/ps5_test_58d"

local ok_shm, ret_shm = pcall(function()
    return sc_shm_open(shm_name, uint64(O_RDWR + O_CREAT), uint64(0x1FF))
end)

if ok_shm then
    local fd_val = to_num(ret_shm)
    print("  RETURNED: fd=" .. fd_val)
    if fd_val >= 0 then
        print("  >>> SHM_OPEN WORKS VIA MAKE_SYSCALL <<<")
        shm_fd = fd_val
    elseif fd_val == -1 then
        print("  >>> SHM_OPEN BLOCKED (ret=-1) <<<")
    else
        print("  >>> UNEXPECTED RETURN VALUE <<<")
    end
else
    print("  PCALL-FAIL — make_syscall(482) crashed or threw")
    print("  >>> SHM_OPEN IS LETHAL EVEN VIA MAKE_SYSCALL <<<")
end

--------------------------------------------------------------------
-- SECTION B: If shm_open worked, test ftruncate + mmap on it
--------------------------------------------------------------------
if shm_fd then
    print("")
    print("--- SECTION B: FTRUNCATE + MMAP ON SHM FD ---")

    local shm_size = PAGE * 4  -- 64KB

    local ok_ft, ret_ft = pcall(function()
        return sc_ftruncate(uint64(shm_fd), uint64(shm_size))
    end)
    if ok_ft then
        print("  ftruncate: ret=" .. tostring(to_num(ret_ft)))
    else
        print("  ftruncate: PCALL-FAIL")
    end

    local ok_mm, ret_mm = pcall(function()
        return sc_mmap(
            uint64(0), uint64(shm_size),
            uint64(3),     -- PROT_READ | PROT_WRITE
            uint64(1),     -- MAP_SHARED
            uint64(shm_fd), uint64(0)
        )
    end)

    local shm_addr = nil
    if ok_mm then
        local addr = to_num(ret_mm)
        print("  mmap: " .. hex(ret_mm))
        if addr > 0 and addr < 0xFFFFFFFF00000000 then
            shm_addr = addr
            print("  >>> SHM MMAP SUCCEEDED <<<")
            -- Try writing
            local ok_w = pcall(function() memory.write_dword(addr, 0xDEAD58D0) end)
            local ok_r, val = pcall(function() return memory.read_dword(addr) end)
            if ok_r then
                print("  write+read: " .. hex(val))
            else
                print("  write+read: FAIL")
            end
        else
            print("  mmap returned invalid address")
        end
    else
        print("  mmap: PCALL-FAIL")
    end

    --------------------------------------------------------------------
    -- SECTION C: SHM_LARGEPAGE test
    --------------------------------------------------------------------
    print("")
    print("--- SECTION C: SHM_LARGEPAGE SUPPORT ---")

    local ok_lp, ret_lp = pcall(function()
        return sc_shm_open("/ps5_lp_58d", uint64(O_RDWR + O_CREAT + SHM_LARGEPAGE), uint64(0x1FF))
    end)

    if ok_lp then
        local lp_fd = to_num(ret_lp)
        print("  shm_open(LARGEPAGE): fd=" .. lp_fd)
        if lp_fd >= 0 then
            print("  >>> SHM_LARGEPAGE SUPPORTED — CVE-2026-49427/49428 PREREQUISITES MET <<<")
            pcall(function() sc_close(uint64(lp_fd)) end)
            pcall(function() sc_shm_unlink("/ps5_lp_58d") end)
        else
            print("  >>> SHM_LARGEPAGE REJECTED (ret=-1) — CVEs likely unreachable <<<")
        end
    else
        print("  PCALL-FAIL — SHM_LARGEPAGE crashes or not supported")
    end

    --------------------------------------------------------------------
    -- SECTION D: sendfile reachability (socket + shm fd)
    --------------------------------------------------------------------
    print("")
    print("--- SECTION D: SENDFILE REACHABILITY ---")

    -- Create a TCP loopback socket pair
    local AF_INET = 2
    local SOCK_STREAM = 1

    local ok_s, ret_s = pcall(function()
        return sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0))
    end)

    local sock_fd = nil
    if ok_s then
        sock_fd = to_num(ret_s)
        print("  socket: fd=" .. sock_fd)
    else
        print("  socket: PCALL-FAIL")
    end

    if sock_fd and sock_fd >= 0 then
        -- sendfile: int sendfile(int fd, int s, off_t offset, size_t nbytes,
        --                        struct sf_hdtr *hdtr, off_t *sbytes, int flags)
        -- Try sendfile with shm fd as source, socket as destination
        -- SF_NOCACHE = 0x10 (FreeBSD)
        local SF_NOCACHE = 0x10

        local ok_sf, ret_sf = pcall(function()
            return sc_sendfile(
                uint64(shm_fd),   -- source fd (shm)
                uint64(sock_fd),  -- dest socket
                uint64(0),        -- offset
                uint64(shm_size), -- nbytes
                uint64(0),        -- hdtr (NULL)
                uint64(0),        -- sbytes (NULL)
                uint64(0)         -- flags (no SF_NOCACHE yet — safe first)
            )
        end)

        if ok_sf then
            print("  sendfile(flags=0): ret=" .. tostring(to_num(ret_sf)))
            print("  >>> SENDFILE REACHABLE <<<")

            -- Now try with SF_NOCACHE (the CVE-2026-49427 trigger flag)
            local ok_sf2, ret_sf2 = pcall(function()
                return sc_sendfile(
                    uint64(shm_fd), uint64(sock_fd),
                    uint64(0), uint64(shm_size),
                    uint64(0), uint64(0),
                    uint64(SF_NOCACHE)
                )
            end)
            if ok_sf2 then
                print("  sendfile(SF_NOCACHE): ret=" .. tostring(to_num(ret_sf2)))
            else
                print("  sendfile(SF_NOCACHE): PCALL-FAIL")
            end
        else
            print("  sendfile: PCALL-FAIL")
            print("  >>> SENDFILE IS LETHAL OR BLOCKED <<<")
        end

        pcall(function() sc_close(uint64(sock_fd)) end)
    end

    --------------------------------------------------------------------
    -- SECTION E: fspacectl reachability
    --------------------------------------------------------------------
    print("")
    print("--- SECTION E: FSPACECTL REACHABILITY ---")

    -- fspacectl(int fd, int cmd, const struct spacectl_range *rqsr,
    --           int flags, struct spacectl_range *rmsr)
    -- cmd=1 (SPACECTL_DEALLOC), flags=0
    local ok_fc, ret_fc = pcall(function()
        return sc_fspacectl(
            uint64(shm_fd),
            uint64(1),     -- SPACECTL_DEALLOC
            uint64(0),     -- rqsr (NULL — will fail but tests reachability)
            uint64(0),     -- flags
            uint64(0)      -- rmsr (NULL)
        )
    end)

    if ok_fc then
        print("  fspacectl: ret=" .. tostring(to_num(ret_fc)))
        print("  >>> FSPACECTL REACHABLE <<<")
    else
        print("  fspacectl: PCALL-FAIL")
        print("  >>> FSPACECTL IS LETHAL OR BLOCKED <<<")
    end

    --------------------------------------------------------------------
    -- CLEANUP
    --------------------------------------------------------------------
    print("")
    print("--- CLEANUP ---")
    if shm_addr then
        pcall(function() sc_munmap(uint64(shm_addr), uint64(shm_size)) end)
        print("  munmap: done")
    end
    pcall(function() sc_close(uint64(shm_fd)) end)
    print("  close shm fd: done")
    pcall(function() sc_shm_unlink(shm_name) end)
    print("  shm_unlink: done")
else
    print("")
    print("--- SECTIONS B-E SKIPPED (shm_open failed) ---")
end

--------------------------------------------------------------------
-- FINAL CANARY
--------------------------------------------------------------------
print("")
print("--- FINAL CANARY ---")
local ok_pid2, pid2 = pcall(function() return sc_getpid() end)
if ok_pid2 then
    print("  getpid: " .. tostring(to_num(pid2)) .. " — process survived")
else
    print("  getpid FAILED — process state corrupted")
end

print("")
print("=== PROBE 58d COMPLETE ===")
