-- CRASH_CLASS: MODERATE
-- PROBE 120a: pdfork(518) + capsicum process descriptors via make_syscall
--
-- Context: Probe 02 tested pdfork at WRONG syscall number 475 (via resolve).
-- Real FreeBSD pdfork is 518, pdgetpid is 519, pdkill is 520, pdwait4 is 521.
-- These were NEVER tested via make_syscall.
--
-- pdfork goes through a DIFFERENT code path than fork/rfork:
--   - fork(2): blocked on PS5 (returns -1)
--   - rfork(251): blocked
--   - thr_new(455): blocked
--   - thr_create(430): returns TID but panics kernel (CS=0 bug)
--   - pdfork(518): NEVER TESTED! Uses process descriptors, may bypass fork block
--
-- If pdfork succeeds: we get a CHILD PROCESS with a process descriptor fd.
-- This is a completely different process creation path. Sony may have blocked
-- fork/rfork but not pdfork because it's a capsicum-specific API.
--
-- Section A: pdfork basic test
-- Section B: pdgetpid/pdkill on valid fds
-- Section C: pdwait4 + WNOHANG
-- Section D: cap_enter + pdfork (capsicum mode)
-- Section E: closefrom/close-on-exec interaction

print("=== PROBE 120a: PDFORK + CAPSICUM ===")
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")

-- Syscall setup
local sc_pdfork   = make_syscall(518)
local sc_pdgetpid = make_syscall(519)
local sc_pdkill   = make_syscall(520)
local sc_pdwait4  = make_syscall(521)
local sc_getpid   = make_syscall(20)
local sc_close    = make_syscall(6)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("[*] PID: " .. pid)


-- ================================================================
-- SECTION A: pdfork basic test
-- ================================================================
print("")
print("--- SECTION A: pdfork(518) basic test ---")
print("")

-- pdfork(int *fdp, int flags)
-- Returns: 0 in child, pid in parent, -1 on error
-- fdp: receives the process descriptor fd

local fdp = memory.alloc(16)
safe_wd(fdp, 0xDEADBEEF)  -- sentinel
safe_wd(fdp + 4, 0xCAFEBABE)

-- Test 1: basic pdfork with flags=0
print("[A1] pdfork(fdp, 0)...")
local rv_a1 = -999
pcall(function()
    rv_a1 = to_num(sc_pdfork(uint64(fdp), uint64(0)))
end)
local fd_a1 = safe_rd(fdp)
print(string.format("[A1] ret=%d fd=%d (0x%08X)", rv_a1, fd_a1 or -1, fd_a1 or 0))

if rv_a1 == 0 then
    print("[A1] *** WE ARE IN THE CHILD! pdfork WORKS! ***")
    print("[A1] *** This is GOLD — fork bypass via capsicum ***")
    -- If we're in the child, get our new PID
    local child_pid = 0
    pcall(function() child_pid = to_num(sc_getpid()) end)
    print("[A1] child PID: " .. child_pid)
elseif rv_a1 > 0 then
    print(string.format("[A1] *** PARENT: child pid=%d fd=%d ***", rv_a1, fd_a1 or -1))
    print("[A1] *** pdfork WORKS! Process creation via capsicum! ***")

    -- Test pdgetpid on the fd
    if fd_a1 and fd_a1 > 0 then
        local pidp = memory.alloc(8)
        safe_wd(pidp, 0)
        local rv_pdget = -999
        pcall(function()
            rv_pdget = to_num(sc_pdgetpid(uint64(fd_a1), uint64(pidp)))
        end)
        local got_pid = safe_rd(pidp)
        print(string.format("[A1] pdgetpid(%d) ret=%d pid=%d", fd_a1, rv_pdget, got_pid or -1))

        -- pdkill to send signal
        local rv_pdkill = -999
        pcall(function()
            rv_pdkill = to_num(sc_pdkill(uint64(fd_a1), uint64(9)))  -- SIGKILL
        end)
        print(string.format("[A1] pdkill(%d, SIGKILL) ret=%d", fd_a1, rv_pdkill))

        -- Close the fd
        pcall(function() sc_close(uint64(fd_a1)) end)
    end
elseif rv_a1 == -1 then
    print("[A1] pdfork returned -1 (blocked or error)")
elseif rv_a1 == -999 then
    print("[A1] pcall FAILED — crash or exception")
end

-- Test 2: pdfork with PD_DAEMON flag (0x01)
print("")
print("[A2] pdfork(fdp, PD_DAEMON=0x01)...")
safe_wd(fdp, 0xDEADBEEF)
local rv_a2 = -999
pcall(function()
    rv_a2 = to_num(sc_pdfork(uint64(fdp), uint64(1)))
end)
local fd_a2 = safe_rd(fdp)
print(string.format("[A2] ret=%d fd=%d", rv_a2, fd_a2 or -1))

if rv_a2 >= 0 and fd_a2 and fd_a2 > 0 then
    print("[A2] *** PD_DAEMON pdfork WORKS! ***")
    pcall(function() sc_close(uint64(fd_a2)) end)
end

-- Test 3: pdfork with PD_CLOEXEC flag (0x02)
print("")
print("[A3] pdfork(fdp, PD_CLOEXEC=0x02)...")
safe_wd(fdp, 0xDEADBEEF)
local rv_a3 = -999
pcall(function()
    rv_a3 = to_num(sc_pdfork(uint64(fdp), uint64(2)))
end)
local fd_a3 = safe_rd(fdp)
print(string.format("[A3] ret=%d fd=%d", rv_a3, fd_a3 or -1))

if rv_a3 >= 0 and fd_a3 and fd_a3 > 0 then
    pcall(function() sc_close(uint64(fd_a3)) end)
end


-- ================================================================
-- SECTION B: pdgetpid/pdkill on various fds
-- ================================================================
print("")
print("--- SECTION B: pdgetpid/pdkill on existing fds ---")
print("")

-- Even if pdfork fails, pdgetpid/pdkill might give useful errors
-- or accept fds from other sources
for test_fd = 0, 10 do
    local pidp = memory.alloc(8)
    safe_wd(pidp, 0)
    local rv = -999
    pcall(function()
        rv = to_num(sc_pdgetpid(uint64(test_fd), uint64(pidp)))
    end)
    local got_pid = safe_rd(pidp)
    if rv ~= -1 then
        print(string.format("  pdgetpid(fd=%d) ret=%d pid=%d", test_fd, rv, got_pid or -1))
    end
end

-- Try pdkill on fd 0 (stdin) with signal 0 (check existence)
local rv_pk = -999
pcall(function()
    rv_pk = to_num(sc_pdkill(uint64(0), uint64(0)))
end)
print(string.format("  pdkill(fd=0, sig=0) ret=%d", rv_pk))


-- ================================================================
-- SECTION C: pdwait4 test
-- ================================================================
print("")
print("--- SECTION C: pdwait4(521) ---")
print("")

-- pdwait4(int fd, int *status, int options, struct rusage *rusage)
-- WNOHANG = 1
local status_buf = memory.alloc(16)
safe_wd(status_buf, 0)

-- Try on various fds with WNOHANG
for test_fd = 0, 5 do
    safe_wd(status_buf, 0xDEAD)
    local rv = -999
    pcall(function()
        rv = to_num(sc_pdwait4(uint64(test_fd), uint64(status_buf), uint64(1), uint64(0)))
    end)
    if rv ~= -1 or test_fd <= 2 then
        local st = safe_rd(status_buf)
        print(string.format("  pdwait4(fd=%d, WNOHANG) ret=%d status=0x%08X", test_fd, rv, st or 0))
    end
end


-- ================================================================
-- SECTION D: pipe2(542) via make_syscall
-- ================================================================
print("")
print("--- SECTION D: pipe2(542) via make_syscall ---")
print("")

-- pipe2(int fildes[2], int flags)
-- This was only tested via resolve (returned -1). NEVER via make_syscall.
local sc_pipe2 = make_syscall(542)
local pipe_fds = memory.alloc(16)
safe_wd(pipe_fds, 0xDEAD)
safe_wd(pipe_fds + 4, 0xBEEF)

-- Test 1: flags=0
print("[D1] pipe2(fds, 0)...")
local rv_d1 = -999
pcall(function()
    rv_d1 = to_num(sc_pipe2(uint64(pipe_fds), uint64(0)))
end)
local pfd0 = safe_rd(pipe_fds)
local pfd1 = safe_rd(pipe_fds + 4)
print(string.format("[D1] ret=%d fds=[%d, %d]", rv_d1, pfd0 or -1, pfd1 or -1))

if rv_d1 == 0 and pfd0 and pfd0 > 0 then
    print("[D1] *** pipe2 WORKS via make_syscall! ***")
    -- We have two new fds — kernel pipe object created
    -- Write and read test
    local sc_write = make_syscall(4)
    local sc_read = make_syscall(3)
    local test_data = memory.alloc(64)
    safe_wd(test_data, 0x41424344)  -- "ABCD"
    local wbuf = memory.alloc(64)
    safe_wd(wbuf, 0)

    local wr_ret = -999
    pcall(function()
        wr_ret = to_num(sc_write(uint64(pfd1), uint64(test_data), uint64(4)))
    end)
    print(string.format("[D1] write(%d, 4 bytes) ret=%d", pfd1, wr_ret))

    local rd_ret = -999
    pcall(function()
        rd_ret = to_num(sc_read(uint64(pfd0), uint64(wbuf), uint64(4)))
    end)
    local rd_val = safe_rd(wbuf)
    print(string.format("[D1] read(%d, 4) ret=%d val=0x%08X", pfd0, rd_ret, rd_val or 0))

    -- Clean up
    pcall(function() sc_close(uint64(pfd0)) end)
    pcall(function() sc_close(uint64(pfd1)) end)
end

-- Test 2: O_CLOEXEC (0x00100000) + O_NONBLOCK (0x04)
print("")
print("[D2] pipe2(fds, O_CLOEXEC|O_NONBLOCK)...")
safe_wd(pipe_fds, 0xDEAD)
safe_wd(pipe_fds + 4, 0xBEEF)
local rv_d2 = -999
pcall(function()
    rv_d2 = to_num(sc_pipe2(uint64(pipe_fds), uint64(0x100004)))
end)
pfd0 = safe_rd(pipe_fds)
pfd1 = safe_rd(pipe_fds + 4)
print(string.format("[D2] ret=%d fds=[%d, %d]", rv_d2, pfd0 or -1, pfd1 or -1))

if rv_d2 == 0 then
    pcall(function() sc_close(uint64(pfd0)) end)
    pcall(function() sc_close(uint64(pfd1)) end)
end

-- Also test plain pipe(42) via make_syscall (known dead: returns 0,0)
print("")
print("[D3] pipe(42) via make_syscall for comparison...")
local sc_pipe = make_syscall(42)
safe_wd(pipe_fds, 0xDEAD)
safe_wd(pipe_fds + 4, 0xBEEF)
local rv_d3 = -999
pcall(function()
    rv_d3 = to_num(sc_pipe(uint64(pipe_fds)))
end)
pfd0 = safe_rd(pipe_fds)
pfd1 = safe_rd(pipe_fds + 4)
print(string.format("[D3] ret=%d fds=[%d, %d]", rv_d3, pfd0 or -1, pfd1 or -1))


-- ================================================================
-- SECTION E: cap_enter(516) + cap_getmode(517)
-- ================================================================
print("")
print("--- SECTION E: Capsicum capability mode ---")
print("")

local sc_cap_getmode = make_syscall(517)
local sc_cap_enter = make_syscall(516)

-- First check if we're already in capability mode
local mode_buf = memory.alloc(8)
safe_wd(mode_buf, 0xDEAD)
local rv_e1 = -999
pcall(function()
    rv_e1 = to_num(sc_cap_getmode(uint64(mode_buf)))
end)
local mode_val = safe_rd(mode_buf)
print(string.format("[E1] cap_getmode ret=%d mode=%d", rv_e1, mode_val or -1))

if mode_val == 0 then
    print("[E1] NOT in capability mode")

    -- cap_enter is one-way — once you enter, you can't leave
    -- Only enter if we want to test pdfork in capability mode
    -- SKIP: this would break subsequent probes
    print("[E2] SKIPPING cap_enter (irreversible, would break other probes)")
elseif mode_val == 1 then
    print("[E1] *** ALREADY IN CAPABILITY MODE ***")
end

-- cap_rights_limit(515) — check if available
local sc_cap_rights = make_syscall(515)
local rv_cap = -999
pcall(function()
    rv_cap = to_num(sc_cap_rights(uint64(0), uint64(0)))
end)
print(string.format("[E3] cap_rights_limit(0,0) ret=%d", rv_cap))


print("")
print("=== PROBE 120a COMPLETE ===")
