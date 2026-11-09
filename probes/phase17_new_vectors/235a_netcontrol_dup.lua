-- CRASH_CLASS: LOW
-- PROBE 235a: does a dup'ped descriptor complete the unregister the closed one cannot?
--
-- Context: 233a/234a show a registration takes a reference and a closed
-- descriptor can no longer be unregistered (-1), so the socket leaks and the
-- ifindex -1 queue is spent for the boot. The one ordering never tried is a
-- duplicate: two descriptors for the same file, one closed, the other used to
-- clear the queue. If the queue keys on the file rather than the descriptor
-- number, the clear succeeds; the question is whether the reference then
-- balances (peer reads 0 after both descriptors close) or is dropped twice.
--
-- A balanced return is the patch working. A second drop would show as the peer
-- going 0 after a single close, or as a fault when the socket is touched again.
--
-- This probe spends the ifindex -1 queue if any clear fails, exactly like
-- 219a/221a. Run it last on a boot.

print("=== PROBE 235a: netcontrol through a duplicate descriptor ===")
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
local function sgn(v)
    local n = to_num(v)
    if n >= 0x8000000000000000 then return n - 0x10000000000000000 end
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end

local sc_netctl  = make_syscall(99)
local sc_sockpair= make_syscall(135)
local sc_close   = make_syscall(6)
local sc_recvfrom= make_syscall(29)
local sc_dup     = make_syscall(41)

local SET_QUEUE, CLEAR_QUEUE = 0x20000003, 0x20000007

local buf = memory.alloc(16)
local rbuf = memory.alloc(64)

local function reg(cmd, fd)
    pcall(function() memory.write_dword(buf, fd) end)
    return sgn(sc_netctl(uint64(0xFFFFFFFF), uint64(cmd), uint64(buf), uint64(8), uint64(0), uint64(0)))
end

local function peer_state(fd)
    local r = sgn(sc_recvfrom(uint64(fd), uint64(rbuf), uint64(1), uint64(0x80), uint64(0), uint64(0)))
    return r
end

local function pair()
    local fds = memory.alloc(16)
    local r = sgn(sc_sockpair(uint64(1), uint64(1), uint64(0), uint64(fds)))
    if r ~= 0 then return nil, nil end
    return to_num(memory.read_dword(fds)), to_num(memory.read_dword(fds + 4))
end

-- [A] control: register, close, then clear through a duplicate of the live end
do
    print("[A] register fd, dup, close fd, clear via the duplicate")
    local a, b = pair()
    if not a then
        print("    socketpair failed")
    else
        local r = reg(SET_QUEUE, a)
        local d = sgn(sc_dup(uint64(a)))
        print(string.format("    register=%d dup=%d", r, d))
        sc_close(uint64(a))
        print(string.format("    peer after close      = %d", peer_state(b)))
        local c = reg(CLEAR_QUEUE, d)
        print(string.format("    clear via duplicate   = %d", c))
        sc_close(uint64(d))
        print(string.format("    peer after dup close  = %d  (0 = reference balanced, -1 = leaked)", peer_state(b)))
        sc_close(uint64(b))
    end
end
print("")

-- [B] does the queue key on the file? register fd, close it, then clear through
-- a duplicate made before the close
do
    print("[B] register fd, dup, close fd, clear via duplicate, then a second clear")
    local a, b = pair()
    if not a then
        print("    socketpair failed")
    else
        local d = sgn(sc_dup(uint64(a)))
        local r = reg(SET_QUEUE, a)
        sc_close(uint64(a))
        local c1 = reg(CLEAR_QUEUE, d)
        local c2 = reg(CLEAR_QUEUE, d)
        print(string.format("    register=%d dup=%d clear1=%d clear2=%d", r, d, c1, c2))
        sc_close(uint64(d))
        print(string.format("    peer = %d", peer_state(b)))
        sc_close(uint64(b))
    end
end
print("")

-- [C] two registrations of the same file through two descriptors, then two clears
do
    print("[C] register fd and its duplicate as two entries")
    local a, b = pair()
    if not a then
        print("    socketpair failed")
    else
        local d = sgn(sc_dup(uint64(a)))
        local r1 = reg(SET_QUEUE, a)
        local r2 = reg(SET_QUEUE, d)
        local c1 = reg(CLEAR_QUEUE, a)
        local c2 = reg(CLEAR_QUEUE, d)
        print(string.format("    reg1=%d reg2=%d clear1=%d clear2=%d", r1, r2, c1, c2))
        sc_close(uint64(a))
        sc_close(uint64(d))
        print(string.format("    peer = %d", peer_state(b)))
        sc_close(uint64(b))
    end
end
print("")

-- [D] the documented ordering, repeated twice, to see whether a second clear of
-- a spent queue returns -1 cleanly
do
    print("[D] register, close, clear the dead number twice")
    local a, b = pair()
    if not a then
        print("    socketpair failed")
    else
        local r = reg(SET_QUEUE, a)
        sc_close(uint64(a))
        local c1 = reg(CLEAR_QUEUE, a)
        local c2 = reg(CLEAR_QUEUE, a)
        print(string.format("    register=%d clear1=%d clear2=%d", r, c1, c2))
        print(string.format("    peer = %d", peer_state(b)))
        sc_close(uint64(b))
    end
end

print("=== PROBE 235a END ===")
