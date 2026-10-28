-- CRASH_CLASS: LOW
-- PROBE 559c: Spray vehicle survey — simplified
--
-- Minimal tests for each spray candidate. 559b crashed silently.

print("=== PROBE 559c: SPRAY SURVEY ===")
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
local function rb(a)
    local d = rd(a); if d == nil then return nil end
    if d < 0 then d = d + 0x100000000 end; return d
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

local Z = uint64(0)
local sc3   = mk(3)
local sc4   = mk(4)
local sc6   = mk(6)
local sc20  = mk(20)
local sc97  = mk(97)
local sc105 = mk(105)
local sc135 = mk(135)
local sc362 = mk(362)
local sc363 = mk(363)
local sc480 = mk(480)
local sc482 = mk(482)
local sc542 = mk(542)

local pid = N(sc20())
print("pid=" .. pid)
io.flush()

-- ============================================================
-- A) PIPE
-- ============================================================
print("")
print("--- A: Pipe ---")
io.flush()

local pf = memory.alloc(8)
local ok1, rv1 = pcall(function() return sc542(uint64(pf), Z) end)
local prv = ok1 and N(rv1) or -999
print("pipe2=" .. prv)

if prv == 0 then
    local prd_fd = rd(pf) or -1
    local pwr_fd = rd(pf + 4) or -1
    print("  rd=" .. prd_fd .. " wr=" .. pwr_fd)

    local wb = memory.alloc(256)
    for off = 0, 252, 4 do wd(wb + off, 0xCAFE0000 + off) end

    -- Write sizes
    for _, sz in ipairs({64, 128, 256, 1024, 4096, 16384}) do
        local ok_w, rv_w = pcall(function()
            return sc4(uint64(pwr_fd), uint64(wb), uint64(math.min(sz, 256)))
        end)
        local wrv = ok_w and N(rv_w) or -999
        print(string.format("  write(%d)=%d", sz, wrv))
        -- Drain
        if wrv > 0 then
            local drn = memory.alloc(0x4000)
            pcall(function() sc3(uint64(prd_fd), uint64(drn), uint64(0x4000)) end)
        end
    end

    -- Mass creation
    local pc = 0
    for i = 1, 200 do
        local pp = memory.alloc(8)
        local ok_pp, rv_pp = pcall(function() return sc542(uint64(pp), Z) end)
        if ok_pp and N(rv_pp) == 0 then
            pc = pc + 1
            local r = rd(pp) or -1
            local w = rd(pp + 4) or -1
            -- Write to fill
            pcall(function() sc4(uint64(w), uint64(wb), uint64(128)) end)
            -- Close read end only (write end keeps buffer alive)
            pcall(function() sc6(uint64(r)) end)
            pcall(function() sc6(uint64(w)) end)
        else
            break
        end
    end
    print("  mass: " .. pc .. " pipes")

    pcall(function() sc6(uint64(prd_fd)) end)
    pcall(function() sc6(uint64(pwr_fd)) end)
end
io.flush()

-- ============================================================
-- B) KQUEUE KNOTES
-- ============================================================
print("")
print("--- B: kqueue ---")
io.flush()

local ok_kq, kqfd = pcall(function() return sc362() end)
kqfd = ok_kq and N(kqfd) or -1
print("kqueue=" .. kqfd)

if kqfd >= 0 then
    local kev = memory.alloc(64)

    -- EVFILT_USER = -11 (0xFFF5 as u16)
    -- EV_ADD = 0x0001
    -- kevent struct on amd64: ident(8) filter(i16) flags(u16) fflags(4) data(8) udata(8)
    -- That's ident at +0, filter at +8 (16-bit), flags at +10 (16-bit), fflags at +12
    local ua = 0
    for i = 1, 50 do
        zero(kev, 32)
        wq(kev + 0, uint64(i))
        -- filter = i16 -11 at offset +8, flags = u16 0x0001 at offset +10
        -- In little-endian: byte 8,9 = 0xF5,0xFF (filter=-11), byte 10,11 = 0x01,0x00 (flags=EV_ADD)
        wd(kev + 8, 0x0001FFF5)
        wd(kev + 12, 0)
        wq(kev + 16, uint64(0))
        wq(kev + 24, uint64(0xDEAD0000 + i))

        local ok_k, rv_k = pcall(function()
            return sc363(uint64(kqfd), uint64(kev), uint64(1), Z, Z, Z)
        end)
        local krv = ok_k and N(rv_k) or -999
        if krv >= 0 then
            ua = ua + 1
        else
            if ua == 0 then print("  EVFILT_USER fail: " .. krv) end
            break
        end
    end
    print("  EVFILT_USER: " .. ua .. " knotes")

    -- EVFILT_TIMER = -7 (0xFFF9)
    local ta = 0
    for i = 1, 20 do
        zero(kev, 32)
        wq(kev + 0, uint64(2000 + i))
        wd(kev + 8, 0x0001FFF9)
        wd(kev + 12, 0)
        wq(kev + 16, uint64(300000))
        wq(kev + 24, Z)

        local ok_k, rv_k = pcall(function()
            return sc363(uint64(kqfd), uint64(kev), uint64(1), Z, Z, Z)
        end)
        local krv = ok_k and N(rv_k) or -999
        if krv >= 0 then ta = ta + 1 end
    end
    print("  EVFILT_TIMER: " .. ta .. " knotes")

    pcall(function() sc6(uint64(kqfd)) end)
end
io.flush()

-- ============================================================
-- C) SHM OBJECTS
-- ============================================================
print("")
print("--- C: SHM ---")
io.flush()

local sc = 0
for i = 1, 100 do
    local ok_s, sfd = pcall(function()
        return sc482(uint64(1), uint64(0x202), uint64(0x1B6))
    end)
    if ok_s and N(sfd) >= 0 then
        sc = sc + 1
        pcall(function() sc480(uint64(N(sfd)), uint64(128)) end)
        pcall(function() sc6(uint64(N(sfd))) end)
    else
        break
    end
end
print("shm_open x " .. sc)
io.flush()

-- ============================================================
-- D) SOCKET OPTIONS
-- ============================================================
print("")
print("--- D: sockopt ---")
io.flush()

-- UDP socket
local ufd = -1
do
    local ok, v = pcall(function() return sc97(uint64(2), uint64(2), uint64(17)) end)
    ufd = ok and N(v) or -1
end
print("udp=" .. ufd)

if ufd >= 0 then
    local ob = memory.alloc(64)

    -- SO_SNDBUF
    wd(ob, 0x10000)
    local ok_s, rv_s = pcall(function()
        return sc105(uint64(ufd), uint64(0xFFFF), uint64(0x1001), uint64(ob), uint64(4))
    end)
    print("  SO_SNDBUF=" .. (ok_s and N(rv_s) or -999))

    -- SO_RCVBUF
    wd(ob, 0x10000)
    ok_s, rv_s = pcall(function()
        return sc105(uint64(ufd), uint64(0xFFFF), uint64(0x1002), uint64(ob), uint64(4))
    end)
    print("  SO_RCVBUF=" .. (ok_s and N(rv_s) or -999))

    -- IP_OPTIONS (IPPROTO_IP=0, opt=6)
    zero(ob, 44)
    wd(ob, 0x01010101)
    ok_s, rv_s = pcall(function()
        return sc105(uint64(ufd), Z, uint64(6), uint64(ob), uint64(4))
    end)
    print("  IP_OPTIONS(4B)=" .. (ok_s and N(rv_s) or -999))

    -- IP_OPTIONS 40 bytes
    for off = 0, 36, 4 do wd(ob + off, 0x01010101) end
    ok_s, rv_s = pcall(function()
        return sc105(uint64(ufd), Z, uint64(6), uint64(ob), uint64(40))
    end)
    print("  IP_OPTIONS(40B)=" .. (ok_s and N(rv_s) or -999))

    pcall(function() sc6(uint64(ufd)) end)
end

-- RAW socket
local rfd = -1
do
    local ok, v = pcall(function() return sc97(uint64(2), uint64(3), Z) end)
    rfd = ok and N(v) or -1
end
print("raw=" .. rfd)
if rfd >= 0 then
    local ob = memory.alloc(44)
    zero(ob, 44)
    wd(ob, 0x01010101)
    local ok_s, rv_s = pcall(function()
        return sc105(uint64(rfd), Z, uint64(6), uint64(ob), uint64(4))
    end)
    print("  IP_OPTIONS(raw,4B)=" .. (ok_s and N(rv_s) or -999))
    pcall(function() sc6(uint64(rfd)) end)
end
io.flush()

-- ============================================================
-- E) TCP options
-- ============================================================
print("")
print("--- E: TCP ---")
io.flush()

local tfd = -1
do
    local ok, v = pcall(function() return sc97(uint64(2), uint64(1), uint64(6)) end)
    tfd = ok and N(v) or -1
end
print("tcp=" .. tfd)

if tfd >= 0 then
    local ob = memory.alloc(256)
    local tcp_tests = {
        {1, 4, "NODELAY"},
        {2, 4, "MAXSEG"},
        {4, 4, "NOOPT"},
        {8, 4, "NOPUSH"},
        {32, 4, "FASTOPEN"},
        {64, 128, "FUNCTION_BLK"},
    }
    for _, t in ipairs(tcp_tests) do
        zero(ob, 256)
        wd(ob, 1)
        local ok_s, rv_s = pcall(function()
            return sc105(uint64(tfd), uint64(6), uint64(t[1]), uint64(ob), uint64(t[2]))
        end)
        local srv = ok_s and N(rv_s) or -999
        if srv >= 0 then
            print(string.format("  TCP_%s(%d,%dB)=OK", t[3], t[1], t[2]))
        end
    end
    pcall(function() sc6(uint64(tfd)) end)
end
io.flush()

print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " DEAD"))
print("=== 559c DONE ===")
