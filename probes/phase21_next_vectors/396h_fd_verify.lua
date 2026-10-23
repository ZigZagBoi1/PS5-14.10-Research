-- CRASH_CLASS: LOW
-- PROBE 396h: verify socket fds are real + diagnose setsockopt failure
--
-- 396g showed ALL setsockopt/getsockopt fail including SO_TYPE.
-- Hypothesis: mk(97) reuses pipe stub which might not create real sockets.
-- Test: fstat the fd to check st_mode (S_IFSOCK=0xC000 vs S_IFIFO=0x1000)
-- Also test bind/listen/connect to verify socket state.
-- And verify sysctl (6 args) still works to confirm chain arg passing.

print("=== PROBE 396h: fd verify ===")

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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

-- PART 1: Verify sysctl STILL works (6-arg syscall, known working)
print("")
print("-- sysctl verify --")
local mib = memory.alloc(16)
wd(N(mib), 1)       -- CTL_KERN
wd(N(mib) + 4, 37)  -- KERN_HOSTNAME
local outbuf = memory.alloc(256)
for i = 0, 252, 4 do wd(N(outbuf) + i, 0) end
local oldlenp = memory.alloc(8)
wq(oldlenp, uint64(256))
local ok_sc, rv_sc = pcall(function()
    return mk(202)(uint64(N(mib)), uint64(2), uint64(N(outbuf)), uint64(N(oldlenp)),
        uint64(0), uint64(0))
end)
local sc_ret = ok_sc and N(rv_sc) or -999
local hostname_len = rd(N(oldlenp)) or 0
local byte0 = rd(N(outbuf)) or 0
print(string.format("sysctl(hostname)=%d len=%d first4=%08X", sc_ret, hostname_len, byte0))

-- PART 2: Create socket via mk(97) and fstat it
print("")
print("-- socket + fstat --")
local ok_s, rv_s = pcall(function()
    return mk(97)(uint64(2), uint64(1), uint64(0))
end)
local fd1 = ok_s and N(rv_s) or -1
print(string.format("mk97_socket=%d (raw: %s)", fd1, tostring(rv_s)))

if fd1 >= 0 then
    -- fstat(189) on the fd
    local statbuf = memory.alloc(256)
    for i = 0, 252, 4 do wd(N(statbuf) + i, 0xCC) end
    local ok_f, rv_f = pcall(function()
        return mk(189)(uint64(fd1), uint64(N(statbuf)))
    end)
    local f_ret = ok_f and N(rv_f) or -999
    local st_dev = rd(N(statbuf)) or 0
    local st_mode = rd(N(statbuf) + 8) or 0
    local st_nlink = rd(N(statbuf) + 12) or 0
    print(string.format("fstat(%d)=%d dev=%X mode=%04X nlink=%d",
        fd1, f_ret, st_dev, st_mode, st_nlink))
    -- S_IFSOCK=0xC000, S_IFIFO=0x1000, S_IFREG=0x8000
    local ftype = bit32 and bit32.band(st_mode, 0xF000) or (st_mode % 0x10000 - st_mode % 0x1000)
    print(string.format("  file_type=%04X (%s)", ftype,
        ftype == 0xC000 and "SOCKET" or
        ftype == 0x1000 and "FIFO/PIPE" or
        ftype == 0x8000 and "REGULAR" or "OTHER"))
end

-- PART 3: Create socket via syscall.socket and fstat it
print("")
print("-- native socket + fstat --")
local ok_s2, rv_s2 = pcall(function()
    return syscall.socket(uint64(2), uint64(1), uint64(0))
end)
local fd2 = ok_s2 and N(rv_s2) or -1
print(string.format("native_socket=%d (raw: %s)", fd2, tostring(rv_s2)))

if fd2 >= 0 then
    local statbuf2 = memory.alloc(256)
    for i = 0, 252, 4 do wd(N(statbuf2) + i, 0xCC) end
    local ok_f2, rv_f2 = pcall(function()
        return mk(189)(uint64(fd2), uint64(N(statbuf2)))
    end)
    local f2_ret = ok_f2 and N(rv_f2) or -999
    local st_mode2 = rd(N(statbuf2) + 8) or 0
    local ftype2 = st_mode2 % 0x10000 - st_mode2 % 0x1000
    print(string.format("fstat(%d)=%d mode=%04X type=%04X (%s)",
        fd2, f2_ret, st_mode2, ftype2,
        ftype2 == 0xC000 and "SOCKET" or
        ftype2 == 0x1000 and "FIFO/PIPE" or "OTHER"))
end

-- PART 4: Try bind on the socket to verify it's actually a socket
-- bind(fd, addr, addrlen) = 3 args, should work via mk
print("")
print("-- bind test --")
local test_fd = fd1 >= 0 and fd1 or fd2
if test_fd >= 0 then
    -- struct sockaddr_in: AF_INET=2, port=5555, addr=0 (INADDR_ANY)
    local saddr = memory.alloc(16)
    wd(N(saddr), 0x15B30002)  -- sin_len=0, sin_family=2, sin_port=0x15B3 (5555 BE)
    wd(N(saddr) + 4, 0)       -- sin_addr=0 (INADDR_ANY)
    wd(N(saddr) + 8, 0)
    wd(N(saddr) + 12, 0)

    local ok_b, rv_b = pcall(function()
        return mk(104)(uint64(test_fd), uint64(N(saddr)), uint64(16))
    end)
    local b_ret = ok_b and N(rv_b) or -999
    print(string.format("bind(%d, :5555)=%d", test_fd, b_ret))
    -- 0=success, -1=error
    -- ENOTSOCK(20): not a socket
    -- EADDRINUSE(48): address in use
    -- EACCES(13): permission denied
    -- EINVAL(22): already bound

    if b_ret == 0 then
        -- listen(fd, backlog) = 2 args
        local ok_l, rv_l = pcall(function()
            return mk(106)(uint64(test_fd), uint64(5))
        end)
        print(string.format("listen=%d", ok_l and N(rv_l) or -999))
    end
end

-- PART 5: Check fd numbers more carefully
-- Open 3 sockets and see if fds increment
print("")
print("-- fd allocation --")
local fds = {}
for i = 1, 3 do
    local ok_si, rv_si = pcall(function()
        return mk(97)(uint64(2), uint64(2), uint64(0))
    end)
    local fdi = ok_si and N(rv_si) or -1
    fds[i] = fdi
    print(string.format("socket[%d]=%d", i, fdi))
end
-- Close them
for i = 1, 3 do
    if fds[i] >= 0 then
        local ok_ci, rv_ci = pcall(function()
            return mk(6)(uint64(fds[i]))
        end)
        print(string.format("close(%d)=%d", fds[i], ok_ci and N(rv_ci) or -999))
    end
end

-- PART 6: socketpair with uint64-wrapped buffer ptr
print("")
print("-- socketpair uint64 --")
local sp_buf = memory.alloc(16)
wd(N(sp_buf), 0xDEAD)
wd(N(sp_buf) + 4, 0xBEEF)
local ok_sp, rv_sp = pcall(function()
    return mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_buf)))
end)
print(string.format("socketpair=%d", ok_sp and N(rv_sp) or -999))
local sp0 = rd(N(sp_buf)) or 0xDEAD
local sp1 = rd(N(sp_buf) + 4) or 0xBEEF
print(string.format("fds=%d,%d (sentinel was DEAD,BEEF)", sp0, sp1))

-- If fds look valid, test write/read on them
if sp0 ~= 0xDEAD and sp1 ~= 0xBEEF and sp0 ~= sp1 then
    local wbuf = memory.alloc(16)
    wd(N(wbuf), 0xCAFE)
    local ok_w, rv_w = pcall(function()
        return mk(4)(uint64(sp0), uint64(N(wbuf)), uint64(4))
    end)
    print(string.format("write(sp0)=%d", ok_w and N(rv_w) or -999))

    local rbuf = memory.alloc(16)
    wd(N(rbuf), 0)
    local ok_r, rv_r = pcall(function()
        return mk(3)(uint64(sp1), uint64(N(rbuf)), uint64(4))
    end)
    local rval = rd(N(rbuf)) or 0
    print(string.format("read(sp1)=%d val=%X", ok_r and N(rv_r) or -999, rval))

    -- NOW try setsockopt on a known-valid socketpair fd
    local optbuf = memory.alloc(16)
    wd(N(optbuf), 16384)
    local ok_so, rv_so = pcall(function()
        return mk(105)(uint64(sp0), uint64(0xFFFF), uint64(0x1002),
            uint64(N(optbuf)), uint64(4))
    end)
    print(string.format("setsockopt(sp0,RCVBUF)=%d", ok_so and N(rv_so) or -999))

    -- getsockopt SO_TYPE on the pair
    local gbuf = memory.alloc(16)
    wd(N(gbuf), 0xCC)
    local glenp = memory.alloc(8)
    wq(glenp, uint64(4))
    local ok_g, rv_g = pcall(function()
        return mk(118)(uint64(sp0), uint64(0xFFFF), uint64(0x1008),
            uint64(N(gbuf)), uint64(N(glenp)))
    end)
    local gval = rd(N(gbuf)) or 0xCC
    print(string.format("getsockopt(sp0,SO_TYPE)=%d val=%X", ok_g and N(rv_g) or -999, gval))

    pcall(function() mk(6)(uint64(sp0)) end)
    pcall(function() mk(6)(uint64(sp1)) end)
end

-- PART 7: Direct comparison — use the EXACT same pattern as sysctl
-- sysctl works with 6 args, verify the mechanism with setsockopt args
print("")
print("-- pattern comparison --")
-- Open fresh socket
local ok_s3, rv_s3 = pcall(function()
    return mk(97)(uint64(2), uint64(1), uint64(0))
end)
local fd3 = ok_s3 and N(rv_s3) or -1
if fd3 >= 0 then
    -- setsockopt(fd, SOL_SOCKET=0xFFFF, SO_REUSEADDR=4, &val, 4)
    local vbuf = memory.alloc(16)
    wd(N(vbuf), 1)
    -- Call EXACTLY like sysctl: mk(N)(uint64, uint64, uint64, uint64, uint64)
    local ok_ss, rv_ss = pcall(function()
        return mk(105)(uint64(fd3), uint64(0xFFFF), uint64(4),
            uint64(N(vbuf)), uint64(4))
    end)
    print(string.format("final_setsockopt=%d", ok_ss and N(rv_ss) or -999))

    -- For comparison: sysctl on same fd number (makes no sense but tests the chain)
    -- Actually test sysctl to prove chain works
    local mib2 = memory.alloc(8)
    wd(N(mib2), 6)  -- CTL_HW
    wd(N(mib2) + 4, 6)  -- HW_PAGESIZE
    local obuf2 = memory.alloc(16)
    local olen2 = memory.alloc(8)
    wq(olen2, uint64(4))
    local ok_sc2, rv_sc2 = pcall(function()
        return mk(202)(uint64(N(mib2)), uint64(2), uint64(N(obuf2)),
            uint64(N(olen2)), uint64(0), uint64(0))
    end)
    local pgsz = rd(N(obuf2)) or 0
    print(string.format("sysctl(pagesize)=%d val=%d", ok_sc2 and N(rv_sc2) or -999, pgsz))

    pcall(function() mk(6)(uint64(fd3)) end)
end

if fd1 >= 0 then pcall(function() mk(6)(uint64(fd1)) end) end
if fd2 >= 0 then pcall(function() mk(6)(uint64(fd2)) end) end

print("")
print("canary=" .. (N(native.fcall_with_rax(stub, 20)) == pid_val and "OK" or "FAIL"))
print("=== 396h COMPLETE ===")
