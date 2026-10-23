-- CRASH_CLASS: LOW
-- PROBE 396g: deep setsockopt/getsockopt diagnostic
--
-- ALL setsockopt calls return -1 in 396f. Even getsockopt fails.
-- Test getsockopt(SO_TYPE) which MUST work on a valid socket.
-- If that fails too, the gen_fcall_chain isn't passing args correctly.
-- Also try raw make_syscall with explicitly correct arg count.

print("=== PROBE 396g: sockopt diag ===")

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

-- socket(AF_INET=2, SOCK_STREAM=1, 0)
local ok_s, rv_s = pcall(function()
    return mk(97)(uint64(2), uint64(1), uint64(0))
end)
local fd = ok_s and N(rv_s) or -1
print(string.format("tcp_fd=%d", fd))

-- PART 1: How does the native API actually work?
-- Check if syscall.setsockopt has the same __call mechanism
print("")
print("-- API structure --")
local so_mt = getmetatable(syscall.setsockopt)
local pipe_mt = getmetatable(syscall.pipe)
print("setsockopt_mt == pipe_mt: " .. tostring(so_mt == pipe_mt))
print("setsockopt.syscall_no = " .. tostring(syscall.setsockopt.syscall_no))
print("getsockopt.syscall_no = " .. tostring(syscall.getsockopt and syscall.getsockopt.syscall_no or "nil"))

-- Check the tostring representation
print("setsockopt: " .. tostring(syscall.setsockopt))
print("pipe: " .. tostring(syscall.pipe))

-- PART 2: Test with KNOWN-WORKING syscalls to verify arg passing
print("")
print("-- arg passing verification --")

-- getpid (0 args) via mk(20)
local ok1, rv1 = pcall(function() return mk(20)() end)
print(string.format("getpid=%d", ok1 and N(rv1) or -999))

-- socket (3 args) via mk(97) - already worked above
-- close (1 arg) via mk(6) on a dup
local dup_ok, dup_rv = pcall(function() return mk(97)(uint64(2), uint64(2), uint64(0)) end)
local dup_fd = dup_ok and N(dup_rv) or -1
print(string.format("dup_fd=%d", dup_fd))
if dup_fd >= 0 then
    local ok_c, rv_c = pcall(function() return mk(6)(uint64(dup_fd)) end)
    print(string.format("close(%d)=%d", dup_fd, ok_c and N(rv_c) or -999))
end

-- write (3 args) via mk(4) to a pipe/socket
-- Actually test with socketpair + write
local sp_buf = memory.alloc(16)
local ok_sp, rv_sp = pcall(function()
    return mk(135)(uint64(1), uint64(2), uint64(0), sp_buf)
end)
print(string.format("socketpair=%d", ok_sp and N(rv_sp) or -999))
local sp0 = rd(N(sp_buf)) or -1
local sp1 = rd(N(sp_buf) + 4) or -1
print(string.format("  fds=%d,%d", sp0, sp1))

if sp0 >= 0 then
    local wbuf = memory.alloc(16)
    wd(N(wbuf), 0xDEAD)
    -- write(fd, buf, len) = 3 args
    local ok_w, rv_w = pcall(function()
        return mk(4)(uint64(sp0), wbuf, uint64(4))
    end)
    print(string.format("write(%d)=%d", sp0, ok_w and N(rv_w) or -999))

    -- setsockopt on the unix socket — SO_RCVBUF=0x1002 at SOL_SOCKET=0xFFFF
    local optbuf = memory.alloc(16)
    wd(N(optbuf), 16384)
    local ok_so1, rv_so1 = pcall(function()
        return mk(105)(uint64(sp0), uint64(0xFFFF), uint64(0x1002), optbuf, uint64(4))
    end)
    print(string.format("setsockopt(unix,RCVBUF)=%d", ok_so1 and N(rv_so1) or -999))

    -- getsockopt(SO_TYPE=0x1008) - MUST work
    local gbuf = memory.alloc(16)
    wd(N(gbuf), 0xCCCC)
    local glenp = memory.alloc(8)
    wq(glenp, uint64(4))
    local ok_g1, rv_g1 = pcall(function()
        return mk(118)(uint64(sp0), uint64(0xFFFF), uint64(0x1008), gbuf, glenp)
    end)
    local gval = rd(N(gbuf)) or 0xCCCC
    local glen = rd(N(glenp)) or 0
    print(string.format("getsockopt(unix,SO_TYPE)=%d val=%X len=%d",
        ok_g1 and N(rv_g1) or -999, gval, glen))

    pcall(function() mk(6)(uint64(sp0)) end)
    pcall(function() mk(6)(uint64(sp1)) end)
end

-- PART 3: Try setsockopt on TCP with native binding using plain Lua numbers
print("")
print("-- native binding test --")
if fd >= 0 then
    -- Allocate proper buffer with value=1
    local nbuf = memory.alloc(16)
    wd(N(nbuf), 1)

    -- Try: setsockopt(fd, level, optname, optval_ptr, optlen)
    -- The native binding might interpret args differently from gen_fcall_chain

    -- Test 1: All uint64
    local ok_n1, rv_n1 = pcall(function()
        return syscall.setsockopt(uint64(fd), uint64(0xFFFF), uint64(4), nbuf, uint64(4))
    end)
    print(string.format("nat_SO_REUSEADDR=%s ret=%s", tostring(ok_n1),
        ok_n1 and tostring(N(rv_n1)) or tostring(rv_n1)))

    -- Test 2: All plain numbers
    local ok_n2, rv_n2 = pcall(function()
        return syscall.setsockopt(fd, 0xFFFF, 4, N(nbuf), 4)
    end)
    print(string.format("nat_plain=%s ret=%s", tostring(ok_n2),
        ok_n2 and tostring(N(rv_n2)) or tostring(rv_n2)))

    -- Test 3: getsockopt SO_TYPE on TCP
    local tbuf = memory.alloc(16)
    wd(N(tbuf), 0xCCCC)
    local tlenp = memory.alloc(8)
    wq(tlenp, uint64(4))
    local ok_n3, rv_n3 = pcall(function()
        return syscall.getsockopt(uint64(fd), uint64(0xFFFF), uint64(0x1008), tbuf, tlenp)
    end)
    local tval = rd(N(tbuf)) or 0xCCCC
    print(string.format("nat_get_SO_TYPE=%s val=%X", tostring(ok_n3),  tval))

    -- Test 4: getsockopt via mk(118)
    wd(N(tbuf), 0xCCCC)
    wq(tlenp, uint64(4))
    local ok_n4, rv_n4 = pcall(function()
        return mk(118)(uint64(fd), uint64(0xFFFF), uint64(0x1008), tbuf, tlenp)
    end)
    tval = rd(N(tbuf)) or 0xCCCC
    print(string.format("mk_get_SO_TYPE=%s val=%X", tostring(ok_n4), tval))
end

-- PART 4: Check if the issue is arg5 by trying setsockopt with a HUGE optlen
-- If the chain doesn't pass arg5, the kernel gets garbage. A huge value should cause EINVAL
-- while a correct value of 4 should give ENOPROTOOPT or success.
print("")
print("-- arg5 test --")
if fd >= 0 then
    local abuf = memory.alloc(16)
    wd(N(abuf), 1)
    -- With optlen=4 (correct)
    local ok_a1, rv_a1 = pcall(function()
        return mk(105)(uint64(fd), uint64(0xFFFF), uint64(4), abuf, uint64(4))
    end)
    print(string.format("SO_REUSEADDR(len=4)=%d", ok_a1 and N(rv_a1) or -999))

    -- With optlen=0 (should fail differently if arg5 IS passed)
    local ok_a2, rv_a2 = pcall(function()
        return mk(105)(uint64(fd), uint64(0xFFFF), uint64(4), abuf, uint64(0))
    end)
    print(string.format("SO_REUSEADDR(len=0)=%d", ok_a2 and N(rv_a2) or -999))

    -- With optlen=0x10000 (huge)
    local ok_a3, rv_a3 = pcall(function()
        return mk(105)(uint64(fd), uint64(0xFFFF), uint64(4), abuf, uint64(0x10000))
    end)
    print(string.format("SO_REUSEADDR(len=64K)=%d", ok_a3 and N(rv_a3) or -999))

    -- Without arg5 at all (3 args only)
    local ok_a4, rv_a4 = pcall(function()
        return mk(105)(uint64(fd), uint64(0xFFFF), uint64(4))
    end)
    print(string.format("SO_REUSEADDR(noarg5)=%d", ok_a4 and N(rv_a4) or -999))

    pcall(function() mk(6)(uint64(fd)) end)
end

-- PART 5: check if prior probes' setsockopt used a different mechanism
-- Try directly using the pipe's __call with setsockopt syscall_no
print("")
print("-- pipe-based setsockopt --")
local fd2_ok, fd2_rv = pcall(function()
    return mk(97)(uint64(2), uint64(1), uint64(0))
end)
local fd2 = fd2_ok and N(fd2_rv) or -1
print(string.format("fd2=%d", fd2))
if fd2 >= 0 then
    local pbuf = memory.alloc(16)
    wd(N(pbuf), 1)
    -- Using the pipe object directly but with setsockopt number
    local pipe_copy = {}
    for k, v in pairs(syscall.pipe) do pipe_copy[k] = v end
    pipe_copy.syscall_no = 105
    setmetatable(pipe_copy, getmetatable(syscall.pipe))
    local ok_p, rv_p = pcall(function()
        return pipe_copy(uint64(fd2), uint64(0xFFFF), uint64(4), uint64(N(pbuf)), uint64(4))
    end)
    print(string.format("pipe105_SO_REUSEADDR=%d", ok_p and N(rv_p) or -999))
    pcall(function() mk(6)(uint64(fd2)) end)
end

print("")
print("canary=" .. (N(native.fcall_with_rax(stub, 20)) == pid_val and "OK" or "FAIL"))
print("=== 396g COMPLETE ===")
