-- 14.10 Recon Probe 29: IPv6 routing header + mmap attack surface
-- From probe 28:
--   IPV6_RTHDR setsockopt works
--   IPV6_RECVRTHDR is already enabled (val=1)
--   sendmsg with routing header ancillary should work
--   HBH blocked, but RTHDR may not be
-- Also: mmap/munmap races, MAP_FIXED overlaps

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: RTHDR + MMAP ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_getpid = 20,
    sc_socket = 97,
    sc_socketpair = 135,
    sc_close = 6,
    sc_read = 3,
    sc_write = 4,
    sc_sendmsg = 28,
    sc_recvmsg = 29,
    sc_sendto = 133,
    sc_recvfrom = 29,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
    sc_bind = 104,
    sc_connect = 98,
    sc_listen = 106,
    sc_accept = 30,
    sc_mmap = 477,
    sc_munmap = 73,
    sc_mprotect = 74,
    sc_minherit = 250,
    sc_madvise = 75,
    sc_msync = 226,
    sc_mlock = 203,
    sc_pipe2 = 542,
    sc_writev = 121,
    sc_readv = 120,
    sc_fcntl = 92,
})

local pid = syscall.sc_getpid():tonumber()
local PROT_READ = 1
local PROT_WRITE = 2
local MAP_PRIVATE = 2
local MAP_ANON = 0x1000
local MAP_FIXED = 0x0010

-- ============================================================
-- PART 1: IPv6 routing header via sendmsg
-- ============================================================
log("")
log("--- PART 1: IPv6 routing header ---")

local raw6_ok, raw6_ret = pcall(function()
    return syscall.sc_socket(28, 3, 0) -- AF_INET6 RAW
end)
local r6 = raw6_ok and raw6_ret:tonumber() or -1
log("  raw6: fd=" .. r6)

if r6 >= 0 then
    local optval = memory.alloc(16)
    -- Enable RTHDR receiving
    memory.write_dword(optval, 1)
    pcall(function() syscall.sc_setsockopt(r6, 41, 27, optval, 4) end) -- IPV6_RECVRTHDR

    -- Build routing header type 0 (deprecated but still parsed)
    -- struct ip6_rthdr { next_hdr(1), len(1), type(1), segleft(1) }
    -- Type 0 routing header: 8 bytes header + 16 bytes per segment
    local rthdr = memory.alloc(64)
    memory.write_byte(rthdr, 59)   -- next header = no next
    memory.write_byte(rthdr + 1, 2) -- len = 2 (24 bytes total = 8 + 16*1)
    memory.write_byte(rthdr + 2, 0) -- type = 0 (deprecated)
    memory.write_byte(rthdr + 3, 1) -- segments left = 1
    memory.write_dword(rthdr + 4, 0) -- reserved
    -- Segment: ::1
    for i = 0, 15 do memory.write_byte(rthdr + 8 + i, 0) end
    memory.write_byte(rthdr + 23, 1) -- ::1

    -- Build cmsg with IPV6_RTHDR
    local cmsg = memory.alloc(64)
    local CMSG_DATA_OFF = 16
    local rthdr_len = 24
    memory.write_dword(cmsg, CMSG_DATA_OFF + rthdr_len) -- cmsg_len
    memory.write_dword(cmsg + 4, 41)   -- IPPROTO_IPV6
    memory.write_dword(cmsg + 8, 36)   -- IPV6_RTHDR
    for i = 0, rthdr_len - 1 do
        memory.write_byte(cmsg + CMSG_DATA_OFF + i, memory.read_byte(rthdr + i):tonumber())
    end

    -- Destination: ::1
    local dst = memory.alloc(32)
    memory.write_byte(dst, 28)      -- sin6_len
    memory.write_byte(dst + 1, 28)  -- AF_INET6
    for i = 2, 27 do memory.write_byte(dst + i, 0) end
    memory.write_byte(dst + 23, 1)  -- ::1

    local payload = memory.alloc(8)
    memory.write_qword(payload, 0x4343434344444444)
    local iov = memory.alloc(16)
    memory.write_qword(iov, payload)
    memory.write_qword(iov + 8, 8)

    local mh = memory.alloc(64)
    for i = 0, 63, 8 do memory.write_qword(mh + i, 0) end
    memory.write_qword(mh, dst)
    memory.write_dword(mh + 8, 28)
    memory.write_qword(mh + 16, iov)
    memory.write_qword(mh + 24, 1)
    memory.write_qword(mh + 32, cmsg)
    memory.write_qword(mh + 40, 48) -- CMSG_SPACE(24)

    local sm_ok, sm_ret = pcall(function() return syscall.sc_sendmsg(r6, mh, 0) end)
    log("  sendmsg RTHDR type0: " .. (sm_ok and "rv=" .. sm_ret:tonumber() or "ERR"))

    -- Try type 2 (mobile IPv6)
    memory.write_byte(rthdr + 2, 2) -- type 2
    for i = 0, rthdr_len - 1 do
        memory.write_byte(cmsg + CMSG_DATA_OFF + i, memory.read_byte(rthdr + i):tonumber())
    end
    local sm2_ok, sm2_ret = pcall(function() return syscall.sc_sendmsg(r6, mh, 0) end)
    log("  sendmsg RTHDR type2: " .. (sm2_ok and "rv=" .. sm2_ret:tonumber() or "ERR"))

    -- Try dstopts
    local dsthdr = memory.alloc(16)
    memory.write_byte(dsthdr, 59)  -- next = none
    memory.write_byte(dsthdr + 1, 0) -- len=0 (8 bytes)
    memory.write_byte(dsthdr + 2, 1) -- PadN
    memory.write_byte(dsthdr + 3, 4) -- pad 4
    memory.write_dword(dsthdr + 4, 0)

    memory.write_dword(cmsg, CMSG_DATA_OFF + 8) -- cmsg_len
    memory.write_dword(cmsg + 8, 40) -- IPV6_DSTOPTS
    for i = 0, 7 do
        memory.write_byte(cmsg + CMSG_DATA_OFF + i, memory.read_byte(dsthdr + i):tonumber())
    end
    memory.write_qword(mh + 40, 32) -- CMSG_SPACE(8)

    local sd_ok, sd_ret = pcall(function() return syscall.sc_sendmsg(r6, mh, 0) end)
    log("  sendmsg DSTOPTS: " .. (sd_ok and "rv=" .. sd_ret:tonumber() or "ERR"))

    -- Try connect + sendto
    local target = memory.alloc(32)
    memory.write_byte(target, 28)
    memory.write_byte(target + 1, 28)
    for i = 2, 27 do memory.write_byte(target + i, 0) end
    memory.write_byte(target + 23, 1)

    local cn_ok, cn_ret = pcall(function() return syscall.sc_connect(r6, target, 28) end)
    log("  connect(::1): " .. (cn_ok and "rv=" .. cn_ret:tonumber() or "ERR"))

    local st_ok, st_ret = pcall(function()
        return syscall.sc_sendto(r6, payload, 8, 0, target, 28)
    end)
    log("  sendto(::1): " .. (st_ok and "rv=" .. st_ret:tonumber() or "ERR"))

    -- Bind to :: port 0
    local baddr = memory.alloc(32)
    memory.write_byte(baddr, 28)
    memory.write_byte(baddr + 1, 28)
    for i = 2, 27 do memory.write_byte(baddr + i, 0) end

    local bn_ok, bn_ret = pcall(function() return syscall.sc_bind(r6, baddr, 28) end)
    log("  bind(::): " .. (bn_ok and "rv=" .. bn_ret:tonumber() or "ERR"))

    pcall(function() syscall.sc_close(r6) end)
end

-- ============================================================
-- PART 2: mmap attack surface
-- ============================================================
log("")
log("--- PART 2: mmap surface ---")

-- Test MAP_FIXED overlapping allocations
local page1_ok, page1 = pcall(function()
    return syscall.sc_mmap(0x40000000, 4096, PROT_READ + PROT_WRITE,
        MAP_PRIVATE + MAP_ANON + MAP_FIXED, -1, 0)
end)
log("  MAP_FIXED 0x40000000: " ..
    (page1_ok and string.format("0x%x", page1:tonumber()) or "ERR"))

if page1_ok and page1:tonumber() > 0 then
    -- Write pattern
    memory.write_dword(page1, 0xDEAD1111)

    -- MAP_FIXED same address again — replaces the mapping
    local page2_ok, page2 = pcall(function()
        return syscall.sc_mmap(0x40000000, 4096, PROT_READ + PROT_WRITE,
            MAP_PRIVATE + MAP_ANON + MAP_FIXED, -1, 0)
    end)
    log("  remap same addr: " ..
        (page2_ok and string.format("0x%x", page2:tonumber()) or "ERR"))

    if page2_ok then
        local val = memory.read_dword(page2):tonumber()
        log(string.format("  after remap: 0x%08x (0=fresh, DEAD1111=stale)", val))
    end

    -- MAP_FIXED overlapping (half-page overlap)
    local page3_ok, page3 = pcall(function()
        return syscall.sc_mmap(0x40000800, 4096, PROT_READ + PROT_WRITE,
            MAP_PRIVATE + MAP_ANON + MAP_FIXED, -1, 0)
    end)
    log("  MAP_FIXED 0x40000800: " ..
        (page3_ok and string.format("0x%x", page3:tonumber()) or "ERR"))

    pcall(function() syscall.sc_munmap(page1, 4096) end)
    pcall(function() syscall.sc_munmap(page3, 4096) end)
end

-- munmap then read (UAF test)
local uaf_ok, uaf_ptr = pcall(function()
    return syscall.sc_mmap(0, 8192, PROT_READ + PROT_WRITE,
        MAP_PRIVATE + MAP_ANON, -1, 0)
end)
if uaf_ok then
    local uaf_addr = uaf_ptr:tonumber()
    log(string.format("  UAF test page: 0x%x", uaf_addr))
    memory.write_dword(uaf_ptr, 0xBEEF2222)

    -- Unmap
    pcall(function() syscall.sc_munmap(uaf_ptr, 8192) end)

    -- Try to read after unmap
    local uaf_rd_ok, uaf_val = pcall(function()
        return memory.read_dword(uaf_ptr):tonumber()
    end)
    log("  read after munmap: " ..
        (uaf_rd_ok and string.format("0x%08x", uaf_val) or "SIGSEGV"))
end

-- madvise
local madv_ok, madv_ptr = pcall(function()
    return syscall.sc_mmap(0, 4096, PROT_READ + PROT_WRITE,
        MAP_PRIVATE + MAP_ANON, -1, 0)
end)
if madv_ok then
    memory.write_dword(madv_ptr, 0xAAAA3333)

    -- MADV_FREE (5) — mark as freeable
    local mf_ok, mf_ret = pcall(function()
        return syscall.sc_madvise(madv_ptr, 4096, 5)
    end)
    log("  madvise(FREE): " .. (mf_ok and "rv=" .. mf_ret:tonumber() or "ERR"))

    -- Check if data still there
    local mf_val = memory.read_dword(madv_ptr):tonumber()
    log(string.format("  after MADV_FREE: 0x%08x", mf_val))

    -- MADV_DONTNEED (4) — hint to release pages
    local md_ok, md_ret = pcall(function()
        return syscall.sc_madvise(madv_ptr, 4096, 4)
    end)
    log("  madvise(DONTNEED): " .. (md_ok and "rv=" .. md_ret:tonumber() or "ERR"))

    local md_val = memory.read_dword(madv_ptr):tonumber()
    log(string.format("  after DONTNEED: 0x%08x (0=page reclaimed)", md_val))

    pcall(function() syscall.sc_munmap(madv_ptr, 4096) end)
end

-- minherit
local mi_ok, mi_ptr = pcall(function()
    return syscall.sc_mmap(0, 4096, PROT_READ + PROT_WRITE,
        MAP_PRIVATE + MAP_ANON, -1, 0)
end)
if mi_ok then
    -- INHERIT_SHARE=0, INHERIT_COPY=1, INHERIT_NONE=2, INHERIT_ZERO=3
    for inherit = 0, 3 do
        local ih_ok, ih_ret = pcall(function()
            return syscall.sc_minherit(mi_ptr, 4096, inherit)
        end)
        log("  minherit(" .. inherit .. "): " ..
            (ih_ok and "rv=" .. ih_ret:tonumber() or "ERR"))
    end
    pcall(function() syscall.sc_munmap(mi_ptr, 4096) end)
end

-- ============================================================
-- PART 3: writev/readv with many iovecs
-- ============================================================
log("")
log("--- PART 3: writev/readv ---")

local sp = memory.alloc(8)
pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local wa = memory.read_dword(sp):tonumber()
local wb = memory.read_dword(sp + 4):tonumber()

-- Build 16 iovecs
local N_IOV = 16
local iovecs = memory.alloc(N_IOV * 16)
local total_write = 0
for i = 0, N_IOV - 1 do
    local buf = memory.alloc(64)
    for j = 0, 63, 4 do memory.write_dword(buf + j, 0x50000000 + i * 64 + j) end
    memory.write_qword(iovecs + i * 16, buf)
    memory.write_qword(iovecs + i * 16 + 8, 64)
    total_write = total_write + 64
end

local wv_ok, wv_ret = pcall(function()
    return syscall.sc_writev(wa, iovecs, N_IOV)
end)
log(string.format("  writev %d iovecs: %s",
    N_IOV, wv_ok and "rv=" .. wv_ret:tonumber() or "ERR"))

-- readv on the other end
local rd_iovecs = memory.alloc(N_IOV * 16)
for i = 0, N_IOV - 1 do
    local buf = memory.alloc(64)
    memory.write_qword(rd_iovecs + i * 16, buf)
    memory.write_qword(rd_iovecs + i * 16 + 8, 64)
end

local rv_ok, rv_ret = pcall(function()
    return syscall.sc_readv(wb, rd_iovecs, N_IOV)
end)
log(string.format("  readv %d iovecs: %s",
    N_IOV, rv_ok and "rv=" .. rv_ret:tonumber() or "ERR"))

-- writev with IOV_MAX+ iovecs (should fail with EINVAL)
local huge_iov = memory.alloc(2048 * 16)
local hbuf = memory.alloc(8)
for i = 0, 2047 do
    memory.write_qword(huge_iov + i * 16, hbuf)
    memory.write_qword(huge_iov + i * 16 + 8, 1)
end
local hv_ok, hv_ret = pcall(function()
    return syscall.sc_writev(wa, huge_iov, 2048)
end)
log(string.format("  writev 2048 iovecs: %s",
    hv_ok and "rv=" .. hv_ret:tonumber() or "ERR"))

-- writev with 0-length iov
local zero_iov = memory.alloc(16)
memory.write_qword(zero_iov, hbuf)
memory.write_qword(zero_iov + 8, 0) -- len=0
local zv_ok, zv_ret = pcall(function()
    return syscall.sc_writev(wa, zero_iov, 1)
end)
log("  writev 0-len: " .. (zv_ok and "rv=" .. zv_ret:tonumber() or "ERR"))

pcall(function() syscall.sc_close(wa) end)
pcall(function() syscall.sc_close(wb) end)

-- ============================================================
-- PART 4: fcntl deep probe
-- ============================================================
log("")
log("--- PART 4: fcntl ---")

local fsp = memory.alloc(8)
pcall(function() syscall.sc_socketpair(1, 1, 0, fsp) end)
local ffd = memory.read_dword(fsp):tonumber()

-- F_GETFL=3, F_SETFL=4, F_GETFD=1, F_SETFD=2
-- F_DUPFD=0, F_GETLK=11, F_SETLK=12
-- F_SETOWN=6, F_GETOWN=5
-- F_OGETLK=7, F_OSETLK=8
-- F_READAHEAD=15, F_RDAHEAD=16
-- F_ADD_SEALS=19, F_GET_SEALS=20

local fcntl_cmds = {
    {0, 0, "F_DUPFD"},
    {1, 0, "F_GETFD"},
    {2, 1, "F_SETFD(CLOEXEC)"},
    {3, 0, "F_GETFL"},
    {4, 0x0004, "F_SETFL(O_NONBLOCK)"},
    {5, 0, "F_GETOWN"},
    {6, pid, "F_SETOWN(self)"},
    {11, 0, "F_GETLK"},
    {15, 0, "F_READAHEAD"},
    {16, 1, "F_RDAHEAD"},
    {20, 0, "F_GET_SEALS"},
}

for _, cmd in ipairs(fcntl_cmds) do
    local fc_ok, fc_ret = pcall(function()
        return syscall.sc_fcntl(ffd, cmd[1], cmd[2])
    end)
    log(string.format("  %-20s %s", cmd[3],
        fc_ok and "rv=" .. fc_ret:tonumber() or "ERR"))
end

pcall(function() syscall.sc_close(ffd) end)
pcall(function() syscall.sc_close(memory.read_dword(fsp + 4):tonumber()) end)

log("")
log("=== RTHDR+MMAP DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
