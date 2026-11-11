-- CRASH_CLASS: MODERATE -- blockpool descriptors are opened write-only (653 passes f_flag = our
-- flags | 2, i.e. FWRITE with no FREAD), so the write path is legal driver traffic and the read
-- path returns EBADF before reaching the driver. Writes are 0x40 bytes of a recognisable pattern
-- into a 0x410b0-byte object; a corrupted pool can only cost a relaunch.
-- PROBE 1399a: the blockpool descriptor as a device -- read, write, lseek, ioctl and mmap.
--
-- 1396a/1397a left three facts: blockpool_open (653) mints descriptors 22/23/902 for flags
-- 0/0x100000/0x400000; fstat on them succeeds with rdev 0xB000 and mode 0; and read returns EBADF
-- while ioctl on the three standard FreeBSD commands returns ENOTTY. EBADF from read is the
-- signature of the fd's f_flag: FreeBSD's FREAD is 0x1 and FWRITE is 0x2, and 653 does
-- `or r15d, 2` before falloc, so every descriptor it mints is WRITE-ONLY. read never reaches the
-- driver; ioctl does (ENOTTY is the driver's own default case, not the kernel's).
--
-- So the two paths nobody has walked are write() and the non-standard ioctl space. That matters
-- because 653's object is 0x410b0 bytes long, it is linked into the global list at RVA 0x3ba5e88,
-- and its +0x30/+0x38/+0x40 fields are filled from a region manager (0x3c3920 / 0x3c3640 /
-- 0x3c36b0) - i.e. it is a memory-pool object, not an opaque handle. A write that lands in that
-- object is a write into kernel memory with a caller-controlled length and offset, which is the
-- primitive this project has never had.
--
-- The ioctl sweep is deliberately narrow: the standard FreeBSD commands are known to return ENOTTY,
-- so the sweep walks the whole 14-bit size field for the low command byte range that Sony's own
-- drivers use (0x8000_0000 direction encodings over type bytes 0x67 'g' and 0x62 'b'), and prints
-- anything that is not ENOTTY. A driver that answers 0 or EINVAL for a real command names itself.
--
-- -- prior art:
--   results/phase36_realargs/1396a_blockpool_open_20261109_142118.txt (descriptors, EBADF/,ENOTTY)
--   results/phase36_realargs/1397a_blockpool_map_probe_20261109_142241.txt (rdev 0xB000, mmap EINVAL)
--   results/kernel_handlers/asm/sys_653_deep.asm (the open body, `or r15d, 2`, kmalloc 0x410b0)
--   docs/DEVICE_IOCTL_14_10.md (the /dev node ioctl sweep, for the command encoding used there)

print("=== PROBE 1399a: BLOCKPOOL DESCRIPTOR AS A DEVICE ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hex(v) v = N(v) % 4294967296 return string.format("%08X", v) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end
print("[0] SIG_IGN installed")

local buf = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do pcall(function() memory.write_dword(buf + i, uint64(0x4B424C50)) end) end

-- ---------------------------------------------------------------- A
print("")
print("[A] open three pools")
local FDS = {}
for _, f in ipairs({0, 0x100000, 0x400000}) do
    local rv = N(mk(653)(uint64(f), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
    if rv >= 3 and rv < 4096 then FDS[#FDS + 1] = {rv, f} end
    print(string.format("   653(0x%X) -> %d %s", f, rv, es()))
end

-- ---------------------------------------------------------------- B
print("")
print("[B] read / write / lseek on every descriptor")
for _, e in ipairs(FDS) do
    local fd, fl = e[1], e[2]
    local rrv = N(mk(3)(uint64(fd), uint64(buf), uint64(0x40), uint64(0), uint64(0), uint64(0)))
    print(string.format("   fd=%d(0x%X) read(0x40)  -> %d %s", fd, fl, rrv, es()))

    local wrv = N(mk(4)(uint64(fd), uint64(buf), uint64(0x40), uint64(0), uint64(0), uint64(0)))
    print(string.format("   fd=%d(0x%X) write(0x40) -> %d %s", fd, fl, wrv, es()))

    local lrv = N(mk(199)(uint64(fd), uint64(0), uint64(1), uint64(0), uint64(0), uint64(0)))
    print(string.format("   fd=%d(0x%X) lseek(0,SEEK_CUR) -> %d %s", fd, fl, lrv, es()))

    for _, prot in ipairs({2, 3}) do
        local mrv = N(mk(477)(uint64(0), uint64(0x10000), uint64(prot), uint64(1), uint64(fd), uint64(0)))
        print(string.format("   fd=%d(0x%X) mmap(0x10000,prot=0x%X,SHARED) -> %d %s", fd, fl, prot, mrv, es()))
    end
end

-- ---------------------------------------------------------------- C
print("")
print("[C] ioctl on the standard commands for every descriptor (baseline)")
if #FDS > 0 then
    for _, e in ipairs(FDS) do
        local fd = e[1]
        local rv = N(mk(54)(uint64(fd), uint64(0x4004667F), uint64(buf), uint64(0), uint64(0), uint64(0)))
        print(string.format("   fd=%d ioctl(0x4004667F) -> %d %s", fd, rv, es()))
    end
end

-- ---------------------------------------------------------------- D
print("")
print("[D] ioctl sweep: Sony encodings, print anything that is not ENOTTY(25)")
if #FDS > 0 then
    local fd = FDS[1][1]
    local anomalies, calls = 0, 0
    local DIRS = {0x40000000, 0x80000000, 0xC0000000, 0x00000000}
    local TYPES = {0x67, 0x62, 0x63, 0x00, 0x01, 0x03}
    local SIZES = {0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0100, 0x1000}
    for _, dir in ipairs(DIRS) do
        for _, ty in ipairs(TYPES) do
            for nr = 0, 0x2F do
                for _, sz in ipairs(SIZES) do
                    local cmd = dir + sz * 0x10000 + ty * 0x100 + nr
                    local ok, rv = pcall(function()
                        return N(mk(54)(uint64(fd), uint64(cmd), uint64(buf), uint64(0), uint64(0), uint64(0)))
                    end)
                    calls = calls + 1
                    if not ok then
                        print(string.format("   ioctl(0x%08X) -> EXC", cmd))
                    elseif rv ~= -1 then
                        anomalies = anomalies + 1
                        print(string.format("   ioctl(0x%08X) -> %d  %s", cmd, rv, es()))
                    else
                        local e = es()
                        if e ~= "25 Inappropriate ioctl for device" then
                            anomalies = anomalies + 1
                            print(string.format("   ioctl(0x%08X) -> -1 %s", cmd, e))
                        end
                    end
                end
            end
        end
    end
    print(string.format("   [D] calls=%d anomalies=%d", calls, anomalies))
end

-- ---------------------------------------------------------------- E
print("")
print("[E] close")
for _, e in ipairs(FDS) do
    local rv = N(mk(6)(uint64(e[1]), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
    print(string.format("   close(%d) -> %d %s", e[1], rv, es()))
end

print("")
print("=== PROBE 1399a COMPLETE ===")
