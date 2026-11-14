-- CRASH_CLASS: MODERATE -- every descriptor is opened O_NONBLOCK and the probe prints the node name
-- before each call, so a blocking driver wedges only the tail and names itself. /dev/notification0
-- is opened but NEVER read (reading it blocks the Lua thread forever).
-- PROBE 1390a: read(), fstat() and a zero-length write() on every /dev node that opens - the
-- ioctl surface was swept to exhaustion (273a-287a), but the read path never was.
--
-- The device work so far has been ioctl-only: docs/DEVICE_IOCTL_14_10.md records ~32 million calls
-- over 31 nodes with no exploitable command, and docs/DEAD_ENDS.md closes the ioctl line. The
-- mmap path is closed too (dmem0/1 read all zero, dmem2 refuses). What has never been measured is
-- the plain read() path: a driver whose read handler copies a kernel structure into the caller's
-- buffer is a far more common leak shape than an ioctl, and 25 of the 34 nodes open for read.
--
-- Each node is opened O_RDWR|O_NONBLOCK (0x4002) falling back to O_RDONLY|O_NONBLOCK (0x4000),
-- read into a 0x4000 page painted 0xAA, then fstat'd into a separate page, then written with a
-- zero-length buffer (a size argument, not a payload) so a write handler that ignores the count
-- cannot push heap bytes into a driver queue. Every buffer is scanned for kernel-band qwords by
-- comparing the high dword at +4 against 0xFF800000 - never :tonumber() a qword, that loses
-- precision above 2^53.
--
-- -- prior art:
--   docs/DEVICE_IOCTL_14_10.md (the ioctl sweep and its null result)
--   results/phase35_dead_end_reruns/1379a_dev_open_modes_20261026_*.txt (open modes per node)
--   probes/phase35_dead_end_reruns/1379a_dev_open_modes.lua (node list, the 0x4000 O_NONBLOCK flag)

print("=== PROBE 1390a: /dev READ PATH ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hex(v) v = v % 4294967296 return string.format("%08X", v) end
local function rd(a) local ok,v = pcall(function() return to_num(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end

local S_OPEN  = mk(5)
local S_CLOSE = mk(6)
local S_READ  = mk(3)
local S_WRITE = mk(4)
local S_FSTAT = mk(189)

local PID = to_num(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

-- a path buffer the open stub can read
local PB = memory.alloc(0x100)
local PA = to_num(PB)
local function setpath(p)
    pcall(function() memory.write_buffer(PB, p .. string.char(0)) end)
end

-- SIG_IGN so an absent slot answers ENOSYS instead of raising SIGSYS
local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
local ign = 0
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    local ok, rv = pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
    if ok and to_num(rv) == 0 then ign = ign + 1 end
end
print(string.format("[0] SIG_IGN installed on %d/10 signals", ign))

local RBUF = memory.alloc(0x4000)
local RA = to_num(RBUF)
local FBUF = memory.alloc(0x200)
local FA = to_num(FBUF)
local PAINT = string.rep(string.char(0xAA), 0x4000)
local PAINT_F = string.rep(string.char(0xAA), 0x200)

local function paint(b, s) pcall(function() memory.write_buffer(b, s) end) end

-- changed dwords vs the 0xAA paint, plus a kernel-band qword scan
local function inspect(base, words)
    local n, acc, kptr = 0, {}, {}
    for i = 0, words - 1 do
        local v = rd(base + i * 4)
        if v and v ~= 0xAAAAAAAA then
            n = n + 1
            if #acc < 8 then acc[#acc + 1] = hex(v) end
        end
    end
    for i = 0, (words * 4) - 8, 8 do
        local hi = rd(base + i + 4)
        if hi and hi >= 0xFF800000 then
            if #kptr < 4 then kptr[#kptr + 1] = string.format("+%X:%s", i, hex(hi)) end
        end
    end
    return n, table.concat(acc, " "), table.concat(kptr, ",")
end

local function openm(p, flags)
    setpath(p)
    local ok, rv = pcall(function() return S_OPEN(uint64(PA), uint64(flags), uint64(0)) end)
    if not ok then return nil end
    local v = to_num(rv)
    if v < 0 then return nil end
    return v
end

local NODES = {"usb", "usbctl", "ajm", "ajmi", "rng", "sce_zlib", "dmem0", "dmem1", "dmem2",
               "uvd_enc", "dipsw", "hmd_cmd", "hmd2_cmd", "bt", "gic", "gc", "dce", "camera",
               "hid", "deci_stdout"}
-- deliberately absent: notification0 (opened everywhere else, never read here)

print("")
print("[A] per node: open, read 0x4000, fstat, write(0)")
for _, name in ipairs(NODES) do
    local fd = openm("/dev/" .. name, 0x4002)
    if not fd then fd = openm("/dev/" .. name, 0x4000) end
    if not fd then
        print(string.format("%-12s SKIP (does not open)", name))
    else
        paint(RBUF, PAINT)
        print(string.format("%-12s fd=%-3d READ...", name, fd))
        local okr, rvr = pcall(function() return S_READ(uint64(fd), uint64(RA), uint64(0x4000)) end)
        local r = okr and to_num(rvr) or -99999
        if r == -99999 then print("  [FATAL] read did not return"); return end
        local n, first, kp = inspect(RA, 0x200)
        print(string.format("  read  rv=%-8d %-24s changed=%-4d %s%s", r, es(), n, first,
            kp ~= "" and (" KPTR " .. kp) or ""))

        paint(FBUF, PAINT_F)
        local okf, rvf = pcall(function() return S_FSTAT(uint64(fd), uint64(FA)) end)
        local fr = okf and to_num(rvf) or -99999
        if fr == -99999 then print("  [FATAL] fstat did not return"); return end
        local fn2, ffirst, fkp = inspect(FA, 0x40)
        print(string.format("  fstat rv=%-8d %-24s changed=%-4d %s%s", fr, es(), fn2, ffirst,
            fkp ~= "" and (" KPTR " .. fkp) or ""))

        local okw, rvw = pcall(function() return S_WRITE(uint64(fd), uint64(RA), uint64(0)) end)
        local wr = okw and to_num(rvw) or -99999
        if wr == -99999 then print("  [FATAL] write did not return"); return end
        print(string.format("  write0 rv=%-7d %s", wr, es()))

        pcall(function() return S_CLOSE(uint64(fd)) end)
    end
end

print("=== PROBE 1390a COMPLETE ===")
