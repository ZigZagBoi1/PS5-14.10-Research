-- CRASH_CLASS: MODERATE
-- PROBE 43n: /dev/hid + ioctl via make_syscall
--
-- Context: Probe 42c showed /dev/hid opens successfully (fd=24).
-- ioctl is "blocked" via syscall.resolve() but UNTESTED via make_syscall().
-- The HID (Human Interface Device) driver on PS5 manages controller/gamepad
-- input. HID ioctls typically expose device descriptors, report buffers,
-- and internal state. If ioctl works via make_syscall, we can interact with
-- the HID driver's kernel state, potentially leaking kernel addresses or
-- gaining a kernel write primitive.

print("=== PROBE 43n: /dev/hid + IOCTL VIA MAKE_SYSCALL ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end

local pid = to_num(syscall.getpid())
print("pid: " .. pid)

local sc_open = make_syscall(5)
local sc_ioctl = make_syscall(54)
local sc_read = make_syscall(3)
local sc_close = make_syscall(6)
local sc_fstat = make_syscall(189)

-- === STEP 1: Open /dev/hid ===
print("--- STEP 1: Open /dev/hid ---")
local path_buf = memory.alloc(64)
local path = "/dev/hid"
for i = 1, #path do
    pcall(function() memory.write_byte(path_buf + i - 1, path:byte(i)) end)
end
pcall(function() memory.write_byte(path_buf + #path, 0) end)

local ok_open, hid_fd = pcall(function()
    return sc_open(uint64(path_buf), uint64(0), uint64(0),  -- O_RDONLY
        uint64(0), uint64(0), uint64(0))
end)

if not ok_open then
    print("  /dev/hid open CRASHED")
    print("=== PROBE 43n ABORTED ===")
    return
end

local fd = to_num(hid_fd)
print(string.format("  /dev/hid fd=%d", fd))
if fd < 0 then
    print("  open failed, trying O_RDWR...")
    ok_open, hid_fd = pcall(function()
        return sc_open(uint64(path_buf), uint64(2), uint64(0),
            uint64(0), uint64(0), uint64(0))
    end)
    fd = ok_open and to_num(hid_fd) or -1
    print(string.format("  /dev/hid O_RDWR fd=%d", fd))
end

if fd < 0 then
    print("  cannot open /dev/hid")
    print("=== PROBE 43n ABORTED ===")
    return
end

-- === STEP 2: fstat the device ===
print("")
print("--- STEP 2: fstat(/dev/hid) ---")
local stat_buf = memory.alloc(256)
local ok_fstat, ret_fstat = pcall(function()
    return sc_fstat(uint64(fd), uint64(stat_buf), uint64(0),
        uint64(0), uint64(0), uint64(0))
end)
if ok_fstat then
    print(string.format("  fstat ret=%d", to_num(ret_fstat)))
    for off = 0, 127, 8 do
        local val = safe_rq(stat_buf + off)
        if val then
            local h, l = get_hi_lo(val)
            if h ~= 0 or l ~= 0 then
                local tag = ""
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then tag = " KPTR!" end
                print(string.format("  +%03X: %08X_%08X%s", off, h, l, tag))
            end
        end
    end
end

-- === STEP 3: Try ioctl via make_syscall ===
print("")
print("--- STEP 3: ioctl via make_syscall ---")

-- FreeBSD ioctl encoding: _IOC(dir, group, num, len)
-- dir: 0x40=write, 0x80=read, 0xC0=read+write
-- Common HID ioctls:
-- USB_GET_REPORT_DESC = _IOR('U', 21, struct usb_gen_descriptor)
-- USB_GET_REPORT_ID = _IOR('U', 23, int)
-- HIDIOCGRDESCSIZE = _IOR('H', 0x01, int)
-- HIDIOCGRDESC = _IOR('H', 0x02, struct hidraw_report_descriptor)

-- Build ioctl codes
-- _IOR(g, n, len) = 0x80000000 | (len << 16) | (g << 8) | n
local function make_ior(group, num, len)
    return 0x80000000 + (len * 0x10000) + (group * 0x100) + num
end
local function make_iow(group, num, len)
    return 0x40000000 + (len * 0x10000) + (group * 0x100) + num
end
local function make_iowr(group, num, len)
    return 0xC0000000 + (len * 0x10000) + (group * 0x100) + num
end

local ioctls = {
    -- HID ioctls (group 'H' = 0x48)
    {make_ior(0x48, 0x01, 4), "HIDIOCGRDESCSIZE", 4},
    {make_ior(0x48, 0x02, 256), "HIDIOCGRDESC", 256},
    {make_ior(0x48, 0x03, 4), "HIDIOCGRAWINFO", 4},
    {make_ior(0x48, 0x04, 256), "HIDIOCGRAWNAME", 256},
    {make_ior(0x48, 0x05, 256), "HIDIOCGRAWPHYS", 256},
    {make_ior(0x48, 0x06, 64), "HIDIOCGFEATURE", 64},
    {make_iow(0x48, 0x07, 64), "HIDIOCSFEATURE", 64},
    {make_ior(0x48, 0x08, 256), "HIDIOCGRAWUNIQ", 256},

    -- USB ioctls (group 'U' = 0x55)
    {make_ior(0x55, 21, 32), "USB_GET_REPORT_DESC", 32},
    {make_ior(0x55, 23, 4), "USB_GET_REPORT_ID", 4},
    {make_ior(0x55, 24, 4), "USB_GET_DEVICEINFO", 4},
    {make_ior(0x55, 100, 4), "USB_DEVICEENUMERATE", 4},

    -- Generic device ioctls
    {0x20006601, "FIONREAD", 4},
    {0x8004667E, "FIONBIO", 4},

    -- Try some plain numbers
    {0, "ioctl(0)", 4},
    {1, "ioctl(1)", 4},
    {2, "ioctl(2)", 4},
}

local ioctl_buf = memory.alloc(512)
for _, ioc in ipairs(ioctls) do
    -- Zero the buffer
    for i = 0, math.min(ioc[3] - 1, 255) do
        pcall(function() memory.write_byte(ioctl_buf + i, 0) end)
    end

    local ok, ret = pcall(function()
        return sc_ioctl(uint64(fd), uint64(ioc[1]), uint64(ioctl_buf),
            uint64(0), uint64(0), uint64(0))
    end)

    if not ok then
        print(string.format("  %s (0x%08X): CRASH", ioc[2], ioc[1]))
    else
        local r = to_num(ret)
        local nonzero = 0
        for i = 0, math.min(ioc[3] - 1, 255) do
            local b = safe_rb(ioctl_buf + i)
            if b and b ~= 0 then nonzero = nonzero + 1 end
        end

        if r == 0 or nonzero > 0 then
            print(string.format("  %s (0x%08X): ret=%d nonzero=%d",
                ioc[2], ioc[1], r, nonzero))

            if nonzero > 0 then
                local limit = math.min(ioc[3], 64)
                for row = 0, limit - 1, 16 do
                    local hex = ""
                    local ascii = ""
                    for col = 0, 15 do
                        if row + col < ioc[3] then
                            local b = safe_rb(ioctl_buf + row + col)
                            if b then
                                hex = hex .. string.format("%02X ", b)
                                if b >= 32 and b < 127 then
                                    ascii = ascii .. string.char(b)
                                else
                                    ascii = ascii .. "."
                                end
                            else
                                hex = hex .. "?? "
                                ascii = ascii .. "?"
                            end
                        end
                    end
                    print(string.format("    +%03X: %s |%s|", row, hex, ascii))
                end

                -- Scan for kernel pointers
                for off = 0, ioc[3] - 8, 8 do
                    local val = safe_rq(ioctl_buf + off)
                    if val then
                        local h, l = get_hi_lo(val)
                        if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                            print(string.format("    KPTR at +%03X: %08X_%08X", off, h, l))
                        end
                    end
                end
            end
        else
            print(string.format("  %s (0x%08X): ret=%d", ioc[2], ioc[1], r))
        end
    end
end

-- === STEP 4: Try read() on the device ===
print("")
print("--- STEP 4: read() from /dev/hid ---")
local read_buf = memory.alloc(1024)
for i = 0, 255 do
    pcall(function() memory.write_byte(read_buf + i, 0) end)
end
local ok_read, ret_read = pcall(function()
    return sc_read(uint64(fd), uint64(read_buf), uint64(256),
        uint64(0), uint64(0), uint64(0))
end)
if not ok_read then
    print("  read: CRASH")
else
    local r = to_num(ret_read)
    print(string.format("  read ret=%d", r))
    if r > 0 then
        for row = 0, math.min(r - 1, 127), 16 do
            local hex = ""
            for col = 0, 15 do
                if row + col < r then
                    local b = safe_rb(read_buf + row + col)
                    if b then
                        hex = hex .. string.format("%02X ", b)
                    else
                        hex = hex .. "?? "
                    end
                end
            end
            print(string.format("  +%03X: %s", row, hex))
        end
    end
end

-- === STEP 5: Try other device files ===
print("")
print("--- STEP 5: Other device files ---")
local devices = {
    "/dev/null",
    "/dev/zero",
    "/dev/urandom",
    "/dev/console",
    "/dev/tty",
    "/dev/bpf",
    "/dev/bpf0",
    "/dev/crypto",
    "/dev/pf",
}

for _, dev in ipairs(devices) do
    local pbuf = memory.alloc(64)
    for i = 1, #dev do
        pcall(function() memory.write_byte(pbuf + i - 1, dev:byte(i)) end)
    end
    pcall(function() memory.write_byte(pbuf + #dev, 0) end)

    local ok, dfd = pcall(function()
        return sc_open(uint64(pbuf), uint64(0), uint64(0),
            uint64(0), uint64(0), uint64(0))
    end)

    if ok then
        local dfdn = to_num(dfd)
        if dfdn >= 0 then
            print(string.format("  %s: fd=%d  *** OPENED ***", dev, dfdn))

            -- Try ioctl on it
            local ibuf = memory.alloc(64)
            local ok2, ret2 = pcall(function()
                return sc_ioctl(uint64(dfdn), uint64(0x20006601), uint64(ibuf),
                    uint64(0), uint64(0), uint64(0))
            end)
            if ok2 then
                print(string.format("    FIONREAD: ret=%d", to_num(ret2)))
            end

            pcall(function() sc_close(uint64(dfdn)) end)
        else
            print(string.format("  %s: ret=%d", dev, dfdn))
        end
    else
        print(string.format("  %s: CRASH", dev))
    end
end

pcall(function() sc_close(uint64(fd)) end)

print("")
print("=== PROBE 43n COMPLETE ===")
