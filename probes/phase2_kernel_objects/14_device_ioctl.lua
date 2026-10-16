-- 14.10 Recon Probe 14: Device ioctl fuzzing
-- PS5-specific devices are custom Sony kernel drivers — prime bug surface
-- Probe 05 showed these open: dmem0, dmem1, dmem2, gc, hid, ajm, camera
-- Strategy: open each device, try known + speculative ioctl numbers,
-- observe return values and check for info leaks in output buffers

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: DEVICE IOCTL FUZZ ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_open = 5, sc_close = 6, sc_ioctl = 54,
    sc_read = 3, sc_write = 4,
    sc_mmap = 477, sc_getpid = 20,
})

-- FreeBSD ioctl encoding: _IOC(inout, group, num, len)
-- inout: 0x20000000=IOC_OUT, 0x40000000=IOC_IN, 0x60000000=IOC_INOUT
-- group: 8 bits, num: 8 bits, len: 13 bits (shifted)
local IOC_OUT   = 0x40000000  -- kernel writes to user
local IOC_IN    = 0x80000000  -- user writes to kernel
local IOC_INOUT = 0xC0000000
local IOC_VOID  = 0x20000000

local function IOC(inout, group, num, len)
    -- _IOC(inout, group, num, len) = inout | ((len & 0x1FFF) << 16) | (group << 8) | num
    local g = group
    if type(group) == "string" then g = string.byte(group) end
    return inout + ((len % 0x2000) * 0x10000) + (g * 256) + num
end

local function IO(group, num) return IOC(IOC_VOID, group, num, 0) end
local function IOR(group, num, len) return IOC(IOC_OUT, group, num, len) end
local function IOW(group, num, len) return IOC(IOC_IN, group, num, len) end
local function IOWR(group, num, len) return IOC(IOC_INOUT, group, num, len) end

-- Devices to test
local devices = {
    "/dev/dmem0", "/dev/dmem1", "/dev/dmem2",
    "/dev/gc", "/dev/hid", "/dev/ajm", "/dev/camera",
    "/dev/dce", "/dev/dipsw", "/dev/notification0",
    "/dev/icc_configuration", "/dev/icc_power",
    "/dev/rng", "/dev/urandom",
}

-- Buffer for ioctl data (reused across calls)
local BUFSIZE = 4096
local iobuf = memory.alloc(BUFSIZE + 256)

local function try_ioctl(fd, cmd, label)
    -- Zero the buffer and fill with marker pattern
    for i = 0, BUFSIZE - 1, 8 do
        memory.write_qword(iobuf + i, 0xDEADBEEFDEADBEEF)
    end

    local ok, ret = pcall(function()
        return syscall.sc_ioctl(fd, cmd, iobuf)
    end)

    local rv = -999
    if ok then rv = ret:tonumber() end

    -- Check if kernel wrote to buffer (info leak check)
    local modified = 0
    local first_mod = -1
    local first_val = 0
    for i = 0, math.min(BUFSIZE - 8, 255), 8 do
        local lo = memory.read_dword(iobuf + i):tonumber()
        local hi = memory.read_dword(iobuf + i + 4):tonumber()
        if lo ~= 0xDEADBEEF or hi ~= 0xDEADBEEF then
            modified = modified + 1
            if first_mod < 0 then
                first_mod = i
                first_val = hi * 0x100000000 + lo
            end
        end
    end

    return rv, modified, first_mod, first_val, ok
end

-- ============================================================
-- PART 1: Open all devices and report
-- ============================================================
log("")
log("--- PART 1: opening devices ---")

local open_fds = {}
for _, path in ipairs(devices) do
    local ok, ret = pcall(function()
        return syscall.sc_open(path, 2):tonumber() -- O_RDWR=2
    end)
    local fd = -1
    if ok then fd = ret end
    if fd < 0 then
        -- Try read-only
        ok, ret = pcall(function()
            return syscall.sc_open(path, 0):tonumber() -- O_RDONLY=0
        end)
        if ok then fd = ret end
    end
    if fd >= 0 then
        open_fds[#open_fds + 1] = {path = path, fd = fd}
        log("  " .. path .. " fd=" .. fd)
    end
end
log("  opened " .. #open_fds .. "/" .. #devices)

-- ============================================================
-- PART 2: Known PS5 ioctl groups
-- Sony uses specific group bytes for their devices
-- ============================================================
log("")
log("--- PART 2: ioctl sweep per device ---")

-- Speculative ioctl commands to try on each device
-- Cover common patterns: void, read 4/8/64/256/4096 bytes
local function fuzz_device(path, fd)
    log("")
    log("  == " .. path .. " (fd=" .. fd .. ") ==")
    local hits = {}

    -- Try group letters commonly used by FreeBSD/Sony
    -- 'd' for dmem, 'G' for gc/gpu, 'H' for hid, 'A' for ajm/audio
    -- Also try the device-specific first char
    local first_char = path:match("/dev/(%a)")
    local groups = {
        string.byte("d"), string.byte("G"), string.byte("H"),
        string.byte("A"), string.byte("C"), string.byte("S"),
        string.byte("N"), string.byte("I"),
    }
    if first_char then
        -- Add uppercase and lowercase of device first letter
        groups[#groups + 1] = string.byte(first_char)
        groups[#groups + 1] = string.byte(first_char:upper())
        groups[#groups + 1] = string.byte(first_char:lower())
    end

    -- Remove duplicates
    local seen = {}
    local unique_groups = {}
    for _, g in ipairs(groups) do
        if not seen[g] then
            seen[g] = true
            unique_groups[#unique_groups + 1] = g
        end
    end

    for _, group in ipairs(unique_groups) do
        for num = 0, 31 do
            -- Try as IOR (kernel writes to us) with various sizes
            for _, sz in ipairs({0, 4, 8, 16, 32, 64, 128, 256, 1024}) do
                local cmd
                if sz == 0 then
                    cmd = IO(group, num)
                else
                    cmd = IOR(group, num, sz)
                end

                local rv, modified, first_mod, first_val, ok = try_ioctl(fd, cmd, "")

                if rv >= 0 or modified > 0 then
                    local tag = ""
                    if modified > 0 then tag = " LEAK:" .. modified .. "qw" end
                    if rv >= 0 then tag = tag .. " OK" end
                    hits[#hits + 1] = string.format(
                        "    cmd=0x%08x grp=%c num=%d sz=%d rv=%d%s",
                        cmd, group, num, sz, rv, tag)
                    if first_mod >= 0 then
                        hits[#hits + 1] = string.format(
                            "      first_mod@+%d = 0x%016x", first_mod, first_val)
                    end
                end
            end

            -- Also try IOW (we write to kernel)
            local cmd_w = IOW(group, num, 64)
            -- Fill buffer with zeros for write (safer than garbage)
            for i = 0, 63, 8 do
                memory.write_qword(iobuf + i, 0)
            end
            local wok, wret = pcall(function()
                return syscall.sc_ioctl(fd, cmd_w, iobuf)
            end)
            if wok and wret:tonumber() >= 0 then
                hits[#hits + 1] = string.format(
                    "    cmd=0x%08x grp=%c num=%d IOW(64) rv=%d ACCEPTED",
                    cmd_w, group, num, wret:tonumber())
            end
        end
    end

    if #hits > 0 then
        log("  HITS: " .. #hits)
        for _, h in ipairs(hits) do log(h) end
    else
        log("  no hits")
    end

    return hits
end

-- ============================================================
-- PART 3: Also try raw ioctl numbers (no encoding)
-- Some Sony drivers use non-standard ioctl numbering
-- ============================================================
local function fuzz_raw(path, fd)
    local hits = {}

    -- Try low numbers (some drivers use simple sequential numbers)
    for cmd = 0, 63 do
        local rv, modified = try_ioctl(fd, cmd, "")
        if rv >= 0 or modified > 0 then
            local tag = ""
            if modified > 0 then tag = " LEAK:" .. modified .. "qw" end
            hits[#hits + 1] = string.format(
                "    raw cmd=%d (0x%x) rv=%d%s", cmd, cmd, rv, tag)
        end
    end

    -- Try PS5-known ioctl ranges
    -- dmem ioctls are around 0x4008xxxx range
    for base = 0x40000000, 0xC0000000, 0x40000000 do
        for sub = 0, 0xFF, 0x10 do
            local cmd = base + sub * 0x10000
            local rv, modified = try_ioctl(fd, cmd, "")
            if rv >= 0 or modified > 0 then
                hits[#hits + 1] = string.format(
                    "    cmd=0x%08x rv=%d mod=%d", cmd, rv, modified)
            end
        end
    end

    if #hits > 0 then
        log("  RAW HITS on " .. path .. ": " .. #hits)
        for _, h in ipairs(hits) do log(h) end
    end
end

-- Run fuzzing on each open device
local total_hits = 0
for _, dev in ipairs(open_fds) do
    local hits = fuzz_device(dev.path, dev.fd)
    total_hits = total_hits + #hits
    fuzz_raw(dev.path, dev.fd)
end

-- Close all FDs
for _, dev in ipairs(open_fds) do
    pcall(function() syscall.sc_close(dev.fd) end)
end

log("")
log("total ioctl hits: " .. total_hits)
log("=== DEVICE IOCTL FUZZ DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
