-- 14.10 Recon Probe 15: Deep dmem/gc/dce ioctl probing
-- Focus on known PS5 device ioctl structures
-- dmem: direct memory allocator (GPU visible memory)
-- gc: GPU command submission
-- dce: display controller engine
-- These are the most complex Sony kernel drivers with the largest attack surface

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: DEVICE DEEP DIVE ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_open = 5, sc_close = 6, sc_ioctl = 54,
    sc_mmap = 477, sc_munmap = 73, sc_getpid = 20,
})

-- Open key devices
local function dev_open(path)
    local ok, ret = pcall(function() return syscall.sc_open(path, 2):tonumber() end)
    if ok and ret >= 0 then return ret end
    ok, ret = pcall(function() return syscall.sc_open(path, 0):tonumber() end)
    if ok and ret >= 0 then return ret end
    return -1
end

local dmem_fd = dev_open("/dev/dmem0")
local gc_fd = dev_open("/dev/gc")
local dce_fd = dev_open("/dev/dce")
local ajm_fd = dev_open("/dev/ajm")
local hid_fd = dev_open("/dev/hid")
local dipsw_fd = dev_open("/dev/dipsw")

log("dmem0=" .. dmem_fd .. " gc=" .. gc_fd .. " dce=" .. dce_fd ..
    " ajm=" .. ajm_fd .. " hid=" .. hid_fd .. " dipsw=" .. dipsw_fd)

local buf = memory.alloc(8192)

local function do_ioctl(fd, cmd, size)
    -- Zero buffer
    for i = 0, math.min(size, 4096) - 1, 8 do
        memory.write_qword(buf + i, 0)
    end
    local ok, ret = pcall(function()
        return syscall.sc_ioctl(fd, cmd, buf)
    end)
    if ok then return ret:tonumber() else return -999 end
end

local function do_ioctl_check(fd, cmd, size, label)
    -- Fill with marker
    for i = 0, math.min(size, 4096) - 1, 8 do
        memory.write_qword(buf + i, 0)
    end
    local ok, ret = pcall(function()
        return syscall.sc_ioctl(fd, cmd, buf)
    end)
    local rv = ok and ret:tonumber() or -999

    -- Read back first 64 bytes
    local vals = {}
    for i = 0, math.min(63, size - 1), 8 do
        local lo = memory.read_dword(buf + i):tonumber()
        local hi = memory.read_dword(buf + i + 4):tonumber()
        if lo ~= 0 or hi ~= 0 then
            vals[#vals + 1] = string.format("+%d:0x%08x%08x", i, hi, lo)
        end
    end

    local data = ""
    if #vals > 0 then data = " [" .. table.concat(vals, " ") .. "]" end
    log(string.format("  %-40s rv=%d%s", label, rv, data))
    return rv
end

-- ============================================================
-- PART 1: dmem0 — known ioctl numbers from PS5 SDK/homebrew
-- dmem ioctls use _IOWR('d', N, struct) pattern
-- Known commands from PS5 homebrew scene:
-- ============================================================
log("")
log("--- PART 1: dmem0 known ioctls ---")

if dmem_fd >= 0 then
    -- DMEM_ALLOC: allocate direct memory
    -- From homebrew: ioctl(fd, DMEM_ALLOC_CMD, &args)
    -- Try various command encodings
    -- Known: 0xC0184401 = _IOWR('D', 1, 24) — dmem alloc
    -- Also: 0xC0184402 = _IOWR('D', 2, 24) — dmem query

    -- Try Sony's known ioctl group 'D' (0x44)
    for num = 0, 15 do
        for _, sz in ipairs({8, 16, 24, 32, 48, 64, 128, 256}) do
            local cmd = 0xC0004400 + num + (sz * 0x10000) -- IOWR('D', num, sz)
            local rv = do_ioctl(dmem_fd, cmd, sz)
            if rv >= 0 then
                log(string.format("  IOWR('D',%d,%d) = 0x%08x: rv=%d *** SUCCESS ***", num, sz, cmd, rv))
            elseif rv ~= -999 then
                -- Check if it was processed (not just ENOTTY)
                -- EINVAL=22 means it was processed, ENOTTY=25 means unknown
                local errno = memory.read_dword(buf):tonumber()
            end
        end
    end

    -- Try specific known PS5 dmem ioctls
    -- sceKernelAllocateDirectMemory -> ioctl on dmem
    -- The ioctl cmd format on PS5: lower 16 bits = command, upper = flags/size
    -- Try sequential raw commands
    log("")
    log("  raw sequential scan 0-255...")
    for cmd = 0, 255 do
        local rv = do_ioctl(dmem_fd, cmd, 256)
        if rv >= 0 then
            log(string.format("    cmd=%d (0x%x): rv=%d SUCCESS", cmd, cmd, rv))
        end
    end

    -- dmem mmap test: can we mmap the dmem device?
    log("")
    log("  mmap test on dmem0...")
    local mmap_ok, mmap_ret = pcall(function()
        return syscall.sc_mmap(0, 0x4000, 3, 1, dmem_fd, 0)
    end)
    if mmap_ok then
        local addr = mmap_ret:tonumber()
        if addr ~= 0 and addr ~= 0xFFFFFFFFFFFFFFFF then
            log("    mmap SUCCESS at " .. string.format("0x%x", addr))
            -- Read first bytes
            local v0 = memory.read_qword(addr):tonumber()
            local v1 = memory.read_qword(addr + 8):tonumber()
            log(string.format("    data: 0x%016x 0x%016x", v0, v1))
            pcall(function() syscall.sc_munmap(addr, 0x4000) end)
        else
            log("    mmap returned " .. string.format("0x%x", addr))
        end
    else
        log("    mmap failed: " .. tostring(mmap_ret):sub(1, 40))
    end
end

-- ============================================================
-- PART 2: dipsw — DIP switch device (security config)
-- Often has simple read ioctls that return system flags
-- ============================================================
log("")
log("--- PART 2: dipsw ---")

if dipsw_fd >= 0 then
    -- dipsw typically uses read()/ioctl() to return flag bits
    -- Try reading from it
    local read_buf = memory.alloc(256)
    local rok, rret = pcall(function()
        return syscall.sc_read(dipsw_fd, read_buf, 256)
    end)
    if rok then
        local nbytes = rret:tonumber()
        log("  read() returned " .. nbytes .. " bytes")
        if nbytes > 0 then
            local hex = {}
            for i = 0, math.min(nbytes - 1, 31) do
                hex[#hex + 1] = string.format("%02x", memory.read_byte(read_buf + i):tonumber())
            end
            log("    data: " .. table.concat(hex, " "))
        end
    else
        log("  read() failed: " .. tostring(rret):sub(1, 40))
    end

    -- Scan ioctls: dipsw might use group 'S' (security) or 'D'
    for _, group in ipairs({0x53, 0x44, 0x64, 0x73}) do -- S, D, d, s
        for num = 0, 31 do
            local cmd = 0x40000000 + (4 * 0x10000) + (group * 256) + num -- IOR(g,n,4)
            do_ioctl_check(dipsw_fd, cmd, 256,
                string.format("IOR('%c',%d,4)", group, num))
        end
    end
end

-- ============================================================
-- PART 3: gc (GPU) — command submission / info queries
-- ============================================================
log("")
log("--- PART 3: gc (GPU) ---")

if gc_fd >= 0 then
    -- GC likely has info query ioctls
    -- Try reading
    local gc_read = memory.alloc(256)
    local grok, grret = pcall(function()
        return syscall.sc_read(gc_fd, gc_read, 256)
    end)
    log("  read(): " .. (grok and tostring(grret:tonumber()) or "FAIL"))

    -- Try known GPU ioctl patterns
    -- Group 'G' (0x47) or 'g' (0x67)
    for _, group in ipairs({0x47, 0x67}) do
        for num = 0, 15 do
            -- IOR: kernel writes back to us (info queries)
            local cmd_r = 0x40000000 + (256 * 0x10000) + (group * 256) + num
            do_ioctl_check(gc_fd, cmd_r, 256,
                string.format("IOR('%c',%d,256)", group, num))
        end
    end

    -- mmap test
    log("")
    log("  mmap test on gc...")
    local gc_mmap_ok, gc_mmap_ret = pcall(function()
        return syscall.sc_mmap(0, 0x4000, 3, 1, gc_fd, 0)
    end)
    if gc_mmap_ok then
        local addr = gc_mmap_ret:tonumber()
        if addr ~= 0 and addr ~= 0xFFFFFFFFFFFFFFFF then
            log("    mmap SUCCESS at " .. string.format("0x%x", addr))
            local v0 = memory.read_qword(addr):tonumber()
            log(string.format("    first qword: 0x%016x", v0))
            pcall(function() syscall.sc_munmap(addr, 0x4000) end)
        else
            log("    mmap returned " .. string.format("0x%x", addr))
        end
    else
        log("    mmap failed")
    end
end

-- ============================================================
-- PART 4: dce (display controller)
-- ============================================================
log("")
log("--- PART 4: dce ---")

if dce_fd >= 0 then
    for _, group in ipairs({0x44, 0x64, 0x45}) do -- D, d, E
        for num = 0, 15 do
            local cmd_r = 0x40000000 + (64 * 0x10000) + (group * 256) + num
            do_ioctl_check(dce_fd, cmd_r, 256,
                string.format("IOR('%c',%d,64)", group, num))
        end
    end
end

-- ============================================================
-- PART 5: notification0 — might expose system events
-- ============================================================
log("")
log("--- PART 5: notification0 ---")

local notif_fd = dev_open("/dev/notification0")
if notif_fd >= 0 then
    log("  fd=" .. notif_fd)

    -- Read test
    local nread_buf = memory.alloc(4096)
    local nrok, nrret = pcall(function()
        return syscall.sc_read(notif_fd, nread_buf, 4096)
    end)
    log("  read(): " .. (nrok and tostring(nrret:tonumber()) or "FAIL"))

    -- Ioctl scan: 'N' group
    for num = 0, 15 do
        local cmd = 0x40000000 + (256 * 0x10000) + (0x4E * 256) + num -- IOR('N',n,256)
        do_ioctl_check(notif_fd, cmd, 256,
            string.format("IOR('N',%d,256)", num))
    end

    pcall(function() syscall.sc_close(notif_fd) end)
end

-- ============================================================
-- PART 6: Try the PS5-specific ioctl encoding
-- PS5 uses some non-standard ioctl encoding for certain drivers
-- Specifically: upper 16 bits encode the driver/function ID
-- Try scanning with known PS5 driver IDs
-- ============================================================
log("")
log("--- PART 6: PS5-specific ioctl scan ---")

-- PS5 known driver ioctl bases (from reverse engineering)
local ps5_bases = {
    {0xC0184401, "sceKernelAllocateDirectMemory"},
    {0xC0184402, "sceKernelMapDirectMemory?"},
    {0x80084403, "sceKernelGetDirectMemorySize?"},
    {0xC0284404, "sceKernelAllocateMainDirectMemory?"},
    {0xC0104405, "sceKernelBatchMap?"},
    {0x40084406, "sceKernelCheckedReleaseDirectMemory?"},
    {0xC0104407, "sceKernelDirectMemoryQuery?"},
    {0x40044408, "sceKernelAvailableDirectMemory?"},
}

if dmem_fd >= 0 then
    for _, spec in ipairs(ps5_bases) do
        local cmd = spec[1]
        local name = spec[2]
        -- Extract size from ioctl encoding
        local encoded_sz = math.floor(cmd / 0x10000) % 0x2000
        do_ioctl_check(dmem_fd, cmd, math.max(encoded_sz, 64), name)
    end
end

-- Also try on gc
if gc_fd >= 0 then
    local gc_cmds = {
        {0xC0104700, "gc submit?"},
        {0x40084701, "gc query?"},
        {0xC0204702, "gc map?"},
        {0x80104703, "gc info?"},
    }
    for _, spec in ipairs(gc_cmds) do
        do_ioctl_check(gc_fd, spec[1], 256, spec[2])
    end
end

-- Close all
for _, fd in ipairs({dmem_fd, gc_fd, dce_fd, ajm_fd, hid_fd, dipsw_fd}) do
    if fd >= 0 then pcall(function() syscall.sc_close(fd) end) end
end

log("")
log("=== DEVICE DEEP DIVE DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
