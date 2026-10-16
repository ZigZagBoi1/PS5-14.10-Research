-- 14.10 Recon Probe 04: Kernel Attack Surface
-- Only safe tests — no calling syscalls with NULL/zero args

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: KERNEL ATTACK SURFACE ===")
log("fw: " .. tostring(FW_VERSION))

syscall.resolve({
    sc_umtx_op = 557,
    sc_kqueueex = 394, sc_kqueuex = 540,
    sc_sysctl = 202,
    sc_shm_open2 = 532,
    sc_open = 5, sc_close = 6,
    sc_setsockopt = 105, sc_getsockopt = 118,
    sc_socket = 97,
    sc_mmap = 477, sc_munmap = 73, sc_mprotect = 74,
    sc_pipe = 42,
})

-- ============================================================
-- TEST 1: umtx_op operations (safe — just returns EINVAL)
-- ============================================================
log("")
log("--- TEST 1: umtx_op ---")

local scratch = memory.alloc(256)
memory.write_dword(scratch, 0)
local umtx_ops = {
    {0, "LOCK"}, {1, "UNLOCK"}, {3, "WAKE"},
    {9, "CV_SIGNAL"}, {10, "CV_BROADCAST"},
    {15, "WAIT_UINT_PRIVATE"}, {16, "WAKE_PRIVATE"},
    {17, "MUTEX_WAIT"}, {18, "MUTEX_WAKE"},
    {20, "SEM_WAKE"}, {21, "NWAKE_PRIVATE"},
    {22, "MUTEX_WAKE2"}, {24, "SEM2_WAKE"},
    {25, "SHM"}, {26, "ROBUST_LISTS"},
}

for _, t in ipairs(umtx_ops) do
    local op, name = t[1], t[2]
    local ok, err = pcall(function()
        return syscall.sc_umtx_op(scratch, op, 0, 0, 0, 0)
    end)
    if ok then
        log("  " .. name .. " (" .. op .. "): OK")
    else
        local es = tostring(err)
        if es:find("ENOSYS") then
            log("  " .. name .. " (" .. op .. "): REMOVED")
        else
            log("  " .. name .. " (" .. op .. "): EXISTS")
        end
    end
end

-- TEST 2: kqueue — skipped (crashes Lua loader, tested via resolve in probe 02)

-- ============================================================
-- TEST 3: IPv6 socket options
-- ============================================================
log("")
log("--- TEST 3: IPv6 socket options ---")

pcall(function()
    local s = syscall.sc_socket(28, 2, 0)
    local fd = s:tonumber()
    log("  IPv6 UDP socket: fd=" .. fd)

    if fd >= 0 then
        local optbuf = memory.alloc(256)
        local opts = {
            {49, "IPV6_HOPOPTS"}, {50, "IPV6_DSTOPTS"}, {51, "IPV6_RTHDR"},
            {52, "IPV6_PKTOPTIONS"}, {36, "IPV6_RECVHOPOPTS"},
            {37, "IPV6_RECVDSTOPTS"}, {38, "IPV6_RECVRTHDR"},
        }

        for _, o in ipairs(opts) do
            memory.write_dword(optbuf, 1)
            local ok2, err2 = pcall(function()
                return syscall.sc_setsockopt(fd, 41, o[1], optbuf, 4)
            end)
            local status = ok2 and "SETTABLE" or tostring(err2):sub(1,30)
            log("    " .. o[2] .. ": " .. status)
        end

        local big = memory.alloc(4096)
        for _, sz in ipairs({256, 1024, 4096}) do
            local ok2 = pcall(function()
                return syscall.sc_setsockopt(fd, 41, 49, big, sz)
            end)
            if ok2 then
                log("    HOPOPTS size=" .. sz .. ": ACCEPTED (!)")
            end
        end

        local optlen = memory.alloc(8)
        for _, o in ipairs(opts) do
            memory.write_dword(optlen, 4096)
            local ok2 = pcall(function()
                return syscall.sc_getsockopt(fd, 41, o[1], big, optlen)
            end)
            local actual = memory.read_dword(optlen):tonumber()
            if ok2 and actual > 0 then
                log("    GET " .. o[2] .. ": " .. actual .. " bytes returned")
            end
        end

        syscall.close(fd)
    end
end)

-- ============================================================
-- TEST 4: sysctl info leaks
-- ============================================================
log("")
log("--- TEST 4: sysctl info ---")

local function try_sysctl(name, mib_vals, mib_len)
    local mib = memory.alloc(mib_len * 4)
    for i, v in ipairs(mib_vals) do
        memory.write_dword(mib + (i-1)*4, v)
    end
    local oldlenp = memory.alloc(8)
    memory.write_qword(oldlenp, 0)

    pcall(function() syscall.sc_sysctl(mib, mib_len, 0, oldlenp, 0, 0) end)
    local sz = memory.read_dword(oldlenp):tonumber()
    if sz > 0 and sz < 4096 then
        local buf = memory.alloc(sz + 1)
        memory.write_qword(oldlenp, sz)
        pcall(function() syscall.sc_sysctl(mib, mib_len, buf, oldlenp, 0, 0) end)
        local chars = {}
        for i = 0, math.min(sz-1, 255) do
            local b = memory.read_byte(buf + i):tonumber()
            if b == 0 then break end
            chars[#chars+1] = string.char(b)
        end
        log("  " .. name .. " = " .. table.concat(chars))
    else
        log("  " .. name .. ": size=" .. sz)
    end
end

try_sysctl("kern.ostype", {1, 1}, 2)
try_sysctl("kern.osrelease", {1, 2}, 2)
try_sysctl("kern.version", {1, 4}, 2)
try_sysctl("kern.hostname", {1, 10}, 2)
try_sysctl("hw.machine", {6, 1}, 2)
try_sysctl("hw.model", {6, 2}, 2)
try_sysctl("hw.ncpu", {6, 3}, 2)
try_sysctl("hw.pagesize", {6, 7}, 2)
try_sysctl("kern.proc.pathname(self)", {1, 14, 12, 0xFFFFFFFF}, 4)

-- ============================================================
-- TEST 5: Device nodes
-- ============================================================
log("")
log("--- TEST 5: device access ---")

local devices = {
    "/dev/null", "/dev/zero", "/dev/urandom",
    "/dev/klog", "/dev/console",
    "/dev/dmem0", "/dev/dmem1", "/dev/dmem2",
    "/dev/dipsw", "/dev/gc", "/dev/hid", "/dev/ajm",
    "/dev/notification0", "/dev/camera",
    "/dev/deci_tty6", "/dev/deci_tty7",
}

for _, dev in ipairs(devices) do
    local ok2, err2 = pcall(function()
        local fd = syscall.sc_open(dev, 0):tonumber()
        if fd >= 0 then
            log("  " .. dev .. ": OPEN fd=" .. fd)
            syscall.close(fd)
        else
            log("  " .. dev .. ": DENIED (" .. fd .. ")")
        end
    end)
    if not ok2 then log("  " .. dev .. ": ERR " .. tostring(err2):sub(1,25)) end
end

-- ============================================================
-- TEST 6: mmap + mprotect (W^X check)
-- ============================================================
log("")
log("--- TEST 6: mmap/mprotect ---")
pcall(function()
    local addr = syscall.sc_mmap(0, 0x4000, 3, 0x1002, -1, 0)
    local a = addr:tonumber()
    if a > 0 then
        log("  anon mmap: 0x" .. string.format("%x", a))
        local ret = syscall.sc_mprotect(addr, 0x4000, 7)
        log("  mprotect RWX: " .. ret:tonumber() .. (ret:tonumber() == 0 and " (!!W^X broken!!)" or " (denied)"))
        syscall.sc_munmap(addr, 0x4000)
    end
end)

-- ============================================================
-- TEST 7: shm_open2
-- ============================================================
log("")
log("--- TEST 7: shm_open2 ---")
pcall(function()
    local ret = syscall.sc_shm_open2(1, 0x602, 0x1FF, 0, 0, 0)
    log("  shm_open2: " .. ret:tonumber())
end)

log("")
log("=== KERNEL SURFACE DONE ===")
return table.concat(out, "\n")
