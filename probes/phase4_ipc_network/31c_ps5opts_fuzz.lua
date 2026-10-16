-- 14.10 Recon Probe 31c: PS5 custom socket option fuzzing
-- Target: SOL_SOCKET 0x2000, 0x10000, 0x20000, 0x40000, 0x100000
-- Also: full scan of SOL_SOCKET option space for hidden options

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: PS5 OPTS FUZZ ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_getpid = 20,
    sc_socket = 97,
    sc_close = 6,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
    sc_socketpair = 135,
})

local function try_set(fd, level, opt, val_buf, val_len)
    local ok, ret = pcall(function()
        return syscall.sc_setsockopt(fd, level, opt, val_buf, val_len)
    end)
    return ok and ret:tonumber() or -999
end

local function try_get(fd, level, opt, buf_len)
    local buf = memory.alloc(512)
    local lenp = memory.alloc(8)
    for i = 0, 511, 8 do memory.write_qword(buf + i, 0xDEADDEADDEADDEAD) end
    memory.write_qword(lenp, buf_len)
    local ok, ret = pcall(function()
        return syscall.sc_getsockopt(fd, level, opt, buf, lenp)
    end)
    local actual_len = memory.read_qword(lenp):tonumber()
    return ok and ret:tonumber() or -999, actual_len, buf
end

local val = memory.alloc(4096)
local sp = memory.alloc(8)

-- ============================================================
-- PART 1: Scan full SOL_SOCKET option space (0x0000-0x1100)
-- Find every accessible option we missed
-- ============================================================
log("")
log("--- PART 1: SOL_SOCKET full scan ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local fd1 = memory.read_dword(sp):tonumber()
local fd1b = memory.read_dword(sp + 4):tonumber()

local accessible = {}
for opt = 1, 0x1100 do
    local rv, len, buf = try_get(fd1, 0xFFFF, opt, 128)
    if rv == 0 then
        local d0 = memory.read_dword(buf):tonumber()
        accessible[#accessible+1] = {opt, len, d0}
    end
end
log("  found " .. #accessible .. " accessible options")
for _, a in ipairs(accessible) do
    log(string.format("  0x%04x: len=%d val=0x%08x", a[1], a[2], a[3]))
end

pcall(function() syscall.sc_close(fd1) end)
pcall(function() syscall.sc_close(fd1b) end)

-- ============================================================
-- PART 2: Deep fuzz each PS5 custom option
-- ============================================================
log("")
log("--- PART 2: PS5 custom opts fuzz ---")

local ps5_opts = {0x2000, 0x10000, 0x20000, 0x40000, 0x100000}

for _, opt in ipairs(ps5_opts) do
    log(string.format("  --- opt 0x%x ---", opt))

    pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
    local fd = memory.read_dword(sp):tonumber()
    local fdb = memory.read_dword(sp + 4):tonumber()

    -- Get with various buffer sizes
    for _, sz in ipairs({0, 1, 4, 8, 16, 64, 256}) do
        local rv, len, buf = try_get(fd, 0xFFFF, opt, sz)
        if rv == 0 then
            local d0 = memory.read_dword(buf):tonumber()
            log(string.format("    get(len=%d): rv=0 actual=%d val=0x%08x", sz, len, d0))
        else
            log(string.format("    get(len=%d): rv=%d", sz, rv))
        end
    end

    -- Set with int values
    local set_vals = {0, 1, 2, 0xFF, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF}
    for _, v in ipairs(set_vals) do
        memory.write_dword(val, v)
        local srv = try_set(fd, 0xFFFF, opt, val, 4)
        if srv == 0 then
            local grv, glen, gbuf = try_get(fd, 0xFFFF, opt, 16)
            local gval = memory.read_dword(gbuf):tonumber()
            log(string.format("    set(0x%x): rv=0 readback=0x%08x", v, gval))
        elseif srv ~= -999 then
            log(string.format("    set(0x%x): rv=%d", v, srv))
        end
    end

    -- Set with length 0
    local srv0 = try_set(fd, 0xFFFF, opt, val, 0)
    if srv0 ~= -999 then
        log(string.format("    set(len=0): rv=%d", srv0))
    end

    -- Set with length 1
    memory.write_byte(val, 0x41)
    local srv1 = try_set(fd, 0xFFFF, opt, val, 1)
    if srv1 ~= -999 then
        log(string.format("    set(len=1): rv=%d", srv1))
    end

    -- Set with length 8 (qword)
    memory.write_qword(val, 0xCAFEBABE12345678)
    local srv8 = try_set(fd, 0xFFFF, opt, val, 8)
    if srv8 ~= -999 then
        log(string.format("    set(len=8,qword): rv=%d", srv8))
    end
    if srv8 == 0 then
        local grv, glen, gbuf = try_get(fd, 0xFFFF, opt, 16)
        local gq = memory.read_qword(gbuf):tonumber()
        log(string.format("    readback qword: 0x%016x (len=%d)", gq, glen))
    end

    -- Set with large length (256 bytes of pattern)
    for i = 0, 255, 4 do memory.write_dword(val + i, 0xAA000000 + i) end
    local srv256 = try_set(fd, 0xFFFF, opt, val, 256)
    if srv256 ~= -999 then
        log(string.format("    set(len=256): rv=%d", srv256))
    end

    pcall(function() syscall.sc_close(fd) end)
    pcall(function() syscall.sc_close(fdb) end)
end

-- ============================================================
-- PART 3: Fuzz on different socket types
-- Some options may behave differently on TCP vs UDP vs RAW
-- ============================================================
log("")
log("--- PART 3: PS5 opts on TCP ---")

local tcp_ok, tcp_ret = pcall(function()
    return syscall.sc_socket(2, 1, 6)
end)
local tcp = tcp_ok and tcp_ret:tonumber() or -1

if tcp >= 0 then
    for _, opt in ipairs(ps5_opts) do
        local rv, len, buf = try_get(tcp, 0xFFFF, opt, 64)
        if rv == 0 then
            local d0 = memory.read_dword(buf):tonumber()
            log(string.format("  TCP 0x%x: len=%d val=0x%08x", opt, len, d0))

            -- Try setting
            memory.write_dword(val, 1)
            local srv = try_set(tcp, 0xFFFF, opt, val, 4)
            if srv == 0 then
                local grv, glen, gbuf = try_get(tcp, 0xFFFF, opt, 16)
                log(string.format("    set(1): rv=0 readback=0x%08x",
                    memory.read_dword(gbuf):tonumber()))
            else
                log(string.format("    set(1): rv=%d", srv))
            end
        end
    end
    pcall(function() syscall.sc_close(tcp) end)
end

log("")
log("--- PART 3b: PS5 opts on RAW ---")

local raw_ok, raw_ret = pcall(function()
    return syscall.sc_socket(2, 3, 255)
end)
local raw = raw_ok and raw_ret:tonumber() or -1

if raw >= 0 then
    for _, opt in ipairs(ps5_opts) do
        local rv, len, buf = try_get(raw, 0xFFFF, opt, 64)
        if rv == 0 then
            local d0 = memory.read_dword(buf):tonumber()
            log(string.format("  RAW 0x%x: len=%d val=0x%08x", opt, len, d0))

            memory.write_dword(val, 1)
            local srv = try_set(raw, 0xFFFF, opt, val, 4)
            if srv == 0 then
                local grv, glen, gbuf = try_get(raw, 0xFFFF, opt, 16)
                log(string.format("    set(1): rv=0 readback=0x%08x",
                    memory.read_dword(gbuf):tonumber()))
            else
                log(string.format("    set(1): rv=%d", srv))
            end
        end
    end
    pcall(function() syscall.sc_close(raw) end)
end

log("")
log("--- PART 3c: PS5 opts on IPv6 RAW ---")

local v6r_ok, v6r_ret = pcall(function()
    return syscall.sc_socket(28, 3, 255)
end)
local v6r = v6r_ok and v6r_ret:tonumber() or -1

if v6r >= 0 then
    for _, opt in ipairs(ps5_opts) do
        local rv, len, buf = try_get(v6r, 0xFFFF, opt, 64)
        if rv == 0 then
            local d0 = memory.read_dword(buf):tonumber()
            log(string.format("  V6RAW 0x%x: len=%d val=0x%08x", opt, len, d0))
        end
    end
    pcall(function() syscall.sc_close(v6r) end)
end

-- ============================================================
-- PART 4: Scan for PS5-specific protocol-level options
-- IPPROTO_TCP=6, IPPROTO_UDP=17, IPPROTO_IPV6=41
-- ============================================================
log("")
log("--- PART 4: PS5 custom at other levels ---")

local tcp2_ok, tcp2_ret = pcall(function()
    return syscall.sc_socket(2, 1, 6)
end)
local tcp2 = tcp2_ok and tcp2_ret:tonumber() or -1

if tcp2 >= 0 then
    -- Scan TCP level for high option numbers
    for _, opt in ipairs({0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000}) do
        local rv, len, buf = try_get(tcp2, 6, opt, 64)
        if rv == 0 then
            log(string.format("  TCP-level 0x%x: len=%d val=0x%08x", opt, len,
                memory.read_dword(buf):tonumber()))
        end
    end
    pcall(function() syscall.sc_close(tcp2) end)
end

-- IPv6 level scan
local v6_ok, v6_ret = pcall(function()
    return syscall.sc_socket(28, 2, 17)
end)
local v6 = v6_ok and v6_ret:tonumber() or -1

if v6 >= 0 then
    for _, opt in ipairs({0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000}) do
        local rv, len, buf = try_get(v6, 41, opt, 64)
        if rv == 0 then
            log(string.format("  IPv6-level 0x%x: len=%d val=0x%08x", opt, len,
                memory.read_dword(buf):tonumber()))
        end
    end
    pcall(function() syscall.sc_close(v6) end)
end

log("")
log("=== PS5 OPTS FUZZ DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
