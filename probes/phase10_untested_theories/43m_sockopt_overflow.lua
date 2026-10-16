-- CRASH_CLASS: MODERATE
-- PROBE 43m: PS5 socket option buffer overflow test
--
-- Context: Probe 31c found 5 PS5-specific socket options (0x2000, 0x10000,
-- 0x20000, 0x40000, 0x100000) that all accept set(len=256) with rv=0.
-- These are boolean flags (4 bytes) but the kernel accepted 256-byte writes.
-- If the kernel copies the full user buffer into a small kernel struct field,
-- this is a kernel heap overflow. We test with progressively larger buffers
-- and check for side effects.

print("=== PROBE 43m: PS5 SOCKOPT BUFFER OVERFLOW ===")
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

local sc_socket = make_syscall(97)
local sc_setsockopt = make_syscall(105)
local sc_getsockopt = make_syscall(118)
local sc_close = make_syscall(6)

-- PS5-specific options found in probe 31c
local ps5_opts = {0x2000, 0x10000, 0x20000, 0x40000, 0x100000}

-- === STEP 1: Baseline — verify opts still work with len=4 ===
print("--- STEP 1: Baseline verification (len=4) ---")
local ok_sock, udp_fd = pcall(function()
    return sc_socket(uint64(2), uint64(2), uint64(17))  -- AF_INET, SOCK_DGRAM, UDP
end)
if not ok_sock then
    print("  FAILED to create UDP socket")
    print("=== PROBE 43m ABORTED ===")
    return
end
local fd = to_num(udp_fd)
print(string.format("  UDP socket fd=%d", fd))

local buf4 = memory.alloc(16)
for _, opt in ipairs(ps5_opts) do
    safe_wd(buf4, 1)  -- enable
    local ok, ret = pcall(function()
        return sc_setsockopt(uint64(fd), uint64(0xFFFF), uint64(opt),
            uint64(buf4), uint64(4), uint64(0))
    end)
    local r = ok and to_num(ret) or -999
    print(string.format("  opt 0x%X set(4): ret=%d", opt, r))
end

-- === STEP 2: Read back — what does getsockopt return? ===
print("")
print("--- STEP 2: Read back via getsockopt ---")
for _, opt in ipairs(ps5_opts) do
    local rbuf = memory.alloc(512)
    local lenp = memory.alloc(8)
    safe_wd(lenp, 256)
    safe_wd(lenp + 4, 0)
    for i = 0, 255 do
        pcall(function() memory.write_byte(rbuf + i, 0xCC) end)
    end

    local ok, ret = pcall(function()
        return sc_getsockopt(uint64(fd), uint64(0xFFFF), uint64(opt),
            uint64(rbuf), uint64(lenp), uint64(0))
    end)
    local r = ok and to_num(ret) or -999
    local rlen = safe_rd(lenp) or 0
    print(string.format("  opt 0x%X get(256): ret=%d rlen=%d", opt, r, rlen))

    if r == 0 and rlen > 0 then
        -- Dump what came back
        local limit = math.min(rlen, 64)
        for row = 0, limit - 1, 16 do
            local hex = ""
            for col = 0, 15 do
                if row + col < rlen then
                    local b = safe_rb(rbuf + row + col)
                    if b then
                        hex = hex .. string.format("%02X ", b)
                    else
                        hex = hex .. "?? "
                    end
                end
            end
            print(string.format("    +%03X: %s", row, hex))
        end

        -- Check for kernel pointers in returned data
        for off = 0, rlen - 8, 8 do
            local val = safe_rq(rbuf + off)
            if val then
                local h, l = get_hi_lo(val)
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    print(string.format("    KPTR at +%03X: %08X_%08X", off, h, l))
                end
            end
        end
    end
end

-- === STEP 3: Progressive buffer size test ===
print("")
print("--- STEP 3: Progressive setsockopt buffer sizes ---")
-- Use a fresh socket for each dangerous test
local test_opt = 0x2000  -- test with first PS5 opt
local sizes = {4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096}

for _, sz in ipairs(sizes) do
    -- Fresh socket each time in case we corrupt kernel state
    local ok_s, tfd = pcall(function()
        return sc_socket(uint64(2), uint64(2), uint64(17))
    end)
    if not ok_s then
        print(string.format("  size=%d: can't create socket (kernel may be corrupted!)", sz))
        break
    end
    local tfd_n = to_num(tfd)

    local bigbuf = memory.alloc(sz + 16)
    -- Fill with pattern to detect how much kernel reads
    for i = 0, math.min(sz - 1, 4095) do
        pcall(function() memory.write_byte(bigbuf + i, (i % 254) + 1) end)
    end

    local ok, ret = pcall(function()
        return sc_setsockopt(uint64(tfd_n), uint64(0xFFFF), uint64(test_opt),
            uint64(bigbuf), uint64(sz), uint64(0))
    end)
    local r = ok and to_num(ret) or -999
    print(string.format("  opt 0x%X set(len=%d): ret=%d", test_opt, sz, r))

    -- If it accepted, try to read back
    if r == 0 then
        local rbuf2 = memory.alloc(sz + 16)
        local lenp2 = memory.alloc(8)
        safe_wd(lenp2, sz)
        for i = 0, math.min(sz - 1, 4095) do
            pcall(function() memory.write_byte(rbuf2 + i, 0) end)
        end
        local ok2, ret2 = pcall(function()
            return sc_getsockopt(uint64(tfd_n), uint64(0xFFFF), uint64(test_opt),
                uint64(rbuf2), uint64(lenp2), uint64(0))
        end)
        local r2 = ok2 and to_num(ret2) or -999
        local rlen2 = safe_rd(lenp2) or 0
        if r2 == 0 and rlen2 > 4 then
            print(string.format("    get returned %d bytes (expected 4 for boolean!)", rlen2))
            -- This is the overflow indicator — dump extra bytes
            for row = 0, math.min(rlen2 - 1, 63), 16 do
                local hex = ""
                for col = 0, 15 do
                    if row + col < rlen2 then
                        local b = safe_rb(rbuf2 + row + col)
                        if b then
                            hex = hex .. string.format("%02X ", b)
                        else
                            hex = hex .. "?? "
                        end
                    end
                end
                print(string.format("    +%03X: %s", row, hex))
            end
        end
    end

    pcall(function() sc_close(uint64(tfd_n)) end)
end

-- === STEP 4: Test on TCP and RAW sockets too ===
print("")
print("--- STEP 4: Other socket types ---")

-- TCP
local ok_tcp, tcp_fd = pcall(function()
    return sc_socket(uint64(2), uint64(1), uint64(6))  -- AF_INET, SOCK_STREAM, TCP
end)
if ok_tcp then
    local tcpn = to_num(tcp_fd)
    print(string.format("  TCP fd=%d", tcpn))
    local tbuf = memory.alloc(1024)
    for i = 0, 1023 do
        pcall(function() memory.write_byte(tbuf + i, 0x41) end)
    end
    for _, opt in ipairs(ps5_opts) do
        local ok, ret = pcall(function()
            return sc_setsockopt(uint64(tcpn), uint64(0xFFFF), uint64(opt),
                uint64(tbuf), uint64(1024), uint64(0))
        end)
        local r = ok and to_num(ret) or -999
        if r == 0 then
            print(string.format("    TCP opt 0x%X set(1024): ret=0  *** ACCEPTED ***", opt))
        end
    end
    pcall(function() sc_close(uint64(tcpn)) end)
end

-- RAW (if allowed)
local ok_raw, raw_fd = pcall(function()
    return sc_socket(uint64(2), uint64(3), uint64(255))  -- AF_INET, SOCK_RAW, RAW
end)
if ok_raw then
    local rawn = to_num(raw_fd)
    print(string.format("  RAW fd=%d", rawn))
    local rbuf3 = memory.alloc(1024)
    for i = 0, 1023 do
        pcall(function() memory.write_byte(rbuf3 + i, 0x42) end)
    end
    for _, opt in ipairs(ps5_opts) do
        local ok, ret = pcall(function()
            return sc_setsockopt(uint64(rawn), uint64(0xFFFF), uint64(opt),
                uint64(rbuf3), uint64(1024), uint64(0))
        end)
        local r = ok and to_num(ret) or -999
        if r == 0 then
            print(string.format("    RAW opt 0x%X set(1024): ret=0  *** ACCEPTED ***", opt))
        end
    end
    pcall(function() sc_close(uint64(rawn)) end)
end

-- === STEP 5: SOL_SOCKET level options with large buffers ===
print("")
print("--- STEP 5: Standard SOL_SOCKET opts with oversized buffers ---")
local ok_s5, fd5 = pcall(function()
    return sc_socket(uint64(2), uint64(2), uint64(17))
end)
if ok_s5 then
    local fd5n = to_num(fd5)
    -- Standard options that normally take 4-byte int
    local std_opts = {
        {0x0004, "SO_KEEPALIVE"},
        {0x0008, "SO_DONTROUTE"},
        {0x0020, "SO_BROADCAST"},
        {0x0080, "SO_LINGER"},
        {0x0100, "SO_OOBINLINE"},
        {0x0200, "SO_REUSEPORT"},
        {0x0400, "SO_TIMESTAMP"},
        {0x1001, "SO_SNDBUF"},
        {0x1002, "SO_RCVBUF"},
    }

    local sbuf = memory.alloc(512)
    for i = 0, 255 do
        pcall(function() memory.write_byte(sbuf + i, 0x43) end)
    end
    safe_wd(sbuf, 1)  -- first 4 bytes = enable

    for _, so in ipairs(std_opts) do
        local ok, ret = pcall(function()
            return sc_setsockopt(uint64(fd5n), uint64(0xFFFF), uint64(so[1]),
                uint64(sbuf), uint64(256), uint64(0))
        end)
        local r = ok and to_num(ret) or -999
        if r == 0 then
            print(string.format("  %s (0x%X) set(256): ret=0  *** ACCEPTED ***", so[2], so[1]))
        else
            print(string.format("  %s (0x%X) set(256): ret=%d", so[2], so[1], r))
        end
    end
    pcall(function() sc_close(uint64(fd5n)) end)
end

print("")
print("=== PROBE 43m COMPLETE ===")
