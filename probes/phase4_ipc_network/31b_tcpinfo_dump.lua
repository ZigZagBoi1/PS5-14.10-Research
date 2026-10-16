-- 14.10 Recon Probe 31b: TCP_INFO full dump
-- Parse 236-byte struct for kernel pointer leaks
-- Also dump IP_HDRINCL anomaly and PS5 custom opts

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: TCP_INFO DUMP ===")
log("fw: " .. tostring(FW_VERSION))
log("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_getpid = 20,
    sc_socket = 97,
    sc_close = 6,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
    sc_socketpair = 135,
    sc_bind = 104,
    sc_connect = 98,
    sc_listen = 106,
    sc_write = 4,
    sc_read = 3,
})

local function try_get(fd, level, opt, buf_len)
    local buf = memory.alloc(512)
    local lenp = memory.alloc(8)
    for i = 0, 511, 8 do memory.write_qword(buf + i, 0) end
    memory.write_qword(lenp, buf_len)
    local ok, ret = pcall(function()
        return syscall.sc_getsockopt(fd, level, opt, buf, lenp)
    end)
    local actual_len = memory.read_qword(lenp):tonumber()
    return ok and ret:tonumber() or -999, actual_len, buf
end

-- ============================================================
-- PART 1: TCP_INFO on fresh TCP socket
-- ============================================================
log("")
log("--- PART 1: TCP_INFO fresh socket ---")

local tcp_ok, tcp_ret = pcall(function()
    return syscall.sc_socket(2, 1, 6)
end)
local tcp = tcp_ok and tcp_ret:tonumber() or -1

if tcp >= 0 then
    local rv, len, buf = try_get(tcp, 6, 32, 512)
    log(string.format("  rv=%d actual_len=%d", rv, len))

    -- Hex dump the full structure
    log("  --- hex dump ---")
    for row = 0, len - 1, 16 do
        local hex = ""
        local ascii = ""
        for col = 0, 15 do
            local off = row + col
            if off < len then
                local b = memory.read_byte(buf + off):tonumber()
                hex = hex .. string.format("%02x ", b)
                if b >= 32 and b < 127 then
                    ascii = ascii .. string.char(b)
                else
                    ascii = ascii .. "."
                end
            end
        end
        log(string.format("  %03x: %-48s %s", row, hex, ascii))
    end

    -- Parse known FreeBSD tcp_info fields
    -- FreeBSD struct tcp_info (from tcp.h):
    -- u_int8_t  tcpi_state (0)
    -- u_int8_t  __tcpi_ca_state (1)
    -- u_int8_t  __tcpi_retransmits (2)
    -- u_int8_t  __tcpi_probes (3)
    -- u_int8_t  __tcpi_backoff (4)
    -- u_int8_t  tcpi_options (5)
    -- u_int8_t  tcpi_snd_wscale:4, tcpi_rcv_wscale:4 (6)
    -- padding (7)
    -- u_int32_t tcpi_rto (8)
    -- ... many more u_int32_t fields
    log("")
    log("  --- parsed fields ---")
    local state = memory.read_byte(buf):tonumber()
    local ca_state = memory.read_byte(buf + 1):tonumber()
    local retrans = memory.read_byte(buf + 2):tonumber()
    local probes = memory.read_byte(buf + 3):tonumber()
    local backoff = memory.read_byte(buf + 4):tonumber()
    local options = memory.read_byte(buf + 5):tonumber()
    local wscale = memory.read_byte(buf + 6):tonumber()
    log(string.format("  state=%d ca=%d retrans=%d probes=%d backoff=%d opts=0x%02x wscale=0x%02x",
        state, ca_state, retrans, probes, backoff, options, wscale))

    local rto = memory.read_dword(buf + 8):tonumber()
    log("  rto=" .. rto)

    -- Scan ALL dwords for pointer-like values (kernel: 0xFFFFxxxx, userland: 0x0000xxxx)
    log("")
    log("  --- pointer scan ---")
    for off = 0, len - 8, 4 do
        local d = memory.read_dword(buf + off):tonumber()
        -- Check for kernel-range values (high bits set)
        if d > 0x80000000 or (d > 0x10000 and d < 0x7FFFFFFF) then
            -- Also check as qword for 64-bit pointers
            local q = memory.read_qword(buf + off):tonumber()
            if q > 0xFFFF000000000000 or (q > 0x100000000 and q < 0x800000000000) then
                log(string.format("  @%03x: qword=0x%016x (POSSIBLE PTR)", off, q))
            elseif d > 0x80000000 then
                log(string.format("  @%03x: dword=0x%08x (high bits)", off, d))
            end
        end
    end

    -- Dump all non-zero qwords
    log("")
    log("  --- non-zero qwords ---")
    for off = 0, len - 8, 8 do
        local q = memory.read_qword(buf + off):tonumber()
        if q ~= 0 then
            log(string.format("  @%03x: 0x%016x", off, q))
        end
    end

    pcall(function() syscall.sc_close(tcp) end)
end

-- ============================================================
-- PART 2: TCP_INFO on connected socket (via socketpair-like)
-- Create TCP, bind, listen, connect, then dump
-- ============================================================
log("")
log("--- PART 2: TCP_INFO loopback connected ---")

local srv_ok, srv_ret = pcall(function()
    return syscall.sc_socket(2, 1, 6)
end)
local srv = srv_ok and srv_ret:tonumber() or -1

if srv >= 0 then
    -- bind to 127.0.0.1:0
    local sa = memory.alloc(16)
    memory.write_byte(sa, 16)       -- sin_len
    memory.write_byte(sa + 1, 2)    -- AF_INET
    memory.write_word(sa + 2, 0)    -- port 0 (auto)
    memory.write_dword(sa + 4, 0x0100007F) -- 127.0.0.1 (network byte order: 7F000001)

    local bind_ok, bind_rv = pcall(function()
        return syscall.sc_bind(srv, sa, 16)
    end)
    log("  bind: rv=" .. (bind_ok and bind_rv:tonumber() or -999))

    -- getsockname to learn assigned port
    local name_buf = memory.alloc(16)
    local name_len = memory.alloc(8)
    memory.write_qword(name_len, 16)

    -- listen
    local lis_ok, lis_rv = pcall(function()
        return syscall.sc_listen(srv, 5)
    end)
    log("  listen: rv=" .. (lis_ok and lis_rv:tonumber() or -999))

    if bind_ok and bind_rv:tonumber() == 0 and lis_ok and lis_rv:tonumber() == 0 then
        -- Read back assigned port via getsockname (syscall 32)
        syscall.resolve({ sc_getsockname = 32 })
        memory.write_qword(name_len, 16)
        pcall(function() syscall.sc_getsockname(srv, name_buf, name_len) end)
        local port_be = memory.read_word(name_buf + 2):tonumber()
        -- Swap bytes for port
        local port = ((port_be % 256) * 256) + math.floor(port_be / 256)
        log("  bound port: " .. port)

        -- Connect client
        local cli_ok, cli_ret = pcall(function()
            return syscall.sc_socket(2, 1, 6)
        end)
        local cli = cli_ok and cli_ret:tonumber() or -1

        if cli >= 0 then
            memory.write_word(sa + 2, port_be) -- use same byte-order port
            -- Fix 127.0.0.1 in correct network byte order
            memory.write_byte(sa + 4, 127)
            memory.write_byte(sa + 5, 0)
            memory.write_byte(sa + 6, 0)
            memory.write_byte(sa + 7, 1)

            local conn_ok, conn_rv = pcall(function()
                return syscall.sc_connect(cli, sa, 16)
            end)
            log("  connect: rv=" .. (conn_ok and conn_rv:tonumber() or -999))

            if conn_ok and conn_rv:tonumber() == 0 then
                -- Send some data
                local data = memory.alloc(64)
                for i = 0, 63, 4 do memory.write_dword(data + i, 0xBEEF0000 + i) end
                pcall(function() syscall.sc_write(cli, data, 64) end)

                -- Dump TCP_INFO on connected client socket
                local rv2, len2, buf2 = try_get(cli, 6, 32, 512)
                log(string.format("  connected TCP_INFO: rv=%d len=%d", rv2, len2))

                -- Hex dump
                log("  --- hex dump (connected) ---")
                for row = 0, len2 - 1, 16 do
                    local hex = ""
                    for col = 0, 15 do
                        local off = row + col
                        if off < len2 then
                            hex = hex .. string.format("%02x ", memory.read_byte(buf2 + off):tonumber())
                        end
                    end
                    log(string.format("  %03x: %s", row, hex))
                end

                -- Pointer scan on connected socket
                log("  --- pointer scan (connected) ---")
                for off = 0, len2 - 8, 4 do
                    local q = memory.read_qword(buf2 + off):tonumber()
                    if q > 0xFFFF000000000000 or (q > 0x100000000 and q < 0x800000000000) then
                        log(string.format("  @%03x: 0x%016x (POSSIBLE PTR)", off, q))
                    end
                end

                -- Non-zero qwords
                log("  --- non-zero qwords (connected) ---")
                for off = 0, len2 - 8, 8 do
                    local q = memory.read_qword(buf2 + off):tonumber()
                    if q ~= 0 then
                        log(string.format("  @%03x: 0x%016x", off, q))
                    end
                end
            end

            pcall(function() syscall.sc_close(cli) end)
        end
    end

    pcall(function() syscall.sc_close(srv) end)
end

-- ============================================================
-- PART 3: IP_HDRINCL anomaly
-- ============================================================
log("")
log("--- PART 3: IP_HDRINCL detail ---")

local raw_ok, raw_ret = pcall(function()
    return syscall.sc_socket(2, 3, 255)
end)
local raw = raw_ok and raw_ret:tonumber() or -1

if raw >= 0 then
    -- Get before set
    local rv0, len0, buf0 = try_get(raw, 0, 2, 16)
    log(string.format("  before set: rv=%d len=%d", rv0, len0))
    for off = 0, 15, 4 do
        log(string.format("    @%d: 0x%08x", off, memory.read_dword(buf0 + off):tonumber()))
    end

    -- Set to 1
    local val = memory.alloc(4)
    memory.write_dword(val, 1)
    pcall(function() syscall.sc_setsockopt(raw, 0, 2, val, 4) end)

    -- Get after set
    local rv1, len1, buf1 = try_get(raw, 0, 2, 16)
    log(string.format("  after set=1: rv=%d len=%d", rv1, len1))
    for off = 0, 15, 4 do
        log(string.format("    @%d: 0x%08x", off, memory.read_dword(buf1 + off):tonumber()))
    end

    -- Set to 0 and re-read
    memory.write_dword(val, 0)
    pcall(function() syscall.sc_setsockopt(raw, 0, 2, val, 4) end)
    local rv2, len2, buf2 = try_get(raw, 0, 2, 16)
    log(string.format("  after set=0: rv=%d len=%d", rv2, len2))
    for off = 0, 15, 4 do
        log(string.format("    @%d: 0x%08x", off, memory.read_dword(buf2 + off):tonumber()))
    end

    pcall(function() syscall.sc_close(raw) end)
end

-- ============================================================
-- PART 4: PS5 custom SOL_SOCKET options deeper scan
-- ============================================================
log("")
log("--- PART 4: PS5 custom opts ---")

local sp = memory.alloc(8)
pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local pa = memory.read_dword(sp):tonumber()

-- Scan SOL_SOCKET option space for accessible ones
local found = {}
for opt = 0x1000, 0x10001, 1 do
    if opt <= 0x1010 or opt == 0x2000 or opt == 0x2001 or opt == 0x2002 or
       opt == 0x3000 or opt == 0x4000 or opt == 0x4001 or opt == 0x5000 or
       opt == 0x8000 or opt == 0x10000 or opt == 0x10001 then
        local rv, len, buf = try_get(pa, 0xFFFF, opt, 128)
        if rv == 0 then
            local d0 = memory.read_dword(buf):tonumber()
            local d1 = memory.read_dword(buf + 4):tonumber()
            log(string.format("  SOL 0x%05x: len=%d val=0x%08x %08x", opt, len, d0, d1))
            found[#found+1] = opt
        end
    end
end

-- Also scan wider range at key intervals
for opt_hi = 0x20000, 0x100000, 0x10000 do
    local rv, len, buf = try_get(pa, 0xFFFF, opt_hi, 128)
    if rv == 0 then
        local d0 = memory.read_dword(buf):tonumber()
        log(string.format("  SOL 0x%05x: len=%d val=0x%08x", opt_hi, len, d0))
    end
end

pcall(function() syscall.sc_close(pa) end)
pcall(function() syscall.sc_close(memory.read_dword(sp + 4):tonumber()) end)

log("")
log("=== TCP_INFO DUMP DONE ===")
log("pid final: " .. syscall.getpid():tonumber())
return table.concat(out, "\n")
