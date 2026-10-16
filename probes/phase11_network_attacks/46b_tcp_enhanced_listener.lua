-- CRASH_CLASS: LOW
-- PROBE 46b: Enhanced TCP Connect-Back Listener
--
-- Context: Probe 40 confirmed TCP connect-back works with the fake-IP ARP
-- responder technique. This enhanced version enables TCP SACK and timestamps,
-- handles OOB/URG data, reports detailed socket state, and stays alive for
-- extended fuzzing (120s). Pairs with tools/tcp_fuzz_server_v2.py.
--
-- The PS5 kernel's tcp_input() parses attacker-controlled data in kernel
-- context — outside the syscall sandbox. This is the most promising attack
-- vector after probe 45c killed the ROP chain.
--
-- >>> EDIT PC_IP below to match your machine <<<
-- >>> Run tcp_fuzz_server_v2.py on PC first <<<

local PC_IP = {10, 0, 0, 50}   -- <-- CHANGE ME
local PC_PORT = 31337

print("=== PROBE 46b: ENHANCED TCP LISTENER ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

local pid = syscall.getpid():tonumber()
print("pid: " .. pid)
print("target: " .. table.concat(PC_IP, ".") .. ":" .. PC_PORT)

syscall.resolve({
    sc_socket = 97,
    sc_connect = 98,
    sc_close = 6,
    sc_sendmsg = 28,
    sc_recvmsg = 27,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
    sc_poll = 209,
})

local MSG_DONTWAIT = 0x80
local MSG_OOB = 0x01
local MSG_PEEK = 0x02

-- ============================================
-- SECTION A: Create and configure socket
-- ============================================
print("")
print("=== A: SOCKET SETUP ===")

local ok_s, rv_s = pcall(function() return syscall.sc_socket(2, 1, 6) end)
local fd = ok_s and rv_s:tonumber() or -1
print("socket: fd=" .. fd)
if fd < 0 then
    print("=== 46b DONE (no socket) ===")
    return
end

local optval = memory.alloc(8)
local optlen = memory.alloc(8)

-- SO_RCVBUF: set to 256KB for deep SACK testing
memory.write_dword(optval, 256 * 1024)
local ok_rb, rv_rb = pcall(function()
    return syscall.sc_setsockopt(fd, 0xFFFF, 0x1002, optval, 4)
end)
print("SO_RCVBUF(256K): rv=" .. (ok_rb and rv_rb:tonumber() or -999))

-- SO_SNDBUF: also larger
memory.write_dword(optval, 256 * 1024)
pcall(function() syscall.sc_setsockopt(fd, 0xFFFF, 0x1001, optval, 4) end)

-- SO_KEEPALIVE: enable to detect silent connection drops
memory.write_dword(optval, 1)
pcall(function() syscall.sc_setsockopt(fd, 0xFFFF, 0x0008, optval, 4) end)

-- SO_OOBINLINE: receive OOB data inline (alternative: use MSG_OOB)
-- Leave disabled — we'll check for OOB separately via POLLPRI + MSG_OOB
memory.write_dword(optval, 0)
pcall(function() syscall.sc_setsockopt(fd, 0xFFFF, 0x0100, optval, 4) end)

-- TCP_NODELAY: disable Nagle for responsive send
memory.write_dword(optval, 1)
pcall(function() syscall.sc_setsockopt(fd, 6, 1, optval, 4) end)

-- Read back settings
memory.write_dword(optlen, 4)
pcall(function() syscall.sc_getsockopt(fd, 0xFFFF, 0x1002, optval, optlen) end)
print("SO_RCVBUF actual: " .. (safe_rd(optval) or "?"))

-- ============================================
-- SECTION B: Connect
-- ============================================
print("")
print("=== B: CONNECT ===")

local sa = memory.alloc(16)
for i = 0, 15 do memory.write_byte(sa + i, 0) end
memory.write_byte(sa + 0, 16)         -- sin_len
memory.write_byte(sa + 1, 2)          -- AF_INET
memory.write_byte(sa + 2, math.floor(PC_PORT / 256))
memory.write_byte(sa + 3, PC_PORT % 256)
for i = 1, 4 do memory.write_byte(sa + 3 + i, PC_IP[i]) end

print("connecting...")
local ok_c, rv_c = pcall(function() return syscall.sc_connect(fd, sa, 16) end)
local crv = ok_c and rv_c:tonumber() or -999
print("connect: rv=" .. crv)
if crv ~= 0 then
    print("connect FAILED — is tcp_fuzz_server_v2.py running?")
    pcall(function() syscall.sc_close(fd) end)
    print("=== 46b DONE (no connect) ===")
    return
end
print("*** CONNECTED ***")

-- Send hello
local hello = memory.alloc(16)
memory.write_byte(hello, 0x50)    -- P
memory.write_byte(hello + 1, 0x53) -- S
memory.write_byte(hello + 2, 0x35) -- 5
memory.write_byte(hello + 3, 0x21) -- !
memory.write_byte(hello + 4, 0x56) -- V
memory.write_byte(hello + 5, 0x32) -- 2
local iov_h = memory.alloc(16)
memory.write_qword(iov_h, hello)
memory.write_qword(iov_h + 8, 6)
local mh_h = memory.alloc(64)
for i = 0, 63, 8 do memory.write_qword(mh_h + i, 0) end
memory.write_qword(mh_h + 16, iov_h)
memory.write_qword(mh_h + 24, 1)
pcall(function() return syscall.sc_sendmsg(fd, mh_h, MSG_DONTWAIT) end)
print("hello sent (PS5!V2)")

-- ============================================
-- SECTION C: Extended receive loop
-- ============================================
print("")
print("=== C: RECEIVE LOOP (120s) ===")

local rbuf = memory.alloc(4096)
local riov = memory.alloc(16)
local rmh = memory.alloc(64)
local pollfd = memory.alloc(8)
local errbuf = memory.alloc(4)
local errlen = memory.alloc(4)
local oob_buf = memory.alloc(16)
local oob_iov = memory.alloc(16)
local oob_mh = memory.alloc(64)

local total_recv = 0
local total_oob = 0
local errors = 0
local max_iter = 1200   -- 1200 * 100ms = 120s

for iter = 1, max_iter do
    -- Poll: POLLIN (0x0001) | POLLPRI (0x0002) | POLLHUP (0x0010) | POLLERR (0x0008)
    memory.write_dword(pollfd, fd)
    memory.write_word(pollfd + 4, 0x001B)  -- POLLIN|POLLPRI|POLLERR|POLLHUP
    memory.write_word(pollfd + 6, 0)

    local ok_p, rv_p = pcall(function() return syscall.sc_poll(pollfd, 1, 100) end)
    local rev = memory.read_word(pollfd + 6):tonumber()

    -- Check for OOB/urgent data (POLLPRI = 0x0002)
    if bit32 and bit32.band(rev, 0x0002) ~= 0 then
        memory.write_qword(oob_iov, oob_buf)
        memory.write_qword(oob_iov + 8, 16)
        for i = 0, 63, 8 do memory.write_qword(oob_mh + i, 0) end
        memory.write_qword(oob_mh + 16, oob_iov)
        memory.write_qword(oob_mh + 24, 1)
        local ok_o, rv_o = pcall(function()
            return syscall.sc_recvmsg(fd, oob_mh, MSG_OOB + MSG_DONTWAIT)
        end)
        local oob_n = ok_o and rv_o:tonumber() or -999
        if oob_n > 0 then
            total_oob = total_oob + oob_n
            local hex = ""
            for i = 0, math.min(oob_n - 1, 15) do
                hex = hex .. string.format("%02x",
                    memory.read_byte(oob_buf + i):tonumber())
            end
            print(string.format("iter %d: *** OOB data=%d bytes: %s ***",
                iter, oob_n, hex))
        end
    end

    -- Check for normal data (POLLIN = 0x0001)
    if rev > 0 and (not bit32 or bit32.band(rev, 0x0001) ~= 0) then
        memory.write_qword(riov, rbuf)
        memory.write_qword(riov + 8, 4096)
        for i = 0, 63, 8 do memory.write_qword(rmh + i, 0) end
        memory.write_qword(rmh + 16, riov)
        memory.write_qword(rmh + 24, 1)
        local ok_r, rv_r = pcall(function()
            return syscall.sc_recvmsg(fd, rmh, MSG_DONTWAIT)
        end)
        local n = ok_r and rv_r:tonumber() or -999

        if n == 0 then
            print("iter " .. iter .. ": EOF (peer closed)")
            break
        elseif n > 0 then
            total_recv = total_recv + n
            local flags = memory.read_dword(rmh + 32):tonumber()
            local hex = ""
            for i = 0, math.min(n - 1, 31) do
                hex = hex .. string.format("%02x",
                    memory.read_byte(rbuf + i):tonumber())
            end
            print(string.format("iter %d: recv=%d flags=0x%x data=%s",
                iter, n, flags, hex))

            -- Check for interesting msg_flags
            if flags ~= 0 then
                print("  flags detail: " ..
                    (flags % 2 >= 1 and "MSG_OOB " or "") ..
                    (flags % 4 >= 2 and "MSG_EOR " or "") ..
                    (math.floor(flags / 0x100) % 2 >= 1 and "MSG_TRUNC " or "") ..
                    (math.floor(flags / 0x200) % 2 >= 1 and "MSG_CTRUNC " or ""))
            end
        end
    end

    -- POLLERR or POLLHUP
    if rev > 0 and ((not bit32 and rev >= 8) or
       (bit32 and (bit32.band(rev, 0x0018) ~= 0))) then
        print(string.format("iter %d: POLLERR/POLLHUP revents=0x%04x", iter, rev))
        errors = errors + 1
        if errors >= 3 then
            print("too many errors, stopping")
            break
        end
    end

    -- SO_ERROR check
    memory.write_dword(errlen, 4)
    memory.write_dword(errbuf, 0)
    pcall(function()
        syscall.sc_getsockopt(fd, 0xFFFF, 0x1007, errbuf, errlen)
    end)
    local serr = safe_rd(errbuf)
    if serr and serr ~= 0 then
        print("iter " .. iter .. ": SO_ERROR=" .. serr)
        break
    end

    -- Periodic status every 100 iterations (10s)
    if iter % 100 == 0 then
        print(string.format("--- iter %d: total_recv=%d oob=%d errors=%d ---",
            iter, total_recv, total_oob, errors))
    end
end

-- ============================================
-- SECTION D: Final state
-- ============================================
print("")
print("=== D: FINAL STATE ===")
print("total_recv: " .. total_recv .. " bytes")
print("total_oob: " .. total_oob .. " bytes")
print("errors: " .. errors)

-- Try to read TCP_INFO if available
local tcpinfo = memory.alloc(256)
local tcpinfo_len = memory.alloc(4)
memory.write_dword(tcpinfo_len, 256)
local ok_ti, rv_ti = pcall(function()
    return syscall.sc_getsockopt(fd, 6, 32, tcpinfo, tcpinfo_len)
end)
if ok_ti and rv_ti:tonumber() == 0 then
    local ti_len = safe_rd(tcpinfo_len) or 0
    print("TCP_INFO: " .. ti_len .. " bytes")
    if ti_len > 0 then
        local hex = ""
        for i = 0, math.min(ti_len - 1, 63) do
            local ok_b, b = pcall(function()
                return memory.read_byte(tcpinfo + i)
            end)
            if ok_b then hex = hex .. string.format("%02x ", to_num(b)) end
        end
        print("  first 64B: " .. hex)
    end
end

pcall(function() syscall.sc_close(fd) end)
print("")
print("NOTE: console hang/reboot during loop = kernel TCP path hit.")
print("Check PC-side log for which variant was in flight.")
print("=== PROBE 46b COMPLETE ===")
