-- CRASH_CLASS: LOW
-- PROBE 46c: IP Options Listener (Real Network)
--
-- Context: Probe 37 tested IP options on loopback but ip_output() validates
-- lengths before ip_dooptions() sees them. This probe opens a UDP listener
-- on the PS5 LAN interface so the PC can send crafted packets with malformed
-- IP options via tools/ip_options_inject.py. Packets arrive at ip_input()
-- on the INBOUND path, bypassing output validation.
--
-- This probe:
--   1. Opens a UDP socket bound to PS5 LAN IP (0.0.0.0:31338)
--   2. Enables IP_RECVOPTS to capture IP options from received packets
--   3. Loops for 120s, reporting every packet received
--   4. Reports packet count, any options seen, and connection status
--
-- Run tools/ip_options_inject.py on the PC side.
-- A crash/reboot during this probe = kernel ip_dooptions() hit.

print("=== PROBE 46c: IP OPTIONS LISTENER ===")
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

syscall.resolve({
    sc_socket = 97,
    sc_bind = 104,
    sc_close = 6,
    sc_sendmsg = 28,
    sc_recvmsg = 27,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
    sc_poll = 209,
})

local MSG_DONTWAIT = 0x80

-- ============================================
-- SECTION A: Create UDP listener
-- ============================================
print("=== A: SETUP ===")

local ok_s, rv_s = pcall(function() return syscall.sc_socket(2, 2, 17) end)
local udp_fd = ok_s and rv_s:tonumber() or -1
print("UDP socket: fd=" .. udp_fd)
if udp_fd < 0 then
    print("=== 46c DONE (no socket) ===")
    return
end

-- Bind to 0.0.0.0:31338 (accept packets on any interface)
local sa = memory.alloc(16)
for i = 0, 15 do memory.write_byte(sa + i, 0) end
memory.write_byte(sa + 0, 16)         -- sin_len
memory.write_byte(sa + 1, 2)          -- AF_INET
memory.write_byte(sa + 2, 0x7A)       -- port 31338 high byte
memory.write_byte(sa + 3, 0x6A)       -- port 31338 low byte
-- 0.0.0.0 (bind all interfaces)

local ok_b, rv_b = pcall(function() return syscall.sc_bind(udp_fd, sa, 16) end)
print("bind(0.0.0.0:31338): rv=" .. (ok_b and rv_b:tonumber() or -999))

if not ok_b or rv_b:tonumber() ~= 0 then
    -- Try alternate ports
    for _, port in ipairs({31337, 9027, 1234, 5000, 8080}) do
        memory.write_byte(sa + 2, math.floor(port / 256))
        memory.write_byte(sa + 3, port % 256)
        ok_b, rv_b = pcall(function() return syscall.sc_bind(udp_fd, sa, 16) end)
        if ok_b and rv_b:tonumber() == 0 then
            print("bind(0.0.0.0:" .. port .. "): rv=0")
            break
        end
    end
    if not ok_b or rv_b:tonumber() ~= 0 then
        print("BIND FAILED on all ports")
        pcall(function() syscall.sc_close(udp_fd) end)
        print("=== 46c DONE (no bind) ===")
        return
    end
end

-- Enable IP_RECVOPTS (receive IP options as control message)
local optval = memory.alloc(4)
memory.write_dword(optval, 1)
local ok_ro, rv_ro = pcall(function()
    return syscall.sc_setsockopt(udp_fd, 0, 6, optval, 4)  -- IPPROTO_IP=0, IP_RECVOPTS=6
end)
print("IP_RECVOPTS: rv=" .. (ok_ro and rv_ro:tonumber() or -999))

-- Also try IP_RECVDSTADDR to see destination IP
memory.write_dword(optval, 1)
pcall(function() syscall.sc_setsockopt(udp_fd, 0, 7, optval, 4) end)  -- IP_RECVDSTADDR=7

-- SO_RCVBUF large
memory.write_dword(optval, 65536)
pcall(function() syscall.sc_setsockopt(udp_fd, 0xFFFF, 0x1002, optval, 4) end)

-- ============================================
-- SECTION B: Also open a RAW socket to see IP headers directly
-- ============================================
print("")
print("=== B: RAW SOCKET FOR IP HEADER ACCESS ===")

local ok_r, rv_r = pcall(function() return syscall.sc_socket(2, 3, 17) end)
local raw_fd = ok_r and rv_r:tonumber() or -1
print("RAW(UDP) socket: fd=" .. raw_fd)

if raw_fd >= 0 then
    -- Bind to all interfaces
    local sa_raw = memory.alloc(16)
    for i = 0, 15 do memory.write_byte(sa_raw + i, 0) end
    memory.write_byte(sa_raw + 0, 16)
    memory.write_byte(sa_raw + 1, 2)
    local ok_rb, rv_rb = pcall(function()
        return syscall.sc_bind(raw_fd, sa_raw, 16)
    end)
    print("RAW bind: rv=" .. (ok_rb and rv_rb:tonumber() or -999))
end

-- ============================================
-- SECTION C: Receive loop
-- ============================================
print("")
print("=== C: RECEIVE LOOP (120s) ===")
print("waiting for packets from PC... run ip_options_inject.py now")
print("")

local rbuf = memory.alloc(2048)
local riov = memory.alloc(16)
local rmh = memory.alloc(64)
local ctrl = memory.alloc(256)  -- cmsg buffer for IP options
local pollfd = memory.alloc(16)  -- room for 2 fds
local from_sa = memory.alloc(16)

local total_pkt = 0
local total_opts = 0

local max_iter = 1200  -- 120s at 100ms poll

for iter = 1, max_iter do
    -- Poll both UDP and RAW sockets
    local nfds = 1
    memory.write_dword(pollfd, udp_fd)
    memory.write_word(pollfd + 4, 0x0001)  -- POLLIN
    memory.write_word(pollfd + 6, 0)
    if raw_fd >= 0 then
        nfds = 2
        memory.write_dword(pollfd + 8, raw_fd)
        memory.write_word(pollfd + 12, 0x0001)
        memory.write_word(pollfd + 14, 0)
    end

    local ok_p, rv_p = pcall(function()
        return syscall.sc_poll(pollfd, nfds, 100)
    end)

    -- Check UDP socket
    local rev_udp = memory.read_word(pollfd + 6):tonumber()
    if rev_udp > 0 then
        -- Receive with cmsg for IP options
        memory.write_qword(riov, rbuf)
        memory.write_qword(riov + 8, 2048)
        for i = 0, 63, 8 do memory.write_qword(rmh + i, 0) end
        memory.write_qword(rmh + 0, from_sa)     -- msg_name
        memory.write_qword(rmh + 8, 16)          -- msg_namelen
        memory.write_qword(rmh + 16, riov)       -- msg_iov
        memory.write_qword(rmh + 24, 1)          -- msg_iovlen
        memory.write_qword(rmh + 32, ctrl)       -- msg_control
        memory.write_qword(rmh + 40, 256)        -- msg_controllen

        local ok_r2, rv_r2 = pcall(function()
            return syscall.sc_recvmsg(udp_fd, rmh, MSG_DONTWAIT)
        end)
        local n = ok_r2 and rv_r2:tonumber() or -999

        if n > 0 then
            total_pkt = total_pkt + 1

            -- Source IP
            local src_ip = string.format("%d.%d.%d.%d",
                memory.read_byte(from_sa + 4):tonumber(),
                memory.read_byte(from_sa + 5):tonumber(),
                memory.read_byte(from_sa + 6):tonumber(),
                memory.read_byte(from_sa + 7):tonumber())

            -- Data preview
            local hex = ""
            for i = 0, math.min(n - 1, 15) do
                hex = hex .. string.format("%02x",
                    memory.read_byte(rbuf + i):tonumber())
            end

            -- Check cmsg (IP options)
            local ctrl_len = safe_rd(rmh + 40) or 0
            local flags = safe_rd(rmh + 48) or 0
            local has_opts = false

            if ctrl_len and ctrl_len > 0 then
                -- Parse cmsg headers
                local coff = 0
                while coff + 12 <= ctrl_len do
                    local cmsg_len = safe_rd(ctrl + coff) or 0
                    local cmsg_level = safe_rd(ctrl + coff + 4) or 0
                    local cmsg_type = safe_rd(ctrl + coff + 8) or 0
                    if cmsg_len == 0 then break end

                    if cmsg_level == 0 and cmsg_type == 6 then
                        -- IP_RECVOPTS — contains the IP options
                        has_opts = true
                        total_opts = total_opts + 1
                        local opt_len = cmsg_len - 12
                        local opt_hex = ""
                        for i = 0, math.min(opt_len - 1, 39) do
                            local ok_ob, ob = pcall(function()
                                return memory.read_byte(ctrl + coff + 12 + i)
                            end)
                            if ok_ob then
                                opt_hex = opt_hex .. string.format("%02x ", to_num(ob))
                            end
                        end
                        print(string.format("pkt %d: from=%s len=%d DATA=%s",
                            total_pkt, src_ip, n, hex))
                        print(string.format("  *** IP OPTIONS (%dB): %s", opt_len, opt_hex))
                    end

                    -- Align to next cmsg
                    coff = coff + math.floor((cmsg_len + 3) / 4) * 4
                end
            end

            if not has_opts then
                print(string.format("pkt %d: from=%s len=%d data=%s (no opts)",
                    total_pkt, src_ip, n, hex))
            end
        end
    end

    -- Check RAW socket (sees full IP header including options)
    if raw_fd >= 0 then
        local rev_raw = memory.read_word(pollfd + 14):tonumber()
        if rev_raw > 0 then
            memory.write_qword(riov, rbuf)
            memory.write_qword(riov + 8, 2048)
            for i = 0, 63, 8 do memory.write_qword(rmh + i, 0) end
            memory.write_qword(rmh + 16, riov)
            memory.write_qword(rmh + 24, 1)

            local ok_rr, rv_rr = pcall(function()
                return syscall.sc_recvmsg(raw_fd, rmh, MSG_DONTWAIT)
            end)
            local rn = ok_rr and rv_rr:tonumber() or -999

            if rn > 20 then
                -- Parse IP header
                local ihl_byte = memory.read_byte(rbuf):tonumber()
                local ihl = (ihl_byte % 16) * 4  -- header length in bytes
                if ihl > 20 then
                    -- IP options present in raw packet
                    local opt_hex = ""
                    for i = 20, ihl - 1 do
                        local ok_ob, ob = pcall(function()
                            return memory.read_byte(rbuf + i)
                        end)
                        if ok_ob then
                            opt_hex = opt_hex .. string.format("%02x ", to_num(ob))
                        end
                    end
                    print(string.format("  RAW: ihl=%d options(%dB): %s",
                        ihl, ihl - 20, opt_hex))
                end
            end
        end
    end

    -- Periodic heartbeat
    if iter % 100 == 0 then
        print(string.format("--- iter %d: %d packets, %d with options ---",
            iter, total_pkt, total_opts))
    end
end

-- ============================================
-- SECTION D: Summary
-- ============================================
print("")
print("=== D: SUMMARY ===")
print("total packets: " .. total_pkt)
print("packets with IP options: " .. total_opts)

pcall(function() syscall.sc_close(udp_fd) end)
if raw_fd >= 0 then pcall(function() syscall.sc_close(raw_fd) end) end

print("")
print("NOTE: if the console hung/rebooted during the loop, the PC-side")
print("ip_options_inject.py log shows which option variant was in flight.")
print("=== PROBE 46c COMPLETE ===")
