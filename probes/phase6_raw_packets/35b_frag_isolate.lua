-- 14.10 Recon Probe 35b: Isolate why fragments don't arrive
-- Probe 34: unfragmented UDP via raw+HDRINCL → arrived at listener
-- Probe 35: ALL fragments (and even test 7 unfragmented) → nothing arrived
-- Hypothesis: port mismatch, listener setup, or raw socket state issue
-- This probe tests step by step with minimal code.

print("=== 35b: FRAG ISOLATE ===")
print("fw: " .. tostring(FW_VERSION))
print("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_socket = 97,
    sc_close = 6,
    sc_sendmsg = 28,
    sc_recvmsg = 27,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
    sc_bind = 104,
    sc_poll = 209,
})

local function send_raw(fd, pkt_buf, pkt_len, dst_sa)
    local iov = memory.alloc(16)
    memory.write_qword(iov, pkt_buf)
    memory.write_qword(iov + 8, pkt_len)
    local mh = memory.alloc(64)
    for i = 0, 63, 8 do memory.write_qword(mh + i, 0) end
    memory.write_qword(mh + 0, dst_sa)
    memory.write_qword(mh + 8, 16)
    memory.write_qword(mh + 16, iov)
    memory.write_qword(mh + 24, 1)
    local ok, ret = pcall(function()
        return syscall.sc_sendmsg(fd, mh, 0x80)
    end)
    return ok and ret:tonumber() or -999
end

local function recv_dw(fd, buf, buf_len)
    local iov = memory.alloc(16)
    memory.write_qword(iov, buf)
    memory.write_qword(iov + 8, buf_len)
    local mh = memory.alloc(64)
    for i = 0, 63, 8 do memory.write_qword(mh + i, 0) end
    memory.write_qword(mh + 16, iov)
    memory.write_qword(mh + 24, 1)
    local ok, ret = pcall(function()
        return syscall.sc_recvmsg(fd, mh, 0x80)
    end)
    return ok and ret:tonumber() or -999
end

local function poll_fd(fd, ms)
    local pfd = memory.alloc(8)
    memory.write_dword(pfd, fd)
    memory.write_word(pfd + 4, 0x0001)
    memory.write_word(pfd + 6, 0)
    local ok, rv = pcall(function() return syscall.sc_poll(pfd, 1, ms) end)
    return ok and rv:tonumber() or -1, memory.read_word(pfd + 6):tonumber()
end

local function make_sa(a, b, c, d, port)
    local sa = memory.alloc(16)
    for i = 0, 15 do memory.write_byte(sa + i, 0) end
    memory.write_byte(sa + 0, 16)
    memory.write_byte(sa + 1, 2)
    memory.write_byte(sa + 2, math.floor(port / 256))
    memory.write_byte(sa + 3, port % 256)
    memory.write_byte(sa + 4, a)
    memory.write_byte(sa + 5, b)
    memory.write_byte(sa + 6, c)
    memory.write_byte(sa + 7, d)
    return sa
end

local pkt = memory.alloc(256)
local rbuf = memory.alloc(256)

-- ============================================================
-- STEP A: Exact clone of probe 34 working test
-- RAW(255) + HDRINCL + unfragmented UDP to listener
-- ============================================================
print("")
print("--- STEP A: clone probe 34 ---")

local ok1, rv1 = pcall(function() return syscall.sc_socket(2, 3, 255) end)
local raw_fd = ok1 and rv1:tonumber() or -1
print("raw_fd=" .. raw_fd)

local val = memory.alloc(4)
memory.write_dword(val, 1)
pcall(function() syscall.sc_setsockopt(raw_fd, 0, 2, val, 4) end)

-- UDP listener on port 55555
local ok_u, rv_u = pcall(function() return syscall.sc_socket(2, 2, 17) end)
local udp_fd = ok_u and rv_u:tonumber() or -1
local sa_bind = make_sa(127, 0, 0, 1, 55555)
local ok_b, rv_b = pcall(function() return syscall.sc_bind(udp_fd, sa_bind, 16) end)
print("udp_fd=" .. udp_fd .. " bind=" .. (ok_b and rv_b:tonumber() or -999))

-- Build unfragmented IP+UDP packet (exact same as probe 34 part 5)
-- IP: 20 bytes, UDP: 8 bytes, data: 4 bytes = 32 total
memory.write_byte(pkt + 0, 0x45)    -- ver=4 ihl=5
memory.write_byte(pkt + 1, 0x00)
memory.write_byte(pkt + 2, 0x00)
memory.write_byte(pkt + 3, 32)      -- total=32
memory.write_byte(pkt + 4, 0x00)
memory.write_byte(pkt + 5, 0x50)    -- ident
memory.write_byte(pkt + 6, 0x40)    -- DF flag, no frag
memory.write_byte(pkt + 7, 0x00)
memory.write_byte(pkt + 8, 64)      -- TTL
memory.write_byte(pkt + 9, 17)      -- UDP
memory.write_byte(pkt + 10, 0)
memory.write_byte(pkt + 11, 0)
memory.write_byte(pkt + 12, 127)
memory.write_byte(pkt + 13, 0)
memory.write_byte(pkt + 14, 0)
memory.write_byte(pkt + 15, 1)
memory.write_byte(pkt + 16, 127)
memory.write_byte(pkt + 17, 0)
memory.write_byte(pkt + 18, 0)
memory.write_byte(pkt + 19, 1)
-- UDP: src=12345 dst=55555
memory.write_byte(pkt + 20, 0x30)   -- 12345
memory.write_byte(pkt + 21, 0x39)
memory.write_byte(pkt + 22, 0xD9)   -- 55555 = 0xD903
memory.write_byte(pkt + 23, 0x03)
memory.write_byte(pkt + 24, 0x00)   -- udp len=12
memory.write_byte(pkt + 25, 0x0C)
memory.write_byte(pkt + 26, 0x00)   -- checksum=0
memory.write_byte(pkt + 27, 0x00)
memory.write_byte(pkt + 28, 0xBE)
memory.write_byte(pkt + 29, 0xEF)
memory.write_byte(pkt + 30, 0xCA)
memory.write_byte(pkt + 31, 0xFE)

local dst = make_sa(127, 0, 0, 1, 0)
local srv = send_raw(raw_fd, pkt, 32, dst)
print("send(unfrag): rv=" .. srv)

local prv, prev = poll_fd(udp_fd, 200)
print("poll: rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
if prev > 0 then
    local rrv = recv_dw(udp_fd, rbuf, 256)
    print("recv: rv=" .. rrv)
    if rrv > 0 then
        local h = ""
        for i = 0, math.min(rrv-1, 7) do h = h .. string.format("%02x", memory.read_byte(rbuf+i):tonumber()) end
        print("data: " .. h)
    end
    print("STEP A: PASS")
else
    print("STEP A: FAIL (unfragmented not arriving)")
end

-- ============================================================
-- STEP B: Same packet but WITHOUT DF flag (flags=0)
-- ============================================================
print("")
print("--- STEP B: no DF flag ---")

memory.write_byte(pkt + 5, 0x51)    -- new ident
memory.write_byte(pkt + 6, 0x00)    -- flags=0, offset=0 (no DF, no MF)
memory.write_byte(pkt + 7, 0x00)
memory.write_byte(pkt + 28, 0xDE)
memory.write_byte(pkt + 29, 0xAD)

srv = send_raw(raw_fd, pkt, 32, dst)
print("send(no-DF): rv=" .. srv)

prv, prev = poll_fd(udp_fd, 200)
print("poll: rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
if prev > 0 then
    local rrv = recv_dw(udp_fd, rbuf, 256)
    print("recv: rv=" .. rrv)
    if rrv > 0 then
        local h = ""
        for i = 0, math.min(rrv-1, 7) do h = h .. string.format("%02x", memory.read_byte(rbuf+i):tonumber()) end
        print("data: " .. h)
    end
    print("STEP B: PASS")
else
    print("STEP B: FAIL")
end

-- ============================================================
-- STEP C: Minimal 2-fragment test
-- Frag1: IP(20) + UDP(8) + 8 data = 36 bytes, offset=0, MF=1
-- Frag2: IP(20) + 8 data = 28 bytes, offset=2, MF=0
-- Same ident, same raw socket, same listener
-- ============================================================
print("")
print("--- STEP C: minimal 2-frag ---")

local frag_id = 0x0060

-- Frag 1: offset=0, MF=1
memory.write_byte(pkt + 0, 0x45)
memory.write_byte(pkt + 1, 0x00)
memory.write_byte(pkt + 2, 0x00)
memory.write_byte(pkt + 3, 36)      -- total_len=36 (this fragment)
memory.write_byte(pkt + 4, 0x00)    -- ident high
memory.write_byte(pkt + 5, 0x60)    -- ident low
memory.write_byte(pkt + 6, 0x20)    -- MF=1 (0x2000), offset=0
memory.write_byte(pkt + 7, 0x00)
memory.write_byte(pkt + 8, 64)
memory.write_byte(pkt + 9, 17)      -- UDP
memory.write_byte(pkt + 10, 0)
memory.write_byte(pkt + 11, 0)
memory.write_byte(pkt + 12, 127)
memory.write_byte(pkt + 13, 0)
memory.write_byte(pkt + 14, 0)
memory.write_byte(pkt + 15, 1)
memory.write_byte(pkt + 16, 127)
memory.write_byte(pkt + 17, 0)
memory.write_byte(pkt + 18, 0)
memory.write_byte(pkt + 19, 1)
-- UDP hdr
memory.write_byte(pkt + 20, 0x30)   -- src 12345
memory.write_byte(pkt + 21, 0x39)
memory.write_byte(pkt + 22, 0xD9)   -- dst 55555
memory.write_byte(pkt + 23, 0x03)
memory.write_byte(pkt + 24, 0x00)   -- udp len = 24 (8 hdr + 16 data total)
memory.write_byte(pkt + 25, 0x18)
memory.write_byte(pkt + 26, 0x00)
memory.write_byte(pkt + 27, 0x00)
-- 8 bytes data
for i = 0, 7 do memory.write_byte(pkt + 28 + i, 0xAA) end

local rv1 = send_raw(raw_fd, pkt, 36, dst)
print("frag1(off=0,MF): rv=" .. rv1)

-- Frag 2: offset=2 (=16 bytes), MF=0
memory.write_byte(pkt + 0, 0x45)
memory.write_byte(pkt + 1, 0x00)
memory.write_byte(pkt + 2, 0x00)
memory.write_byte(pkt + 3, 28)      -- total_len=28 (this fragment)
memory.write_byte(pkt + 4, 0x00)
memory.write_byte(pkt + 5, 0x60)    -- same ident
memory.write_byte(pkt + 6, 0x00)    -- MF=0, offset=2
memory.write_byte(pkt + 7, 0x02)
memory.write_byte(pkt + 8, 64)
memory.write_byte(pkt + 9, 17)
memory.write_byte(pkt + 10, 0)
memory.write_byte(pkt + 11, 0)
memory.write_byte(pkt + 12, 127)
memory.write_byte(pkt + 13, 0)
memory.write_byte(pkt + 14, 0)
memory.write_byte(pkt + 15, 1)
memory.write_byte(pkt + 16, 127)
memory.write_byte(pkt + 17, 0)
memory.write_byte(pkt + 18, 0)
memory.write_byte(pkt + 19, 1)
-- 8 bytes data
for i = 0, 7 do memory.write_byte(pkt + 20 + i, 0xBB) end

local rv2 = send_raw(raw_fd, pkt, 28, dst)
print("frag2(off=2): rv=" .. rv2)

prv, prev = poll_fd(udp_fd, 500)
print("poll(500ms): rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
if prev > 0 then
    local rrv = recv_dw(udp_fd, rbuf, 256)
    print("recv: rv=" .. rrv)
    if rrv > 0 then
        local h = ""
        for i = 0, math.min(rrv-1, 23) do h = h .. string.format("%02x", memory.read_byte(rbuf+i):tonumber()) end
        print("data: " .. h)
    end
    print("STEP C: FRAG REASSEMBLY WORKS")
else
    print("STEP C: FRAG REASSEMBLY DEAD")
end

-- ============================================================
-- STEP D: Check if raw socket RECEIVES the fragments itself
-- Raw socket with proto=17 should get copies of UDP fragments
-- ============================================================
print("")
print("--- STEP D: raw recv check ---")

-- Create a second raw socket for receiving (proto=UDP)
local ok_r2, rv_r2 = pcall(function() return syscall.sc_socket(2, 3, 17) end)
local raw_recv = ok_r2 and rv_r2:tonumber() or -1
print("raw_recv_fd=" .. raw_recv)

if raw_recv >= 0 then
    -- Bind it to loopback
    local sa_lo = make_sa(127, 0, 0, 1, 0)
    pcall(function() syscall.sc_bind(raw_recv, sa_lo, 16) end)

    -- Send a single unfragmented UDP via raw+HDRINCL
    memory.write_byte(pkt + 0, 0x45)
    memory.write_byte(pkt + 1, 0x00)
    memory.write_byte(pkt + 2, 0x00)
    memory.write_byte(pkt + 3, 32)
    memory.write_byte(pkt + 4, 0x00)
    memory.write_byte(pkt + 5, 0x70)
    memory.write_byte(pkt + 6, 0x40)    -- DF
    memory.write_byte(pkt + 7, 0x00)
    memory.write_byte(pkt + 8, 64)
    memory.write_byte(pkt + 9, 17)
    memory.write_byte(pkt + 10, 0)
    memory.write_byte(pkt + 11, 0)
    memory.write_byte(pkt + 12, 127)
    memory.write_byte(pkt + 13, 0)
    memory.write_byte(pkt + 14, 0)
    memory.write_byte(pkt + 15, 1)
    memory.write_byte(pkt + 16, 127)
    memory.write_byte(pkt + 17, 0)
    memory.write_byte(pkt + 18, 0)
    memory.write_byte(pkt + 19, 1)
    memory.write_byte(pkt + 20, 0x30)
    memory.write_byte(pkt + 21, 0x39)
    memory.write_byte(pkt + 22, 0xD9)
    memory.write_byte(pkt + 23, 0x03)
    memory.write_byte(pkt + 24, 0x00)
    memory.write_byte(pkt + 25, 0x0C)
    memory.write_byte(pkt + 26, 0x00)
    memory.write_byte(pkt + 27, 0x00)
    memory.write_byte(pkt + 28, 0x42)
    memory.write_byte(pkt + 29, 0x42)
    memory.write_byte(pkt + 30, 0x42)
    memory.write_byte(pkt + 31, 0x42)

    send_raw(raw_fd, pkt, 32, dst)
    print("sent unfrag UDP via HDRINCL")

    -- Check UDP listener
    prv, prev = poll_fd(udp_fd, 100)
    print("udp poll: rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
    if prev > 0 then
        recv_dw(udp_fd, rbuf, 256)
        print("udp: got data")
    end

    -- Check raw recv socket
    prv, prev = poll_fd(raw_recv, 100)
    print("raw_recv poll: rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
    if prev > 0 then
        local rrv = recv_dw(raw_recv, rbuf, 256)
        print("raw_recv: rv=" .. rrv)
        if rrv > 0 then
            local h = ""
            for i = 0, math.min(rrv-1, 31) do h = h .. string.format("%02x", memory.read_byte(rbuf+i):tonumber()) end
            print("raw data: " .. h)
        end
    end

    -- Now send a fragment via HDRINCL and see if raw socket sees it
    print("")
    print("sending frag via HDRINCL...")
    memory.write_byte(pkt + 5, 0x80)    -- new ident
    memory.write_byte(pkt + 6, 0x20)    -- MF=1, offset=0
    memory.write_byte(pkt + 7, 0x00)
    send_raw(raw_fd, pkt, 32, dst)

    prv, prev = poll_fd(raw_recv, 200)
    print("raw_recv(frag) poll: rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
    if prev > 0 then
        local rrv = recv_dw(raw_recv, rbuf, 256)
        print("raw_recv frag: rv=" .. rrv)
        if rrv > 0 then
            local h = ""
            for i = 0, math.min(rrv-1, 31) do h = h .. string.format("%02x", memory.read_byte(rbuf+i):tonumber()) end
            print("raw frag data: " .. h)
        end
    else
        print("raw socket also doesn't see the fragment")
    end

    pcall(function() syscall.sc_close(raw_recv) end)
end

-- ============================================================
-- STEP E: Send fragment to real interface IP instead of loopback
-- Maybe loopback skips ip_reass but real NIC doesn't
-- ============================================================
print("")
print("--- STEP E: to real IP ---")

-- We know 10.0.0.96 is the PS5. Try sending to self via real IP.
local udp2_fd = -1
local ok_u2, rv_u2 = pcall(function() return syscall.sc_socket(2, 2, 17) end)
udp2_fd = ok_u2 and rv_u2:tonumber() or -1
if udp2_fd >= 0 then
    local sa2 = make_sa(10, 0, 0, 96, 55556)
    local ok_b2, rv_b2 = pcall(function() return syscall.sc_bind(udp2_fd, sa2, 16) end)
    print("bind(10.0.0.96:55556): rv=" .. (ok_b2 and rv_b2:tonumber() or -999))

    -- Unfragmented first
    memory.write_byte(pkt + 3, 32)
    memory.write_byte(pkt + 5, 0x90)
    memory.write_byte(pkt + 6, 0x40)    -- DF
    memory.write_byte(pkt + 7, 0x00)
    -- src=10.0.0.96
    memory.write_byte(pkt + 12, 10)
    memory.write_byte(pkt + 13, 0)
    memory.write_byte(pkt + 14, 0)
    memory.write_byte(pkt + 15, 96)
    -- dst=10.0.0.96
    memory.write_byte(pkt + 16, 10)
    memory.write_byte(pkt + 17, 0)
    memory.write_byte(pkt + 18, 0)
    memory.write_byte(pkt + 19, 96)
    -- dst port 55556 = 0xD904
    memory.write_byte(pkt + 22, 0xD9)
    memory.write_byte(pkt + 23, 0x04)
    memory.write_byte(pkt + 28, 0x77)
    memory.write_byte(pkt + 29, 0x77)
    memory.write_byte(pkt + 30, 0x77)
    memory.write_byte(pkt + 31, 0x77)

    local dst2 = make_sa(10, 0, 0, 96, 0)
    send_raw(raw_fd, pkt, 32, dst2)
    print("sent unfrag to 10.0.0.96")

    prv, prev = poll_fd(udp2_fd, 200)
    print("poll: rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
    if prev > 0 then
        local rrv = recv_dw(udp2_fd, rbuf, 256)
        print("recv: rv=" .. rrv)
        print("REAL IP unfrag: WORKS")
    else
        print("REAL IP unfrag: FAILED")
    end

    -- Now try 2-frag to real IP
    print("")
    print("2-frag to real IP...")
    local fid = 0x00A0

    -- Frag1: off=0, MF=1, 16 bytes payload (UDP hdr + 8 data)
    memory.write_byte(pkt + 3, 36)
    memory.write_byte(pkt + 4, 0x00)
    memory.write_byte(pkt + 5, 0xA0)
    memory.write_byte(pkt + 6, 0x20)    -- MF=1
    memory.write_byte(pkt + 7, 0x00)
    memory.write_byte(pkt + 24, 0x00)   -- udp len=24
    memory.write_byte(pkt + 25, 0x18)
    for i = 0, 7 do memory.write_byte(pkt + 28 + i, 0xCC) end
    send_raw(raw_fd, pkt, 36, dst2)
    print("frag1: rv=ok")

    -- Frag2: off=2, MF=0, 8 bytes payload
    memory.write_byte(pkt + 3, 28)
    memory.write_byte(pkt + 6, 0x00)    -- MF=0
    memory.write_byte(pkt + 7, 0x02)    -- offset=2
    for i = 0, 7 do memory.write_byte(pkt + 20 + i, 0xDD) end
    send_raw(raw_fd, pkt, 28, dst2)
    print("frag2: rv=ok")

    prv, prev = poll_fd(udp2_fd, 500)
    print("poll(500ms): rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
    if prev > 0 then
        local rrv = recv_dw(udp2_fd, rbuf, 256)
        print("recv: rv=" .. rrv)
        if rrv > 0 then
            local h = ""
            for i = 0, math.min(rrv-1, 23) do h = h .. string.format("%02x", memory.read_byte(rbuf+i):tonumber()) end
            print("data: " .. h)
        end
        print("*** FRAG REASSEMBLY ON REAL IP WORKS ***")
    else
        print("FRAG REASSEMBLY ON REAL IP ALSO DEAD")
    end

    pcall(function() syscall.sc_close(udp2_fd) end)
end

-- Cleanup
pcall(function() syscall.sc_close(raw_fd) end)
pcall(function() syscall.sc_close(udp_fd) end)

print("")
print("=== 35b DONE ===")
