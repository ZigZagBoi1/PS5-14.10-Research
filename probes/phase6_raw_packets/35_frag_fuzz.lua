-- 14.10 Recon Probe 35: IP fragment reassembly fuzzing
-- RAW+HDRINCL confirmed working (probe 34). UDP with checksum 0 accepted.
-- Target: kernel ip_reass() — overlapping frags, tiny frags, frag bombs
-- Each test sends fragments to a UDP listener and checks what arrives.

print("=== 35: FRAG REASSEMBLY FUZZ ===")
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

local function poll_fd(fd, timeout_ms)
    local pfd = memory.alloc(8)
    memory.write_dword(pfd, fd)
    memory.write_word(pfd + 4, 0x0001)
    memory.write_word(pfd + 6, 0)
    local ok, rv = pcall(function() return syscall.sc_poll(pfd, 1, timeout_ms) end)
    return ok and rv:tonumber() or -1, memory.read_word(pfd + 6):tonumber()
end

local function make_sockaddr_in(a, b, c, d, port)
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

-- Build IP header into buf at offset 0
-- frag_off is in 8-byte units, MF = more fragments flag
-- total_len includes IP header
local function write_ip_hdr(buf, total_len, ident, MF, frag_off, proto)
    memory.write_byte(buf + 0, 0x45)       -- ver=4, ihl=5
    memory.write_byte(buf + 1, 0x00)       -- tos
    memory.write_byte(buf + 2, math.floor(total_len / 256))
    memory.write_byte(buf + 3, total_len % 256)
    memory.write_byte(buf + 4, math.floor(ident / 256))
    memory.write_byte(buf + 5, ident % 256)
    -- flags + frag offset (13 bits, in 8-byte units)
    local flags_frag = frag_off
    if MF then flags_frag = flags_frag + 0x2000 end  -- MF bit
    memory.write_byte(buf + 6, math.floor(flags_frag / 256))
    memory.write_byte(buf + 7, flags_frag % 256)
    memory.write_byte(buf + 8, 64)         -- TTL
    memory.write_byte(buf + 9, proto)      -- protocol
    memory.write_byte(buf + 10, 0)         -- checksum (kernel fills for loopback)
    memory.write_byte(buf + 11, 0)
    memory.write_byte(buf + 12, 127)       -- src
    memory.write_byte(buf + 13, 0)
    memory.write_byte(buf + 14, 0)
    memory.write_byte(buf + 15, 1)
    memory.write_byte(buf + 16, 127)       -- dst
    memory.write_byte(buf + 17, 0)
    memory.write_byte(buf + 18, 0)
    memory.write_byte(buf + 19, 1)
end

-- Fill payload bytes at buf+offset with pattern
local function fill_pattern(buf, offset, len, pat_byte)
    for i = 0, len - 1 do
        memory.write_byte(buf + offset + i, pat_byte)
    end
end

-- Setup: RAW socket + UDP listener
local ok1, rv1 = pcall(function() return syscall.sc_socket(2, 3, 255) end)
local raw_fd = ok1 and rv1:tonumber() or -1
print("raw_fd=" .. raw_fd)

local val = memory.alloc(4)
memory.write_dword(val, 1)
pcall(function() syscall.sc_setsockopt(raw_fd, 0, 2, val, 4) end)

local dst_sa = make_sockaddr_in(127, 0, 0, 1, 0)

local ok_u, rv_u = pcall(function() return syscall.sc_socket(2, 2, 17) end)
local udp_fd = ok_u and rv_u:tonumber() or -1
local sa_udp = make_sockaddr_in(127, 0, 0, 1, 44444)
pcall(function() syscall.sc_bind(udp_fd, sa_udp, 16) end)
print("udp_fd=" .. udp_fd)

local rbuf = memory.alloc(2048)
local pkt = memory.alloc(1600)

local test_id = 100  -- IP identification counter

-- ============================================================
-- TEST 1: Normal 2-fragment reassembly (baseline)
-- Fragment 1: IP(20) + UDP(8) + 8 bytes data, MF=1, offset=0
-- Fragment 2: IP(20) + 8 bytes data, MF=0, offset=2 (=16 bytes)
-- Total payload: UDP(8) + 16 bytes = reassembled
-- ============================================================
print("")
print("--- TEST 1: normal 2-frag ---")
test_id = test_id + 1

-- Frag 1: offset=0, MF=1, carries UDP header + 8 bytes
-- UDP hdr: src=11111, dst=44444, len=24 (8+16), cksum=0
write_ip_hdr(pkt, 20 + 16, test_id, true, 0, 17)
-- UDP header in payload
memory.write_byte(pkt + 20, 0x2B)   -- src port 11111 = 0x2B67
memory.write_byte(pkt + 21, 0x67)
memory.write_byte(pkt + 22, 0xAD)   -- dst port 44444 = 0xAD9C
memory.write_byte(pkt + 23, 0x9C)
memory.write_byte(pkt + 24, 0x00)   -- UDP length 24
memory.write_byte(pkt + 25, 0x18)
memory.write_byte(pkt + 26, 0x00)   -- checksum 0
memory.write_byte(pkt + 27, 0x00)
fill_pattern(pkt, 28, 8, 0xAA)      -- 8 bytes data

local rv_f1 = send_raw(raw_fd, pkt, 36, dst_sa)
print("frag1(MF,off=0): rv=" .. rv_f1)

-- Frag 2: offset=2 (=16 bytes), MF=0, 8 bytes payload
write_ip_hdr(pkt, 20 + 8, test_id, false, 2, 17)
fill_pattern(pkt, 20, 8, 0xBB)

local rv_f2 = send_raw(raw_fd, pkt, 28, dst_sa)
print("frag2(off=2): rv=" .. rv_f2)

local prv, prev = poll_fd(udp_fd, 200)
print("poll: rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
if prev > 0 then
    local rrv = recv_dw(udp_fd, rbuf, 2048)
    print("recv: rv=" .. rrv)
    if rrv > 0 then
        local hex = ""
        for i = 0, math.min(rrv - 1, 31) do
            hex = hex .. string.format("%02x", memory.read_byte(rbuf + i):tonumber())
            if i % 8 == 7 then hex = hex .. " " end
        end
        print("data: " .. hex)
    end
else
    print("NO DATA (reassembly failed or dropped)")
end

-- ============================================================
-- TEST 2: Reverse order fragments (frag2 first, then frag1)
-- ============================================================
print("")
print("--- TEST 2: reverse order ---")
test_id = test_id + 1

-- Send last fragment first
write_ip_hdr(pkt, 20 + 8, test_id, false, 2, 17)
fill_pattern(pkt, 20, 8, 0xDD)
send_raw(raw_fd, pkt, 28, dst_sa)
print("frag2 sent first")

-- Now send first fragment
write_ip_hdr(pkt, 20 + 16, test_id, true, 0, 17)
memory.write_byte(pkt + 20, 0x2B)
memory.write_byte(pkt + 21, 0x67)
memory.write_byte(pkt + 22, 0xAD)
memory.write_byte(pkt + 23, 0x9C)
memory.write_byte(pkt + 24, 0x00)
memory.write_byte(pkt + 25, 0x18)
memory.write_byte(pkt + 26, 0x00)
memory.write_byte(pkt + 27, 0x00)
fill_pattern(pkt, 28, 8, 0xCC)
send_raw(raw_fd, pkt, 36, dst_sa)
print("frag1 sent second")

prv, prev = poll_fd(udp_fd, 200)
print("poll: rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
if prev > 0 then
    local rrv = recv_dw(udp_fd, rbuf, 2048)
    print("recv: rv=" .. rrv)
    if rrv > 0 then
        local hex = ""
        for i = 0, math.min(rrv - 1, 31) do
            hex = hex .. string.format("%02x", memory.read_byte(rbuf + i):tonumber())
            if i % 8 == 7 then hex = hex .. " " end
        end
        print("data: " .. hex)
    end
end

-- ============================================================
-- TEST 3: Overlapping fragments (classic teardrop)
-- Frag1: offset=0, 24 bytes payload (UDP hdr + 16 data), MF=1
-- Frag2: offset=2 (16 bytes), 16 bytes payload, MF=0
-- Overlap: frag2 starts at byte 16, frag1 covers bytes 0-23
-- So bytes 16-23 are covered by BOTH fragments
-- ============================================================
print("")
print("--- TEST 3: overlapping (teardrop) ---")
test_id = test_id + 1

-- Frag1: offset=0, MF=1, 24 bytes payload
write_ip_hdr(pkt, 20 + 24, test_id, true, 0, 17)
memory.write_byte(pkt + 20, 0x2B)
memory.write_byte(pkt + 21, 0x67)
memory.write_byte(pkt + 22, 0xAD)
memory.write_byte(pkt + 23, 0x9C)
memory.write_byte(pkt + 24, 0x00)
memory.write_byte(pkt + 25, 0x28)   -- UDP len 40
memory.write_byte(pkt + 26, 0x00)
memory.write_byte(pkt + 27, 0x00)
fill_pattern(pkt, 28, 16, 0x11)     -- 16 bytes of 0x11

local rv_t3a = send_raw(raw_fd, pkt, 44, dst_sa)
print("frag1(0-23,MF): rv=" .. rv_t3a)

-- Frag2: offset=2 (byte 16), MF=0, 16 bytes payload (overlaps 8 bytes)
write_ip_hdr(pkt, 20 + 16, test_id, false, 2, 17)
fill_pattern(pkt, 20, 16, 0x22)     -- 16 bytes of 0x22

local rv_t3b = send_raw(raw_fd, pkt, 36, dst_sa)
print("frag2(16-31,overlap): rv=" .. rv_t3b)

prv, prev = poll_fd(udp_fd, 200)
print("poll: rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
if prev > 0 then
    local rrv = recv_dw(udp_fd, rbuf, 2048)
    print("recv: rv=" .. rrv .. " (overlap result)")
    if rrv > 0 then
        local hex = ""
        for i = 0, math.min(rrv - 1, 39) do
            hex = hex .. string.format("%02x", memory.read_byte(rbuf + i):tonumber())
            if i % 8 == 7 then hex = hex .. " " end
        end
        print("data: " .. hex)
    end
end

-- ============================================================
-- TEST 4: Tiny fragment (8-byte payload, minimum)
-- ============================================================
print("")
print("--- TEST 4: tiny fragments ---")
test_id = test_id + 1

-- 4 fragments of 8 bytes each = 32 bytes total
-- Frag0: UDP hdr (8 bytes), offset=0, MF=1
write_ip_hdr(pkt, 20 + 8, test_id, true, 0, 17)
memory.write_byte(pkt + 20, 0x2B)
memory.write_byte(pkt + 21, 0x67)
memory.write_byte(pkt + 22, 0xAD)
memory.write_byte(pkt + 23, 0x9C)
memory.write_byte(pkt + 24, 0x00)
memory.write_byte(pkt + 25, 0x20)   -- UDP len 32
memory.write_byte(pkt + 26, 0x00)
memory.write_byte(pkt + 27, 0x00)
send_raw(raw_fd, pkt, 28, dst_sa)

-- Frag1: 8 bytes, offset=1, MF=1
write_ip_hdr(pkt, 20 + 8, test_id, true, 1, 17)
fill_pattern(pkt, 20, 8, 0x41)
send_raw(raw_fd, pkt, 28, dst_sa)

-- Frag2: 8 bytes, offset=2, MF=1
write_ip_hdr(pkt, 20 + 8, test_id, true, 2, 17)
fill_pattern(pkt, 20, 8, 0x42)
send_raw(raw_fd, pkt, 28, dst_sa)

-- Frag3: 8 bytes, offset=3, MF=0 (last)
write_ip_hdr(pkt, 20 + 8, test_id, false, 3, 17)
fill_pattern(pkt, 20, 8, 0x43)
send_raw(raw_fd, pkt, 28, dst_sa)
print("sent 4x8-byte frags")

prv, prev = poll_fd(udp_fd, 200)
print("poll: rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
if prev > 0 then
    local rrv = recv_dw(udp_fd, rbuf, 2048)
    print("recv: rv=" .. rrv)
    if rrv > 0 then
        local hex = ""
        for i = 0, math.min(rrv - 1, 31) do
            hex = hex .. string.format("%02x", memory.read_byte(rbuf + i):tonumber())
            if i % 8 == 7 then hex = hex .. " " end
        end
        print("data: " .. hex)
    end
end

-- ============================================================
-- TEST 5: Duplicate fragment (same offset twice)
-- ============================================================
print("")
print("--- TEST 5: duplicate fragment ---")
test_id = test_id + 1

-- Frag0: UDP hdr + 8 data, offset=0, MF=1
write_ip_hdr(pkt, 20 + 16, test_id, true, 0, 17)
memory.write_byte(pkt + 20, 0x2B)
memory.write_byte(pkt + 21, 0x67)
memory.write_byte(pkt + 22, 0xAD)
memory.write_byte(pkt + 23, 0x9C)
memory.write_byte(pkt + 24, 0x00)
memory.write_byte(pkt + 25, 0x18)
memory.write_byte(pkt + 26, 0x00)
memory.write_byte(pkt + 27, 0x00)
fill_pattern(pkt, 28, 8, 0x55)
send_raw(raw_fd, pkt, 36, dst_sa)

-- Duplicate frag0 with DIFFERENT data
write_ip_hdr(pkt, 20 + 16, test_id, true, 0, 17)
memory.write_byte(pkt + 20, 0x2B)
memory.write_byte(pkt + 21, 0x67)
memory.write_byte(pkt + 22, 0xAD)
memory.write_byte(pkt + 23, 0x9C)
memory.write_byte(pkt + 24, 0x00)
memory.write_byte(pkt + 25, 0x18)
memory.write_byte(pkt + 26, 0x00)
memory.write_byte(pkt + 27, 0x00)
fill_pattern(pkt, 28, 8, 0x66)
send_raw(raw_fd, pkt, 36, dst_sa)
print("sent duplicate frag0")

-- Final frag
write_ip_hdr(pkt, 20 + 8, test_id, false, 2, 17)
fill_pattern(pkt, 20, 8, 0x77)
send_raw(raw_fd, pkt, 28, dst_sa)

prv, prev = poll_fd(udp_fd, 200)
print("poll: rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
if prev > 0 then
    local rrv = recv_dw(udp_fd, rbuf, 2048)
    print("recv: rv=" .. rrv)
    if rrv > 0 then
        local hex = ""
        for i = 0, math.min(rrv - 1, 31) do
            hex = hex .. string.format("%02x", memory.read_byte(rbuf + i):tonumber())
            if i % 8 == 7 then hex = hex .. " " end
        end
        print("data: " .. hex)
        -- Check which data won in the overlap
        local b8 = memory.read_byte(rbuf + 0):tonumber()
        if b8 == 0x55 then print("FIRST frag data kept")
        elseif b8 == 0x66 then print("SECOND (dup) frag data kept")
        else print("UNEXPECTED data: " .. string.format("0x%02x", b8)) end
    end
end

-- ============================================================
-- TEST 6: Fragment with offset but no first fragment (orphan)
-- Then send first fragment late — tests queue timeout behavior
-- ============================================================
print("")
print("--- TEST 6: orphan then late first ---")
test_id = test_id + 1

-- Frag at offset=2, MF=0 (final, but no frag0 yet)
write_ip_hdr(pkt, 20 + 8, test_id, false, 2, 17)
fill_pattern(pkt, 20, 8, 0x88)
send_raw(raw_fd, pkt, 28, dst_sa)
print("orphan frag2 sent")

-- Quick poll — should not reassemble yet
prv, prev = poll_fd(udp_fd, 50)
print("poll(50ms): rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))

-- Now send frag0 (late)
write_ip_hdr(pkt, 20 + 16, test_id, true, 0, 17)
memory.write_byte(pkt + 20, 0x2B)
memory.write_byte(pkt + 21, 0x67)
memory.write_byte(pkt + 22, 0xAD)
memory.write_byte(pkt + 23, 0x9C)
memory.write_byte(pkt + 24, 0x00)
memory.write_byte(pkt + 25, 0x18)
memory.write_byte(pkt + 26, 0x00)
memory.write_byte(pkt + 27, 0x00)
fill_pattern(pkt, 28, 8, 0x99)
send_raw(raw_fd, pkt, 36, dst_sa)
print("late frag0 sent")

prv, prev = poll_fd(udp_fd, 200)
print("poll: rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
if prev > 0 then
    local rrv = recv_dw(udp_fd, rbuf, 2048)
    print("recv: rv=" .. rrv)
end

-- ============================================================
-- TEST 7: Zero-offset fragment with MF=0 and non-zero offset with MF=0
-- (conflicting "last fragment" indicators)
-- ============================================================
print("")
print("--- TEST 7: conflicting last-frag ---")
test_id = test_id + 1

-- Two fragments both claiming to be last (MF=0)
-- Frag at offset=0, MF=0 (claims total = 16 bytes)
write_ip_hdr(pkt, 20 + 16, test_id, false, 0, 17)
memory.write_byte(pkt + 20, 0x2B)
memory.write_byte(pkt + 21, 0x67)
memory.write_byte(pkt + 22, 0xAD)
memory.write_byte(pkt + 23, 0x9C)
memory.write_byte(pkt + 24, 0x00)
memory.write_byte(pkt + 25, 0x10)
memory.write_byte(pkt + 26, 0x00)
memory.write_byte(pkt + 27, 0x00)
fill_pattern(pkt, 28, 8, 0xA1)
send_raw(raw_fd, pkt, 36, dst_sa)

-- But offset=0,MF=0 is NOT a fragment — it's a complete packet!
-- So it should just be delivered as-is
prv, prev = poll_fd(udp_fd, 100)
print("complete pkt poll: rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
if prev > 0 then
    local rrv = recv_dw(udp_fd, rbuf, 2048)
    print("recv: rv=" .. rrv)
end

-- ============================================================
-- TEST 8: Large reassembled packet (near 64KB)
-- Many fragments building toward a large buffer
-- Tests ip_reass mbuf chain handling
-- ============================================================
print("")
print("--- TEST 8: large reassembly (1024 bytes) ---")
test_id = test_id + 1

-- 1024 byte payload = UDP(8) + 1016 data
-- Fragment size: 128 bytes payload each = 8 fragments + 1 first w/ UDP
-- Frag0: UDP hdr(8) + 120 bytes = 128 payload, offset=0, MF=1
write_ip_hdr(pkt, 20 + 128, test_id, true, 0, 17)
memory.write_byte(pkt + 20, 0x2B)
memory.write_byte(pkt + 21, 0x67)
memory.write_byte(pkt + 22, 0xAD)
memory.write_byte(pkt + 23, 0x9C)
memory.write_byte(pkt + 24, 0x04)   -- UDP len 1024
memory.write_byte(pkt + 25, 0x00)
memory.write_byte(pkt + 26, 0x00)
memory.write_byte(pkt + 27, 0x00)
fill_pattern(pkt, 28, 120, 0xF0)
send_raw(raw_fd, pkt, 148, dst_sa)

-- Frags 1-6: 128 bytes each, MF=1
for f = 1, 6 do
    -- offset in 8-byte units: f * 16
    write_ip_hdr(pkt, 20 + 128, test_id, true, f * 16, 17)
    fill_pattern(pkt, 20, 128, 0xF0 + f)
    send_raw(raw_fd, pkt, 148, dst_sa)
end

-- Last frag: remaining bytes. Total=1024, sent=128*7=896, remaining=128
write_ip_hdr(pkt, 20 + 128, test_id, false, 7 * 16, 17)
fill_pattern(pkt, 20, 128, 0xF8)
send_raw(raw_fd, pkt, 148, dst_sa)
print("sent 8 frags (1024 byte total)")

prv, prev = poll_fd(udp_fd, 300)
print("poll: rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
if prev > 0 then
    local rrv = recv_dw(udp_fd, rbuf, 2048)
    print("recv: rv=" .. rrv)
    if rrv > 0 then
        -- Show first and last 8 bytes
        local hex1 = ""
        for i = 0, 7 do hex1 = hex1 .. string.format("%02x", memory.read_byte(rbuf + i):tonumber()) end
        local hex2 = ""
        local start = math.max(0, rrv - 8)
        for i = start, rrv - 1 do hex2 = hex2 .. string.format("%02x", memory.read_byte(rbuf + i):tonumber()) end
        print("first8: " .. hex1 .. " last8: " .. hex2)
    end
end

-- ============================================================
-- TEST 9: Fragment bomb — 64 unique IDs, each with orphan frag
-- Stress the fragment reassembly queue
-- ============================================================
print("")
print("--- TEST 9: frag bomb (64 orphans) ---")

for i = 0, 63 do
    local bomb_id = 5000 + i
    write_ip_hdr(pkt, 20 + 8, bomb_id, true, 1, 17)
    fill_pattern(pkt, 20, 8, i)
    send_raw(raw_fd, pkt, 28, dst_sa)
end
print("sent 64 orphan fragments")

-- Check if we can still do normal reassembly after the bomb
test_id = test_id + 1
write_ip_hdr(pkt, 20 + 16, test_id, true, 0, 17)
memory.write_byte(pkt + 20, 0x2B)
memory.write_byte(pkt + 21, 0x67)
memory.write_byte(pkt + 22, 0xAD)
memory.write_byte(pkt + 23, 0x9C)
memory.write_byte(pkt + 24, 0x00)
memory.write_byte(pkt + 25, 0x10)
memory.write_byte(pkt + 26, 0x00)
memory.write_byte(pkt + 27, 0x00)
fill_pattern(pkt, 28, 8, 0xEE)
send_raw(raw_fd, pkt, 36, dst_sa)

write_ip_hdr(pkt, 20 + 8, test_id, false, 2, 17)
fill_pattern(pkt, 20, 8, 0xFF)
send_raw(raw_fd, pkt, 28, dst_sa)
print("sent normal 2-frag after bomb")

prv, prev = poll_fd(udp_fd, 200)
print("post-bomb poll: rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
if prev > 0 then
    local rrv = recv_dw(udp_fd, rbuf, 2048)
    print("recv: rv=" .. rrv .. " (reassembly still works)")
else
    print("*** REASSEMBLY BROKEN AFTER BOMB ***")
end

-- ============================================================
-- TEST 10: Fragment with impossibly large offset
-- offset=8191 (max 13-bit) = byte offset 65528
-- Total implied size near 64KB — tests size limit checks
-- ============================================================
print("")
print("--- TEST 10: max offset fragment ---")
test_id = test_id + 1

-- First fragment (so reassembly queue is started)
write_ip_hdr(pkt, 20 + 8, test_id, true, 0, 17)
memory.write_byte(pkt + 20, 0x2B)
memory.write_byte(pkt + 21, 0x67)
memory.write_byte(pkt + 22, 0xAD)
memory.write_byte(pkt + 23, 0x9C)
memory.write_byte(pkt + 24, 0x00)
memory.write_byte(pkt + 25, 0x08)
memory.write_byte(pkt + 26, 0x00)
memory.write_byte(pkt + 27, 0x00)
send_raw(raw_fd, pkt, 28, dst_sa)

-- Fragment at max offset (8191 * 8 = 65528)
write_ip_hdr(pkt, 20 + 8, test_id, false, 8191, 17)
fill_pattern(pkt, 20, 8, 0xDE)
local rv_max = send_raw(raw_fd, pkt, 28, dst_sa)
print("max_offset frag: rv=" .. rv_max)

prv, prev = poll_fd(udp_fd, 200)
print("poll: rv=" .. prv .. " rev=0x" .. string.format("%04x", prev))
if prev > 0 then
    local rrv = recv_dw(udp_fd, rbuf, 2048)
    print("recv: rv=" .. rrv .. " *** LARGE REASSEMBLY ACCEPTED ***")
else
    print("rejected (expected — exceeds 64KB)")
end

-- Cleanup
pcall(function() syscall.sc_close(raw_fd) end)
pcall(function() syscall.sc_close(udp_fd) end)

print("")
print("=== 35 FRAG FUZZ DONE ===")
