-- 14.10 Probe 39: IP fragment reassembly (retry of 35/35b with fixed bind)
-- Target: ip_reass() — historically one of the buggiest paths in BSD.
-- Cases: baseline, out-of-order, overlap, tiny-first, dup-final-overwrite.
-- Detection: UDP listener receives reassembled datagram (or console dies).

print("=== 39: FRAGMENT REASSEMBLY ===")
print("fw: " .. tostring(FW_VERSION))
print("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_socket = 97,
    sc_bind = 104,
    sc_close = 6,
    sc_sendmsg = 28,
    sc_recvmsg = 27,
    sc_setsockopt = 105,
    sc_poll = 209,
})

local MSG_DONTWAIT = 0x80

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

local function ip_checksum(buf, len)
    local sum = 0
    local i = 0
    while i + 1 < len do
        sum = sum + memory.read_byte(buf + i):tonumber() * 256
              + memory.read_byte(buf + i + 1):tonumber()
        i = i + 2
    end
    while sum > 0xFFFF do
        sum = math.floor(sum / 65536) + (sum % 65536)
    end
    return 0xFFFF - sum
end

-- RAW socket
local ok_r, rv_r = pcall(function() return syscall.sc_socket(2, 3, 255) end)
local raw_fd = ok_r and rv_r:tonumber() or -1
if raw_fd < 0 then
    print("no raw socket"); print("=== 39 DONE (no raw) ===")
    return
end
local val = memory.alloc(4)
memory.write_dword(val, 1)
pcall(function() syscall.sc_setsockopt(raw_fd, 0, 2, val, 4) end)

-- UDP listener: candidate ports until bind works
local udp_fd, listen_port = -1, 0
for _, p in ipairs({31338, 31337, 9027, 40000, 50000, 1234}) do
    local ok_s, rv_s = pcall(function() return syscall.sc_socket(2, 2, 17) end)
    local fd = ok_s and rv_s:tonumber() or -1
    if fd >= 0 then
        local sa = make_sockaddr_in(127, 0, 0, 1, p)
        local ok_b, rv_b = pcall(function() return syscall.sc_bind(fd, sa, 16) end)
        if ok_b and rv_b:tonumber() == 0 then
            udp_fd, listen_port = fd, p
            break
        end
        pcall(function() syscall.sc_close(fd) end)
    end
end
if udp_fd < 0 then
    print("no bindable UDP port — run probe 36")
    print("=== 39 DONE (no listener) ===")
    return
end
print("listener: 127.0.0.1:" .. listen_port .. " fd=" .. udp_fd)

-- send one IP fragment. data = byte array, frag_off in BYTES, mf = bool
local ident = 0x1000
local function send_frag(data, frag_off, mf, proto)
    local total = 20 + #data
    local pkt = memory.alloc(total)
    for i = 0, total - 1 do memory.write_byte(pkt + i, 0) end
    memory.write_byte(pkt + 0, 0x45)
    memory.write_byte(pkt + 1, 0x00)
    memory.write_byte(pkt + 2, math.floor(total / 256))
    memory.write_byte(pkt + 3, total % 256)
    memory.write_byte(pkt + 4, math.floor(ident / 256))
    memory.write_byte(pkt + 5, ident % 256)
    local fo = math.floor(frag_off / 8) + (mf and 0x2000 or 0)
    memory.write_byte(pkt + 6, math.floor(fo / 256))
    memory.write_byte(pkt + 7, fo % 256)
    memory.write_byte(pkt + 8, 64)
    memory.write_byte(pkt + 9, proto or 17)
    memory.write_byte(pkt + 12, 127)
    memory.write_byte(pkt + 15, 1)
    memory.write_byte(pkt + 16, 127)
    memory.write_byte(pkt + 19, 1)
    for i, b in ipairs(data) do
        memory.write_byte(pkt + 19 + i, b)
    end
    local cks = ip_checksum(pkt, 20)
    memory.write_byte(pkt + 10, math.floor(cks / 256))
    memory.write_byte(pkt + 11, cks % 256)

    local iov = memory.alloc(16)
    memory.write_qword(iov, pkt)
    memory.write_qword(iov + 8, total)
    local mh = memory.alloc(64)
    for i = 0, 63, 8 do memory.write_qword(mh + i, 0) end
    local sa = make_sockaddr_in(127, 0, 0, 1, 0)
    memory.write_qword(mh + 0, sa)
    memory.write_qword(mh + 8, 16)
    memory.write_qword(mh + 16, iov)
    memory.write_qword(mh + 24, 1)
    local ok, ret = pcall(function() return syscall.sc_sendmsg(raw_fd, mh, MSG_DONTWAIT) end)
    return ok and ret:tonumber() or -999
end

-- Build a full UDP datagram as byte array (hdr + payload), then slice it.
local function make_udp(payload)
    local udp_len = 8 + #payload
    local d = {}
    table.insert(d, 0x30); table.insert(d, 0x39)               -- src 12345
    table.insert(d, math.floor(listen_port / 256))
    table.insert(d, listen_port % 256)                          -- dst
    table.insert(d, math.floor(udp_len / 256))
    table.insert(d, udp_len % 256)                              -- len
    table.insert(d, 0); table.insert(d, 0)                      -- csum 0
    for _, b in ipairs(payload) do table.insert(d, b) end
    return d
end

local function slice(t, i, j)
    local o = {}
    for k = i, j do table.insert(o, t[k]) end
    return o
end

local function drain(tag)
    local pollfd = memory.alloc(8)
    memory.write_dword(pollfd, udp_fd)
    memory.write_word(pollfd + 4, 0x0001)
    memory.write_word(pollfd + 6, 0)
    pcall(function() syscall.sc_poll(pollfd, 1, 200) end)
    local rev = memory.read_word(pollfd + 6):tonumber()
    if rev > 0 then
        local rbuf = memory.alloc(128)
        local iov = memory.alloc(16)
        memory.write_qword(iov, rbuf)
        memory.write_qword(iov + 8, 128)
        local mh = memory.alloc(64)
        for i = 0, 63, 8 do memory.write_qword(mh + i, 0) end
        memory.write_qword(mh + 16, iov)
        memory.write_qword(mh + 24, 1)
        local ok_rr, rv_rr = pcall(function() return syscall.sc_recvmsg(udp_fd, mh, MSG_DONTWAIT) end)
        local n = ok_rr and rv_rr:tonumber() or -999
        local hex = ""
        if n > 0 then
            for i = 0, math.min(n - 1, 23) do
                hex = hex .. string.format("%02x", memory.read_byte(rbuf + i):tonumber())
            end
        end
        print(string.format("%-26s REASSEMBLED recv=%d data=%s", tag, n, hex))
    else
        print(string.format("%-26s no delivery", tag))
    end
end

local P16 = {0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
             0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,0x50}

print("")
print("--- reassembly cases ---")

-- Case 1: baseline, in-order, 2 fragments (16 + 8 bytes)
ident = 0x2001
local dg = make_udp(P16)
send_frag(slice(dg, 1, 16), 0, true)
send_frag(slice(dg, 17, 24), 16, false)
drain("baseline 2-frag")

-- Case 2: out-of-order (second fragment first)
ident = 0x2002
send_frag(slice(dg, 17, 24), 16, false)
send_frag(slice(dg, 1, 16), 0, true)
drain("out-of-order")

-- Case 3: overlapping fragments — frag2 starts 8 bytes early,
-- conflicting data in the overlap region
ident = 0x2003
send_frag(slice(dg, 1, 16), 0, true)
send_frag(slice(dg, 9, 24), 8, false)   -- overlaps bytes 8..15
drain("overlap -8B")

-- Case 4: tiny first fragment (8 bytes), then rest
ident = 0x2004
send_frag(slice(dg, 1, 8), 0, true)
send_frag(slice(dg, 9, 24), 8, false)
drain("tiny-first 8B")

-- Case 5: duplicate final fragment with DIFFERENT data (overwrite test)
ident = 0x2005
send_frag(slice(dg, 1, 16), 0, true)
send_frag(slice(dg, 17, 24), 16, false)
local evil = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}
send_frag(evil, 16, false)
drain("dup-final-overwrite")

-- Case 6: many 8-byte fragments (stress reassembly queue)
ident = 0x2006
local big = {}
for i = 1, 64 do table.insert(big, i % 256) end
local dg64 = make_udp(big)   -- 72 bytes = 9 fragments of 8
for f = 0, 7 do
    send_frag(slice(dg64, f * 8 + 1, f * 8 + 8), f * 8, true)
end
send_frag(slice(dg64, 65, 72), 64, false)
drain("9x 8-byte frags")

-- Case 7: fragment with bogus protocol (47=GRE) — exercises non-UDP reass path
ident = 0x2007
send_frag(slice(dg, 1, 16), 0, true, 47)
send_frag(slice(dg, 17, 24), 16, false, 47)
drain("proto=47 frags (expect none)")

print("")
print("NOTE: a queue-size or overlap handling bug here typically shows as a")
print("hang/reboot mid-case. Last tag printed before silence = suspect case.")
print("=== 39 DONE ===")
