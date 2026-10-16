-- 14.10 Recon Probe 33e: MSG_DONTWAIT nonblocking I/O
-- F_SETFL NONBLOCK is cosmetic only. Test per-call MSG_DONTWAIT (0x80).
-- NO blocking reads or writes in this probe.

print("=== 33e: MSG_DONTWAIT ===")
print("fw: " .. tostring(FW_VERSION))
print("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_socketpair = 135,
    sc_close = 6,
    sc_write = 4,
    sc_read = 3,
    sc_sendmsg = 28,
    sc_recvmsg = 27,
    sc_sendto = 133,
    sc_recvfrom = 29,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
    sc_fcntl = 92,
})

local sp = memory.alloc(8)

-- Helper: sendmsg with MSG_DONTWAIT
local function send_dw(fd, data_buf, data_len)
    local iov = memory.alloc(16)
    memory.write_qword(iov, data_buf)
    memory.write_qword(iov + 8, data_len)
    local mh = memory.alloc(64)
    for i = 0, 63, 8 do memory.write_qword(mh + i, 0) end
    memory.write_qword(mh + 16, iov)
    memory.write_qword(mh + 24, 1)
    local ok, ret = pcall(function()
        return syscall.sc_sendmsg(fd, mh, 0x80)
    end)
    return ok and ret:tonumber() or -999
end

-- Helper: recvmsg with MSG_DONTWAIT
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

-- ============================================================
-- PART 1: Basic MSG_DONTWAIT test
-- ============================================================
print("")
print("--- PART 1: MSG_DONTWAIT basic ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local sa = memory.read_dword(sp):tonumber()
local sb = memory.read_dword(sp + 4):tonumber()
print("pair: " .. sa .. "," .. sb)

-- Recv on empty socket — should EAGAIN immediately
local rb = memory.alloc(64)
local rv_re = recv_dw(sa, rb, 64)
print("recv(empty, DONTWAIT): rv=" .. rv_re)

-- Send 8 bytes
local wb = memory.alloc(8)
memory.write_qword(wb, 0xDEADBEEFCAFE0001)
local rv_s1 = send_dw(sa, wb, 8)
print("send(8, DONTWAIT): rv=" .. rv_s1)

-- Recv should get data
local rv_r1 = recv_dw(sb, rb, 64)
print("recv(DONTWAIT): rv=" .. rv_r1)
print("  data: 0x" .. string.format("%016x", memory.read_qword(rb):tonumber()))

-- Recv again — empty, should EAGAIN
local rv_r2 = recv_dw(sb, rb, 64)
print("recv(empty again): rv=" .. rv_r2)

pcall(function() syscall.sc_close(sa) end)
pcall(function() syscall.sc_close(sb) end)

-- ============================================================
-- PART 2: SNDBUF=1 with MSG_DONTWAIT
-- ============================================================
print("")
print("--- PART 2: SNDBUF=1 + DONTWAIT ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
sa = memory.read_dword(sp):tonumber()
sb = memory.read_dword(sp + 4):tonumber()

local val = memory.alloc(4)
memory.write_dword(val, 1)
pcall(function() syscall.sc_setsockopt(sa, 0xFFFF, 0x1001, val, 4) end)
print("SNDBUF=1 set")

-- Send 1 byte — should succeed
memory.write_byte(wb, 0x41)
local rv_s2 = send_dw(sa, wb, 1)
print("send1(1): rv=" .. rv_s2)

-- Send again — buffer full, should EAGAIN
local rv_s3 = send_dw(sa, wb, 1)
print("send2(1, full): rv=" .. rv_s3)

-- Send 4 bytes — too big for SNDBUF=1
memory.write_dword(wb, 0xDEAD)
local rv_s4 = send_dw(sa, wb, 4)
print("send3(4, full): rv=" .. rv_s4)

-- Drain
local rv_dr = recv_dw(sb, rb, 64)
print("drain: rv=" .. rv_dr)

-- Send 4 after drain
local rv_s5 = send_dw(sa, wb, 4)
print("send4(4, drained): rv=" .. rv_s5)

-- Send 1024
local big = memory.alloc(1024)
memory.write_dword(big, 0xBEEF)
local rv_s6 = send_dw(sa, big, 1024)
print("send5(1024): rv=" .. rv_s6)

-- Drain all
local rv_dr2 = recv_dw(sb, rb, 64)
print("drain2: rv=" .. rv_dr2)

-- Rapid fire: send/recv cycle 100 times
local ok_count = 0
for i = 1, 100 do
    memory.write_byte(wb, i)
    local srv = send_dw(sa, wb, 1)
    if srv == 1 then
        local rrv = recv_dw(sb, rb, 1)
        if rrv == 1 then ok_count = ok_count + 1 end
    end
end
print("rapid fire 100x: " .. ok_count .. " ok")

pcall(function() syscall.sc_close(sa) end)
pcall(function() syscall.sc_close(sb) end)

-- ============================================================
-- PART 3: RCVBUF=1 + SNDBUF=1 stress
-- ============================================================
print("")
print("--- PART 3: both buf=1 ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
sa = memory.read_dword(sp):tonumber()
sb = memory.read_dword(sp + 4):tonumber()

memory.write_dword(val, 1)
pcall(function() syscall.sc_setsockopt(sa, 0xFFFF, 0x1001, val, 4) end)
pcall(function() syscall.sc_setsockopt(sb, 0xFFFF, 0x1002, val, 4) end)
print("SNDBUF=1 + RCVBUF=1")

-- Send 1 byte
local rv_b1 = send_dw(sa, wb, 1)
print("send(1): rv=" .. rv_b1)

-- Send another — should EAGAIN
local rv_b2 = send_dw(sa, wb, 1)
print("send(1, full): rv=" .. rv_b2)

-- Large send
local rv_b3 = send_dw(sa, big, 1024)
print("send(1024): rv=" .. rv_b3)

-- Drain
local rv_b4 = recv_dw(sb, rb, 64)
print("drain: rv=" .. rv_b4)

-- Repeat send+drain 50 times
local ok3 = 0
for i = 1, 50 do
    memory.write_byte(wb, i)
    local s = send_dw(sa, wb, 1)
    if s == 1 then
        local r = recv_dw(sb, rb, 1)
        if r == 1 then ok3 = ok3 + 1 end
    end
end
print("50x send/recv: " .. ok3 .. " ok")

pcall(function() syscall.sc_close(sa) end)
pcall(function() syscall.sc_close(sb) end)

-- ============================================================
-- PART 4: sendto/recvfrom with MSG_DONTWAIT
-- ============================================================
print("")
print("--- PART 4: sendto/recvfrom ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
sa = memory.read_dword(sp):tonumber()
sb = memory.read_dword(sp + 4):tonumber()

-- sendto with MSG_DONTWAIT (flags in arg4)
memory.write_dword(wb, 0xAAAA)
local ok_st, rv_st = pcall(function()
    return syscall.sc_sendto(sa, wb, 4, 0x80, 0, 0) -- MSG_DONTWAIT, no addr
end)
print("sendto(DONTWAIT): rv=" .. (ok_st and rv_st:tonumber() or -999))

-- recvfrom with MSG_DONTWAIT
local from = memory.alloc(32)
local fromlen = memory.alloc(8)
memory.write_qword(fromlen, 32)
local ok_rf, rv_rf = pcall(function()
    return syscall.sc_recvfrom(sb, rb, 64, 0x80, from, fromlen)
end)
print("recvfrom(DONTWAIT): rv=" .. (ok_rf and rv_rf:tonumber() or -999))

-- recvfrom on empty
local ok_rf2, rv_rf2 = pcall(function()
    return syscall.sc_recvfrom(sb, rb, 64, 0x80, from, fromlen)
end)
print("recvfrom(empty): rv=" .. (ok_rf2 and rv_rf2:tonumber() or -999))

pcall(function() syscall.sc_close(sa) end)
pcall(function() syscall.sc_close(sb) end)

print("")
print("=== MSG_DONTWAIT DONE ===")
