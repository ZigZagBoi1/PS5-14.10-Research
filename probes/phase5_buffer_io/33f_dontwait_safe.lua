-- 14.10 Recon Probe 33f: MSG_DONTWAIT (safe version)
-- No sendto/recvfrom — those may crash resolve

print("=== 33f: DONTWAIT SAFE ===")
print("fw: " .. tostring(FW_VERSION))
print("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_socketpair = 135,
    sc_close = 6,
    sc_sendmsg = 28,
    sc_recvmsg = 27,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
})

local sp = memory.alloc(8)

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

-- PART 1: Basic MSG_DONTWAIT
print("")
print("--- PART 1: basic ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local sa = memory.read_dword(sp):tonumber()
local sb = memory.read_dword(sp + 4):tonumber()
print("pair: " .. sa .. "," .. sb)

local rb = memory.alloc(64)
local rv_re = recv_dw(sa, rb, 64)
print("recv(empty): rv=" .. rv_re)

local wb = memory.alloc(8)
memory.write_qword(wb, 0xDEADBEEFCAFE0001)
local rv_s1 = send_dw(sa, wb, 8)
print("send(8): rv=" .. rv_s1)

local rv_r1 = recv_dw(sb, rb, 64)
print("recv: rv=" .. rv_r1)

local rv_r2 = recv_dw(sb, rb, 64)
print("recv(empty2): rv=" .. rv_r2)

pcall(function() syscall.sc_close(sa) end)
pcall(function() syscall.sc_close(sb) end)

-- PART 2: SNDBUF=1 + DONTWAIT
print("")
print("--- PART 2: SNDBUF=1 ---")

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
sa = memory.read_dword(sp):tonumber()
sb = memory.read_dword(sp + 4):tonumber()

local val = memory.alloc(4)
memory.write_dword(val, 1)
pcall(function() syscall.sc_setsockopt(sa, 0xFFFF, 0x1001, val, 4) end)
print("SNDBUF=1")

memory.write_byte(wb, 0x41)
print("send1(1): rv=" .. send_dw(sa, wb, 1))
print("send2(1,full): rv=" .. send_dw(sa, wb, 1))

-- Drain
print("drain: rv=" .. recv_dw(sb, rb, 64))

print("send3(4): rv=" .. send_dw(sa, wb, 4))
print("drain2: rv=" .. recv_dw(sb, rb, 64))

-- Rapid fire
local ok_count = 0
for i = 1, 100 do
    memory.write_byte(wb, i)
    if send_dw(sa, wb, 1) == 1 then
        if recv_dw(sb, rb, 1) == 1 then
            ok_count = ok_count + 1
        end
    end
end
print("rapid 100x: " .. ok_count .. " ok")

-- PART 3: both buf=1
print("")
print("--- PART 3: both=1 ---")
memory.write_dword(val, 1)
pcall(function() syscall.sc_setsockopt(sb, 0xFFFF, 0x1002, val, 4) end)
print("RCVBUF=1 on sb")

local ok3 = 0
for i = 1, 50 do
    memory.write_byte(wb, i)
    if send_dw(sa, wb, 1) == 1 then
        if recv_dw(sb, rb, 1) == 1 then
            ok3 = ok3 + 1
        end
    end
end
print("50x both=1: " .. ok3 .. " ok")

pcall(function() syscall.sc_close(sa) end)
pcall(function() syscall.sc_close(sb) end)

print("")
print("=== DONTWAIT SAFE DONE ===")
