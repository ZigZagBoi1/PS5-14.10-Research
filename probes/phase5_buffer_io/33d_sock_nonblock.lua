-- 14.10 Recon Probe 33d: SOCK_NONBLOCK at creation
-- F_SETFL doesn't actually enable nonblock. Try socket flags instead.

print("=== 33d: SOCK_NONBLOCK ===")
print("fw: " .. tostring(FW_VERSION))
print("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_socketpair = 135,
    sc_close = 6,
    sc_write = 4,
    sc_read = 3,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
    sc_fcntl = 92,
})

local rb = memory.alloc(16)

-- Try SOCK_NONBLOCK (0x20000000) in type field
local sp = memory.alloc(8)
local ok1, rv1 = pcall(function()
    return syscall.sc_socketpair(1, 1 + 0x20000000, 0, sp) -- STREAM|NONBLOCK
end)
print("socketpair(STREAM|NONBLOCK): rv=" .. (ok1 and rv1:tonumber() or -999))

if ok1 and rv1:tonumber() == 0 then
    local na = memory.read_dword(sp):tonumber()
    local nb = memory.read_dword(sp + 4):tonumber()
    print("fds: " .. na .. "," .. nb)

    local ok_f, rv_f = pcall(function() return syscall.sc_fcntl(na, 3, 0) end)
    print("F_GETFL: " .. (ok_f and rv_f:tonumber() or -999))

    -- Test: read empty should return immediately with EAGAIN
    print("about to read empty...")
    local ok_r, rv_r = pcall(function() return syscall.sc_read(na, rb, 16) end)
    print("read(empty): rv=" .. (ok_r and rv_r:tonumber() or -999))

    -- SNDBUF=1 test
    local val = memory.alloc(4)
    memory.write_dword(val, 1)
    pcall(function() syscall.sc_setsockopt(na, 0xFFFF, 0x1001, val, 4) end)

    local wb = memory.alloc(4)
    memory.write_byte(wb, 0x42)
    local ok_w1, rv_w1 = pcall(function() return syscall.sc_write(na, wb, 1) end)
    print("write1(1, SNDBUF=1): rv=" .. (ok_w1 and rv_w1:tonumber() or -999))

    print("about to write2...")
    local ok_w2, rv_w2 = pcall(function() return syscall.sc_write(na, wb, 1) end)
    print("write2(1, SNDBUF=1): rv=" .. (ok_w2 and rv_w2:tonumber() or -999))

    pcall(function() syscall.sc_close(na) end)
    pcall(function() syscall.sc_close(nb) end)
else
    print("SOCK_NONBLOCK failed, trying SOCK_DGRAM|NONBLOCK")
    local ok2, rv2 = pcall(function()
        return syscall.sc_socketpair(1, 2 + 0x20000000, 0, sp) -- DGRAM|NONBLOCK
    end)
    print("socketpair(DGRAM|NONBLOCK): rv=" .. (ok2 and rv2:tonumber() or -999))

    if ok2 and rv2:tonumber() == 0 then
        local da = memory.read_dword(sp):tonumber()
        local db = memory.read_dword(sp + 4):tonumber()
        print("dgram fds: " .. da .. "," .. db)

        print("about to read empty dgram...")
        local ok_dr, rv_dr = pcall(function() return syscall.sc_read(da, rb, 16) end)
        print("dgram read(empty): rv=" .. (ok_dr and rv_dr:tonumber() or -999))

        pcall(function() syscall.sc_close(da) end)
        pcall(function() syscall.sc_close(db) end)
    end

    -- Also try MSG_DONTWAIT on sendmsg (0x80)
    print("")
    print("--- MSG_DONTWAIT ---")
    pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
    local ma = memory.read_dword(sp):tonumber()
    local mb = memory.read_dword(sp + 4):tonumber()

    -- Set SNDBUF=1
    local val2 = memory.alloc(4)
    memory.write_dword(val2, 1)
    pcall(function() syscall.sc_setsockopt(ma, 0xFFFF, 0x1001, val2, 4) end)

    -- Write 1 byte
    local wb = memory.alloc(4)
    memory.write_byte(wb, 0x43)
    pcall(function() syscall.sc_write(ma, wb, 1) end)
    print("write1(1): done")

    -- sendmsg with MSG_DONTWAIT on full buffer
    syscall.resolve({ sc_sendmsg = 28 })
    local pl = memory.alloc(4)
    memory.write_byte(pl, 0x44)
    local iov = memory.alloc(16)
    memory.write_qword(iov, pl)
    memory.write_qword(iov + 8, 1)
    local mh = memory.alloc(64)
    for i = 0, 63, 8 do memory.write_qword(mh + i, 0) end
    memory.write_qword(mh + 16, iov)
    memory.write_qword(mh + 24, 1)

    print("about to sendmsg DONTWAIT...")
    local ok_sm, rv_sm = pcall(function()
        return syscall.sc_sendmsg(ma, mh, 0x80) -- MSG_DONTWAIT
    end)
    print("sendmsg(DONTWAIT): rv=" .. (ok_sm and rv_sm:tonumber() or -999))

    -- Also try recv with MSG_DONTWAIT on empty
    syscall.resolve({ sc_recvmsg = 27 })
    local rbuf = memory.alloc(16)
    local riov = memory.alloc(16)
    memory.write_qword(riov, rbuf)
    memory.write_qword(riov + 8, 16)
    local rmh = memory.alloc(64)
    for i = 0, 63, 8 do memory.write_qword(rmh + i, 0) end
    memory.write_qword(rmh + 16, riov)
    memory.write_qword(rmh + 24, 1)

    print("about to recvmsg DONTWAIT on empty mb...")
    local ok_rm, rv_rm = pcall(function()
        return syscall.sc_recvmsg(mb, rmh, 0x80) -- MSG_DONTWAIT
    end)
    print("recvmsg(DONTWAIT, empty): rv=" .. (ok_rm and rv_rm:tonumber() or -999))

    pcall(function() syscall.sc_close(ma) end)
    pcall(function() syscall.sc_close(mb) end)
end

print("=== SOCK_NONBLOCK DONE ===")
