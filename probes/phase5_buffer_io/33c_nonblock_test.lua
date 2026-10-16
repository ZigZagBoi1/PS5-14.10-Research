-- 14.10 Recon Probe 33c: Does O_NONBLOCK actually work?
-- Test if the F_SETFL bypass really gives nonblocking I/O

print("=== 33c: NONBLOCK TEST ===")
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
    sc_socket = 97,
})

local sp = memory.alloc(8)
local val = memory.alloc(8)

-- Test 1: NONBLOCK read on empty socket
pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local sa = memory.read_dword(sp):tonumber()
local sb = memory.read_dword(sp + 4):tonumber()

-- Set nonblock
pcall(function() syscall.sc_fcntl(sa, 4, 4) end)
local ok_f, rv_f = pcall(function() return syscall.sc_fcntl(sa, 3, 0) end)
print("flags after SETFL: " .. (ok_f and rv_f:tonumber() or -999))

-- Read from empty socket — if NONBLOCK works, should return -35 (EAGAIN) immediately
print("about to read empty socket with NONBLOCK...")
local rb = memory.alloc(16)
local ok_r, rv_r = pcall(function() return syscall.sc_read(sa, rb, 16) end)
print("read(empty, NONBLK): rv=" .. (ok_r and rv_r:tonumber() or -999))
-- If we get here, NONBLOCK works for reads

-- Test 2: Fill the send buffer with default SNDBUF, then try one more
-- Default SNDBUF=8192, fill it
print("filling default buffer...")
local big = memory.alloc(8192)
memory.write_dword(big, 0xAAAA)
local ok_w1, rv_w1 = pcall(function() return syscall.sc_write(sa, big, 8192) end)
print("write(8192): rv=" .. (ok_w1 and rv_w1:tonumber() or -999))

-- Try another write — buffer should be full
print("about to write to full buffer...")
local ok_w2, rv_w2 = pcall(function() return syscall.sc_write(sa, big, 1) end)
print("write(1, full): rv=" .. (ok_w2 and rv_w2:tonumber() or -999))

-- Try with SOCK_NONBLOCK flag at creation (0x20000000)
pcall(function() syscall.sc_close(sa) end)
pcall(function() syscall.sc_close(sb) end)

-- socketpair with SOCK_NONBLOCK (type | 0x20000000)
print("")
print("--- SOCK_NONBLOCK at creation ---")
local sp2 = memory.alloc(8)
local ok_sp, rv_sp = pcall(function()
    return syscall.sc_socketpair(1, 1 + 0x20000000, 0, sp2)
end)
print("socketpair(NONBLOCK): rv=" .. (ok_sp and rv_sp:tonumber() or -999))

if ok_sp and rv_sp:tonumber() == 0 then
    local na = memory.read_dword(sp2):tonumber()
    local nb = memory.read_dword(sp2 + 4):tonumber()
    print("pair: " .. na .. "," .. nb)

    local ok_nf, rv_nf = pcall(function() return syscall.sc_fcntl(na, 3, 0) end)
    print("flags: " .. (ok_nf and rv_nf:tonumber() or -999))

    -- Read empty — should EAGAIN
    print("about to read empty SOCK_NONBLOCK...")
    local ok_nr, rv_nr = pcall(function() return syscall.sc_read(na, rb, 16) end)
    print("read(empty): rv=" .. (ok_nr and rv_nr:tonumber() or -999))

    -- Set SNDBUF=1 and test
    memory.write_dword(val, 1)
    pcall(function() syscall.sc_setsockopt(na, 0xFFFF, 0x1001, val, 4) end)

    -- Write 1 byte
    memory.write_byte(big, 0x42)
    local ok_nw1, rv_nw1 = pcall(function() return syscall.sc_write(na, big, 1) end)
    print("write(1, SNDBUF=1): rv=" .. (ok_nw1 and rv_nw1:tonumber() or -999))

    -- Write second byte — should EAGAIN if nonblock works
    print("about to write2 SNDBUF=1...")
    local ok_nw2, rv_nw2 = pcall(function() return syscall.sc_write(na, big, 1) end)
    print("write2(1, SNDBUF=1): rv=" .. (ok_nw2 and rv_nw2:tonumber() or -999))

    pcall(function() syscall.sc_close(na) end)
    pcall(function() syscall.sc_close(nb) end)
else
    print("SOCK_NONBLOCK not supported, trying O_NONBLOCK via ioctl")
end

print("=== NONBLOCK TEST DONE ===")
