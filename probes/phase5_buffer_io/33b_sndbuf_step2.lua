-- 14.10 Recon Probe 33b: SNDBUF=1 step 2
-- Write 1 byte (fills buffer), then try second write (should get EAGAIN)
-- Then try progressively larger writes

print("=== 33b: SNDBUF=1 STEP2 ===")
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

local sp = memory.alloc(8)
local val = memory.alloc(8)

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local sa = memory.read_dword(sp):tonumber()
local sb = memory.read_dword(sp + 4):tonumber()

-- NONBLOCK first
pcall(function() syscall.sc_fcntl(sa, 4, 4) end)
pcall(function() syscall.sc_fcntl(sb, 4, 4) end)

-- SNDBUF=1
memory.write_dword(val, 1)
pcall(function() syscall.sc_setsockopt(sa, 0xFFFF, 0x1001, val, 4) end)
print("SNDBUF=1 set")

-- Write 1: should succeed
local wb = memory.alloc(4)
memory.write_byte(wb, 0x41)
local ok1, rv1 = pcall(function() return syscall.sc_write(sa, wb, 1) end)
print("write1(1): rv=" .. (ok1 and rv1:tonumber() or -999))

-- Write 2: buffer full, should EAGAIN (-35) in nonblock
print("about to write2...")
local ok2, rv2 = pcall(function() return syscall.sc_write(sa, wb, 1) end)
print("write2(1): rv=" .. (ok2 and rv2:tonumber() or -999))

-- Write 3: 4 bytes
print("about to write3...")
local wb4 = memory.alloc(4)
memory.write_dword(wb4, 0xDEAD)
local ok3, rv3 = pcall(function() return syscall.sc_write(sa, wb4, 4) end)
print("write3(4): rv=" .. (ok3 and rv3:tonumber() or -999))

-- Drain from sb
print("about to drain...")
local drain = memory.alloc(256)
local ok_d, rv_d = pcall(function() return syscall.sc_read(sb, drain, 256) end)
print("drain: rv=" .. (ok_d and rv_d:tonumber() or -999))

-- Write after drain: 4 bytes
print("about to write4 after drain...")
local ok4, rv4 = pcall(function() return syscall.sc_write(sa, wb4, 4) end)
print("write4(4): rv=" .. (ok4 and rv4:tonumber() or -999))

-- Write 64 bytes
print("about to write5...")
local wb64 = memory.alloc(64)
memory.write_dword(wb64, 0xBEEF)
local ok5, rv5 = pcall(function() return syscall.sc_write(sa, wb64, 64) end)
print("write5(64): rv=" .. (ok5 and rv5:tonumber() or -999))

-- Write 1024 bytes
print("about to write6...")
local wb1k = memory.alloc(1024)
memory.write_dword(wb1k, 0xCAFE)
local ok6, rv6 = pcall(function() return syscall.sc_write(sa, wb1k, 1024) end)
print("write6(1024): rv=" .. (ok6 and rv6:tonumber() or -999))

print("=== STEP2 SURVIVED ===")
pcall(function() syscall.sc_close(sa) end)
pcall(function() syscall.sc_close(sb) end)
print("=== DONE ===")
