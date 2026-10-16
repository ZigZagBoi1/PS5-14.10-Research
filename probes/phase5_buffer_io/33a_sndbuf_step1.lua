-- 14.10 Recon Probe 33a: SNDBUF=1 isolation step 1
-- Just set SNDBUF=1 + NONBLOCK, do ONE write of 1 byte, report, exit
-- If this survives, step 2 adds more writes

print("=== 33a: SNDBUF=1 STEP1 ===")
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
local lenp = memory.alloc(8)

pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local sa = memory.read_dword(sp):tonumber()
local sb = memory.read_dword(sp + 4):tonumber()
print("pair: " .. sa .. "," .. sb)

-- Set NONBLOCK on both FIRST
pcall(function() syscall.sc_fcntl(sa, 4, 4) end)
pcall(function() syscall.sc_fcntl(sb, 4, 4) end)
print("nonblock set")

-- Verify flags
local ok_f, rv_f = pcall(function() return syscall.sc_fcntl(sa, 3, 0) end)
print("sa flags: " .. (ok_f and rv_f:tonumber() or -999))

-- Set SNDBUF=1
memory.write_dword(val, 1)
local ok_s, rv_s = pcall(function()
    return syscall.sc_setsockopt(sa, 0xFFFF, 0x1001, val, 4)
end)
print("set SNDBUF=1: rv=" .. (ok_s and rv_s:tonumber() or -999))

-- Verify
memory.write_qword(lenp, 4)
memory.write_dword(val, 0)
pcall(function() syscall.sc_getsockopt(sa, 0xFFFF, 0x1001, val, lenp) end)
print("actual SNDBUF: " .. memory.read_dword(val):tonumber())

-- Single 1-byte write
local wb = memory.alloc(4)
memory.write_byte(wb, 0x41)
local ok_w, rv_w = pcall(function() return syscall.sc_write(sa, wb, 1) end)
print("write(1): rv=" .. (ok_w and rv_w:tonumber() or -999))

print("=== STEP1 SURVIVED ===")

pcall(function() syscall.sc_close(sa) end)
pcall(function() syscall.sc_close(sb) end)
print("=== DONE ===")
