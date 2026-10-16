-- 14.10 Recon Probe 32d: minimal test after crash
print("=== ALIVE ===")
print("fw: " .. tostring(FW_VERSION))
print("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_getpid = 20,
    sc_socketpair = 135,
    sc_close = 6,
    sc_setsockopt = 105,
    sc_getsockopt = 118,
})

local sp = memory.alloc(8)
pcall(function() syscall.sc_socketpair(1, 1, 0, sp) end)
local a = memory.read_dword(sp):tonumber()
local b = memory.read_dword(sp + 4):tonumber()
print("pair: " .. a .. "," .. b)

-- SO_SETFIB
local val = memory.alloc(4)
local lenp = memory.alloc(8)
memory.write_qword(lenp, 4)
memory.write_dword(val, 0)
local ok, ret = pcall(function()
    return syscall.sc_getsockopt(a, 0xFFFF, 0x1011, val, lenp)
end)
print("SETFIB get: rv=" .. (ok and ret:tonumber() or -999) .. " val=" .. memory.read_dword(val):tonumber())

-- Try set FIB=1
memory.write_dword(val, 1)
local ok2, ret2 = pcall(function()
    return syscall.sc_setsockopt(a, 0xFFFF, 0x1011, val, 4)
end)
print("SETFIB set(1): rv=" .. (ok2 and ret2:tonumber() or -999))

memory.write_qword(lenp, 4)
memory.write_dword(val, 0)
pcall(function() syscall.sc_getsockopt(a, 0xFFFF, 0x1011, val, lenp) end)
print("SETFIB verify: " .. memory.read_dword(val):tonumber())

pcall(function() syscall.sc_close(a) end)
pcall(function() syscall.sc_close(b) end)
print("=== DONE ===")
