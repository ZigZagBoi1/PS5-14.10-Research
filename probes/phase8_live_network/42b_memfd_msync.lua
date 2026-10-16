-- 14.10 Probe 42b: memfd + vectored I/O + msync isolation
-- Probe 38 died at minherit (phase 3) — msync never got tested.
-- Also memfd_create returned rv=1 (fd 1?) which is suspicious; check
-- whether it's a real kernel object usable with preadv/pwritev/ftruncate.

print("=== 42b: MEMFD + PREADV + MSYNC ===")
print("fw: " .. tostring(FW_VERSION))
print("pid: " .. syscall.getpid():tonumber())

syscall.resolve({
    sc_memfd_create = 585,
    sc_pwritev = 290,
    sc_preadv = 289,
    sc_ftruncate = 480,
    sc_mmap = 477,
    sc_msync = 226,
    sc_close = 6,
    sc_write = 4,
    sc_read = 3,
})

local function report(tag, fn)
    local ok, rv = pcall(fn)
    if not ok then
        print(tag .. ": PCALL ERR")
    elseif rv == nil then
        print(tag .. ": nil")
    else
        local okn, n = pcall(function() return rv:tonumber() end)
        print(tag .. ": rv=" .. (okn and tostring(n) or tostring(rv)))
    end
end

-- ---------------------------------------------------------------
-- PART 1: memfd_create — is the returned fd real?
-- ---------------------------------------------------------------
print("")
print("--- PART 1: memfd ---")
local nm = memory.alloc(8)
memory.write_byte(nm, 0x6B)   -- "k"
memory.write_byte(nm + 1, 0)

local ok_m, rv_m = pcall(function() return syscall.sc_memfd_create(nm, 0) end)
local mfd = ok_m and rv_m:tonumber() or -999
print("memfd_create: fd=" .. mfd)

if mfd >= 0 and mfd > 2 then
    -- grow it
    report("ftruncate(mfd, 0x10000)", function() return syscall.sc_ftruncate(mfd, 0x10000) end)

    -- write via plain write
    local wbuf = memory.alloc(16)
    for i = 0, 7 do memory.write_byte(wbuf + i, 0x41 + i) end
    report("write(mfd)", function() return syscall.sc_write(mfd, wbuf, 8) end)

    -- pwritev at offset 0x8000
    local iov = memory.alloc(16)
    memory.write_qword(iov, wbuf)
    memory.write_qword(iov + 8, 8)
    report("pwritev(mfd, off=0x8000)", function()
        return syscall.sc_pwritev(mfd, iov, 1, 0x8000)
    end)

    -- read back via preadv
    local rbuf = memory.alloc(16)
    for i = 0, 15 do memory.write_byte(rbuf + i, 0) end
    memory.write_qword(iov, rbuf)
    memory.write_qword(iov + 8, 8)
    report("preadv(mfd, off=0x8000)", function()
        return syscall.sc_preadv(mfd, iov, 1, 0x8000)
    end)
    local hex = ""
    for i = 0, 7 do hex = hex .. string.format("%02x", memory.read_byte(rbuf + i):tonumber()) end
    print("  readback: " .. hex)

    -- preadv at huge offset (validation check)
    report("preadv(mfd, off=2^62)", function()
        return syscall.sc_preadv(mfd, iov, 1, 0x4000000000000000)
    end)
    -- negative offset
    report("preadv(mfd, off=-1)", function()
        return syscall.sc_preadv(mfd, iov, 1, -1)
    end)
    -- iovlen abuse
    report("preadv(mfd, iovlen=0)", function() return syscall.sc_preadv(mfd, iov, 0, 0) end)
    report("preadv(mfd, iovlen=-1)", function() return syscall.sc_preadv(mfd, iov, -1, 0) end)
    report("preadv(mfd, iovlen=1025)", function() return syscall.sc_preadv(mfd, iov, 1025, 0) end)

    -- mmap the memfd (shared) — does PS5 allow mapping memfd?
    local ok_mm, rv_mm = pcall(function()
        return syscall.sc_mmap(0, 0x10000, 3, 0x0001, mfd, 0)  -- RW, MAP_SHARED
    end)
    local maddr = 0
    if ok_mm then
        local okn, n = pcall(function() return rv_mm:tonumber() end)
        maddr = okn and n or 0
    end
    print(string.format("mmap(memfd SHARED): 0x%x", maddr))
else
    print("memfd fd looks fake (<=2) — sandbox stub")
end

-- ---------------------------------------------------------------
-- PART 2: msync isolated (probe 38 died at minherit before reaching it)
-- ---------------------------------------------------------------
print("")
print("--- PART 2: msync isolated ---")
print("(if loader dies here, msync was the second probe-30 killer)")
local region = memory.alloc(0x4000)
local raddr = 0
local okr, nrr = pcall(function() return region:tonumber() end)
raddr = okr and nrr or 0
print(string.format("region @ 0x%x", raddr))
report("msync(MS_SYNC=0)", function() return syscall.sc_msync(region, 0x4000, 0) end)
report("msync(MS_INVALIDATE=2)", function() return syscall.sc_msync(region, 0x4000, 2) end)
report("msync(MS_ASYNC=1)", function() return syscall.sc_msync(region, 0x4000, 1) end)
report("msync(bad flag 0x100)", function() return syscall.sc_msync(region, 0x4000, 0x100) end)
report("msync(len=0)", function() return syscall.sc_msync(region, 0, 0) end)
report("msync(unmapped)", function() return syscall.sc_msync(region + 0x100000, 0x4000, 0) end)

print("=== 42b DONE ===")
