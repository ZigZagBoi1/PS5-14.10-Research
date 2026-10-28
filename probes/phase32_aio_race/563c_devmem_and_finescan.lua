-- CRASH_CLASS: LOW
-- PROBE 563c: Try /dev/mem + fine scan non-zero regions
--
-- 563b: dmem0 covers 0-5.375GB (game direct memory), kernel not there.
-- Need access to higher physical ranges where the kernel lives.
--
-- PLAN:
-- [A] Try to open /dev/mem, /dev/kmem, /dev/physmem, /dev/iomem
-- [B] Fine scan around phys 0x000000000 at 16KB stride (first 16MB)
-- [C] Fine scan around phys 0x011600000 (AFAF data) ±8MB at 16KB
-- [D] Test dmem0 mmap above 5GB range — does d_mmap have a higher limit?
-- [E] Write-then-read test on allocated dmem0 page

print("=== PROBE 563c: /DEV/MEM + FINE SCAN ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if not ok then return nil end
    local n = N(v); if n < 0 then n = n + 0x100000000 end; return n
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local Z = uint64(0)
local sc477 = mk(477)
local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
io.flush()

-- Helper: try to open a device path
local function try_open(path_str)
    local p = memory.alloc(32)
    for i = 0, 28, 4 do wd(N(p) + i, 0) end
    -- Write path as bytes
    for i = 1, #path_str do
        local addr = N(p) + i - 1
        local byte = string.byte(path_str, i)
        -- Write byte by byte using dword write at aligned address
        local aligned = addr - (addr % 4)
        local off_in_dword = addr % 4
        local cur = rb(aligned) or 0
        -- Clear the byte position and set new value
        local mask = 0xFF * (256 ^ off_in_dword)
        cur = cur - (cur % (256 ^ (off_in_dword + 1))) % (256 ^ off_in_dword) * (256 ^ off_in_dword)
        -- Simpler: just write dwords
    end
    -- Actually, let me use a simpler approach: write full dwords
    return p
end

-- Write string to memory (pad to dword alignment)
local function write_str(buf, str)
    local b = N(buf)
    for i = 0, #str + 4, 4 do wd(b + i, 0) end  -- clear
    -- Write as dwords (little-endian)
    for i = 0, #str - 1, 4 do
        local val = 0
        for j = 0, 3 do
            local idx = i + j + 1
            if idx <= #str then
                val = val + string.byte(str, idx) * (256 ^ j)
            end
        end
        wd(b + i, val)
    end
end

-- ============================================================
-- [A] Try to open memory devices
-- ============================================================
print("[A] device open attempts")
local path_buf = memory.alloc(64)

local devices = {
    "/dev/mem", "/dev/kmem", "/dev/physmem",
    "/dev/iomem", "/dev/dmpdev"
}

for _, dev in ipairs(devices) do
    write_str(path_buf, dev)
    -- Try O_RDONLY=0, O_RDWR=2
    local ok1, fd1 = pcall(function()
        return native.fcall_with_rax(stub, 5, path_buf, Z)
    end)
    local f1 = ok1 and N(fd1) or -999
    local ok2, fd2 = pcall(function()
        return native.fcall_with_rax(stub, 5, path_buf, uint64(2))
    end)
    local f2 = ok2 and N(fd2) or -999
    print(string.format("  %-16s RD=%d RW=%d", dev, f1, f2))
    -- Close if opened
    if f1 >= 0 then pcall(function() native.fcall_with_rax(stub, 6, uint64(f1)) end) end
    if f2 >= 0 then pcall(function() native.fcall_with_rax(stub, 6, uint64(f2)) end) end
end
io.flush()

-- ============================================================
-- [B] Fine scan phys 0x000000000..0x01000000 at 16KB stride
-- ============================================================
print("")
print("[B] fine scan phys 0-16MB (16KB stride)")

local dp = memory.alloc(16)
wd(N(dp), 0x7665642F); wd(N(dp) + 4, 0x656D642F); wd(N(dp) + 8, 0x0000306D)
local ok_o, fd_raw = pcall(function()
    return native.fcall_with_rax(stub, 5, dp, uint64(2))
end)
local fd = ok_o and N(fd_raw) or -999
if fd < 0 then print("dmem0 OPEN FAIL"); return end

local PAGE = 0x4000
local nz_fine = 0
local elf_fine = 0

for off = 0, 0x1000000 - PAGE, PAGE do
    local ok_mm, va_raw = pcall(function()
        return sc477(Z, uint64(PAGE), uint64(1),
            uint64(0x0001), uint64(fd), uint64(off))
    end)
    local va = ok_mm and N(va_raw) or 0
    if va > 0x10000 and va < 0x800000000000 then
        local v0 = rb(va) or 0
        local v4 = rb(va + 4) or 0
        if v0 ~= 0 or v4 ~= 0 then
            nz_fine = nz_fine + 1
            local tag = ""
            if v0 == 0x464C457F then tag = " ELF!"; elf_fine = elf_fine + 1 end
            if nz_fine <= 20 then
                print(string.format("  0x%08X: %08X_%08X%s", off, v4, v0, tag))
            end
        end
        pcall(function()
            native.fcall_with_rax(stub, 73, uint64(va), uint64(PAGE))
        end)
    end
end
print(string.format("  nz=%d elf=%d in 0-16MB", nz_fine, elf_fine))
io.flush()

-- ============================================================
-- [C] Fine scan around 0x11600000 ±8MB at 16KB
-- ============================================================
print("")
print("[C] fine scan 0x10E00000-0x11E00000 (16KB stride)")
local nz2 = 0
for off = 0x10E00000, 0x11E00000 - PAGE, PAGE do
    local ok_mm, va_raw = pcall(function()
        return sc477(Z, uint64(PAGE), uint64(1),
            uint64(0x0001), uint64(fd), uint64(off))
    end)
    local va = ok_mm and N(va_raw) or 0
    if va > 0x10000 and va < 0x800000000000 then
        local v0 = rb(va) or 0
        local v4 = rb(va + 4) or 0
        if v0 ~= 0 or v4 ~= 0 then
            nz2 = nz2 + 1
            local tag = ""
            if v0 == 0x464C457F then tag = " ELF!" end
            if nz2 <= 20 then
                print(string.format("  0x%08X: %08X_%08X%s", off, v4, v0, tag))
            end
        end
        pcall(function()
            native.fcall_with_rax(stub, 73, uint64(va), uint64(PAGE))
        end)
    end
end
print(string.format("  nz=%d in range", nz2))
io.flush()

-- ============================================================
-- [D] Try dmem0 mmap above 5GB — does d_mmap extend beyond AllocDM range?
-- ============================================================
print("")
print("[D] dmem0 mmap above 5GB")
local high_tests = {
    "0x160000000",  -- 5.5GB (just above GetDMSize)
    "0x200000000",  -- 8GB
    "0x300000000",  -- 12GB
    "0x3F0000000",  -- ~15.75GB
}
for _, phys_str in ipairs(high_tests) do
    local ok_mm, va_raw = pcall(function()
        return sc477(Z, uint64(PAGE), uint64(1),
            uint64(0x0001), uint64(fd), uint64(phys_str))
    end)
    local va = ok_mm and N(va_raw) or 0
    local status = "FAIL"
    if va > 0x10000 and va < 0x800000000000 then
        local v = rb(va)
        if v ~= nil then
            status = string.format("OK data=%08X", v)
            if v == 0x464C457F then status = status .. " ELF!" end
        else
            status = "MMAP_OK_READ_FAIL"
        end
        pcall(function()
            native.fcall_with_rax(stub, 73, uint64(va), uint64(PAGE))
        end)
    end
    print(string.format("  %s: %s", phys_str, status))
end
io.flush()

-- ============================================================
-- [E] Write-read test on allocated dmem0 page
-- ============================================================
print("")
print("[E] dmem0 write-read test")
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local llo = rb(N(ib) + 0x108) or 0
local lhi = rb(N(ib) + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lhi, llo))
local alloc_fn = lk + uint64(0x17EF0)

local phys_out = memory.alloc(8)
wq(N(phys_out), Z)
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        Z, uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), phys_out)
end)
local plo = rb(N(phys_out)) or 0
local phi = rb(N(phys_out) + 4) or 0
print(string.format("  alloc phys=0x%X%08X", phi, plo))

if plo > 0 or phi > 0 then
    local phys_a = uint64(string.format("0x%X%08X", phi, plo))
    -- mmap with PROT_READ|PROT_WRITE
    local ok_mm, va_raw = pcall(function()
        return sc477(Z, uint64(PAGE), uint64(3),
            uint64(0x0001), uint64(fd), phys_a)
    end)
    local va = ok_mm and N(va_raw) or 0
    if va > 0x10000 then
        local before = rb(va) or 0
        -- Write known pattern
        pcall(function() memory.write_dword(va, 0xCAFEBABE) end)
        local after = rb(va) or 0
        print(string.format("  before=0x%08X after=0x%08X", before, after))
        if after == 0xCAFEBABE then
            print("  WRITE-READ VERIFIED!")
        end
        pcall(function()
            native.fcall_with_rax(stub, 73, uint64(va), uint64(PAGE))
        end)
    else
        print("  mmap fail")
    end
end
io.flush()

-- Close
pcall(function() native.fcall_with_rax(stub, 6, uint64(fd)) end)
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid and " ALIVE" or " DEAD"))
print("=== 563c DONE ===")
