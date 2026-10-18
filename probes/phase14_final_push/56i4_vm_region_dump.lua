-- CRASH_CLASS: LOW
-- PROBE 56i4: Dump ALL 371 VM regions — find timekeep page, stack, unusual regions
--
-- Context: 56i3 confirmed 371 regions but zero kernel pointers.
-- We need to find the timekeep/vDSO shared page (kernel maps it, may have kptrs).
-- Also need to find stack region (name matching failed).
-- Dump every region's full record to find anything unusual.

print("=== PROBE 56i4: VM REGION FULL DUMP ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function hexval_short(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h < 0xFFFFFFFF
end

print("[A] Setup")
local sc_getpid = make_syscall(20)
local our_pid = to_num(sc_getpid())
print("  PID: " .. our_pid)

collectgarbage("stop")

-- ============================================================
-- [B] sys 674 full region dump
-- Record layout (72 bytes):
--   +0x00: start addr (8)
--   +0x08: end addr (8)
--   +0x10: offset? (8)
--   +0x18: protection (4)
--   +0x1C: max_protection? (4)
--   +0x20: name (32 bytes)
--   +0x40: type? (4)
--   +0x44: flags? (4)
-- ============================================================
print("")
print("[B] sys 674 full dump")

local sc674 = make_syscall(674)
local STRIDE = 72
local MAX_RECORDS = 400
local vm_buf = memory.alloc(STRIDE * MAX_RECORDS)
local countp = memory.alloc(16)
safe_wq(countp, uint64(0))

local ok, ret = pcall(function()
    return sc674(uint64(vm_buf), uint64(STRIDE), uint64(MAX_RECORDS),
                  uint64(countp), uint64(0x40000000))
end)
local vm_ret = ok and to_num(ret) or -999
print("  ret=" .. vm_ret)

if vm_ret ~= 0 then
    print("  FAILED")
    collectgarbage("restart")
    print("")
    print("=== PROBE 56i4 COMPLETE ===")
    return
end

local count = safe_rd(countp) or 0
print("  regions: " .. count)
if count > MAX_RECORDS then count = MAX_RECORDS end

-- First pass: dump every region with name, prot, size, unusual fields
local stack_region = nil
local small_ro_regions = {}
local interesting = {}

for e = 0, count - 1 do
    local base = vm_buf + e * STRIDE
    local start_val = safe_rq(base)
    local end_val = safe_rq(base + 8)
    local offset_val = safe_rq(base + 0x10)
    local prot = safe_rd(base + 0x18) or 0
    local maxprot = safe_rd(base + 0x1C) or 0

    -- Read name
    local name = ""
    for ci = 0, 31 do
        local b = safe_rd(base + 0x20 + ci)
        if b and b > 0 and b < 128 then
            name = name .. string.char(b)
        elseif b == 0 then break end
    end

    local type_val = safe_rd(base + 0x40) or 0
    local flags_val = safe_rd(base + 0x44) or 0

    local sh, sl = get_hi_lo(start_val)
    local eh, el = get_hi_lo(end_val)
    local size = 0
    if eh == sh then size = el - sl
    else size = (eh - sh) * 0x100000000 + (el - sl) end

    -- Check for stack-like region (large, high address, RW)
    if name:lower():find("stack") then
        stack_region = e
    end

    -- Check for small read-only regions (timekeep candidate)
    if size > 0 and size <= 0x10000 and prot == 1 then
        small_ro_regions[#small_ro_regions + 1] = e
    end

    -- Check for unusual type/flags
    if type_val ~= 0 or flags_val ~= 0 then
        interesting[#interesting + 1] = e
    end

    -- Print every region (compact format)
    local prot_str = ""
    if bit32 then
        prot_str = (prot % 2 == 1 and "R" or "-") ..
                   (math.floor(prot / 2) % 2 == 1 and "W" or "-") ..
                   (math.floor(prot / 4) % 2 == 1 and "X" or "-")
    else
        local p = prot
        prot_str = (p % 2 == 1 and "R" or "-")
        p = math.floor(p / 2)
        prot_str = prot_str .. (p % 2 == 1 and "W" or "-")
        p = math.floor(p / 2)
        prot_str = prot_str .. (p % 2 == 1 and "X" or "-")
    end

    local size_str = ""
    if size >= 0x100000 then
        size_str = string.format("%dMB", math.floor(size / 0x100000))
    elseif size >= 0x400 then
        size_str = string.format("%dKB", math.floor(size / 0x400))
    else
        size_str = size .. "B"
    end

    -- Only print regions that are interesting or at boundaries
    local print_it = false
    if name ~= "" then print_it = true end
    if type_val ~= 0 or flags_val ~= 0 then print_it = true end
    if prot == 1 and size <= 0x10000 then print_it = true end  -- small RO
    if prot == 0 then print_it = true end  -- no access
    if sh >= 0x0F then print_it = true end -- high address
    if e < 5 or e > count - 6 then print_it = true end -- first/last

    if print_it then
        local extra = ""
        if type_val ~= 0 then extra = extra .. " typ=" .. type_val end
        if flags_val ~= 0 then extra = extra .. string.format(" flg=0x%X", flags_val) end
        local oh, ol = get_hi_lo(offset_val)
        if oh ~= 0 or ol ~= 0 then extra = extra .. " off=" .. hexval_short(offset_val) end
        if name ~= "" then extra = extra .. " [" .. name .. "]" end
        print(string.format("  %3d: %s-%s %s %s mp=0x%X%s",
            e, hexval_short(start_val), hexval_short(end_val),
            size_str, prot_str, maxprot, extra))
    end
end

-- ============================================================
-- [C] Small RO region scan (timekeep candidates)
-- The timekeep page is typically a small read-only shared mapping
-- ============================================================
print("")
print("[C] Small read-only regions (timekeep candidates): " .. #small_ro_regions)

for _, e in ipairs(small_ro_regions) do
    local base = vm_buf + e * STRIDE
    local start_val = safe_rq(base)
    local end_val = safe_rq(base + 8)
    local sh, sl = get_hi_lo(start_val)
    local eh, el = get_hi_lo(end_val)
    local size = (eh == sh) and (el - sl) or ((eh - sh) * 0x100000000 + (el - sl))

    print(string.format("  Region %d: %s size=%d", e, hexval(start_val), size))

    -- Scan first 256 bytes for interesting data
    local kptrs = 0
    local nonzero = 0
    for off = 0, math.min(size - 1, 0x1FF), 8 do
        local scan_l = sl + off
        local scan_h = sh
        if scan_l >= 0x100000000 then
            scan_h = scan_h + 1
            scan_l = scan_l - 0x100000000
        end
        local addr = uint64(string.format("0x%X%08X", scan_h, scan_l))
        local val = safe_rq(addr)
        if val then
            local vh, vl = get_hi_lo(val)
            if vh ~= 0 or vl ~= 0 then
                nonzero = nonzero + 1
                if is_kptr(val) then
                    kptrs = kptrs + 1
                    print(string.format("    +0x%03X: %s KPTR!", off, hexval(val)))
                elseif nonzero <= 16 then
                    print(string.format("    +0x%03X: %s", off, hexval(val)))
                end
            end
        end
    end
    print(string.format("    nonzero=%d kptrs=%d", nonzero, kptrs))

    -- If page has data, scan full range for kptrs
    if nonzero > 0 and size <= 0x4000 then
        for off = 0x200, size - 1, 8 do
            local scan_l = sl + off
            local scan_h = sh
            if scan_l >= 0x100000000 then
                scan_h = scan_h + 1
                scan_l = scan_l - 0x100000000
            end
            local addr = uint64(string.format("0x%X%08X", scan_h, scan_l))
            local val = safe_rq(addr)
            if val and is_kptr(val) then
                kptrs = kptrs + 1
                if kptrs <= 10 then
                    print(string.format("    +0x%04X: %s KPTR!", off, hexval(val)))
                end
            end
        end
        if kptrs > 0 then
            print(string.format("    TOTAL KPTRS: %d", kptrs))
        end
    end
end

-- ============================================================
-- [D] Last 20 regions (high VA — stack/vdso typically here)
-- ============================================================
print("")
print("[D] Last 20 regions detail")

local scan_start = count - 20
if scan_start < 0 then scan_start = 0 end

for e = scan_start, count - 1 do
    local base = vm_buf + e * STRIDE
    local start_val = safe_rq(base)
    local end_val = safe_rq(base + 8)
    local prot = safe_rd(base + 0x18) or 0
    local sh, sl = get_hi_lo(start_val)
    local eh, el = get_hi_lo(end_val)
    local size = (eh == sh) and (el - sl) or ((eh - sh) * 0x100000000 + (el - sl))

    local name = ""
    for ci = 0, 31 do
        local b = safe_rd(base + 0x20 + ci)
        if b and b > 0 and b < 128 then
            name = name .. string.char(b)
        elseif b == 0 then break end
    end

    -- Dump full 72-byte record as hex
    print(string.format("  [%d] %s-%s prot=0x%X size=0x%X name='%s'",
        e, hexval_short(start_val), hexval_short(end_val), prot, size, name))

    -- Dump raw record bytes at non-standard offsets
    for off = 0x10, 0x44, 4 do
        if off < 0x20 or off >= 0x40 then
            local val = safe_rd(base + off)
            if val and val ~= 0 then
                print(string.format("    +0x%02X: 0x%08X", off, val))
            end
        end
    end

    -- If RW and large (>1MB), likely stack — scan top 8KB
    if prot == 3 and size >= 0x100000 and sh >= 0x07 then
        print("    Scanning top 8KB for kernel pointers...")
        local sk = 0
        for soff = 0x2000, 8, -8 do
            local a_l = el - soff
            local a_h = eh
            if a_l < 0 then a_h = a_h - 1; a_l = a_l + 0x100000000 end
            local addr = uint64(string.format("0x%X%08X", a_h, a_l))
            local val = safe_rq(addr)
            if val and is_kptr(val) then
                sk = sk + 1
                if sk <= 10 then
                    print(string.format("      end-0x%04X: %s KPTR!", soff, hexval(val)))
                end
            end
        end
        print("      Stack kernel pointers: " .. sk)
    end

    -- If small RO, scan contents
    if prot == 1 and size > 0 and size <= 0x4000 then
        print("    Scanning RO region contents...")
        local rk = 0
        for soff = 0, size - 1, 8 do
            local a_l = sl + soff
            local a_h = sh
            if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
            local addr = uint64(string.format("0x%X%08X", a_h, a_l))
            local val = safe_rq(addr)
            if val and is_kptr(val) then
                rk = rk + 1
                if rk <= 5 then
                    print(string.format("      +0x%04X: %s KPTR!", soff, hexval(val)))
                end
            end
        end
        if rk > 0 then print("      RO region KPTRS: " .. rk) end
    end
end

-- ============================================================
-- [E] Scan ALL regions' non-address fields for kernel pointers
-- Offsets +0x10 (8 bytes) might contain object pointers on some OS versions
-- ============================================================
print("")
print("[E] Scan offset +0x10 across all regions")

local off10_kptrs = 0
for e = 0, count - 1 do
    local base = vm_buf + e * STRIDE
    local val = safe_rq(base + 0x10)
    if val and is_kptr(val) then
        off10_kptrs = off10_kptrs + 1
        print(string.format("  region[%d]+0x10: %s KPTR!", e, hexval(val)))
    end
end
print("  Offset +0x10 kernel pointers: " .. off10_kptrs)

collectgarbage("restart")

print("")
print("=== PROBE 56i4 COMPLETE ===")
