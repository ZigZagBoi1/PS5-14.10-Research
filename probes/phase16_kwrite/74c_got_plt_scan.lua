-- CRASH_CLASS: LOW
-- PROBE 74c: Eboot GOT/PLT and writable data segment kernel pointer scan
--
-- Eboot .text is RX (readable). Its writable data segment (p=0x3) contains
-- GOT entries, vtable pointers, and runtime-resolved addresses. If the
-- dynamic linker resolved any kernel-facing function pointers or the runtime
-- stored kernel addresses in global data, they'd be here.
--
-- Uses sys 674 (VM map) to find eboot's writable regions, then scans them.

print("=== PROBE 74c: EBOOT GOT/PLT + DATA SCAN ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Get eboot base via dynlib_get_info
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eboot_lo = rd(N(info) + 0x108) or 0
local eboot_hi = rd(N(info) + 0x10C) or 0
if eboot_lo < 0 then eboot_lo = eboot_lo + 0x100000000 end
if eboot_hi < 0 then eboot_hi = eboot_hi + 0x100000000 end
local eboot_base = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
print(string.format("eboot_base=0x%X%08X", eboot_hi, eboot_lo))

-- ============================================================
-- [A] Use sys 674 to find eboot writable data regions
-- ============================================================
print("")
print("[A] VM map scan for eboot writable regions")

local sc_674 = mk(674)
local entry = memory.alloc(0x100)
local total_writable = 0
local writable_regions = {}

-- Scan from eboot base for ~16MB range
local scan_start = eboot_base
local scan_end_lo = eboot_lo + 0x1000000  -- 16MB past eboot
local scan_end_hi = eboot_hi
if scan_end_lo >= 0x100000000 then
    scan_end_lo = scan_end_lo - 0x100000000
    scan_end_hi = scan_end_hi + 1
end

local addr_lo = eboot_lo
local addr_hi = eboot_hi
local region_count = 0

for iter = 1, 100 do
    if not alive() then break end

    local query_addr = uint64(string.format("0x%X%08X", addr_hi, addr_lo))
    for i = 0, 0x50 do wd(N(entry) + i, 0) end

    local ret = -999
    pcall(function()
        ret = N(sc_674(query_addr, uint64(0), entry))
    end)
    if ret ~= 0 then break end

    local start_lo = rd(N(entry) + 0x00) or 0
    local start_hi = rd(N(entry) + 0x04) or 0
    local end_lo = rd(N(entry) + 0x08) or 0
    local end_hi = rd(N(entry) + 0x0C) or 0
    local prot = rd(N(entry) + 0x18) or 0

    if start_lo < 0 then start_lo = start_lo + 0x100000000 end
    if start_hi < 0 then start_hi = start_hi + 0x100000000 end
    if end_lo < 0 then end_lo = end_lo + 0x100000000 end
    if end_hi < 0 then end_hi = end_hi + 0x100000000 end
    if prot < 0 then prot = prot + 0x100000000 end

    -- Check if past eboot range
    if start_hi > scan_end_hi or (start_hi == scan_end_hi and start_lo >= scan_end_lo) then
        break
    end

    -- Name at +0x20
    local name_bytes = {}
    for i = 0, 31 do
        local b = rd(N(entry) + 0x20 + i)
        if b and b > 0 and b < 128 then name_bytes[#name_bytes + 1] = string.char(b)
        elseif b == 0 then break end
    end
    local name = table.concat(name_bytes)

    local size = (end_hi * 0x100000000 + end_lo) - (start_hi * 0x100000000 + start_lo)

    if prot == 0x3 or prot == 0x33 then
        print(string.format("  WRITABLE: 0x%X%08X-0x%X%08X prot=0x%X size=0x%X %s",
            start_hi, start_lo, end_hi, end_lo, prot, size, name))
        writable_regions[#writable_regions + 1] = {
            lo = start_lo, hi = start_hi,
            end_lo = end_lo, end_hi = end_hi,
            size = size, prot = prot, name = name
        }
        total_writable = total_writable + size
    else
        region_count = region_count + 1
        if region_count <= 5 or prot == 0x5 then
            print(string.format("  region: 0x%X%08X prot=0x%X size=0x%X %s",
                start_hi, start_lo, prot, size, name))
        end
    end

    -- Next region
    addr_lo = end_lo
    addr_hi = end_hi
end

print("  total writable regions: " .. #writable_regions)
print(string.format("  total writable bytes: 0x%X", total_writable))

if not alive() then print("DEAD after [A]"); return end

-- ============================================================
-- [B] Scan writable regions for kernel pointers
-- ============================================================
print("")
print("[B] Scanning writable regions for kernel pointers")

local total_kptrs = 0
local total_scanned = 0

for ri, reg in ipairs(writable_regions) do
    if not alive() then break end
    local scan_size = math.min(reg.size, 0x100000)  -- cap at 1MB per region
    local base_addr = uint64(string.format("0x%X%08X", reg.hi, reg.lo))

    print(string.format("  scanning region %d: 0x%X%08X size=0x%X %s",
        ri, reg.hi, reg.lo, scan_size, reg.name))

    local region_kptrs = 0
    local i = 0
    while i + 7 < scan_size do
        if not alive() then break end
        local addr = uint64(string.format("0x%X%08X", reg.hi, reg.lo + i))
        local val = rq(addr)
        if val then
            local h, l = get_hi_lo(val)
            if h < 0 then h = h + 0x100000000 end
            if l < 0 then l = l + 0x100000000 end
            -- Real kernel pointer: 0xFFFF8xxx but not sentinels
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print(string.format("    *** KPTR at +0x%X: 0x%08X%08X ***", i, h, l))
                region_kptrs = region_kptrs + 1
                if region_kptrs >= 20 then
                    print("    (capped at 20 per region)")
                    break
                end
            end
        end
        i = i + 8
        total_scanned = total_scanned + 8
    end

    total_kptrs = total_kptrs + region_kptrs
    print(string.format("  region %d kptrs: %d", ri, region_kptrs))
end

print(string.format("  TOTAL kernel pointers: %d (scanned 0x%X bytes)", total_kptrs, total_scanned))

if not alive() then print("DEAD after [B]"); return end

-- ============================================================
-- [C] Scan eboot GOT specifically (look for relocated function pointers)
-- ============================================================
print("")
print("[C] GOT-style pointer scan in first writable region")

if #writable_regions > 0 then
    local reg = writable_regions[1]
    local scan_size = math.min(reg.size, 0x40000)  -- first 256KB
    local base_lo = reg.lo
    local base_hi = reg.hi

    -- Count pointer categories
    local counts = {eboot=0, heap=0, lib=0, stack=0, kptr=0, zero=0, other=0}
    local sample_ptrs = {}

    local i = 0
    while i + 7 < scan_size do
        local addr = uint64(string.format("0x%X%08X", base_hi, base_lo + i))
        local val = rq(addr)
        if val then
            local h, l = get_hi_lo(val)
            if h < 0 then h = h + 0x100000000 end
            if l < 0 then l = l + 0x100000000 end

            if h == 0 and l == 0 then
                counts.zero = counts.zero + 1
            elseif h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                counts.kptr = counts.kptr + 1
                if #sample_ptrs < 10 then
                    sample_ptrs[#sample_ptrs + 1] = string.format("+0x%X: 0x%08X%08X", i, h, l)
                end
            elseif h >= 0x30 and h <= 0x3F then
                counts.heap = counts.heap + 1
            elseif eboot_hi > 0 and h == eboot_hi then
                counts.eboot = counts.eboot + 1
            elseif h >= 0x80 and h <= 0x90 then
                counts.lib = counts.lib + 1
            else
                counts.other = counts.other + 1
            end
        end
        i = i + 8
    end

    print(string.format("  Pointer categories (first 0x%X of writable region):", scan_size))
    print(string.format("    eboot ptrs: %d", counts.eboot))
    print(string.format("    heap ptrs:  %d", counts.heap))
    print(string.format("    lib ptrs:   %d", counts.lib))
    print(string.format("    kptr:       %d", counts.kptr))
    print(string.format("    zeros:      %d", counts.zero))
    print(string.format("    other:      %d", counts.other))

    if #sample_ptrs > 0 then
        print("  Sample kernel pointers:")
        for _, s in ipairs(sample_ptrs) do print("    " .. s) end
    end
end

if not alive() then print("DEAD after [C]"); return end

-- ============================================================
-- [D] Scan ALL modules' writable data for kernel pointers
-- ============================================================
print("")
print("[D] All-module writable data kernel pointer scan")

local all_module_kptrs = 0
local sc_info2 = mk(593)

for handle = 0, 50 do
    if not alive() then break end

    local minfo = memory.alloc(0x200)
    wd(N(minfo), 0x160)
    local ret = -999
    pcall(function() ret = N(sc_info2(uint64(handle), minfo)) end)
    if ret ~= 0 then
        -- skip invalid handle
    else
        -- Get data segment info
        local data_lo = rd(N(minfo) + 0x118) or 0
        local data_hi = rd(N(minfo) + 0x11C) or 0
        local data_sz = rd(N(minfo) + 0x120) or 0
        if data_lo < 0 then data_lo = data_lo + 0x100000000 end
        if data_hi < 0 then data_hi = data_hi + 0x100000000 end
        if data_sz < 0 then data_sz = data_sz + 0x100000000 end

        if data_sz > 0 and data_hi > 0 then
            local scan_sz = math.min(data_sz, 0x40000)
            local mkptr = 0
            local i = 0
            while i + 7 < scan_sz do
                local a = uint64(string.format("0x%X%08X", data_hi, data_lo + i))
                local v = rq(a)
                if v then
                    local h, l = get_hi_lo(v)
                    if h < 0 then h = h + 0x100000000 end
                    if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                        mkptr = mkptr + 1
                        if mkptr <= 3 then
                            print(string.format("  *** MODULE %d +0x%X: 0x%08X%08X ***",
                                handle, i, h, l))
                        end
                    end
                end
                i = i + 8
            end
            if mkptr > 0 then
                print(string.format("  module %d: %d kptrs in 0x%X bytes", handle, mkptr, scan_sz))
                all_module_kptrs = all_module_kptrs + mkptr
            end
        end
    end
end

print("  ALL-MODULE kernel pointers: " .. all_module_kptrs)

if not alive() then print("DEAD after [D]"); return end

-- ============================================================
-- [E] Scan heap for any kernel pointers (sample first 1MB)
-- ============================================================
print("")
print("[E] Heap kernel pointer sample")

local sc_mmap = mk(477)
local heap_page = nil
pcall(function()
    heap_page = sc_mmap(uint64(0), uint64(0x100000), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

if heap_page then
    local hp_h, hp_l = get_hi_lo(heap_page)
    if hp_h < 0 then hp_h = hp_h + 0x100000000 end
    if hp_l < 0 then hp_l = hp_l + 0x100000000 end
    print(string.format("  heap sample at 0x%X%08X (1MB)", hp_h, hp_l))

    local heap_kptrs = 0
    for i = 0, 0xFFFF8 - 1, 8 do
        local v = rq(uint64(string.format("0x%X%08X", hp_h, hp_l + i)))
        if v then
            local h, l = get_hi_lo(v)
            if h < 0 then h = h + 0x100000000 end
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                heap_kptrs = heap_kptrs + 1
                if heap_kptrs <= 5 then
                    print(string.format("    KPTR at heap+0x%X: 0x%08X%08X", i, h, l))
                end
            end
        end
    end
    print("  heap kptrs: " .. heap_kptrs)
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 74c COMPLETE ===")
