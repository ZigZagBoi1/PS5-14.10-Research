-- CRASH_CLASS: LOW
-- PROBE 56i5: Investigate kernel pointer at region 51 +0x07F8
--
-- Context: 56i4 found ONE kernel pointer: 0xFFFFFFFE_082E0057 at region 51
-- (0x2_006AC000, 16KB R--, tag [3]) offset +0x07F8.
-- Need to:
--   [B] Dump full 16KB of region 51 for all kernel pointers
--   [C] Get remaining 368 regions (768 total, only got 400)
--   [D] Check if the kptr is stable across runs (real vs stale)
--   [E] Scan region 14 (canary page) and region 60 (loader metadata)
--   [F] Read eboot .rodata for function pointers that might reference kernel

print("=== PROBE 56i5: KPTR INVESTIGATION ===")
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
-- [B] Get VM map and find region 51 equivalent in this run
-- (ASLR means addresses change each connection)
-- ============================================================
print("")
print("[B] Find RO region with tag [3]")

local sc674 = make_syscall(674)
local STRIDE = 72

-- First pass: get all 768 regions (need 2 calls)
local MAX1 = 512
local buf1 = memory.alloc(STRIDE * MAX1)
local countp = memory.alloc(16)
safe_wq(countp, uint64(0))

local ok, ret = pcall(function()
    return sc674(uint64(buf1), uint64(STRIDE), uint64(MAX1),
                  uint64(countp), uint64(0x40000000))
end)
local total = safe_rd(countp) or 0
print("  Total regions: " .. total)

-- Find the RO region tagged [3] and other interesting ones
local target_region = nil
local target_start_h, target_start_l = 0, 0
local all_ro_regions = {}

local limit = total
if limit > MAX1 then limit = MAX1 end

for e = 0, limit - 1 do
    local base = buf1 + e * STRIDE
    local start_val = safe_rq(base)
    local end_val = safe_rq(base + 8)
    local prot = safe_rd(base + 0x18) or 0

    local name = ""
    for ci = 0, 3 do
        local b = safe_rd(base + 0x20 + ci)
        if b and b > 0 and b < 128 then
            name = name .. string.char(b)
        elseif b == 0 then break end
    end

    if prot == 1 then
        local sh, sl = get_hi_lo(start_val)
        local eh, el = get_hi_lo(end_val)
        local size = (eh == sh) and (el - sl) or ((eh - sh) * 0x100000000 + (el - sl))
        all_ro_regions[#all_ro_regions + 1] = {idx=e, name=name, sh=sh, sl=sl, size=size}
        print(string.format("  RO[%d] %s size=%d name='%s'", e, hexval(start_val), size, name))

        if name == "3" then
            target_region = e
            target_start_h = sh
            target_start_l = sl
        end
    end
end

-- ============================================================
-- [C] Deep scan of region tagged [3]
-- ============================================================
print("")
print("[C] Full scan of RO region [3]")

if target_region then
    print("  Found at region " .. target_region .. ": " ..
        string.format("0x%X_%08X", target_start_h, target_start_l))

    -- Scan full 16KB for ALL kernel pointers and interesting values
    local kptr_count = 0
    local interesting_count = 0

    for off = 0, 0x3FF8, 8 do
        local sl = target_start_l + off
        local sh = target_start_h
        if sl >= 0x100000000 then
            sh = sh + 1
            sl = sl - 0x100000000
        end
        local addr = uint64(string.format("0x%X%08X", sh, sl))
        local val = safe_rq(addr)
        if val then
            local vh, vl = get_hi_lo(val)
            if is_kptr(val) then
                kptr_count = kptr_count + 1
                print(string.format("  +0x%04X: %s KPTR!", off, hexval(val)))
            elseif vh >= 0xFFFFFFF0 then
                -- Near-kernel values (might be off by one from sentinels)
                interesting_count = interesting_count + 1
                if interesting_count <= 10 then
                    print(string.format("  +0x%04X: %s (near-kernel)", off, hexval(val)))
                end
            end
        end
    end
    print("  Kernel pointers: " .. kptr_count)
    print("  Near-kernel values: " .. interesting_count)

    -- Dump the area around +0x07F8 in detail
    print("")
    print("  Detail around +0x07F8:")
    for off = 0x07D0, 0x0810, 4 do
        local sl = target_start_l + off
        local sh = target_start_h
        if sl >= 0x100000000 then sh = sh + 1; sl = sl - 0x100000000 end
        local addr = uint64(string.format("0x%X%08X", sh, sl))
        local dw = safe_rd(addr)
        if dw and dw ~= 0 then
            print(string.format("    +0x%04X: 0x%08X", off, dw))
        end
    end
else
    print("  Region [3] not found!")
    -- List what RO regions we do have
    for _, r in ipairs(all_ro_regions) do
        print(string.format("  RO: idx=%d name='%s' size=%d", r.idx, r.name, r.size))
    end
end

-- ============================================================
-- [D] Scan ALL 512 regions for kernel pointers (not just record fields)
-- Read actual memory contents of every readable region
-- Focus on small regions — skip huge ones (>1MB)
-- ============================================================
print("")
print("[D] Scan all small regions for kernel pointers")

local total_kptrs = 0
local regions_scanned = 0

for e = 0, limit - 1 do
    local base = buf1 + e * STRIDE
    local start_val = safe_rq(base)
    local end_val = safe_rq(base + 8)
    local prot = safe_rd(base + 0x18) or 0

    -- Only scan readable regions (prot bit 0)
    if prot % 2 == 1 then
        local sh, sl = get_hi_lo(start_val)
        local eh, el = get_hi_lo(end_val)
        local size = (eh == sh) and (el - sl) or ((eh - sh) * 0x100000000 + (el - sl))

        -- Skip huge regions and XO regions
        if size > 0 and size <= 0x10000 and prot ~= 4 then
            regions_scanned = regions_scanned + 1
            local rgn_kptrs = 0

            for off = 0, size - 1, 8 do
                local a_l = sl + off
                local a_h = sh
                if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
                local addr = uint64(string.format("0x%X%08X", a_h, a_l))
                local val = safe_rq(addr)
                if val and is_kptr(val) then
                    rgn_kptrs = rgn_kptrs + 1
                    total_kptrs = total_kptrs + 1
                    if total_kptrs <= 20 then
                        local name = ""
                        for ci = 0, 3 do
                            local b = safe_rd(base + 0x20 + ci)
                            if b and b > 0 and b < 128 then name = name .. string.char(b)
                            elseif b == 0 then break end
                        end
                        print(string.format("  rgn[%d '%s']+0x%04X: %s", e, name, off, hexval(val)))
                    end
                end
            end
        end
    end
end
print("  Regions scanned: " .. regions_scanned)
print("  TOTAL kernel pointers found: " .. total_kptrs)

-- ============================================================
-- [E] Scan eboot .rodata (region 1) for kernel-range values
-- Region 1 = 0x4A610000-0x4A628000 96KB R--
-- May contain function pointers or vtables referencing kernel
-- ============================================================
print("")
print("[E] Eboot .rodata scan for kernel pointers")

-- Find eboot RO region (first R-- region)
for e = 0, limit - 1 do
    local base = buf1 + e * STRIDE
    local start_val = safe_rq(base)
    local end_val = safe_rq(base + 8)
    local prot = safe_rd(base + 0x18) or 0

    local name = ""
    for ci = 0, 3 do
        local b = safe_rd(base + 0x20 + ci)
        if b and b > 0 and b < 128 then name = name .. string.char(b)
        elseif b == 0 then break end
    end

    if name == "e" and prot == 1 then
        local sh, sl = get_hi_lo(start_val)
        local eh, el = get_hi_lo(end_val)
        local size = (eh == sh) and (el - sl) or ((eh - sh) * 0x100000000 + (el - sl))
        print(string.format("  Eboot .rodata: %s size=%d", hexval(start_val), size))

        local rodata_kptrs = 0
        local scan_max = size
        if scan_max > 0x18000 then scan_max = 0x18000 end -- cap at 96KB

        for off = 0, scan_max - 1, 8 do
            local a_l = sl + off
            local a_h = sh
            if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
            local addr = uint64(string.format("0x%X%08X", a_h, a_l))
            local val = safe_rq(addr)
            if val and is_kptr(val) then
                rodata_kptrs = rodata_kptrs + 1
                if rodata_kptrs <= 10 then
                    print(string.format("  +0x%04X: %s KPTR!", off, hexval(val)))
                end
            end
        end
        print("  Eboot .rodata kernel pointers: " .. rodata_kptrs)
        break
    end
end

-- ============================================================
-- [F] Check region 60 deeper (32KB RO, loader metadata)
-- Contains 0xC28C0000_00000000 and 0xFE98 patterns
-- ============================================================
print("")
print("[F] Loader metadata region scan")

for e = 0, limit - 1 do
    local base = buf1 + e * STRIDE
    local start_val = safe_rq(base)
    local end_val = safe_rq(base + 8)
    local prot = safe_rd(base + 0x18) or 0
    local mp = safe_rd(base + 0x1C) or 0

    local name = ""
    for ci = 0, 3 do
        local b = safe_rd(base + 0x20 + ci)
        if b and b > 0 and b < 128 then name = name .. string.char(b)
        elseif b == 0 then break end
    end

    -- Look for 32KB RO region with mp=0xC (loader metadata from 56i4)
    if prot == 1 and mp == 0xC then
        local sh, sl = get_hi_lo(start_val)
        local eh, el = get_hi_lo(end_val)
        local size = (eh == sh) and (el - sl) or ((eh - sh) * 0x100000000 + (el - sl))
        print(string.format("  Region[%d] '%s': %s size=%d prot=%d mp=0x%X",
            e, name, hexval(start_val), size, prot, mp))

        local ldr_kptrs = 0
        local scan_sz = size
        if scan_sz > 0x8000 then scan_sz = 0x8000 end

        for off = 0, scan_sz - 1, 8 do
            local a_l = sl + off
            local a_h = sh
            if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
            local addr = uint64(string.format("0x%X%08X", a_h, a_l))
            local val = safe_rq(addr)
            if val and is_kptr(val) then
                ldr_kptrs = ldr_kptrs + 1
                if ldr_kptrs <= 10 then
                    print(string.format("  +0x%04X: %s KPTR!", off, hexval(val)))
                end
            end
        end
        print("  Loader metadata kernel pointers: " .. ldr_kptrs)
        break
    end
end

collectgarbage("restart")

print("")
print("=== PROBE 56i5 COMPLETE ===")
