-- CRASH_CLASS: LOW
-- PROBE 74b: Eboot GOT/PLT and writable data scan for kernel pointers
--
-- The dynamic linker resolves import stubs by writing target addresses into
-- the GOT (Global Offset Table) in the writable .data segment. On FreeBSD,
-- some GOT entries may point into kernel helper pages (signal trampoline,
-- vDSO) or contain kernel-resolved addresses. Even if all GOT entries are
-- userland, the writable data segment may contain kernel-written values
-- from process initialization.
--
-- Strategy: use sys 674 (VM map) to find all writable (prot & 2) regions
-- that belong to eboot, then scan every qword for kernel pointer patterns.
-- Also scan libkernel's writable segment.

print("=== PROBE 74b: EBOOT GOT KPTR SCAN ===")
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
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Get eboot base via dynlib_get_info(593) handle=0
local info_buf = memory.alloc(0x200)
wd(N(info_buf), 0x160)
pcall(function() mk(593)(uint64(0), info_buf) end)
local eboot_text_lo = rd(N(info_buf) + 0x108) or 0
local eboot_text_hi = rd(N(info_buf) + 0x10C) or 0
local eboot_base = uint64(string.format("0x%X%08X", eboot_text_hi, eboot_text_lo))
print("eboot_base=" .. fmt(eboot_base))

-- Get eboot data segment info
local eboot_data_lo = rd(N(info_buf) + 0x118) or 0
local eboot_data_hi = rd(N(info_buf) + 0x11C) or 0
local eboot_data_base = uint64(string.format("0x%X%08X", eboot_data_hi, eboot_data_lo))
local eboot_data_size_lo = rd(N(info_buf) + 0x120) or 0
local eboot_data_size_hi = rd(N(info_buf) + 0x124) or 0
print("eboot_data_base=" .. fmt(eboot_data_base))
print("eboot_data_size=" .. string.format("0x%X%08X", eboot_data_size_hi, eboot_data_size_lo))

-- ============================================================
-- [A] Scan eboot writable data for kernel pointers
-- ============================================================
print("")
print("[A] Eboot data segment scan")
local total_kptrs = 0
local total_scanned = 0
local kptr_list = {}

-- Scan eboot data segment
if eboot_data_hi > 0 or eboot_data_lo > 0 then
    local data_size = eboot_data_size_lo
    if data_size > 0x200000 then data_size = 0x200000 end  -- cap at 2MB
    if data_size < 0x1000 then data_size = 0x100000 end    -- min 1MB
    print("  scanning " .. string.format("0x%X", data_size) .. " bytes of eboot data")

    local scan_addr = N(eboot_data_base)
    local end_addr = scan_addr + data_size
    local batch_size = 0x1000  -- 4KB at a time
    local readable_count = 0

    while scan_addr < end_addr and #kptr_list < 100 do
        local ok_batch = true
        for off = 0, batch_size - 8, 8 do
            local val = rq(uint64(scan_addr + off))
            if val ~= nil then
                total_scanned = total_scanned + 1
                readable_count = readable_count + 1
                if is_kptr(val) then
                    total_kptrs = total_kptrs + 1
                    local offset_from_base = scan_addr + off - N(eboot_data_base)
                    kptr_list[#kptr_list + 1] = {
                        offset = offset_from_base,
                        value = val,
                        segment = "eboot_data"
                    }
                    print(string.format("  *** KPTR at data+0x%X: %s ***",
                        offset_from_base, fmt(val)))
                end
            else
                ok_batch = false
                break
            end
        end
        scan_addr = scan_addr + batch_size
        if not ok_batch then
            -- Hit unmapped, skip to next page boundary
            scan_addr = math.floor((scan_addr + 0x3FFF) / 0x4000) * 0x4000
        end
    end
    print("  readable qwords: " .. readable_count .. " kptrs: " .. total_kptrs)
end

if not alive() then print("DEAD after [A]"); return end

-- ============================================================
-- [B] Scan via sys 674 for all writable regions
-- ============================================================
print("")
print("[B] sys 674 writable region enumeration")
local outbuf = memory.alloc(0x10000)
local outlen = memory.alloc(8)
wd(N(outlen), 0x10000)
wd(N(outlen) + 4, 0)
pcall(function() mk(674)(uint64(N(outbuf)), uint64(N(outlen)), uint64(0)) end)
local used = rd(N(outlen)) or 0
print("  674 returned " .. used .. " bytes")

-- Parse 72-byte records, find writable regions
local rec_size = 72
local writable_regions = {}
local pos = 0
while pos + rec_size <= used do
    local start_lo = rd(N(outbuf) + pos) or 0
    local start_hi = rd(N(outbuf) + pos + 4) or 0
    local end_lo = rd(N(outbuf) + pos + 8) or 0
    local end_hi = rd(N(outbuf) + pos + 12) or 0
    local prot = rd(N(outbuf) + pos + 0x18) or 0

    -- prot & 2 = writable, prot & 4 = executable (skip exec-only)
    if prot == 3 or prot == 0x33 then  -- RW or RW+special
        local size = 0
        if start_hi == end_hi then
            size = end_lo - start_lo
        else
            size = (end_hi - start_hi) * 0x100000000 + (end_lo - start_lo)
        end
        -- Read the name at +0x20
        local name_bytes = {}
        for i = 0, 31 do
            local b = rd(N(outbuf) + pos + 0x20 + i)
            if b and b > 0 and b < 128 then
                name_bytes[#name_bytes + 1] = string.char(b)
            else
                break
            end
        end
        local name = table.concat(name_bytes)

        writable_regions[#writable_regions + 1] = {
            start_hi = start_hi, start_lo = start_lo,
            end_hi = end_hi, end_lo = end_lo,
            prot = prot, size = size, name = name
        }
        print(string.format("  RW: 0x%X%08X-0x%X%08X p=%d sz=0x%X %s",
            start_hi, start_lo, end_hi, end_lo, prot, size, name))
    end
    pos = pos + rec_size
end
print("  found " .. #writable_regions .. " writable regions")

if not alive() then print("DEAD after [B]"); return end

-- ============================================================
-- [C] Scan interesting writable regions for kernel pointers
-- ============================================================
print("")
print("[C] Writable region kernel pointer scan")

local section_kptrs = 0
for ri, reg in ipairs(writable_regions) do
    -- Skip GPU/mapped regions (p=0x33), focus on p=3 with names
    if reg.prot == 3 and reg.size > 0 and reg.size <= 0x200000 then
        local scan_start = uint64(string.format("0x%X%08X", reg.start_hi, reg.start_lo))
        local scan_size = reg.size
        if scan_size > 0x100000 then scan_size = 0x100000 end  -- cap 1MB

        local region_kptrs = 0
        local readable = 0
        local addr = N(scan_start)
        local limit = addr + scan_size

        while addr < limit and region_kptrs < 20 do
            local val = rq(uint64(addr))
            if val ~= nil then
                readable = readable + 1
                if is_kptr(val) then
                    region_kptrs = region_kptrs + 1
                    section_kptrs = section_kptrs + 1
                    local off = addr - N(scan_start)
                    print(string.format("  *** KPTR in %s +0x%X: %s ***",
                        reg.name, off, fmt(val)))
                end
            end
            addr = addr + 8
        end
        if readable > 0 then
            print(string.format("  %s: scanned %d qwords, %d kptrs",
                reg.name, readable, region_kptrs))
        end
    end
end
print("  writable region kptrs: " .. section_kptrs)
total_kptrs = total_kptrs + section_kptrs

if not alive() then print("DEAD after [C]"); return end

-- ============================================================
-- [D] Scan libkernel data segment specifically
-- ============================================================
print("")
print("[D] libkernel data segment scan")

-- Find libkernel: handle=1 usually
local lk_kptrs = 0
for handle = 1, 50 do
    wd(N(info_buf), 0x160)
    for i = 4, 0x15F, 4 do wd(N(info_buf) + i, 0) end
    local ret = -1
    pcall(function() ret = N(mk(593)(uint64(handle), info_buf)) end)
    if ret == 0 then
        local data_lo = rd(N(info_buf) + 0x118) or 0
        local data_hi = rd(N(info_buf) + 0x11C) or 0
        if data_hi > 0 or data_lo > 0 then
            -- Read module name from info struct (offset 0x00-0x??)
            local name_bytes = {}
            for i = 4, 35 do
                local b = rd(N(info_buf) + i)
                if b and b > 0 and b < 128 then
                    name_bytes[#name_bytes + 1] = string.char(b)
                else
                    break
                end
            end
            local mod_name = table.concat(name_bytes)

            -- Check if this is libkernel or libSceLibcInternal
            local data_size_lo = rd(N(info_buf) + 0x120) or 0
            local scan_size = data_size_lo
            if scan_size > 0x100000 then scan_size = 0x100000 end
            if scan_size < 0x100 then scan_size = 0x10000 end

            local data_base = uint64(string.format("0x%X%08X", data_hi, data_lo))
            local scan_addr = N(data_base)
            local mod_kptrs = 0
            local mod_readable = 0

            for off = 0, scan_size - 8, 8 do
                local val = rq(uint64(scan_addr + off))
                if val ~= nil then
                    mod_readable = mod_readable + 1
                    if is_kptr(val) then
                        mod_kptrs = mod_kptrs + 1
                        lk_kptrs = lk_kptrs + 1
                        print(string.format("  *** KPTR in module %d data+0x%X: %s ***",
                            handle, off, fmt(val)))
                        if mod_kptrs >= 20 then break end
                    end
                else
                    break
                end
            end
            if mod_readable > 100 then
                print(string.format("  module %d: scanned %d qwords, %d kptrs",
                    handle, mod_readable, mod_kptrs))
            end
        end
    end
end
print("  libkernel scan kptrs: " .. lk_kptrs)
total_kptrs = total_kptrs + lk_kptrs

if not alive() then print("DEAD after [D]"); return end

-- ============================================================
-- [E] TLS / TCB area scan
-- ============================================================
print("")
print("[E] TCB / FS base area scan")

-- Read FS base from sysarch(130 = AMD64_GET_FSBASE)
local fsbase_buf = memory.alloc(16)
wd(N(fsbase_buf), 0); wd(N(fsbase_buf) + 4, 0)
pcall(function() mk(165)(uint64(130), uint64(N(fsbase_buf))) end)
local fsbase = rq(uint64(N(fsbase_buf)))
print("  fsbase=" .. fmt(fsbase))

if fsbase ~= nil then
    local fs_addr = N(fsbase)
    local tcb_kptrs = 0
    -- Scan TCB and surrounding TLS area (4KB)
    for off = -0x200, 0x200, 8 do
        local val = rq(uint64(fs_addr + off))
        if val ~= nil and is_kptr(val) then
            tcb_kptrs = tcb_kptrs + 1
            print(string.format("  *** KPTR at FS%+d: %s ***", off, fmt(val)))
        end
    end
    print("  TCB area kptrs: " .. tcb_kptrs)
    total_kptrs = total_kptrs + tcb_kptrs
end

if not alive() then print("DEAD after [E]"); return end

-- ============================================================
-- [F] Stack area scan (look for kernel-placed values)
-- ============================================================
print("")
print("[F] Stack area scan")

-- Get current RSP approximately via alloc
local stack_probe = memory.alloc(8)
local stack_area = N(stack_probe)
-- The stack is somewhere near alloc'd memory, scan conservatively
-- Actually, let's use the eboot's .bss section instead
-- Look at the top of the 674 map for stack-like regions
local stack_kptrs = 0
for ri, reg in ipairs(writable_regions) do
    if reg.name == "" and reg.prot == 3 and reg.size >= 0x4000 and reg.size <= 0x100000 then
        -- Unnamed writable region could be stack or BSS
        local scan_start = uint64(string.format("0x%X%08X", reg.start_hi, reg.start_lo))
        local addr = N(scan_start)
        local scan_count = math.min(math.floor(reg.size / 8), 8192)  -- max 8K qwords
        local rgn_kptrs = 0
        local rgn_readable = 0

        for i = 0, scan_count - 1 do
            local val = rq(uint64(addr + i * 8))
            if val ~= nil then
                rgn_readable = rgn_readable + 1
                if is_kptr(val) then
                    rgn_kptrs = rgn_kptrs + 1
                    stack_kptrs = stack_kptrs + 1
                    print(string.format("  *** KPTR in unnamed@0x%X%08X +0x%X: %s ***",
                        reg.start_hi, reg.start_lo, i * 8, fmt(val)))
                    if rgn_kptrs >= 10 then break end
                end
            end
        end
        if rgn_readable > 100 then
            print(string.format("  unnamed@0x%X%08X: %d qwords, %d kptrs",
                reg.start_hi, reg.start_lo, rgn_readable, rgn_kptrs))
        end
    end
end
print("  stack/unnamed area kptrs: " .. stack_kptrs)
total_kptrs = total_kptrs + stack_kptrs

-- ============================================================
-- [G] SUMMARY
-- ============================================================
print("")
print("[G] SUMMARY")
print("  total kernel pointers found: " .. total_kptrs)
print("  eboot data kptrs: " .. #kptr_list)
print("  writable region kptrs: " .. section_kptrs)
print("  module data kptrs: " .. lk_kptrs)
print("  alive=" .. tostring(alive()))
print("")
print("=== PROBE 74b COMPLETE ===")
