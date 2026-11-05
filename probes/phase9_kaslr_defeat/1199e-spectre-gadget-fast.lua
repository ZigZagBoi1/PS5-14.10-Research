-- CRASH_CLASS: LOW
-- PROBE 1199e: Fast Spectre gadget scan — dword-stride with early reporting
--
-- 1199d was too slow (6M individual reads). This version:
-- 1. Reads dwords (4 bytes at a time) and checks ALL patterns per read
-- 2. Reports findings IMMEDIATELY (before scan completes)
-- 3. Scans only first 2MB (most gadgets are in hot code)
-- 4. If nothing found, extends to 4MB

print("=== PROBE 1199e: Fast Spectre gadget scan ===")
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
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

-- Get eboot base
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)

local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
if not text_lo or not text_hi then
    print("FATAL: cannot get eboot base")
    return
end

local eboot_base = uint64(string.format("0x%X%08X", text_hi, text_lo))
print(string.format("eboot base: 0x%X%08X", text_hi, text_lo))

-- Gadget targets (byte patterns within a dword read):
-- rdtsc;ret     = 0F 31 C3 (bytes 0,1,2 of a dword)
-- clflush [rdi];ret = 0F AE 3F C3 (full dword)
-- lfence;ret    = 0F AE E8 C3 (full dword)
-- mfence;ret    = 0F AE F0 C3 (full dword)

-- We scan dword-aligned AND dword+1,+2,+3 by reading overlapping dwords
-- Strategy: read at every 1-byte offset but decode from the dword

local results = {
    rdtsc = {},       -- 0F 31 anywhere
    rdtsc_ret = {},   -- 0F 31 C3
    clflush_rdi_ret = {}, -- 0F AE 3F C3
    lfence_ret = {},  -- 0F AE E8 C3
    mfence_ret = {},  -- 0F AE F0 C3
    clflush_any = {}, -- 0F AE [38-3F]
    rdtscp = {},      -- 0F 01 F9
}

-- Scan in dword steps, checking byte patterns
-- To catch unaligned: read TWO adjacent dwords per position = 8 bytes
-- Step by 4 bytes, extract 8 bytes, check all positions within

local SCAN_MB = 2
local scan_size = SCAN_MB * 1024 * 1024
print(string.format("Scanning %d MB ...", SCAN_MB))
print("")

local MAX_PER = 8

for off = 0, scan_size - 8, 4 do
    local addr = eboot_base + uint64(off)
    local dw1 = safe_rd(addr)
    local dw2 = safe_rd(addr + uint64(4))
    if dw1 and dw2 then
        -- Extract 8 bytes
        local b = {}
        b[0] = dw1 % 256
        b[1] = math.floor(dw1 / 256) % 256
        b[2] = math.floor(dw1 / 65536) % 256
        b[3] = math.floor(dw1 / 16777216) % 256
        b[4] = dw2 % 256
        b[5] = math.floor(dw2 / 256) % 256
        b[6] = math.floor(dw2 / 65536) % 256
        b[7] = math.floor(dw2 / 16777216) % 256

        -- Check each byte position for 0F prefix
        for i = 0, 4 do  -- positions 0-4 can start a 4-byte pattern
            if b[i] == 0x0F then
                -- rdtsc = 0F 31
                if b[i+1] == 0x31 then
                    local roff = off + i
                    if #results.rdtsc < MAX_PER then
                        table.insert(results.rdtsc, roff)
                    end
                    -- rdtsc;ret = 0F 31 C3
                    if b[i+2] == 0xC3 then
                        if #results.rdtsc_ret < MAX_PER then
                            table.insert(results.rdtsc_ret, roff)
                            print(string.format("FOUND rdtsc;ret at +0x%X", roff))
                        end
                    end
                end

                -- rdtscp = 0F 01 F9
                if b[i+1] == 0x01 and b[i+2] == 0xF9 then
                    local roff = off + i
                    if #results.rdtscp < MAX_PER then
                        table.insert(results.rdtscp, roff)
                        print(string.format("FOUND rdtscp at +0x%X", roff))
                    end
                end

                -- clflush/lfence/mfence = 0F AE ...
                if b[i+1] == 0xAE then
                    local modrm = b[i+2]
                    -- clflush = /7 (modrm 38-3F for [reg] forms)
                    local reg = math.floor(modrm / 8) % 8
                    if reg == 7 then
                        local roff = off + i
                        if #results.clflush_any < MAX_PER then
                            table.insert(results.clflush_any, roff)
                            print(string.format("FOUND clflush (modrm=0x%02X) at +0x%X", modrm, roff))
                        end
                        -- clflush [rdi];ret = 0F AE 3F C3
                        if modrm == 0x3F and b[i+3] == 0xC3 then
                            if #results.clflush_rdi_ret < MAX_PER then
                                table.insert(results.clflush_rdi_ret, roff)
                                print(string.format("FOUND clflush [rdi];ret at +0x%X", roff))
                            end
                        end
                    end
                    -- lfence = 0F AE E8
                    if modrm == 0xE8 then
                        local roff = off + i
                        if b[i+3] == 0xC3 then
                            if #results.lfence_ret < MAX_PER then
                                table.insert(results.lfence_ret, roff)
                                print(string.format("FOUND lfence;ret at +0x%X", roff))
                            end
                        end
                    end
                    -- mfence = 0F AE F0
                    if modrm == 0xF0 then
                        local roff = off + i
                        if b[i+3] == 0xC3 then
                            if #results.mfence_ret < MAX_PER then
                                table.insert(results.mfence_ret, roff)
                                print(string.format("FOUND mfence;ret at +0x%X", roff))
                            end
                        end
                    end
                end
            end
        end
    end

    -- Progress every 512KB
    if off % (512 * 1024) == 0 and off > 0 then
        print(string.format("  ... %dK / %dK", off / 1024, scan_size / 1024))
    end
end

print("")
print("=== SUMMARY ===")
print(string.format("rdtsc:             %d hits", #results.rdtsc))
print(string.format("rdtsc;ret:         %d hits", #results.rdtsc_ret))
print(string.format("rdtscp:            %d hits", #results.rdtscp))
print(string.format("clflush (any):     %d hits", #results.clflush_any))
print(string.format("clflush [rdi];ret: %d hits", #results.clflush_rdi_ret))
print(string.format("lfence;ret:        %d hits", #results.lfence_ret))
print(string.format("mfence;ret:        %d hits", #results.mfence_ret))
print("")

-- List offsets
for name, list in pairs(results) do
    if #list > 0 then
        local offs = {}
        for _, o in ipairs(list) do table.insert(offs, string.format("+0x%X", o)) end
        print(string.format("  %s: %s", name, table.concat(offs, ", ")))
    end
end

-- Also check for clflushopt = 66 0F AE /7
print("")
print("--- Bonus: clflushopt scan (66 0F AE /7) ---")
local clflushopt = {}
for off = 0, scan_size - 8, 4 do
    local addr = eboot_base + uint64(off)
    local dw1 = safe_rd(addr)
    local dw2 = safe_rd(addr + uint64(4))
    if dw1 and dw2 then
        local b = {}
        b[0] = dw1 % 256
        b[1] = math.floor(dw1 / 256) % 256
        b[2] = math.floor(dw1 / 65536) % 256
        b[3] = math.floor(dw1 / 16777216) % 256
        b[4] = dw2 % 256

        for i = 0, 3 do
            if b[i] == 0x66 and b[i+1] == 0x0F and b[i+2] == 0xAE then
                local modrm = b[i+3]
                local reg = math.floor(modrm / 8) % 8
                if reg == 7 then
                    local roff = off + i
                    if #clflushopt < MAX_PER then
                        table.insert(clflushopt, roff)
                        print(string.format("FOUND clflushopt (modrm=0x%02X) at +0x%X", modrm, roff))
                    end
                end
            end
        end
    end
end
if #clflushopt == 0 then
    print("  No clflushopt found")
end

print("")
print("=== PROBE 1199e COMPLETE ===")
