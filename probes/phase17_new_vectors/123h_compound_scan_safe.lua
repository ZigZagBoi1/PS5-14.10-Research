-- CRASH_CLASS: LOW
-- PROBE 123h: Compound gadget scan — safe boundary detection
--
-- 123g crashed because the eboot_end detection loop hit XO pages
-- adjacent to eboot. XO reads kill past pcall.
-- Fix: use known safe scan limit of 0x480000 (~4.6MB) and stop at
-- first read failure within the aligned scan.

print("=== PROBE 123h: COMPOUND GADGET SCAN (SAFE) ===")
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

local function get_eboot_base()
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local sc_info = make_syscall(593)
    pcall(function() sc_info(uint64(0), info) end)
    local lo = safe_rd(info + 0x108)
    local hi = safe_rd(info + 0x10C)
    if lo and hi then
        return uint64(string.format("0x%X%08X", hi, lo)), hi, lo
    end
    return nil, 0, 0
end

collectgarbage("stop")

local eboot_base, eboot_hi, eboot_lo = get_eboot_base()
print(string.format("[*] eboot base: 0x%08X_%08X", eboot_hi, eboot_lo))
if not eboot_base then print("ABORT") return end

local function ea(off)
    local lo = eboot_lo + off
    local hi = eboot_hi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return uint64(string.format("0x%X%08X", hi, lo))
end

-- Use conservative limit — scan first 2MB only (known RX from prior probes)
local SCAN_LIMIT = 0x200000

-- Verify we can read at start
local test_rd = safe_rd(ea(0))
if not test_rd then print("ABORT: can't read eboot+0") return end
print(string.format("[*] Scanning first %d KB of eboot .text", SCAN_LIMIT / 1024))

local pop_names = {
    [0x58] = "pop rax",
    [0x59] = "pop rcx",
    [0x5A] = "pop rdx",
    [0x5B] = "pop rbx",
    [0x5D] = "pop rbp",
    [0x5E] = "pop rsi",
    [0x5F] = "pop rdi",
}

local rex_pop_names = {
    [0x58] = "pop r8",  [0x59] = "pop r9",
    [0x5A] = "pop r10", [0x5B] = "pop r11",
    [0x5C] = "pop r12", [0x5D] = "pop r13",
    [0x5E] = "pop r14", [0x5F] = "pop r15",
}

-- =============================================
-- Find ALL xor eax,eax;ret (31 C0 C3) locations first
-- Then check what's immediately before each one
-- This is more efficient than scanning for every compound pattern
-- =============================================
print("")
print("--- Finding all xor eax,eax;ret (31 C0 C3) ---")

local xor_locs = {}
for off = 0, SCAN_LIMIT - 4, 4 do
    local dw = safe_rd(ea(off))
    if dw == nil then
        print(string.format("[*] Read failed at eboot+0x%X, stopping scan", off))
        break
    end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    if b0 == 0x31 and b1 == 0xC0 and b2 == 0xC3 then
        xor_locs[#xor_locs + 1] = off
    end
    if b1 == 0x31 and b2 == 0xC0 and b3 == 0xC3 then
        xor_locs[#xor_locs + 1] = off + 1
    end
end

print(string.format("[*] Found %d xor eax,eax;ret locations", #xor_locs))

-- For each xor location, check preceding bytes for useful gadgets
print("")
print("--- Compound gadgets (prefix + xor eax,eax;ret) ---")

local compounds = {}

for _, xoff in ipairs(xor_locs) do
    -- Read the 4 bytes BEFORE the xor
    if xoff >= 4 then
        local prev_dw = safe_rd(ea(xoff - 4))
        local prev2_dw = safe_rd(ea(xoff - 3))
        if prev_dw then
            local p0 = prev_dw % 256
            local p1 = math.floor(prev_dw / 256) % 256
            local p2 = math.floor(prev_dw / 65536) % 256
            local p3 = math.floor(prev_dw / 16777216) % 256

            -- 1 byte before: single pop REG
            if pop_names[p3] then
                compounds[#compounds + 1] = {
                    off = xoff - 1,
                    desc = pop_names[p3] .. "; xor eax,eax; ret",
                    len = 4
                }
            end

            -- 2 bytes before: REX pop (41 5X) or double pop
            if p2 == 0x41 and rex_pop_names[p3] then
                compounds[#compounds + 1] = {
                    off = xoff - 2,
                    desc = rex_pop_names[p3] .. "; xor eax,eax; ret",
                    len = 5
                }
            end
            if pop_names[p2] and pop_names[p3] then
                compounds[#compounds + 1] = {
                    off = xoff - 2,
                    desc = pop_names[p2] .. "; " .. pop_names[p3] .. "; xor eax,eax; ret",
                    len = 5
                }
            end

            -- 3 bytes before: triple pop or REX+double
            if pop_names[p1] and pop_names[p2] and pop_names[p3] then
                compounds[#compounds + 1] = {
                    off = xoff - 3,
                    desc = pop_names[p1] .. "; " .. pop_names[p2] .. "; " .. pop_names[p3] .. "; xor eax,eax; ret",
                    len = 6
                }
            end
        end
    end

    -- Also check 1 byte before directly (handles unaligned)
    if xoff >= 1 then
        local byte_addr = ea(xoff - 1)
        local byte_dw = safe_rd(byte_addr)
        if byte_dw then
            -- The byte at xoff-1 depends on alignment
            local align = (xoff - 1) % 4
            local byte_val
            if align == 0 then byte_val = byte_dw % 256
            elseif align == 1 then byte_val = math.floor(byte_dw / 256) % 256
            elseif align == 2 then byte_val = math.floor(byte_dw / 65536) % 256
            else byte_val = math.floor(byte_dw / 16777216) % 256
            end
            -- Already handled by p3 check above, skip duplicates
        end
    end
end

-- Deduplicate by offset
local seen = {}
local unique_compounds = {}
for _, c in ipairs(compounds) do
    if not seen[c.off] then
        seen[c.off] = true
        unique_compounds[#unique_compounds + 1] = c
    end
end

-- Sort by offset
table.sort(unique_compounds, function(a, b) return a.off < b.off end)

print(string.format("[*] Found %d unique compound gadgets:", #unique_compounds))
for _, c in ipairs(unique_compounds) do
    print(string.format("  *** eboot+0x%06X: %s ***", c.off, c.desc))
end


-- =============================================
-- leave;ret + pop rbp;ret
-- =============================================
print("")
print("--- leave;ret + pop rbp;ret ---")

local leave_first = nil
local leave_count = 0
local pop_rbp_off = nil

for off = 0, SCAN_LIMIT - 4, 4 do
    local dw = safe_rd(ea(off))
    if dw == nil then break end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    if b0 == 0xC9 and b1 == 0xC3 then
        leave_count = leave_count + 1
        if not leave_first then leave_first = off end
    end
    if b1 == 0xC9 and b2 == 0xC3 then
        leave_count = leave_count + 1
        if not leave_first then leave_first = off+1 end
    end
    if b2 == 0xC9 and b3 == 0xC3 then
        leave_count = leave_count + 1
        if not leave_first then leave_first = off+2 end
    end

    if not pop_rbp_off then
        if b0 == 0x5D and b1 == 0xC3 then pop_rbp_off = off end
        if b1 == 0x5D and b2 == 0xC3 then pop_rbp_off = off+1 end
    end
end

print(string.format("[*] leave;ret: %d instances, first at eboot+0x%X",
    leave_count, leave_first or 0))
print(string.format("[*] pop rbp;ret: %s",
    pop_rbp_off and string.format("eboot+0x%X", pop_rbp_off) or "NOT FOUND"))


-- =============================================
-- mov eax,0;ret and mov eax,1;ret scan
-- =============================================
print("")
print("--- mov eax,imm;ret (small values) ---")

for off = 0, SCAN_LIMIT - 8, 4 do
    local dw = safe_rd(ea(off))
    if dw == nil then break end
    local b0 = dw % 256

    if b0 == 0xB8 then
        -- B8 XX XX XX XX C3 — check if byte at off+5 is C3
        local dw2 = safe_rd(ea(off + 4))
        if dw2 then
            local byte5 = math.floor(dw2 / 256) % 256
            if byte5 == 0xC3 then
                local imm_b1 = math.floor(dw / 256) % 256
                local imm_b2 = math.floor(dw / 65536) % 256
                local imm_b3 = math.floor(dw / 16777216) % 256
                local imm_b4 = dw2 % 256
                local val = imm_b1 + imm_b2*256 + imm_b3*65536 + imm_b4*16777216
                if val <= 10 then
                    print(string.format("  eboot+0x%X: mov eax,%d; ret", off, val))
                end
            end
        end
    end
end


print("")
print("=== PROBE 123h COMPLETE ===")
