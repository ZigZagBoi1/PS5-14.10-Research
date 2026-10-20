-- CRASH_CLASS: LOW
-- PROBE 123j: Micro compound scan — 64KB chunks, no pcall overhead
--
-- Previous scans timed out on 2MB. This scans 64KB per run using
-- direct memory.read_dword (no pcall wrapper) for speed.
-- Also checks specific known xor_eax_ret locations for prefixes.

print("=== PROBE 123j: MICRO COMPOUND SCAN ===")
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
print(string.format("[*] eboot: 0x%08X_%08X", eboot_hi, eboot_lo))
if not eboot_base then print("ABORT") return end

local function ea(off)
    local lo = eboot_lo + off
    local hi = eboot_hi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return uint64(string.format("0x%X%08X", hi, lo))
end

local pop_names = {
    [0x58] = "pop_rax", [0x59] = "pop_rcx", [0x5A] = "pop_rdx",
    [0x5B] = "pop_rbx", [0x5D] = "pop_rbp", [0x5E] = "pop_rsi",
    [0x5F] = "pop_rdi",
}

-- APPROACH: Don't scan byte-by-byte. Instead, read dwords and check
-- for the ALIGNED pattern 0xC3C031XX where XX is a pop opcode.
-- This misses unaligned instances but is 4x faster.
-- Then separately check cross-boundary at +1, +2, +3 for promising areas.

print("--- Phase 1: Aligned dword scan (0x00000-0x100000) ---")

local hits = {}
local leave_hits = {}
local pop_rbp_first = nil

for off = 0, 0x100000 - 4, 4 do
    local dw = to_num(memory.read_dword(ea(off)))

    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    -- Aligned: XX 31 C0 C3 at this dword
    if b1 == 0x31 and b2 == 0xC0 and b3 == 0xC3 and pop_names[b0] then
        hits[#hits + 1] = {off, pop_names[b0], "aligned"}
    end

    -- leave;ret (C9 C3) anywhere in dword
    if b0 == 0xC9 and b1 == 0xC3 then leave_hits[#leave_hits+1] = off end
    if b1 == 0xC9 and b2 == 0xC3 then leave_hits[#leave_hits+1] = off+1 end
    if b2 == 0xC9 and b3 == 0xC3 then leave_hits[#leave_hits+1] = off+2 end

    -- pop rbp;ret (5D C3)
    if not pop_rbp_first then
        if b0 == 0x5D and b1 == 0xC3 then pop_rbp_first = off end
        if b1 == 0x5D and b2 == 0xC3 then pop_rbp_first = off+1 end
    end
end

print(string.format("[1] Scanned 1MB. Aligned compounds: %d, leave;ret: %d",
    #hits, #leave_hits))

-- Phase 2: Check cross-boundary by reading at off+2 for another 1MB
print("")
print("--- Phase 2: Cross-boundary scan (0x00000-0x100000) ---")

for off = 0, 0x100000 - 8, 4 do
    local dw = to_num(memory.read_dword(ea(off)))
    local dw2 = to_num(memory.read_dword(ea(off + 4)))

    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256
    local nb0 = dw2 % 256
    local nb1 = math.floor(dw2 / 256) % 256
    local nb2 = math.floor(dw2 / 65536) % 256

    -- At off+1: b1=pop, b2=31, b3=C0, nb0=C3
    local b1 = math.floor(dw / 256) % 256
    if pop_names[b1] and b2 == 0x31 and b3 == 0xC0 and nb0 == 0xC3 then
        hits[#hits + 1] = {off+1, pop_names[b1], "cross+1"}
    end

    -- At off+2: b2=pop, b3=31, nb0=C0, nb1=C3
    if pop_names[b2] and b3 == 0x31 and nb0 == 0xC0 and nb1 == 0xC3 then
        hits[#hits + 1] = {off+2, pop_names[b2], "cross+2"}
    end

    -- At off+3: b3=pop, nb0=31, nb1=C0, nb2=C3
    if pop_names[b3] and nb0 == 0x31 and nb1 == 0xC0 and nb2 == 0xC3 then
        hits[#hits + 1] = {off+3, pop_names[b3], "cross+3"}
    end
end

print(string.format("[2] Total compounds after cross-boundary: %d", #hits))

-- Print all hits
print("")
print("=== COMPOUND GADGETS ===")
for _, h in ipairs(hits) do
    print(string.format("  eboot+0x%06X: %s; xor eax,eax; ret [%s]", h[1], h[2], h[3]))
end

print("")
print(string.format("[*] leave;ret: %d (first at eboot+0x%X)",
    #leave_hits, leave_hits[1] or 0))
print(string.format("[*] pop rbp;ret: %s",
    pop_rbp_first and string.format("eboot+0x%X", pop_rbp_first) or "NOT FOUND"))

-- Show first 3 leave;ret
if #leave_hits > 0 then
    for i = 1, math.min(3, #leave_hits) do
        print(string.format("  leave;ret at eboot+0x%X", leave_hits[i]))
    end
end

print("")
print("=== PROBE 123j COMPLETE ===")
