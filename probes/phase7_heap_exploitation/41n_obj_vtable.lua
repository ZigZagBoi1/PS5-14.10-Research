-- CRASH_CLASS: SAFE (read-only, heap objects only)
-- PROBE 41n: dump full qwords from heap objects referenced by bucket table
-- From 41l: objects start with dword 0x1A3A4EE0 but we only read 4 bytes
-- We need the FULL 8-byte value to know the real pointer
-- AVOID reading 0x1A3A4EE0 directly — it crashed 41m

print("=== PROBE 41n: OBJECT VTABLE ANALYSIS ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function dump_qword(val)
    if type(val) == "table" and val.h then
        return string.format("%08X_%08X", val.h, val.l)
    end
    return string.format("%016X", to_num(val))
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end

--------------------------------------------------------------------
-- SECTION 1: Read full qwords from known heap objects
-- These are the targets from the bucket table at 0x142621xxx
--------------------------------------------------------------------
print("--- SECTION 1: HEAP OBJECT FULL QWORD DUMPS ---")

local targets = {
    {name="bucket808", addr=0x3108608D0},
    {name="bucket848", addr=0x31057AB10},
    {name="bucket888", addr=0x310840CF0},
    {name="bucket8C8", addr=0x310617AD0},
    {name="ref3_948",  addr=0x310838010},
    {name="ref4_950",  addr=0x31084B430},
    {name="bucket958", addr=0x3107D8F70},
    {name="bucket960", addr=0x3106A08D0},
}

local vtable_values = {}

for _, t in ipairs(targets) do
    print(string.format("  %s at 0x%X:", t.name, t.addr))
    local q0 = safe_rq(uint64(t.addr))
    if q0 == nil then
        print("    FAULT")
    else
        local h0, l0 = get_hi_lo(q0)
        print(string.format("    +00: %s", dump_qword(q0)))

        -- record the vtable value
        local key = string.format("%08X_%08X", h0, l0)
        vtable_values[key] = (vtable_values[key] or 0) + 1

        -- dump +08 through +78 as qwords
        for off = 8, 0x78, 8 do
            local q = safe_rq(uint64(t.addr + off))
            if q then
                local h, l = get_hi_lo(q)
                local tag = ""
                if h >= 0xFFFFFF80 then tag = " KPTR!" end
                if h == 0 and l >= 0x80000000 and l < 0x90000000 then tag = " TEXT" end
                if h == 3 then tag = " HEAP" end
                if h == 1 then tag = " DATA" end
                if h == 0 and l == 0 then tag = " NULL" end
                if h ~= 0 or l ~= 0 then
                    print(string.format("    +%02X: %s%s", off, dump_qword(q), tag))
                end
            end
        end
    end
    print("")
end

--------------------------------------------------------------------
-- SECTION 2: Summarize vtable/first-qword values
--------------------------------------------------------------------
print("--- SECTION 2: VTABLE VALUE DISTRIBUTION ---")
for key, cnt in pairs(vtable_values) do
    print(string.format("  %s : %d objects", key, cnt))
end
print("")

--------------------------------------------------------------------
-- SECTION 3: If the vtable value is a 64-bit pointer, dereference it
-- The full qword at +00 might be 0xXXXXXXXX_1A3A4EE0
-- Dereference it to see if it points to a function table
--------------------------------------------------------------------
print("--- SECTION 3: DEREFERENCE VTABLE POINTER ---")

for key, _ in pairs(vtable_values) do
    -- parse the key back to hi/lo
    local hi_str = key:sub(1, 8)
    local lo_str = key:sub(10, 17)
    local hi = tonumber(hi_str, 16)
    local lo = tonumber(lo_str, 16)

    if hi == 0 and lo == 0 then
        print("  NULL vtable, skipping")
    else
        print(string.format("  vtable ptr: %08X_%08X", hi, lo))

        -- construct the full address
        -- If hi=0, it's a 32-bit pointer
        -- If hi>0, it's a full 64-bit address
        local vtable_addr
        if hi > 0 then
            vtable_addr = uint64(hi * 0x100000000 + lo)
        else
            vtable_addr = uint64(lo)
        end

        -- try to read at this address (the vtable itself)
        local vt0 = safe_rq(vtable_addr)
        if vt0 then
            print("  READABLE! vtable contents:")
            for off = 0, 0x78, 8 do
                local q = safe_rq(vtable_addr + off)
                if q then
                    local vh, vl = get_hi_lo(q)
                    local tag = ""
                    if vh == 0 and vl >= 0x80000000 and vl < 0x90000000 then
                        tag = " TEXT(code?)"
                    end
                    if vh >= 0xFFFFFF80 then tag = " KPTR!" end
                    if vh == 3 then tag = " HEAP" end
                    if vh == 0 and vl == 0 then tag = " NULL" end
                    if vh ~= 0 or vl ~= 0 then
                        print(string.format("    [+%02X] %s%s", off, dump_qword(q), tag))
                    end
                else
                    print(string.format("    [+%02X] FAULT", off))
                    break
                end
            end

            -- try to dereference entries that look like text-range pointers
            print("  deref code check:")
            local checked = 0
            for off = 0, 0x78, 8 do
                if checked >= 8 then break end
                local q = safe_rq(vtable_addr + off)
                if q then
                    local vh, vl = get_hi_lo(q)
                    -- text range: 0x80000000-0x8FFFFFFF (32-bit)
                    if vh == 0 and vl >= 0x80000000 and vl < 0x90000000 then
                        local code_dw = safe_rd(vl)
                        if code_dw then
                            local b0 = code_dw % 256
                            local is_code = (b0 == 0x55 or b0 == 0x48 or
                                b0 == 0x41 or b0 == 0xE8 or b0 == 0xE9 or
                                b0 == 0xCC or b0 == 0xC3 or b0 == 0x53 or
                                b0 == 0x57 or b0 == 0x89 or b0 == 0x8B or
                                b0 == 0x4C or b0 == 0x50 or b0 == 0x56 or
                                b0 == 0x0F)
                            print(string.format("    [+%02X] -> 0x%08X = %08X b0=%02X %s",
                                off, vl, code_dw, b0, is_code and "CODE!" or "data"))
                            checked = checked + 1
                        end
                    end
                end
            end
        else
            print("  FAULT — not a readable pointer")
            -- maybe it's not a pointer but a magic/tag
            print(string.format("  (value 0x%X_%X may be a type tag, not a pointer)",
                hi, lo))
        end
    end
    print("")
end

--------------------------------------------------------------------
-- SECTION 4: VA map — text/safe addresses only, no risky ranges
--------------------------------------------------------------------
print("--- SECTION 4: TEXT SEGMENT SCAN ---")
do
    -- scan the text range 0x80000000-0x8F000000 at coarse grain
    local text_probes = {
        0x80000000, 0x80100000, 0x80200000, 0x80400000,
        0x80800000, 0x80C00000, 0x80D00000, 0x80E00000,
        0x81000000, 0x82000000, 0x84000000, 0x88000000,
        0x8C000000, 0x8F000000,
    }
    for _, addr in ipairs(text_probes) do
        local d = safe_rd(addr)
        if d then
            local b0 = d % 256
            local tag = ""
            if b0 == 0x55 or b0 == 0x48 or b0 == 0x41 then tag = " (code)" end
            if b0 == 0x7F then tag = " (ELF?)" end
            if b0 == 0 then tag = " (zeroed)" end
            print(string.format("  0x%08X: %08X%s", addr, d, tag))
        else
            print(string.format("  0x%08X: FAULT", addr))
        end
    end
end
print("")

--------------------------------------------------------------------
-- SECTION 5: Also check 0x1_1A3A4EE0 and 0x0_1A3A4EE0 via uint64
-- carefully with a single read, no loops
--------------------------------------------------------------------
print("--- SECTION 5: SINGLE-SHOT POINTER CHECKS ---")
do
    -- 0x1A3A4EE0 as uint64 — single read
    local t1 = safe_rq(uint64("0x1A3A4EE0"))
    print("  uint64(0x1A3A4EE0): " .. (t1 and dump_qword(t1) or "FAULT"))

    -- 0x1_1A3A4EE0
    local t2 = safe_rq(uint64("0x11A3A4EE0"))
    print("  uint64(0x11A3A4EE0): " .. (t2 and dump_qword(t2) or "FAULT"))

    -- 0x0_1A3A4EE0 with dword read
    local t3 = safe_rd(0x1A3A4EE0)
    print("  dword(0x1A3A4EE0): " .. (t3 and string.format("0x%08X", t3) or "FAULT"))
end
print("")

print("=== PROBE 41n COMPLETE ===")
