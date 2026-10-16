-- CRASH_CLASS: SAFE (read-only)
-- PROBE 41m: dump 0x1A3A4EE0 — the common first-dword across heap objects
-- From 41l: every heap object in the bucket table starts with dword 0x1A3A4EE0
-- This could be a vtable ptr, type descriptor, or class metadata pointer
-- We need to: read the region, dereference entries, check for code

print("=== PROBE 41m: TYPE DESCRIPTOR DUMP ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function hex(n)
    if type(n) == "table" and n.h then
        return string.format("0x%08X%08X", n.h, n.l)
    end
    return string.format("0x%X", tonumber(n) or 0)
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
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end

--------------------------------------------------------------------
-- SECTION 1: Read 0x1A3A4EE0 as a 32-bit address
--------------------------------------------------------------------
print("--- SECTION 1: 0x1A3A4EE0 (32-bit) ---")
local v32 = safe_rd(0x1A3A4EE0)
if v32 then
    print("  readable as 32-bit: " .. hex(v32))
    -- dump 256 bytes around it
    for off = -0x20, 0x100, 4 do
        local d = safe_rd(0x1A3A4EE0 + off)
        if d then
            if d ~= 0 then
                print(string.format("  [%+04X] %08X", off, d))
            end
        else
            print(string.format("  [%+04X] FAULT", off))
            break
        end
    end
else
    print("  NOT readable as 32-bit")
end
print("")

--------------------------------------------------------------------
-- SECTION 2: Read as 64-bit (0x00000000_1A3A4EE0)
--------------------------------------------------------------------
print("--- SECTION 2: uint64(0x1A3A4EE0) ---")
local q64 = safe_rq(uint64("0x1A3A4EE0"))
if q64 then
    print("  readable: " .. dump_qword(q64))
    for off = 0, 0x100, 8 do
        local q = safe_rq(uint64("0x1A3A4EE0") + off)
        if q then
            local h, l = get_hi_lo(q)
            if h ~= 0 or l ~= 0 then
                local tag = ""
                if h >= 0xFFFFFF80 then tag = " KPTR!" end
                if h == 0 and l >= 0x80000000 and l < 0x90000000 then tag = " TEXT" end
                if h == 3 then tag = " HEAP" end
                if h == 1 then tag = " SELF?" end
                print(string.format("  [+%03X] %s%s", off, dump_qword(q), tag))
            end
        else
            print(string.format("  [+%03X] FAULT", off))
            break
        end
    end
else
    print("  NOT readable as uint64")
end
print("")

--------------------------------------------------------------------
-- SECTION 3: Maybe it's stored as 0x0000001A_3A4EE0xx?
-- Or maybe the heap object stores it as a 32-bit offset/tag
-- Let's read actual heap objects and examine their structure
--------------------------------------------------------------------
print("--- SECTION 3: HEAP OBJECT STRUCTURES ---")

-- From 41l: the bucket table at 0x142621xxx has heap ptrs
-- Let's pick a few known ones and dump their full structure
local heap_targets = {
    0x3108608D0,  -- from bucket 0x142621808
    0x31057AB10,  -- from bucket 0x142621848
    0x310840CF0,  -- from bucket 0x142621888
    0x310617AD0,  -- from bucket 0x1426218C8
    0x31084B430,  -- from bucket 0x142621950 (ref4)
    0x310838010,  -- from bucket 0x142621948 (ref3)
}

for idx, tgt in ipairs(heap_targets) do
    print(string.format("  OBJ #%d at 0x%X:", idx, tgt))
    local first_dw = safe_rd(tgt)
    if first_dw == nil then
        print("    FAULT (not readable)")
    else
        -- dump 128 bytes as dwords for fine-grained view
        local line = ""
        local count = 0
        for off = 0, 0x7C, 4 do
            local d = safe_rd(tgt + off)
            if d then
                if off % 16 == 0 then
                    if line ~= "" then print(line) end
                    line = string.format("    [+%02X]", off)
                end
                line = line .. string.format(" %08X", d)
            end
        end
        if line ~= "" then print(line) end

        -- classify key fields
        local q0 = safe_rq(uint64(tgt))
        local q8 = safe_rq(uint64(tgt + 8))
        local q10 = safe_rq(uint64(tgt + 0x10))
        local q18 = safe_rq(uint64(tgt + 0x18))
        local q20 = safe_rq(uint64(tgt + 0x20))

        if q0 then
            local h0, l0 = get_hi_lo(q0)
            print(string.format("    +00 qword: %s (vtable/type?)", dump_qword(q0)))
        end
        if q8 then print(string.format("    +08 qword: %s", dump_qword(q8))) end
        if q10 then print(string.format("    +10 qword: %s", dump_qword(q10))) end
        if q18 then print(string.format("    +18 qword: %s", dump_qword(q18))) end
        if q20 then print(string.format("    +20 qword: %s", dump_qword(q20))) end
    end
    print("")
    if idx >= 4 then break end  -- limit output
end

--------------------------------------------------------------------
-- SECTION 4: The 0x1A3A4EE0 value — is it a pointer or a tag?
-- Try reading it as different address forms
--------------------------------------------------------------------
print("--- SECTION 4: INTERPRETING 0x1A3A4EE0 ---")

-- Form A: raw 32-bit
local formA = safe_rd(0x1A3A4EE0)
print("  as raw 0x1A3A4EE0: " .. (formA and hex(formA) or "FAULT"))

-- Form B: 0x0_1A3A4EE0 (33-bit, in low heap range)
local formB = safe_rq(uint64("0x1A3A4EE0"))
print("  as uint64(0x1A3A4EE0): " .. (formB and dump_qword(formB) or "FAULT"))

-- Form C: maybe the objects store a relative offset from some base
-- If base is the object itself, 0x1A3A4EE0 would be a huge forward offset
-- More likely: maybe it's an absolute 32-bit address in a data segment

-- Form D: check if it's in the ELF data segment
-- Text is 0x80000000-0x90000000, data might be adjacent
local probes_d = {
    {name="0x1A000000", addr=0x1A000000},
    {name="0x1A300000", addr=0x1A300000},
    {name="0x1A3A0000", addr=0x1A3A0000},
    {name="0x1A3A4000", addr=0x1A3A4000},
    {name="0x1A3A4E00", addr=0x1A3A4E00},
    {name="0x1A3A4EE0", addr=0x1A3A4EE0},
    {name="0x1A3A4F00", addr=0x1A3A4F00},
    {name="0x1A3A5000", addr=0x1A3A5000},
    {name="0x1A3B0000", addr=0x1A3B0000},
    {name="0x1A400000", addr=0x1A400000},
    {name="0x1B000000", addr=0x1B000000},
    {name="0x20000000", addr=0x20000000},
}
print("  data segment scan:")
for _, p in ipairs(probes_d) do
    local v = safe_rd(p.addr)
    print(string.format("    %-16s %s", p.name, v and hex(v) or "FAULT"))
end
print("")

--------------------------------------------------------------------
-- SECTION 5: If 0x1A3A4EE0 is readable, dump it as a potential
-- vtable (array of function pointers)
--------------------------------------------------------------------
print("--- SECTION 5: VTABLE DEREF ---")
if formA then
    print("  0x1A3A4EE0 is readable (value " .. hex(formA) .. ")")
    -- treat formA as a pointer, dereference it
    local inner = safe_rd(formA)
    if inner then
        print("  *(" .. hex(formA) .. ") = " .. hex(inner))
        -- check if it looks like code
        local b0 = inner % 256
        local tag = "?"
        if b0 == 0x55 or b0 == 0x48 or b0 == 0x41 or b0 == 0x53 then tag = "CODE" end
        print("  first byte: " .. string.format("0x%02X [%s]", b0, tag))
    else
        print("  *(" .. hex(formA) .. ") = FAULT")
    end

    -- also read a wider vtable dump at 0x1A3A4EE0
    print("  entries at 0x1A3A4EE0 as potential function table:")
    for off = 0, 0x78, 4 do
        local d = safe_rd(0x1A3A4EE0 + off)
        if d then
            if d ~= 0 then
                -- try to dereference each non-zero value
                local inner2 = safe_rd(d)
                local tag2 = ""
                if inner2 then
                    local ib = inner2 % 256
                    if ib == 0x55 or ib == 0x48 or ib == 0x41 or
                       ib == 0xE8 or ib == 0xE9 or ib == 0x53 or
                       ib == 0x50 or ib == 0x56 or ib == 0x57 or
                       ib == 0x0F or ib == 0x4C or ib == 0x89 then
                        tag2 = string.format(" -> CODE (%02X...)", ib)
                    elseif inner2 == 0 then
                        tag2 = " -> NULL"
                    else
                        tag2 = string.format(" -> %08X", inner2)
                    end
                else
                    tag2 = " -> FAULT"
                end
                print(string.format("    [+%02X] %08X%s", off, d, tag2))
            end
        else
            break
        end
    end
end
print("")

--------------------------------------------------------------------
-- SECTION 6: Full VA map (text output only, no binary)
--------------------------------------------------------------------
print("--- SECTION 6: VA MAP ---")
local va_probes = {
    0x400000, 0x800000, 0x1000000, 0x2000000, 0x4000000,
    0x8000000, 0x10000000, 0x1A000000, 0x1A3A4EE0,
    0x20000000, 0x40000000, 0x80000000, 0x80100000,
    0x80200000, 0x80D00000, 0x81000000, 0x82000000,
    0x84000000, 0x88000000, 0x8C000000, 0x90000000,
    0xA0000000, 0xC0000000, 0xF0000000,
}
for _, addr in ipairs(va_probes) do
    local d = safe_rd(addr)
    local r = d and string.format("%08X", d) or "---FAULT---"
    print(string.format("  %08X: %s", addr, r))
end
print("")

print("=== PROBE 41m COMPLETE ===")
