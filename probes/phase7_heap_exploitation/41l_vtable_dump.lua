-- CRASH_CLASS: SAFE (read-only)
-- PROBE 41l: dump the 0x142621xxx region
-- From 41i/41k: live objects reference 0x142621908, 918, 948, 950
-- If this is a vtable/function table, we can redirect it

print("=== PROBE 41l: VTABLE REGION DUMP ===")
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
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
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
-- SECTION 1: Probe the 0x142621xxx region
-- Known refs: 0x142621908, 0x142621918, 0x142621948, 0x142621950
--------------------------------------------------------------------
print("--- SECTION 1: VTABLE REGION 0x142621800-0x142621A00 ---")

local region_base = 0x142621800
local region_end  = 0x142621A00

-- first check if region is even readable
local test = safe_rd(region_base)
if test == nil then
    print("  0x142621800 NOT READABLE")
    -- try broader probes
    local probes = {
        0x142621000, 0x142620000, 0x142600000,
        0x142000000, 0x140000000, 0x100000000,
    }
    for _, p in ipairs(probes) do
        local v = safe_rd(p)
        print(string.format("  %s: %s", hex(p), v and hex(v) or "FAULT"))
    end
    print("")
    print("  the 0x1_4xxxxxxx region may not be directly addressable")
    print("  (the values may be 32-bit with high bit = ptr tag)")
else
    -- dump the whole region
    for addr = region_base, region_end - 8, 8 do
        local q = safe_rq(addr)
        if q then
            local h, l = get_hi_lo(q)
            local tag = ""
            if h >= 0xFFFFFF80 then tag = " KPTR!" end
            if h == 0 and l >= 0x80000000 and l < 0x90000000 then tag = " TEXT!" end
            if h == 3 and l >= 0x10000000 then tag = " HEAP" end
            if h == 0 and l == 0 then tag = " NULL" end
            -- mark the known referenced addresses
            if addr == 0x142621908 then tag = tag .. " <-- ref1" end
            if addr == 0x142621918 then tag = tag .. " <-- ref2" end
            if addr == 0x142621948 then tag = tag .. " <-- ref3" end
            if addr == 0x142621950 then tag = tag .. " <-- ref4" end
            if h ~= 0 or l ~= 0 then
                print(string.format("  %s: %s%s", hex(addr), dump_qword(q), tag))
            end
        else
            print(string.format("  %s: FAULT", hex(addr)))
            break
        end
    end
end
print("")

--------------------------------------------------------------------
-- SECTION 2: Wider scan — what IS the 0x1_4xxxxxxx range?
-- Maybe it's 0x00000001_42621xxx in 64-bit (a valid heap region?)
--------------------------------------------------------------------
print("--- SECTION 2: IS 0x1_42621xxx A 64-BIT ADDR? ---")

local addr64 = uint64(0x142621900)
local test64 = safe_rq(addr64)
if test64 then
    print("  uint64(0x142621900) readable: " .. dump_qword(test64))
    -- dump around it
    for off = -0x40, 0xC0, 8 do
        local q = safe_rq(uint64(0x142621900 + off))
        if q then
            local h, l = get_hi_lo(q)
            local tag = ""
            if h >= 0xFFFFFF80 then tag = " KPTR!" end
            if h == 0 and l >= 0x80000000 and l < 0x90000000 then tag = " TEXT!" end
            if h == 1 and l >= 0x40000000 then tag = " SELF?" end
            if h == 3 then tag = " HEAP" end
            if h == 0 and l == 0 then
                -- skip zeros for brevity
            else
                print(string.format("  [%+04X] %s%s", off, dump_qword(q), tag))
            end
        end
    end
else
    print("  uint64(0x142621900) NOT READABLE")
end
print("")

--------------------------------------------------------------------
-- SECTION 3: Dereference values found in the vtable region
-- If they're function pointers, reading them should give code bytes
--------------------------------------------------------------------
print("--- SECTION 3: DEREFERENCE VTABLE ENTRIES ---")
do
    -- collect non-zero values from the region
    local entries = {}
    for off = 0, 0x100, 8 do
        local q = safe_rq(uint64(0x142621900 + off))
        if q then
            local h, l = get_hi_lo(q)
            if h ~= 0 or l ~= 0 then
                entries[#entries + 1] = {off = off, hi = h, lo = l, q = q}
            end
        end
    end

    local derefed = 0
    for _, e in ipairs(entries) do
        if derefed >= 12 then break end
        -- try to read at the value as an address
        local target
        if e.hi == 0 and e.lo >= 0x80000000 and e.lo < 0xFFFF0000 then
            -- 32-bit address in text range
            target = e.lo
        elseif e.hi >= 1 and e.hi <= 3 then
            -- 64-bit heap/data address
            target = e.hi * 0x100000000 + e.lo
        end

        if target then
            local dw = safe_rd(target)
            if dw then
                local b0 = dw % 256
                local tag = "?"
                if b0 == 0x55 or b0 == 0x48 or b0 == 0x41 or
                   b0 == 0xE8 or b0 == 0xE9 or b0 == 0xCC or
                   b0 == 0xC3 or b0 == 0x53 or b0 == 0x57 or
                   b0 == 0x89 or b0 == 0x8B or b0 == 0x4C or
                   b0 == 0x50 or b0 == 0x56 or b0 == 0x0F then
                    tag = "CODE"
                elseif dw == 0 then
                    tag = "ZERO"
                else
                    tag = "DATA"
                end
                print(string.format("  [+%03X] val=%s -> *%s = %s [%s] b0=%02X",
                    e.off, dump_qword(e.q), hex(target), hex(dw), tag, b0))
                derefed = derefed + 1
            else
                print(string.format("  [+%03X] val=%s -> *%s = FAULT",
                    e.off, dump_qword(e.q), hex(target)))
                derefed = derefed + 1
            end
        end
    end
    if derefed == 0 then
        print("  no dereferenceable entries found")
    end
end
print("")

--------------------------------------------------------------------
-- SECTION 4: What other ranges are readable?
-- Map the process VA space at coarse granularity
--------------------------------------------------------------------
print("--- SECTION 4: VA SPACE MAP ---")
do
    local ranges = {
        {name="0x400000",       addr=0x400000},
        {name="0x800000",       addr=0x800000},
        {name="0x80000000",     addr=0x80000000},
        {name="0x80D000000",    addr=0x80D000000},
        {name="0x100000000",    addr=0x100000000},
        {name="0x140000000",    addr=0x140000000},
        {name="0x142000000",    addr=0x142000000},
        {name="0x142600000",    addr=0x142600000},
        {name="0x142620000",    addr=0x142620000},
        {name="0x142621000",    addr=0x142621000},
        {name="0x142621900",    addr=0x142621900},
        {name="0x142622000",    addr=0x142622000},
        {name="0x142630000",    addr=0x142630000},
        {name="0x142700000",    addr=0x142700000},
        {name="0x143000000",    addr=0x143000000},
        {name="0x150000000",    addr=0x150000000},
        {name="0x1A0000000",    addr=0x1A0000000},
        {name="0x1A3A00000",    addr=0x1A3A00000},
        {name="0x200000000",    addr=0x200000000},
        {name="0x300000000",    addr=0x300000000},
        {name="0x310000000",    addr=0x310000000},
        {name="0x400000000",    addr=0x400000000},
    }
    for _, r in ipairs(ranges) do
        local v = safe_rd(r.addr)
        local tag = v and hex(v) or "FAULT"
        -- if readable, also get qword
        if v then
            local q = safe_rq(uint64(r.addr))
            if q then tag = dump_qword(q) end
        end
        print(string.format("  %-18s %s", r.name, tag))
    end
end
print("")

--------------------------------------------------------------------
-- SECTION 5: Is 0x1A3A4EE0 in the objects also interesting?
-- (appeared in every rc=4 object at +10)
--------------------------------------------------------------------
print("--- SECTION 5: COMMON POINTER 0x1_1A3A4EE0 ---")
do
    local q = safe_rq(uint64(0x11A3A4EE0))
    if q then
        print("  readable: " .. dump_qword(q))
        for off = 0, 0x38, 8 do
            local v = safe_rq(uint64(0x11A3A4EE0 + off))
            if v then
                local h, l = get_hi_lo(v)
                local tag = ""
                if h >= 0xFFFFFF80 then tag = " KPTR!" end
                if h == 0 and l >= 0x80000000 and l < 0x90000000 then tag = " TEXT!" end
                print(string.format("    [+%02X] %s%s", off, dump_qword(v), tag))
            end
        end
    else
        print("  NOT READABLE")
        -- try as 32-bit
        local v32 = safe_rd(0x1A3A4EE0)
        if v32 then
            print("  32-bit 0x1A3A4EE0 readable: " .. hex(v32))
        else
            print("  32-bit also FAULT")
        end
    end
end

print("")
print("=== PROBE 41l COMPLETE ===")
