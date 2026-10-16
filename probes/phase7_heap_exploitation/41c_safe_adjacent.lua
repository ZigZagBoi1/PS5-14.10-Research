-- CRASH_CLASS: SAFE
-- PROBE 41c: scan readable pages BEFORE gpu mmap only (after-scan crashes loader)
-- Finding from 41b: 4 pages before the mapping are READABLE (zeroes)
-- Question: how far back can we read? Is there useful data?

print("=== PROBE 41c: SAFE ADJACENT PAGE SCAN ===")
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

local function dump_qword(val)
    if type(val) == "table" and val.h then
        return string.format("%08X_%08X", val.h, val.l)
    end
    return string.format("%016X", to_num(val))
end

local sc_mmap   = make_syscall(477)
local sc_munmap = make_syscall(588)
local PAGE = 0x4000

local function do_mmap(sz)
    local ok, ret = pcall(function()
        return sc_mmap(
            uint64(0), uint64(sz), uint64(0x33),
            uint64(0x1002),
            uint64("0xFFFFFFFFFFFFFFFF"), uint64(0)
        )
    end)
    if not ok then return nil end
    local addr = to_num(ret)
    if addr == 0 or addr >= 0xFFFFFFFF00000000 then return nil end
    return addr
end

--------------------------------------------------------------------
-- SECTION 1: Allocate, then scan backwards to find how far we can read
--------------------------------------------------------------------
print("--- SECTION 1: BACKWARD SCAN FROM GPU MMAP ---")
do
    local base = do_mmap(PAGE)
    if not base then
        print("  mmap FAILED")
    else
        print("  mmap base: " .. hex(base))
        pcall(function() memory.write_dword(base, 0xDEADCAFE) end)
        local ok_v, vv = pcall(function() return memory.read_dword(base) end)
        if ok_v then print("  verify write: " .. hex(vv)) end

        -- scan backwards in 0x1000 steps (not PAGE to catch 4K sub-pages)
        local readable_count = 0
        local first_fault = nil
        local nonzero_pages = {}

        for i = 1, 256 do
            local addr = base - i * 0x1000
            if addr <= 0 then break end
            local ok_r, val = pcall(function() return memory.read_dword(addr) end)
            if ok_r then
                readable_count = readable_count + 1
                local v = to_num(val)
                if v ~= 0 then
                    nonzero_pages[#nonzero_pages + 1] = {offset = -i * 0x1000, addr = addr, val = v}
                end
            else
                first_fault = i * 0x1000
                break
            end
        end

        print("  readable pages before base: " .. readable_count .. " (at 0x1000 stride)")
        if first_fault then
            print("  first fault at: base-0x" .. string.format("%X", first_fault))
            print("  readable range: " .. hex(base - first_fault + 0x1000) .. " to " .. hex(base))
        else
            print("  readable range: 256+ pages (no fault found)")
        end

        if #nonzero_pages > 0 then
            print("  NON-ZERO pages found: " .. #nonzero_pages)
            for j, p in ipairs(nonzero_pages) do
                if j > 16 then
                    print("    ... and " .. (#nonzero_pages - 16) .. " more")
                    break
                end
                local ok_q, qval = pcall(function() return memory.read_qword(p.addr) end)
                local qs = ok_q and dump_qword(qval) or "??"
                print(string.format("    [%+07X] %s = %s", p.offset, hex(p.addr), qs))
            end
        else
            print("  all readable pages are ZERO")
        end

        pcall(function() sc_munmap(uint64(base), uint64(PAGE)) end)
    end
end
print("")

--------------------------------------------------------------------
-- SECTION 2: Two allocations, scan the gap between them
--------------------------------------------------------------------
print("--- SECTION 2: GAP BETWEEN TWO MMAPS ---")
do
    local a1 = do_mmap(PAGE)
    local a2 = do_mmap(PAGE)
    if a1 and a2 then
        local lo = math.min(a1, a2)
        local hi = math.max(a1, a2)
        local gap = hi - lo - PAGE
        print("  alloc1: " .. hex(a1))
        print("  alloc2: " .. hex(a2))
        print("  gap: " .. hex(gap) .. " (" .. (gap / 0x1000) .. " x 4KB)")

        if gap > 0 and gap <= PAGE * 64 then
            -- scan pages in the gap
            local gap_readable = 0
            local gap_nonzero = 0
            for off = PAGE, gap, 0x1000 do
                local addr = lo + off
                if addr < hi then
                    local ok_r, val = pcall(function() return memory.read_dword(addr) end)
                    if ok_r then
                        gap_readable = gap_readable + 1
                        if to_num(val) ~= 0 then gap_nonzero = gap_nonzero + 1 end
                    end
                end
            end
            print("  gap pages readable: " .. gap_readable)
            print("  gap pages nonzero: " .. gap_nonzero)
        elseif gap == 0 then
            print("  CONTIGUOUS — no gap!")
            -- write to a1, read from a2-PAGE boundary
            pcall(function() memory.write_dword(a1, 0x11111111) end)
            pcall(function() memory.write_dword(a2, 0x22222222) end)
            local ok_r, bv = pcall(function() return memory.read_dword(lo + PAGE) end)
            if ok_r then
                print("  cross-boundary read: " .. hex(bv))
            end
        end

        pcall(function() sc_munmap(uint64(a1), uint64(PAGE)) end)
        pcall(function() sc_munmap(uint64(a2), uint64(PAGE)) end)
    else
        print("  mmap failed")
    end
end
print("")

--------------------------------------------------------------------
-- SECTION 3: Large alloc (1MB) backward scan — more surface
--------------------------------------------------------------------
print("--- SECTION 3: 1MB ALLOC BACKWARD SCAN ---")
do
    local sz = PAGE * 64
    local base = do_mmap(sz)
    if base then
        print("  base: " .. hex(base) .. " size: " .. hex(sz))
        -- write pattern
        pcall(function() memory.write_dword(base, 0xFACEFEED) end)
        pcall(function() memory.write_dword(base + sz - 4, 0xCAFEBABE) end)

        -- scan 128 pages backward
        local readable = 0
        local first_nonzero = nil
        for i = 1, 128 do
            local addr = base - i * PAGE
            if addr <= 0 then break end
            local ok_r, val = pcall(function() return memory.read_dword(addr) end)
            if ok_r then
                readable = readable + 1
                if to_num(val) ~= 0 and not first_nonzero then
                    first_nonzero = {i = i, addr = addr, val = to_num(val)}
                end
            else
                break
            end
        end
        print("  readable pages before: " .. readable)
        if first_nonzero then
            print(string.format("  first nonzero at -%d pages: %s = %s",
                first_nonzero.i, hex(first_nonzero.addr), hex(first_nonzero.val)))
        else
            print("  all zero")
        end

        pcall(function() sc_munmap(uint64(base), uint64(sz)) end)
    else
        print("  mmap failed")
    end
end
print("")

--------------------------------------------------------------------
-- SECTION 4: Read existing process memory around known module addresses
-- (from probe 39b: modules live at 0x80d0xxxxx range)
--------------------------------------------------------------------
print("--- SECTION 4: KNOWN VA RANGE SCAN ---")
do
    local known_ranges = {
        { name = "modules_0x800", addr = 0x800000000 },
        { name = "modules_0x80d", addr = 0x80D000000 },
        { name = "heap_0x200",    addr = 0x200000000 },
        { name = "heap_0x300",    addr = 0x300000000 },
        { name = "stack_hi",      addr = 0x7FFFFF0000 },
        { name = "low_text",      addr = 0x400000 },
        { name = "gpu_mmap_area", addr = 0x310000000 },
    }
    for _, r in ipairs(known_ranges) do
        local ok_r, val = pcall(function() return memory.read_dword(r.addr) end)
        if ok_r then
            local ok_q, qval = pcall(function() return memory.read_qword(r.addr) end)
            local qs = ok_q and dump_qword(qval) or hex(val)
            print(string.format("  %-18s %s = %s READABLE", r.name, hex(r.addr), qs))
        else
            print(string.format("  %-18s %s = FAULT", r.name, hex(r.addr)))
        end
    end
end

print("")
print("=== PROBE 41c COMPLETE ===")
