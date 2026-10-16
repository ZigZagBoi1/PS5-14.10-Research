-- CRASH_CLASS: SAFE
-- PROBE 41b: boundary scan using mmap+GPU (0x33 confirmed working)
-- Skips GPU-only and risky combos that crashed the loader in 41.

print("=== PROBE 41b: MMAP GPU BOUNDARY SCAN ===")
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

local function safe_read_qword(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return true, val end
    return false, nil
end

local function safe_read_byte(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return true, to_num(val) end
    return false, 0
end

local sc_mmap   = make_syscall(477)
local sc_munmap = make_syscall(588)

local PAGE = 0x4000
local PROT_ALL = 0x33
local MAP_PRIVATE = 0x0002
local MAP_ANON    = 0x1000

local probe_before = { -0x4000, -0x3000, -0x2000, -0x1000 }
local probe_after  = {  0x0000,  0x1000,  0x2000,  0x3000,  0x4000 }

local function do_mmap(sz)
    local ok, ret = pcall(function()
        return sc_mmap(
            uint64(0), uint64(sz), uint64(PROT_ALL),
            uint64(MAP_PRIVATE + MAP_ANON),
            uint64("0xFFFFFFFFFFFFFFFF"), uint64(0)
        )
    end)
    if not ok then return nil end
    local addr = to_num(ret)
    if addr == 0 or addr >= 0xFFFFFFFF00000000 then return nil end
    return addr
end

--------------------------------------------------------------------
-- SECTION 1: Multi-size boundary probe (0x33 = CPU+GPU RW)
--------------------------------------------------------------------
local test_sizes = {
    { name = "16KB (1 page)",     size = PAGE },
    { name = "64KB (4 pages)",    size = PAGE * 4 },
    { name = "256KB (16 pages)",  size = PAGE * 16 },
    { name = "1MB (64 pages)",    size = PAGE * 64 },
}

for ti, tinfo in ipairs(test_sizes) do
  repeat
    print("--- SIZE " .. ti .. ": " .. tinfo.name .. " ---")
    local sz = tinfo.size

    local va_base = do_mmap(sz)
    if not va_base then
        print("  mmap FAILED")
        break
    end
    local va_end = va_base + sz
    print("  base=" .. hex(va_base) .. " end=" .. hex(va_end))

    -- write markers every page
    local marker = 0xCAFE0040 + ti
    local pages_ok = 0
    for off = 0, sz - 1, PAGE do
        local ok_w = pcall(function() memory.write_dword(va_base + off, marker) end)
        if ok_w then
            pcall(function() memory.write_dword(va_base + off + 4, 0xDEAD0000 + ti) end)
            pages_ok = pages_ok + 1
        end
    end
    print("  pages marked: " .. pages_ok .. "/" .. (sz / PAGE))

    -- verify
    local ok_v, v_val = safe_read_qword(uint64(va_base))
    if ok_v then print("  verify: " .. dump_qword(v_val)) end

    -- probe BEFORE
    print("  -- before --")
    for _, off in ipairs(probe_before) do
        local addr = va_base + off
        if addr > 0 then
            local ok_r, qval = safe_read_qword(uint64(addr))
            if ok_r then
                print(string.format("    [%+06X] %s READABLE", off, dump_qword(qval)))
            else
                print(string.format("    [%+06X] FAULT", off))
            end
        end
    end

    -- probe AFTER
    print("  -- after --")
    for _, off in ipairs(probe_after) do
        local addr = va_end + off
        local ok_r, qval = safe_read_qword(uint64(addr))
        if ok_r then
            local tag = (off == 0) and " <-- past end" or ""
            print(string.format("    [+%05X] %s READABLE%s", off, dump_qword(qval), tag))
        else
            local tag = (off == 0) and " <-- guard OK" or ""
            print(string.format("    [+%05X] FAULT%s", off, tag))
        end
    end

    -- marker leak
    local leaked = false
    for _, off in ipairs({ -PAGE, sz, sz + PAGE }) do
        local addr = va_base + off
        if addr > 0 and (addr < va_base or addr >= va_end) then
            local ok_r, qval = safe_read_qword(uint64(addr))
            if ok_r then
                local lo = (type(qval) == "table" and qval.l) and qval.l or to_num(qval)
                if lo == marker then
                    print("    MARKER LEAK at " .. hex(off) .. "!")
                    leaked = true
                end
            end
        end
    end
    if not leaked then print("    no marker leak") end

    -- adjacency: where does next mmap land?
    local a2 = do_mmap(PAGE)
    if a2 then
        local gap = (a2 >= va_end) and (a2 - va_end) or (va_base - a2)
        print("  next mmap=" .. hex(a2) .. " gap=" .. hex(gap))
        pcall(function() sc_munmap(uint64(a2), uint64(PAGE)) end)
    end

    pcall(function() sc_munmap(uint64(va_base), uint64(sz)) end)
    print("")
  until true
end

--------------------------------------------------------------------
-- SECTION 2: Contiguous allocation test
-- Allocate 4 pages back-to-back, check if VAs are contiguous
--------------------------------------------------------------------
print("--- SECTION 2: CONTIGUOUS ALLOCATION ---")
do
    local addrs = {}
    for i = 1, 4 do
        local a = do_mmap(PAGE)
        if a then
            addrs[#addrs + 1] = a
            print("  alloc " .. i .. ": " .. hex(a))
        end
    end

    if #addrs >= 2 then
        for i = 2, #addrs do
            local gap = addrs[i] - addrs[i-1]
            print("  gap " .. (i-1) .. "->" .. i .. ": " .. hex(gap) ..
                  (gap == PAGE and " (CONTIGUOUS)" or ""))
        end

        -- can we read across the boundary between alloc 1 and 2?
        if addrs[2] - addrs[1] == PAGE then
            print("  boundary test: allocs 1-2 are adjacent")
            pcall(function() memory.write_dword(addrs[1], 0xAAAAAAAA) end)
            pcall(function() memory.write_dword(addrs[2], 0xBBBBBBBB) end)
            -- read from alloc1 end into alloc2
            local bridge_addr = addrs[1] + PAGE - 4
            local ok_r, bv = pcall(function() return memory.read_dword(bridge_addr) end)
            if ok_r then
                print("  read at alloc1+PAGE-4: " .. hex(bv))
            end
            local ok_r2, bv2 = pcall(function() return memory.read_dword(addrs[1] + PAGE) end)
            if ok_r2 then
                print("  read at alloc1+PAGE (=alloc2 base): " .. hex(bv2))
                if to_num(bv2) == 0xBBBBBBBB then
                    print("  CROSS-BOUNDARY READ WORKS (alloc1 can read alloc2)")
                end
            end
        end
    end

    for _, a in ipairs(addrs) do
        pcall(function() sc_munmap(uint64(a), uint64(PAGE)) end)
    end
end
print("")

--------------------------------------------------------------------
-- SECTION 3: Large gap scan — what's between GPU mmaps and
-- existing process memory?
--------------------------------------------------------------------
print("--- SECTION 3: VA SPACE LAYOUT ---")
do
    local gpu_page = do_mmap(PAGE)
    if gpu_page then
        print("  gpu mmap at: " .. hex(gpu_page))

        -- probe well-known VA ranges for data
        local probes = {
            { name = "stack_area",   addr = 0x7FFFFFFFD000 },
            { name = "heap_low",     addr = 0x200000000 },
            { name = "heap_mid",     addr = 0x800000000 },
            { name = "text_base",    addr = 0x400000 },
            { name = "lib_area",     addr = 0x80000000 },
        }
        for _, p in ipairs(probes) do
            local ok_r, qval = safe_read_qword(uint64(p.addr))
            if ok_r then
                print(string.format("  %-15s %s = %s READABLE", p.name, hex(p.addr), dump_qword(qval)))
            else
                print(string.format("  %-15s %s = FAULT", p.name, hex(p.addr)))
            end
        end

        pcall(function() sc_munmap(uint64(gpu_page), uint64(PAGE)) end)
    end
end

print("")
print("=== PROBE 41b COMPLETE ===")
