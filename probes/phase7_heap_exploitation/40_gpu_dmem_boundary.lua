-- CRASH_CLASS: SAFE
-- PROBE: 40 — GPU/CPU shared direct-memory boundary scanner
-- PURPOSE: Allocate physical memory with CPU+GPU visibility at multiple
--          sizes, write marker patterns, probe adjacent virtual pages
--          for leaked data, report VA layout around each allocation.

print("=== PROBE 40: GPU/CPU DMEM BOUNDARY SCANNER ===")
print("")

--------------------------------------------------------------------
-- helpers
--------------------------------------------------------------------
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

local function safe_read_byte(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return true, to_num(val) end
    return false, 0
end

local function safe_read_qword(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return true, val end
    return false, nil
end

--------------------------------------------------------------------
-- syscalls
--------------------------------------------------------------------
local sc_mmap         = make_syscall(477)
local sc_alloc_dmem   = make_syscall(547)
local sc_map_dmem     = make_syscall(548)
local sc_dmem_total   = make_syscall(549)
local sc_release_dmem = make_syscall(550)
local sc_dmem_avail   = make_syscall(552)
local sc_munmap       = make_syscall(588)

--------------------------------------------------------------------
-- constants
--------------------------------------------------------------------
local PROT_READ      = 1
local PROT_WRITE     = 2
local PROT_GPU_READ  = 0x10
local PROT_GPU_WRITE = 0x20
local PROT_CPU_RW    = PROT_READ + PROT_WRITE
local PROT_ALL       = PROT_READ + PROT_WRITE + PROT_GPU_READ + PROT_GPU_WRITE

local MAP_SHARED  = 0x0001
local MAP_PRIVATE = 0x0002
local MAP_ANON    = 0x1000

local DMEM_TYPE_MAIN = 0
local PAGE = 0x4000  -- 16 KB PS5 page

--------------------------------------------------------------------
-- SECTION 1: Direct memory pool stats
--------------------------------------------------------------------
print("--- SECTION 1: DIRECT MEMORY POOL STATS ---")

local pool_total = 0
do
    local ok, ret = pcall(function() return sc_dmem_total() end)
    if ok then
        pool_total = to_num(ret)
        print("  total dmem pool  : " .. hex(ret) .. " (" .. string.format("%.1f MB", pool_total / 1048576) .. ")")
    else
        print("  total dmem pool  : FAILED (" .. tostring(ret) .. ")")
    end

    local search_end = pool_total > 0 and pool_total or 0x300000000
    local size_buf = memory.alloc(8)
    memory.write_qword(size_buf, uint64(0))

    local ok2, err2 = pcall(function()
        return sc_dmem_avail(
            uint64(0),
            uint64(search_end),
            uint64(PAGE),
            size_buf
        )
    end)
    if ok2 then
        local avail = memory.read_qword(size_buf)
        print("  available dmem   : " .. hex(avail) .. " (" .. string.format("%.1f MB", to_num(avail) / 1048576) .. ")")
    else
        -- try 5-arg form (searchStart, searchEnd, alignment, startOut, sizeOut)
        local start_buf = memory.alloc(8)
        memory.write_qword(start_buf, uint64(0))
        memory.write_qword(size_buf, uint64(0))
        local ok3, err3 = pcall(function()
            return sc_dmem_avail(
                uint64(0),
                uint64(search_end),
                uint64(PAGE),
                start_buf,
                size_buf
            )
        end)
        if ok3 then
            local avail = memory.read_qword(size_buf)
            print("  available dmem   : " .. hex(avail) .. " (" .. string.format("%.1f MB", to_num(avail) / 1048576) .. ")")
        else
            print("  available dmem   : FAILED (" .. tostring(err3) .. ")")
        end
    end
end
print("")

--------------------------------------------------------------------
-- SECTION 2: Multi-size allocation + boundary probing
--------------------------------------------------------------------
local test_sizes = {
    { name = "4KB  (1 page)",   size = 0x1000   },
    { name = "64KB (16 pages)", size = 0x10000  },
    { name = "2MB  (large)",    size = 0x200000 },
}

-- page-boundary offsets to probe around the mapping
local probe_before = { -0x4000, -0x3000, -0x2000, -0x1000 }
local probe_after  = {  0x0000,  0x1000,  0x2000,  0x3000 }

for ti, tinfo in ipairs(test_sizes) do
  repeat
    print("--- SECTION 2." .. ti .. ": " .. tinfo.name .. " ---")
    local alloc_size = tinfo.size
    local alignment  = alloc_size < PAGE and PAGE or alloc_size

    -- 2a: allocate physical dmem
    local phys_out = memory.alloc(8)
    memory.write_qword(phys_out, uint64(0))

    local ok_a, ret_a = pcall(function()
        return sc_alloc_dmem(
            uint64(0),
            uint64("0x0000000300000000"),
            uint64(alloc_size),
            uint64(alignment),
            uint64(DMEM_TYPE_MAIN),
            phys_out
        )
    end)

    if not ok_a then
        print("  alloc_dmem FAILED: " .. tostring(ret_a))
        print("")
        break
    end

    local alloc_rv = to_num(ret_a)
    local phys_addr = memory.read_qword(phys_out)
    print("  alloc return     : " .. alloc_rv)
    print("  phys addr        : " .. hex(phys_addr))

    if alloc_rv ~= 0 then
        print("  alloc returned non-zero, skipping")
        print("")
        break
    end

    -- 2b: map with CPU+GPU visibility
    local va_buf = memory.alloc(8)
    memory.write_qword(va_buf, uint64(0))

    local ok_m, ret_m = pcall(function()
        return sc_map_dmem(
            va_buf,
            uint64(alloc_size),
            uint64(PROT_ALL),
            uint64(0),
            phys_addr,
            uint64(alignment)
        )
    end)

    if not ok_m then
        print("  map_dmem FAILED  : " .. tostring(ret_m))
        pcall(function() sc_release_dmem(phys_addr, uint64(alloc_size)) end)
        print("")
        break
    end

    local map_rv  = to_num(ret_m)
    local va_base = to_num(memory.read_qword(va_buf))
    local va_end  = va_base + alloc_size
    print("  map return       : " .. map_rv)
    print("  virt base        : " .. hex(va_base))
    print("  virt end         : " .. hex(va_end))
    print("  size             : " .. hex(alloc_size))
    print("  prot             : CPU_RW + GPU_RW (0x" .. string.format("%X", PROT_ALL) .. ")")

    if map_rv ~= 0 or va_base == 0 then
        print("  map failed or returned NULL, skipping")
        pcall(function() sc_release_dmem(phys_addr, uint64(alloc_size)) end)
        print("")
        break
    end

    -- 2c: write marker pattern into every page
    local marker_dw0 = 0xDEAD4000 + ti
    local marker_dw1 = 0xBEEF0040 + ti
    local pages_written = 0
    for off = 0, alloc_size - 1, PAGE do
        local ok_w = pcall(function() memory.write_dword(va_base + off, marker_dw0) end)
        if ok_w then
            pcall(function() memory.write_dword(va_base + off + 4, marker_dw1) end)
            pages_written = pages_written + 1
        end
    end
    if alloc_size < PAGE then
        for off = 0, alloc_size - 4, 0x1000 do
            pcall(function() memory.write_dword(va_base + off, marker_dw0) end)
            pcall(function() memory.write_dword(va_base + off + 4, marker_dw1) end)
        end
    end
    print("  pages marked     : " .. pages_written)

    -- 2d: verify first qword
    local ok_v, v_val = safe_read_qword(uint64(va_base))
    if ok_v then
        print("  verify [base]    : " .. dump_qword(v_val))
    else
        print("  verify [base]    : READ FAILED")
    end

    -- 2e: probe pages BEFORE the mapping
    print("  -- probing BEFORE mapping --")
    for _, off in ipairs(probe_before) do
        local addr = va_base + off
        if addr > 0 then
            local ok_r, qval = safe_read_qword(uint64(addr))
            if ok_r then
                local bytes = {}
                for i = 0, 7 do
                    local ok_b, bv = safe_read_byte(uint64(addr + i))
                    bytes[#bytes + 1] = ok_b and string.format("%02X", bv) or "??"
                end
                print(string.format("    [base%+06X] %s = %s [%s]  READABLE",
                    off, hex(addr), dump_qword(qval), table.concat(bytes, " ")))
            else
                print(string.format("    [base%+06X] %s = FAULT", off, hex(addr)))
            end
        end
    end

    -- 2f: probe pages AT AND AFTER the mapping end
    print("  -- probing AT/AFTER mapping end --")
    for _, off in ipairs(probe_after) do
        local addr = va_end + off
        local ok_r, qval = safe_read_qword(uint64(addr))
        if ok_r then
            local bytes = {}
            for i = 0, 7 do
                local ok_b, bv = safe_read_byte(uint64(addr + i))
                bytes[#bytes + 1] = ok_b and string.format("%02X", bv) or "??"
            end
            local tag = ""
            if off == 0 then tag = " <-- first page past end" end
            print(string.format("    [end+%05X]  %s = %s [%s]  READABLE%s",
                off, hex(addr), dump_qword(qval), table.concat(bytes, " "), tag))
        else
            local tag = ""
            if off == 0 then tag = " <-- guard page OK" end
            print(string.format("    [end+%05X]  %s = FAULT%s", off, hex(addr), tag))
        end
    end

    -- 2g: marker leak check
    print("  -- marker leak check --")
    local leaked = false
    local leak_check_offsets = { -PAGE, -0x1000, alloc_size, alloc_size + 0x1000, alloc_size + PAGE }
    for _, off in ipairs(leak_check_offsets) do
        local addr = va_base + off
        if addr < va_base or addr >= va_end then
            if addr > 0 then
                local ok_r, qval = safe_read_qword(uint64(addr))
                if ok_r then
                    local hi = 0
                    local lo = 0
                    if type(qval) == "table" and qval.h then
                        hi = qval.h
                        lo = qval.l
                    else
                        lo = to_num(qval)
                    end
                    if lo == marker_dw0 and hi == marker_dw1 then
                        print("    WARNING: marker found at " .. hex(addr) .. " (offset " .. hex(off) .. ") -- ALIASING!")
                        leaked = true
                    elseif lo == marker_dw0 or hi == marker_dw1 then
                        print("    PARTIAL marker match at " .. hex(addr) .. " lo=" .. hex(lo) .. " hi=" .. hex(hi))
                        leaked = true
                    end
                end
            end
        end
    end
    if not leaked then
        print("    no marker leakage detected in adjacent pages")
    end

    -- 2h: wider non-zero data survey (32 pages each direction)
    print("  -- wider survey: non-zero pages within 32 pages --")
    local data_found = 0
    for i = 1, 32 do
        for _, sign in ipairs({-1, 1}) do
            local addr = (sign < 0) and (va_base - i * PAGE) or (va_end + (i - 1) * PAGE)
            if addr > 0 and addr < 0x7FFFFFFFFFFF then
                local ok_r, dval = pcall(function() return memory.read_dword(addr) end)
                if ok_r and to_num(dval) ~= 0 then
                    if addr < va_base or addr >= va_end then
                        data_found = data_found + 1
                        local ok_q, qval = safe_read_qword(uint64(addr))
                        local q_str = ok_q and dump_qword(qval) or "??"
                        local dir = sign < 0 and "before" or "after"
                        print(string.format("    DATA at %s (%s, %d pages): %s",
                            hex(addr), dir, i, q_str))
                        if data_found >= 8 then break end
                    end
                end
            end
        end
        if data_found >= 8 then break end
    end
    print("    non-zero pages found: " .. data_found)

    -- 2i: mmap adjacency
    print("  -- mmap adjacency test --")
    do
        local ok_mm, mm_ret = pcall(function()
            return sc_mmap(
                uint64(0),
                uint64(PAGE),
                uint64(PROT_CPU_RW),
                uint64(MAP_PRIVATE + MAP_ANON),
                uint64("0xFFFFFFFFFFFFFFFF"),
                uint64(0)
            )
        end)
        if ok_mm then
            local mmap_addr = to_num(mm_ret)
            if mmap_addr > 0 and mmap_addr ~= 0xFFFFFFFFFFFFFFFF then
                local distance
                if mmap_addr >= va_end then
                    distance = mmap_addr - va_end
                else
                    distance = va_base - mmap_addr
                end
                print("    anon mmap at   : " .. hex(mmap_addr))
                print("    distance       : " .. hex(distance) .. " (" .. string.format("%.1f MB", distance / 1048576) .. ")")
                pcall(function() sc_munmap(uint64(mmap_addr), uint64(PAGE)) end)
            else
                print("    mmap returned  : " .. hex(mm_ret) .. " (failed)")
            end
        else
            print("    mmap FAILED    : " .. tostring(mm_ret))
        end
    end

    -- 2j: cleanup this allocation
    print("  -- cleanup --")
    local ok_um = pcall(function() sc_munmap(uint64(va_base), uint64(alloc_size)) end)
    print("    munmap         : " .. (ok_um and "OK" or "FAILED"))
    local ok_rl = pcall(function() sc_release_dmem(phys_addr, uint64(alloc_size)) end)
    print("    release        : " .. (ok_rl and "OK" or "FAILED"))

    print("")
  until true
end

--------------------------------------------------------------------
-- SECTION 3: GPU-only mapping test (no CPU prot)
--------------------------------------------------------------------
print("--- SECTION 3: GPU-ONLY MAPPING TEST ---")
do
    local phys_out = memory.alloc(8)
    memory.write_qword(phys_out, uint64(0))

    local ok_a, ret_a = pcall(function()
        return sc_alloc_dmem(
            uint64(0),
            uint64("0x0000000300000000"),
            uint64(PAGE),
            uint64(PAGE),
            uint64(DMEM_TYPE_MAIN),
            phys_out
        )
    end)

    if ok_a and to_num(ret_a) == 0 then
        local phys = memory.read_qword(phys_out)
        print("  gpu-only phys    : " .. hex(phys))

        local va_buf = memory.alloc(8)
        memory.write_qword(va_buf, uint64(0))

        local ok_m, ret_m = pcall(function()
            return sc_map_dmem(
                va_buf,
                uint64(PAGE),
                uint64(PROT_GPU_READ + PROT_GPU_WRITE),  -- GPU only
                uint64(0),
                phys,
                uint64(PAGE)
            )
        end)

        local map_rv = ok_m and to_num(ret_m) or -1
        local va = to_num(memory.read_qword(va_buf))
        print("  gpu-only map ret : " .. map_rv)
        print("  gpu-only VA      : " .. hex(va))

        if map_rv == 0 and va ~= 0 then
            -- try CPU read — should fault if truly GPU-only
            local ok_cpu, cpu_val = pcall(function() return memory.read_dword(va) end)
            if ok_cpu then
                print("  CPU read of GPU-only page SUCCEEDED: " .. hex(cpu_val))
                print("  => GPU-only pages may be CPU-accessible (FINDING)")
            else
                print("  CPU read of GPU-only page faulted (expected)")
            end
            pcall(function() sc_munmap(uint64(va), uint64(PAGE)) end)
        end

        pcall(function() sc_release_dmem(phys, uint64(PAGE)) end)
    else
        print("  gpu-only alloc failed: " .. tostring(ret_a))
    end
end
print("")

--------------------------------------------------------------------
-- SECTION 4: Post-release pool stats
--------------------------------------------------------------------
print("--- SECTION 4: POST-RELEASE POOL STATS ---")
do
    local ok, ret = pcall(function() return sc_dmem_total() end)
    if ok then
        print("  total dmem pool  : " .. hex(ret))
    end

    local search_end = pool_total > 0 and pool_total or 0x300000000
    local size_buf = memory.alloc(8)
    memory.write_qword(size_buf, uint64(0))

    local ok2 = pcall(function()
        return sc_dmem_avail(uint64(0), uint64(search_end), uint64(PAGE), size_buf)
    end)
    if ok2 then
        local avail = memory.read_qword(size_buf)
        print("  available dmem   : " .. hex(avail) .. " (" .. string.format("%.1f MB", to_num(avail) / 1048576) .. ")")
    else
        local start_buf = memory.alloc(8)
        memory.write_qword(start_buf, uint64(0))
        memory.write_qword(size_buf, uint64(0))
        local ok3 = pcall(function()
            return sc_dmem_avail(uint64(0), uint64(search_end), uint64(PAGE), start_buf, size_buf)
        end)
        if ok3 then
            local avail = memory.read_qword(size_buf)
            print("  available dmem   : " .. hex(avail) .. " (" .. string.format("%.1f MB", to_num(avail) / 1048576) .. ")")
        else
            print("  available dmem   : FAILED")
        end
    end
end

print("")
print("=== PROBE 40 COMPLETE ===")
