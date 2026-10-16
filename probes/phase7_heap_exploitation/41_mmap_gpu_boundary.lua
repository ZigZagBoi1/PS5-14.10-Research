-- CRASH_CLASS: SAFE
-- PROBE 41: mmap with GPU prot flags + boundary scanning
-- Instead of dmem syscalls (which return -1), try regular mmap
-- with GPU protection bits to get CPU+GPU shared pages.

print("=== PROBE 41: MMAP GPU BOUNDARY SCANNER ===")
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

local sc_mmap   = make_syscall(477)
local sc_munmap = make_syscall(588)

local PAGE = 0x4000

local PROT_READ      = 1
local PROT_WRITE     = 2
local PROT_GPU_READ  = 0x10
local PROT_GPU_WRITE = 0x20

local MAP_PRIVATE = 0x0002
local MAP_SHARED  = 0x0001
local MAP_ANON    = 0x1000

local probe_before = { -0x4000, -0x3000, -0x2000, -0x1000 }
local probe_after  = {  0x0000,  0x1000,  0x2000,  0x3000,  0x4000 }

--------------------------------------------------------------------
-- SECTION 1: Test which prot flag combos succeed with mmap
--------------------------------------------------------------------
print("--- SECTION 1: PROT FLAG COMBOS ---")

local combos = {
    { name = "CPU_RW",              prot = PROT_READ + PROT_WRITE },
    { name = "CPU_RW+GPU_R",       prot = PROT_READ + PROT_WRITE + PROT_GPU_READ },
    { name = "CPU_RW+GPU_RW",     prot = PROT_READ + PROT_WRITE + PROT_GPU_READ + PROT_GPU_WRITE },
    { name = "GPU_RW_only",        prot = PROT_GPU_READ + PROT_GPU_WRITE },
    { name = "CPU_R+GPU_RW",      prot = PROT_READ + PROT_GPU_READ + PROT_GPU_WRITE },
    { name = "ALL_0x33",           prot = 0x33 },
    { name = "PROT_0x37",         prot = 0x37 },
    { name = "PROT_0x3F",         prot = 0x3F },
}

local working = {}

for _, c in ipairs(combos) do
    local ok, ret = pcall(function()
        return sc_mmap(
            uint64(0),
            uint64(PAGE),
            uint64(c.prot),
            uint64(MAP_PRIVATE + MAP_ANON),
            uint64("0xFFFFFFFFFFFFFFFF"),
            uint64(0)
        )
    end)
    local addr = ok and to_num(ret) or 0
    local fail = (not ok) or (addr == 0) or (addr >= 0xFFFFFFFF00000000)
    if not fail then
        local can_read = false
        local can_write = false
        local ok_r, rv = pcall(function() return memory.read_dword(addr) end)
        if ok_r then can_read = true end
        local ok_w = pcall(function() memory.write_dword(addr, 0x41414141) end)
        if ok_w then can_write = true end
        print(string.format("  %-18s prot=0x%02X -> %s  R=%s W=%s",
            c.name, c.prot, hex(addr),
            can_read and "Y" or "N", can_write and "Y" or "N"))
        working[#working + 1] = { name = c.name, prot = c.prot, addr = addr, r = can_read, w = can_write }
        pcall(function() sc_munmap(uint64(addr), uint64(PAGE)) end)
    else
        local err_str = ok and hex(ret) or tostring(ret)
        print(string.format("  %-18s prot=0x%02X -> FAILED (%s)", c.name, c.prot, err_str))
    end
end

print(string.format("  working combos: %d / %d", #working, #combos))
print("")

--------------------------------------------------------------------
-- SECTION 2: MAP_SHARED vs MAP_PRIVATE with GPU flags
--------------------------------------------------------------------
print("--- SECTION 2: SHARED vs PRIVATE ---")

for _, map_flag in ipairs({ {name="PRIVATE", val=MAP_PRIVATE}, {name="SHARED", val=MAP_SHARED} }) do
    local ok, ret = pcall(function()
        return sc_mmap(
            uint64(0),
            uint64(PAGE),
            uint64(PROT_READ + PROT_WRITE + PROT_GPU_READ + PROT_GPU_WRITE),
            uint64(map_flag.val + MAP_ANON),
            uint64("0xFFFFFFFFFFFFFFFF"),
            uint64(0)
        )
    end)
    local addr = ok and to_num(ret) or 0
    local fail = (not ok) or (addr == 0) or (addr >= 0xFFFFFFFF00000000)
    if not fail then
        print(string.format("  %s+ANON+GPU_RW -> %s  OK", map_flag.name, hex(addr)))
        pcall(function() sc_munmap(uint64(addr), uint64(PAGE)) end)
    else
        local err_str = ok and hex(ret) or tostring(ret)
        print(string.format("  %s+ANON+GPU_RW -> FAILED (%s)", map_flag.name, err_str))
    end
end
print("")

--------------------------------------------------------------------
-- SECTION 3: Multi-size boundary probe with best working combo
--------------------------------------------------------------------
print("--- SECTION 3: BOUNDARY PROBING ---")

local best_prot = PROT_READ + PROT_WRITE + PROT_GPU_READ + PROT_GPU_WRITE
local test_sizes = {
    { name = "16KB (1 page)",    size = PAGE },
    { name = "64KB (4 pages)",   size = PAGE * 4 },
    { name = "1MB (64 pages)",   size = PAGE * 64 },
}

for ti, tinfo in ipairs(test_sizes) do
  repeat
    print("  -- " .. tinfo.name .. " --")
    local sz = tinfo.size

    local ok, ret = pcall(function()
        return sc_mmap(
            uint64(0),
            uint64(sz),
            uint64(best_prot),
            uint64(MAP_PRIVATE + MAP_ANON),
            uint64("0xFFFFFFFFFFFFFFFF"),
            uint64(0)
        )
    end)
    local va_base = ok and to_num(ret) or 0
    if va_base == 0 or va_base >= 0xFFFFFFFF00000000 then
        print("    mmap FAILED: " .. (ok and hex(ret) or tostring(ret)))
        break
    end
    local va_end = va_base + sz
    print("    base: " .. hex(va_base) .. "  end: " .. hex(va_end))

    -- write markers
    local marker = 0xCAFE0040 + ti
    local pages_ok = 0
    for off = 0, sz - 1, PAGE do
        local ok_w = pcall(function() memory.write_dword(va_base + off, marker) end)
        if ok_w then pages_ok = pages_ok + 1 end
    end
    print("    pages written: " .. pages_ok .. "/" .. (sz / PAGE))

    -- probe BEFORE
    print("    -- before mapping --")
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
                print(string.format("      [base%+06X] %s [%s] READABLE",
                    off, dump_qword(qval), table.concat(bytes, " ")))
            else
                print(string.format("      [base%+06X] FAULT", off))
            end
        end
    end

    -- probe AFTER
    print("    -- after mapping --")
    for _, off in ipairs(probe_after) do
        local addr = va_end + off
        local ok_r, qval = safe_read_qword(uint64(addr))
        if ok_r then
            local bytes = {}
            for i = 0, 7 do
                local ok_b, bv = safe_read_byte(uint64(addr + i))
                bytes[#bytes + 1] = ok_b and string.format("%02X", bv) or "??"
            end
            local tag = (off == 0) and " <-- first past end" or ""
            print(string.format("      [end+%05X] %s [%s] READABLE%s",
                off, dump_qword(qval), table.concat(bytes, " "), tag))
        else
            local tag = (off == 0) and " <-- guard OK" or ""
            print(string.format("      [end+%05X] FAULT%s", off, tag))
        end
    end

    -- marker leak check
    local leaked = false
    for _, off in ipairs({ -PAGE, sz, sz + PAGE }) do
        local addr = va_base + off
        if addr > 0 and (addr < va_base or addr >= va_end) then
            local ok_r, qval = safe_read_qword(uint64(addr))
            if ok_r then
                local lo = 0
                if type(qval) == "table" and qval.l then lo = qval.l
                else lo = to_num(qval) end
                if lo == marker then
                    print("      MARKER LEAK at offset " .. hex(off) .. "!")
                    leaked = true
                end
            end
        end
    end
    if not leaked then
        print("      no marker leakage")
    end

    -- second mmap adjacency
    local ok2, ret2 = pcall(function()
        return sc_mmap(
            uint64(0), uint64(PAGE), uint64(best_prot),
            uint64(MAP_PRIVATE + MAP_ANON),
            uint64("0xFFFFFFFFFFFFFFFF"), uint64(0)
        )
    end)
    if ok2 then
        local addr2 = to_num(ret2)
        if addr2 > 0 and addr2 < 0xFFFFFFFF00000000 then
            local gap
            if addr2 >= va_end then gap = addr2 - va_end
            else gap = va_base - addr2 end
            print("    next mmap at " .. hex(addr2) .. " gap=" .. hex(gap))
            pcall(function() sc_munmap(uint64(addr2), uint64(PAGE)) end)
        end
    end

    -- cleanup
    pcall(function() sc_munmap(uint64(va_base), uint64(sz)) end)
    print("")
  until true
end

--------------------------------------------------------------------
-- SECTION 4: GPU-only mmap (no CPU prot)
--------------------------------------------------------------------
print("--- SECTION 4: GPU-ONLY MMAP (no CPU prot) ---")
do
    local ok, ret = pcall(function()
        return sc_mmap(
            uint64(0),
            uint64(PAGE),
            uint64(PROT_GPU_READ + PROT_GPU_WRITE),
            uint64(MAP_PRIVATE + MAP_ANON),
            uint64("0xFFFFFFFFFFFFFFFF"),
            uint64(0)
        )
    end)
    local addr = ok and to_num(ret) or 0
    if addr > 0 and addr < 0xFFFFFFFF00000000 then
        print("  gpu-only VA: " .. hex(addr))
        local ok_r, rv = pcall(function() return memory.read_dword(addr) end)
        if ok_r then
            print("  CPU read of GPU-only page SUCCEEDED: " .. hex(rv) .. " (FINDING)")
        else
            print("  CPU read of GPU-only page faulted (expected)")
        end
        local ok_w = pcall(function() memory.write_dword(addr, 0xBBBBBBBB) end)
        if ok_w then
            print("  CPU write of GPU-only page SUCCEEDED (FINDING)")
        else
            print("  CPU write of GPU-only page faulted (expected)")
        end
        pcall(function() sc_munmap(uint64(addr), uint64(PAGE)) end)
    else
        print("  gpu-only mmap failed: " .. (ok and hex(ret) or tostring(ret)))
    end
end
print("")

--------------------------------------------------------------------
-- SECTION 5: Double-map test — same phys via two VAs?
-- Use MAP_SHARED to see if two mmaps can alias
--------------------------------------------------------------------
print("--- SECTION 5: DOUBLE MAP ALIAS TEST ---")
do
    local ok1, ret1 = pcall(function()
        return sc_mmap(
            uint64(0), uint64(PAGE),
            uint64(PROT_READ + PROT_WRITE),
            uint64(MAP_SHARED + MAP_ANON),
            uint64("0xFFFFFFFFFFFFFFFF"), uint64(0)
        )
    end)
    local a1 = ok1 and to_num(ret1) or 0
    if a1 > 0 and a1 < 0xFFFFFFFF00000000 then
        pcall(function() memory.write_dword(a1, 0x12345678) end)
        local ok2, ret2 = pcall(function()
            return sc_mmap(
                uint64(0), uint64(PAGE),
                uint64(PROT_READ + PROT_WRITE),
                uint64(MAP_SHARED + MAP_ANON),
                uint64("0xFFFFFFFFFFFFFFFF"), uint64(0)
            )
        end)
        local a2 = ok2 and to_num(ret2) or 0
        if a2 > 0 and a2 < 0xFFFFFFFF00000000 then
            local ok_r, v2 = pcall(function() return memory.read_dword(a2) end)
            local val2 = ok_r and to_num(v2) or -1
            print("  map1=" .. hex(a1) .. " map2=" .. hex(a2))
            print("  wrote 0x12345678 to map1, read from map2: " .. hex(val2))
            if val2 == 0x12345678 then
                print("  ALIAS DETECTED — same physical page! (FINDING)")
            else
                print("  no alias (different physical pages)")
            end
            pcall(function() sc_munmap(uint64(a2), uint64(PAGE)) end)
        end
        pcall(function() sc_munmap(uint64(a1), uint64(PAGE)) end)
    else
        print("  shared mmap failed: " .. (ok1 and hex(ret1) or tostring(ret1)))
    end
end

print("")
print("=== PROBE 41 COMPLETE ===")
