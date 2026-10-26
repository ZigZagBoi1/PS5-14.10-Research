-- CRASH_CLASS: LOW
-- PROBE 547c: Large dmem0 mapping + dense physical scan
--
-- 547b found only 2 non-zero pages in coarse 16MB-step scan.
-- Hypothesis: kernel is between steps. Solution: map LARGE regions
-- and scan every page within them.
--
-- Plan:
-- A) Test if large mmap (1MB, 16MB, 256MB) works on dmem0
-- B) If yes, scan every 16KB page for non-zero data
-- C) If large mmap fails, do page-by-page scan of first 64MB

print("=== 547c: LARGE PHYS MAP ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end

local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)
local sc_open = make_syscall(5)

-- Open /dev/dmem0
local path_buf = memory.alloc(16)
wd(path_buf, 0x7665642F)
wd(path_buf + 4, 0x656D642F)
wd(path_buf + 8, 0x00306D)
local ok_o, fd_v = pcall(function()
    return sc_open(uint64(path_buf), uint64(2), uint64(0))
end)
local dmem_fd = ok_o and to_num(fd_v) or -1
print("dmem0 fd=" .. dmem_fd)
if dmem_fd < 0 then print("FATAL"); return end

local MAP_SHARED = 0x1
local MAP_FIXED = 0x10
local PAGE = 0x4000  -- 16KB
local base_va = uint64("0x880000000")

-- Phase A: test large mapping sizes
print("[A] Large mapping test")
local sizes = {
    {0x4000,     "16KB (baseline)"},
    {0x10000,    "64KB"},
    {0x40000,    "256KB"},
    {0x100000,   "1MB"},
    {0x400000,   "4MB"},
    {0x1000000,  "16MB"},
    {0x4000000,  "64MB"},
    {0x10000000, "256MB"},
}

local best_size = PAGE
for _, entry in ipairs(sizes) do
    local sz, label = entry[1], entry[2]
    local ok_m, rv_m = pcall(function()
        return sc_mmap(base_va, uint64(sz), uint64(0x33),
            uint64(MAP_SHARED + MAP_FIXED), uint64(dmem_fd), uint64(0))
    end)
    if ok_m and to_num(rv_m) ~= -1 then
        -- Verify: read first and last page
        local d0 = rd(base_va)
        local d_end = rd(base_va + sz - 4)
        print(string.format("  %s: OK (d0=%s)", label,
            d0 and string.format("%08X", d0 < 0 and d0 + 0x100000000 or d0) or "nil"))
        best_size = sz
        pcall(function() sc_munmap(base_va, uint64(sz)) end)
    else
        print("  " .. label .. ": FAIL")
        break
    end
end
print("  Best size: " .. string.format("0x%X", best_size))

-- Phase B: Dense scan using largest working size
-- Map region, scan every 16KB page for non-zero first dword
print("")
local total_scan = 0
local hits = {}

if best_size >= 0x100000 then
    -- Large mapping works! Scan in chunks
    local chunk = best_size
    local total_range = 0x10000000  -- scan first 256MB
    local chunks = math.floor(total_range / chunk)

    print(string.format("[B] Dense scan: 0 to 0x%X, chunk=0x%X (%d chunks)",
        total_range, chunk, chunks))

    for ci = 0, chunks - 1 do
        local phys_off = uint64(ci * chunk)
        local ok_m, rv_m = pcall(function()
            return sc_mmap(base_va, uint64(chunk), uint64(0x33),
                uint64(MAP_SHARED + MAP_FIXED), uint64(dmem_fd), phys_off)
        end)

        if ok_m and to_num(rv_m) ~= -1 then
            local pages_in_chunk = math.floor(chunk / PAGE)
            for pi = 0, pages_in_chunk - 1 do
                local page_va = base_va + uint64(pi * PAGE)
                local d0 = rd(page_va)
                total_scan = total_scan + 1

                if d0 and d0 ~= 0 then
                    local d0u = d0; if d0u < 0 then d0u = d0u + 0x100000000 end
                    local phys_page = ci * chunk + pi * PAGE
                    hits[#hits+1] = {phys = phys_page, va = page_va, d0 = d0u, chunk_idx = ci}
                    print(string.format("  HIT phys=0x%X d0=%08X", phys_page, d0u))

                    if d0u == 0x464C457F then
                        print("  *** ELF HEADER ***")
                    end
                end
            end
            pcall(function() sc_munmap(base_va, uint64(chunk)) end)
        end
    end

    -- Also scan 256MB-1GB
    print("")
    print("[B2] Scan 256MB-1GB, chunk=0x" .. string.format("%X", chunk))
    for ci = 0, math.floor(0x30000000 / chunk) - 1 do
        local phys_off = uint64(0x10000000 + ci * chunk)
        local ok_m = pcall(function()
            sc_mmap(base_va, uint64(chunk), uint64(0x33),
                uint64(MAP_SHARED + MAP_FIXED), uint64(dmem_fd), phys_off)
        end)
        if ok_m then
            local pages_in_chunk = math.floor(chunk / PAGE)
            for pi = 0, pages_in_chunk - 1 do
                local d0 = rd(base_va + uint64(pi * PAGE))
                total_scan = total_scan + 1
                if d0 and d0 ~= 0 then
                    local d0u = d0; if d0u < 0 then d0u = d0u + 0x100000000 end
                    local phys_page = 0x10000000 + ci * chunk + pi * PAGE
                    hits[#hits+1] = {phys = phys_page, d0 = d0u}
                    print(string.format("  HIT phys=0x%X d0=%08X", phys_page, d0u))
                    if d0u == 0x464C457F then
                        print("  *** ELF HEADER ***")
                    end
                end
            end
            pcall(function() sc_munmap(base_va, uint64(chunk)) end)
        end
    end

else
    -- Large mapping failed, do page-by-page for first 64MB
    local scan_end = 0x4000000  -- 64MB
    local pages = math.floor(scan_end / PAGE)
    print(string.format("[B] Page scan: 0 to 0x%X (%d pages)", scan_end, pages))

    for pi = 0, pages - 1 do
        local phys = uint64(pi * PAGE)
        local ok_m = pcall(function()
            sc_mmap(base_va, uint64(PAGE), uint64(0x33),
                uint64(MAP_SHARED + MAP_FIXED), uint64(dmem_fd), phys)
        end)
        if ok_m then
            local d0 = rd(base_va)
            total_scan = total_scan + 1
            if d0 and d0 ~= 0 then
                local d0u = d0; if d0u < 0 then d0u = d0u + 0x100000000 end
                hits[#hits+1] = {phys = pi * PAGE, d0 = d0u}
                print(string.format("  HIT phys=0x%X d0=%08X", pi * PAGE, d0u))
                if d0u == 0x464C457F then print("  *** ELF HEADER ***") end
            end
            pcall(function() sc_munmap(base_va, uint64(PAGE)) end)
        end
    end
end

print("")
print("SUMMARY: scanned " .. total_scan .. " pages, found " .. #hits .. " non-zero")
for i, h in ipairs(hits) do
    if i > 30 then print("  (truncated)"); break end
    print(string.format("  phys=0x%X d0=%08X", h.phys, h.d0))
end

print("")
print("=== 547c DONE ===")
