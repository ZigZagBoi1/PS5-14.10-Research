-- CRASH_CLASS: LOW
-- PROBE 547b: Physical memory scanner via dmem0
--
-- 547a confirmed: dmem0 maps ANY 16KB-aligned physical address.
-- The kernel is somewhere in the PS5's 16GB RAM.
-- Scan physical memory looking for non-zero pages and kernel signatures.
--
-- Strategy: map 16KB at each offset, read first qword.
-- If non-zero, dump more and check for kernel signatures.
-- Scan in 16MB steps first (coarse), then refine around hits.

print("=== 547b: PHYS MEMORY SCAN ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
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
local va = uint64("0x880000000")
local PAGE = 0x4000  -- 16KB

-- Phase 1: Coarse scan — every 16MB from 0 to 16GB
-- 16MB = 0x1000000. 16GB = 0x400000000. That's 1024 steps.
-- Too many for one probe. Scan first 4GB (256 steps) + spot checks above.

print("[PHASE 1] Coarse scan: 0 to 4GB, step=16MB")
local hits = {}
local STEP = 0x1000000  -- 16MB

for idx = 0, 255 do
    local phys = uint64(idx * STEP)

    local ok_m, rv_m = pcall(function()
        return sc_mmap(va, uint64(PAGE), uint64(0x33),
            uint64(MAP_SHARED + MAP_FIXED), uint64(dmem_fd), phys)
    end)

    if ok_m and to_num(rv_m) ~= -1 then
        local d0 = rd(va)
        local d1 = rd(va + 4)

        pcall(function() sc_munmap(va, uint64(PAGE)) end)

        if d0 and d0 ~= 0 then
            local d0u = d0; if d0u < 0 then d0u = d0u + 0x100000000 end
            local d1u = d1 or 0; if d1u < 0 then d1u = d1u + 0x100000000 end
            hits[#hits+1] = {phys = phys, d0 = d0u, d1 = d1u}
            print(string.format("  HIT phys=%s d0=%08X d1=%08X",
                q(phys), d0u, d1u))

            if d0u == 0x464C457F then
                print("  *** ELF HEADER at " .. q(phys) .. " ***")
            end
        end
    else
        -- mmap failed — note it if it's the first failure
        if idx < 5 then
            print("  FAIL at " .. q(uint64(idx * STEP)))
        end
    end
end
print("  Hits in 0-4GB: " .. #hits)

-- Phase 1b: Spot checks above 4GB
print("")
print("[PHASE 1b] Above 4GB: 4GB-16GB, step=64MB")
local STEP2 = 0x4000000  -- 64MB

for idx = 0, 191 do  -- 4GB to 16GB
    local phys_n = 0x100000000 + idx * STEP2
    local phys_hi = math.floor(phys_n / 0x100000000)
    local phys_lo = phys_n % 0x100000000
    local phys = uint64(string.format("0x%X%08X", phys_hi, phys_lo))

    local ok_m, rv_m = pcall(function()
        return sc_mmap(va, uint64(PAGE), uint64(0x33),
            uint64(MAP_SHARED + MAP_FIXED), uint64(dmem_fd), phys)
    end)

    if ok_m and to_num(rv_m) ~= -1 then
        local d0 = rd(va)
        pcall(function() sc_munmap(va, uint64(PAGE)) end)

        if d0 and d0 ~= 0 then
            local d0u = d0; if d0u < 0 then d0u = d0u + 0x100000000 end
            local d1 = rd(va + 4) or 0
            hits[#hits+1] = {phys = phys, d0 = d0u}
            print(string.format("  HIT phys=%s d0=%08X", q(phys), d0u))
            if d0u == 0x464C457F then
                print("  *** ELF HEADER at " .. q(phys) .. " ***")
            end
        end
    end
end
print("  Total hits: " .. #hits)

-- Phase 2: For each hit from phase 1, dump first 256 bytes
if #hits > 0 then
    print("")
    print("[PHASE 2] Dump hits")
    for i, hit in ipairs(hits) do
        if i > 20 then print("  (truncated)"); break end

        local ok_m2 = pcall(function()
            sc_mmap(va, uint64(PAGE), uint64(0x33),
                uint64(MAP_SHARED + MAP_FIXED), uint64(dmem_fd), hit.phys)
        end)
        if ok_m2 then
            print("")
            print("  === " .. q(hit.phys) .. " ===")
            for row = 0, 15 do
                local off = row * 16
                local vals = {}
                for col = 0, 12, 4 do
                    local v = rd(va + off + col)
                    if v then
                        if v < 0 then v = v + 0x100000000 end
                        vals[#vals+1] = string.format("%08X", v)
                    else
                        vals[#vals+1] = "________"
                    end
                end
                print(string.format("  +%03X: %s", off, table.concat(vals, " ")))
            end

            -- Also read as ASCII for string detection
            local ascii = {}
            for off = 0, 255 do
                local byte_off = math.floor(off / 4)
                local byte_pos = off % 4
                local dw = rd(va + byte_off * 4)
                if dw then
                    if dw < 0 then dw = dw + 0x100000000 end
                    local b = math.floor(dw / (256 ^ byte_pos)) % 256
                    if b >= 32 and b < 127 then
                        ascii[#ascii+1] = string.char(b)
                    else
                        ascii[#ascii+1] = "."
                    end
                end
            end
            local ascii_str = table.concat(ascii)
            -- Print non-dot runs (potential strings)
            local str_found = false
            for s in ascii_str:gmatch("[%w_/%.%-:]+") do
                if #s >= 4 then
                    if not str_found then
                        print("  STRINGS:")
                        str_found = true
                    end
                    print("    \"" .. s .. "\"")
                end
            end

            pcall(function() sc_munmap(va, uint64(PAGE)) end)
        end
    end
end

-- Phase 3: Fine scan around phys=0 (we know it has data)
print("")
print("[PHASE 3] Fine scan around phys=0, step=16KB")
for page = 0, 63 do
    local phys = uint64(page * PAGE)
    local ok_m3 = pcall(function()
        sc_mmap(va, uint64(PAGE), uint64(0x33),
            uint64(MAP_SHARED + MAP_FIXED), uint64(dmem_fd), phys)
    end)
    if ok_m3 then
        local d0 = rd(va)
        pcall(function() sc_munmap(va, uint64(PAGE)) end)
        if d0 and d0 ~= 0 then
            local d0u = d0; if d0u < 0 then d0u = d0u + 0x100000000 end
            print(string.format("  page=%d phys=0x%X d0=%08X", page, page * PAGE, d0u))
        end
    end
end

print("")
print("=== 547b DONE ===")
