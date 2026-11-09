-- CRASH_CLASS: LOW
-- PROBE 547d: Dense physical scan using 1MB dmem0 mappings
--
-- 547c confirmed: 1MB mmap works on dmem0, 4MB crashes.
-- Use 1MB chunks to scan every 16KB page in the first 1GB.
-- That's 1024 chunks x 64 pages = 65536 pages total.
--
-- Goal: find all non-zero physical pages → locate kernel in RAM.

print("=== 547d: DENSE PHYS SCAN ===")
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
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end

local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)
local sc_open = make_syscall(5)

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

local MAP_SF = 0x11  -- MAP_SHARED | MAP_FIXED
local PAGE = 0x4000
local CHUNK = 0x100000  -- 1MB
local PAGES_PER_CHUNK = CHUNK / PAGE  -- 64

-- Use a VA far from any process region
local va = uint64("0x880000000")

-- Scan first 1GB = 1024 chunks
local TOTAL = 0x40000000  -- 1GB
local n_chunks = TOTAL / CHUNK  -- 1024

print("Scanning " .. n_chunks .. " chunks (1GB, 1MB each)")
local hits = {}
local scanned = 0

for ci = 0, n_chunks - 1 do
    local phys = uint64(ci * CHUNK)
    local ok_m, rv_m = pcall(function()
        return sc_mmap(va, uint64(CHUNK), uint64(0x33),
            uint64(MAP_SF), uint64(dmem_fd), phys)
    end)

    if ok_m and to_num(rv_m) ~= -1 then
        for pi = 0, PAGES_PER_CHUNK - 1 do
            local d0 = rd(va + pi * PAGE)
            scanned = scanned + 1
            if d0 and d0 ~= 0 then
                local d0u = d0; if d0u < 0 then d0u = d0u + 0x100000000 end
                local phys_addr = ci * CHUNK + pi * PAGE
                hits[#hits+1] = {p = phys_addr, d = d0u}
                if d0u == 0x464C457F then
                    print(string.format("*** ELF @ 0x%X ***", phys_addr))
                end
            end
        end
        pcall(function() sc_munmap(va, uint64(CHUNK)) end)
    end

    -- Progress every 128MB
    if ci % 128 == 127 then
        print(string.format("  %dMB: %d hits so far", (ci + 1), #hits))
    end
end

-- Results
print("")
print(string.format("DONE: %d pages scanned, %d non-zero", scanned, #hits))
print("")

-- Print all hits (expect <100)
for i, h in ipairs(hits) do
    if i > 100 then print("(truncated at 100)"); break end
    print(string.format("  0x%08X: %08X", h.p, h.d))
end

-- Dump first 64 bytes of each hit (up to 20)
print("")
print("DUMPS:")
for i, h in ipairs(hits) do
    if i > 20 then break end
    local phys = uint64(h.p)
    local chunk_base = uint64(math.floor(h.p / CHUNK) * CHUNK)
    local page_off = h.p - math.floor(h.p / CHUNK) * CHUNK

    pcall(function()
        sc_mmap(va, uint64(CHUNK), uint64(0x33),
            uint64(MAP_SF), uint64(dmem_fd), chunk_base)
    end)

    local page_va = va + page_off
    local line = {}
    for off = 0, 60, 4 do
        local v = rd(page_va + off)
        if v then
            if v < 0 then v = v + 0x100000000 end
            line[#line+1] = string.format("%08X", v)
        end
    end
    print(string.format("  0x%08X: %s", h.p, table.concat(line, " ")))
    pcall(function() sc_munmap(va, uint64(CHUNK)) end)
end

print("")
print("=== 547d DONE ===")
