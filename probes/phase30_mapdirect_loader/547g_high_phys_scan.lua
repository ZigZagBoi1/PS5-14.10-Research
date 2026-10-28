-- CRASH_CLASS: LOW
-- PROBE 547g: Dense scan 5.25GB to 16GB via dmem0
--
-- 547d/547e covered 0-5.25GB (278K pages, 12 GPU hits, no kernel).
-- This closes the gap: 5.25GB to 16GB = 10.75GB = ~688K pages.
-- If dmem0 can map these offsets, scan every 16KB page.
-- If most/all reject or read zero, dmem0 is confirmed GPU-pool-only.

print("=== 547g: HIGH PHYS (5.25-16GB) ===")
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

local PAGE = 0x4000
local CHUNK = 0x100000  -- 1MB
local PPC = CHUNK / PAGE
local va = uint64("0x880000000")

-- 5.25GB = 0x150000000, 16GB = 0x400000000
local START = 0x150000000  -- 5.25GB
local STOP  = 0x400000000  -- 16GB
local total_bytes = STOP - START  -- 10.75GB
local n_chunks = math.floor(total_bytes / CHUNK)  -- 10944

print(string.format("Range: 0x%X to 0x%X (%d chunks, ~%dGB)",
    START, STOP, n_chunks, math.floor(total_bytes / 0x40000000)))

local hits = {}
local scanned = 0
local rejected = 0

for ci = 0, n_chunks - 1 do
    local phys_raw = START + ci * CHUNK
    local hi = math.floor(phys_raw / 0x100000000)
    local lo = phys_raw % 0x100000000
    local phys = uint64(string.format("0x%X%08X", hi, lo))

    local ok_m, rv_m = pcall(function()
        return sc_mmap(va, uint64(CHUNK), uint64(0x33),
            uint64(0x11), uint64(dmem_fd), phys)
    end)

    if ok_m and to_num(rv_m) ~= -1 then
        for pi = 0, PPC - 1 do
            local d0 = rd(va + pi * PAGE)
            scanned = scanned + 1
            if d0 and d0 ~= 0 then
                local d0u = d0; if d0u < 0 then d0u = d0u + 0x100000000 end
                local pa = phys_raw + pi * PAGE
                hits[#hits+1] = {p = pa, d = d0u}
                if d0u == 0x464C457F then
                    local phi = math.floor(pa / 0x100000000)
                    local plo = pa % 0x100000000
                    print(string.format("*** ELF @ 0x%X%08X ***", phi, plo))
                end
            end
        end
        pcall(function() sc_munmap(va, uint64(CHUNK)) end)
    else
        rejected = rejected + 1
        -- On first rejection, note it
        if rejected == 1 then
            local phi = math.floor(phys_raw / 0x100000000)
            local plo = phys_raw % 0x100000000
            print(string.format("  First reject at 0x%X%08X (chunk %d)", phi, plo, ci))
        end
    end

    -- Progress every ~1GB (1024 chunks)
    if ci % 1024 == 1023 then
        local mb = math.floor((START + (ci+1)*CHUNK) / 0x100000)
        print(string.format("  %dMB: %d scanned, %d rejected, %d hits",
            mb, scanned, rejected, #hits))
    end
end

print("")
print(string.format("DONE: %d scanned, %d rejected, %d non-zero", scanned, rejected, #hits))

if rejected > 0 then
    print(string.format("  Rejection rate: %d/%d chunks (%.1f%%)",
        rejected, n_chunks, rejected * 100 / n_chunks))
end

for i, h in ipairs(hits) do
    if i > 100 then print("(truncated)"); break end
    local phi = math.floor(h.p / 0x100000000)
    local plo = h.p % 0x100000000
    print(string.format("  0x%X%08X: %08X", phi, plo, h.d))
end

-- Dump first 64 bytes of up to 10 hits
if #hits > 0 then
    print("")
    print("DUMPS:")
    local dumped = 0
    for _, h in ipairs(hits) do
        if dumped >= 10 then break end
        dumped = dumped + 1
        local pa = h.p
        local cb = math.floor(pa / CHUNK) * CHUNK
        local po = pa - cb
        local chi = math.floor(cb / 0x100000000)
        local clo = cb % 0x100000000
        local chunk_phys = uint64(string.format("0x%X%08X", chi, clo))

        pcall(function()
            sc_mmap(va, uint64(CHUNK), uint64(0x33), uint64(0x11), uint64(dmem_fd), chunk_phys)
        end)
        local line = {}
        for off = 0, 60, 4 do
            local v = rd(va + po + off)
            if v then
                if v < 0 then v = v + 0x100000000 end
                line[#line+1] = string.format("%08X", v)
            end
        end
        local phi2 = math.floor(pa / 0x100000000)
        local plo2 = pa % 0x100000000
        print(string.format("  0x%X%08X: %s", phi2, plo2, table.concat(line, " ")))
        pcall(function() sc_munmap(va, uint64(CHUNK)) end)
    end
end

print("")
print("=== 547g DONE ===")
