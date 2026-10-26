-- CRASH_CLASS: LOW
-- PROBE 547e: Scan rest of GPU pool (1GB to 5.25GB) via dmem0
--
-- 547d covered 0-1GB. Pool goes to 0x150000000 (5.25GB).
-- Scan 1GB-5.25GB = 4.25GB = 4352 chunks of 1MB.

print("=== 547e: POOL REST (1-5.25GB) ===")
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
local CHUNK = 0x100000
local PPC = CHUNK / PAGE  -- 64
local va = uint64("0x880000000")

local START = 0x40000000    -- 1GB
local STOP  = 0x150000000   -- 5.25GB
local n_chunks = math.floor((STOP - START) / CHUNK)  -- 4352

print("Scanning " .. n_chunks .. " chunks (1GB to 5.25GB)")
local hits = {}
local scanned = 0

for ci = 0, n_chunks - 1 do
    local phys_raw = START + ci * CHUNK
    local hi = math.floor(phys_raw / 0x100000000)
    local lo = phys_raw % 0x100000000
    local phys
    if hi > 0 then
        phys = uint64(string.format("0x%X%08X", hi, lo))
    else
        phys = uint64(lo)
    end

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
                    print(string.format("*** ELF @ 0x%X ***", pa))
                end
            end
        end
        pcall(function() sc_munmap(va, uint64(CHUNK)) end)
    end

    if ci % 512 == 511 then
        local mb = math.floor((START + (ci+1)*CHUNK) / 0x100000)
        print(string.format("  %dMB: %d pages, %d hits", mb, scanned, #hits))
    end
end

print("")
print(string.format("DONE: %d pages, %d non-zero", scanned, #hits))

-- Print hits (truncate at 200)
for i, h in ipairs(hits) do
    if i > 200 then print("(truncated)"); break end
    local hi2 = math.floor(h.p / 0x100000000)
    local lo2 = h.p % 0x100000000
    if hi2 > 0 then
        print(string.format("  0x%X%08X: %08X", hi2, lo2, h.d))
    else
        print(string.format("  0x%08X: %08X", lo2, h.d))
    end
end

-- Dump first 64 bytes of up to 10 unique first-dword hits
print("")
print("SAMPLE DUMPS:")
local seen = {}
local dumped = 0
for _, h in ipairs(hits) do
    if dumped >= 10 then break end
    local key = string.format("%08X", h.d)
    if not seen[key] then
        seen[key] = true
        dumped = dumped + 1

        local pa = h.p
        local cb = math.floor(pa / CHUNK) * CHUNK
        local po = pa - cb
        local hi3 = math.floor(cb / 0x100000000)
        local lo3 = cb % 0x100000000
        local chunk_phys = hi3 > 0 and uint64(string.format("0x%X%08X", hi3, lo3)) or uint64(lo3)

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
        if hi3 > 0 then
            print(string.format("  0x%X%08X: %s", math.floor(pa/0x100000000), pa%0x100000000, table.concat(line, " ")))
        else
            print(string.format("  0x%08X: %s", pa, table.concat(line, " ")))
        end
        pcall(function() sc_munmap(va, uint64(CHUNK)) end)
    end
end

print("")
print("=== 547e DONE ===")
