-- CRASH_CLASS: LOW
-- PROBE 563b: Dmem0 physical memory heatmap — what's actually there?
--
-- 563a scanned 16GB at 2MB stride: 0 ELF headers. Either the kernel
-- isn't there or we're reading zeros. Need diagnostic data:
-- - How many pages are readable vs fail?
-- - How many have non-zero content?
-- - What physical ranges have data?
-- - Are there any interesting signatures (not just ELF)?
--
-- Scan 0..16GB at 2MB stride, report:
-- [ok] successful mmap+read count
-- [nz] non-zero dword count
-- [ranges] contiguous non-zero ranges
-- [sigs] first 8 bytes at each non-zero location

print("=== PROBE 563b: DMEM0 HEATMAP ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if not ok then return nil end
    local n = N(v); if n < 0 then n = n + 0x100000000 end; return n
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local Z = uint64(0)
local sc477 = mk(477)
local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

-- Open dmem0
local dp = memory.alloc(16)
wd(N(dp), 0x7665642F); wd(N(dp) + 4, 0x656D642F); wd(N(dp) + 8, 0x0000306D)
local ok_o, fd_raw = pcall(function()
    return native.fcall_with_rax(stub, 5, dp, uint64(2))
end)
local fd = ok_o and N(fd_raw) or -999
if fd < 0 then print("OPEN FAIL"); return end
print("fd=" .. fd)
io.flush()

local STRIDE = 0x200000  -- 2MB
local PAGE = 0x4000       -- 16KB
local ok_count = 0
local fail_count = 0
local nz_count = 0
local nonzero_locs = {}
local MAX_NZ_REPORT = 50

-- Check for various signatures
local SIGS = {
    [0x464C457F] = "ELF",
    [0x00000001] = "ONE",     -- common in tables
    [0x46524545] = "FREE",    -- "FREE" ASCII
    [0x44524246] = "FBRD",    -- "FBRD" reversed
}

for hi = 0, 3 do
    local lo = 0
    while lo < 0x100000000 do
        local phys_off
        if hi > 0 then
            phys_off = uint64(string.format("0x%X%08X", hi, lo))
        else
            if lo > 0 then
                phys_off = uint64(lo)
            else
                phys_off = Z
            end
        end

        local ok_mm, va_raw = pcall(function()
            return sc477(Z, uint64(PAGE), uint64(1),
                uint64(0x0001), uint64(fd), phys_off)
        end)

        local va = ok_mm and N(va_raw) or 0
        -- Check for MAP_FAILED (-1 → huge number or negative)
        -- On 64-bit, MAP_FAILED = 0xFFFFFFFFFFFFFFFF
        -- N() on uint64 might give weird results. Check va is reasonable.
        local readable = false
        local v0, v4

        if va > 0x10000 and va < 0x800000000000 then
            v0 = rb(va)
            if v0 ~= nil then
                readable = true
                ok_count = ok_count + 1
                if v0 ~= 0 then
                    v4 = rb(va + 4) or 0
                    nz_count = nz_count + 1
                    if #nonzero_locs < MAX_NZ_REPORT then
                        local label = SIGS[v0] or ""
                        table.insert(nonzero_locs,
                            string.format("0x%X%08X %08X_%08X %s", hi, lo, v4, v0, label))
                    end
                else
                    -- First dword is 0, check a few more
                    v4 = rb(va + 4) or 0
                    local v8 = rb(va + 8) or 0
                    local v12 = rb(va + 12) or 0
                    if v4 ~= 0 or v8 ~= 0 or v12 ~= 0 then
                        nz_count = nz_count + 1
                        if #nonzero_locs < MAX_NZ_REPORT then
                            table.insert(nonzero_locs,
                                string.format("0x%X%08X 0_%08X_%08X_%08X",
                                    hi, lo, v4, v8, v12))
                        end
                    end
                end
            else
                fail_count = fail_count + 1
            end

            -- munmap
            pcall(function()
                native.fcall_with_rax(stub, 73, uint64(va), uint64(PAGE))
            end)
        else
            fail_count = fail_count + 1
        end

        if lo > 0x100000000 - STRIDE then break end
        lo = lo + STRIDE
    end

    -- Progress after each 4GB
    print(string.format("  0x%X00000000: ok=%d fail=%d nz=%d",
        hi + 1, ok_count, fail_count, nz_count))
    io.flush()
end

-- ============================================================
-- Report
-- ============================================================
print("")
print(string.format("TOTAL: ok=%d fail=%d nonzero=%d", ok_count, fail_count, nz_count))
print("")
print("NON-ZERO LOCATIONS (first " .. #nonzero_locs .. "):")
for _, entry in ipairs(nonzero_locs) do
    print("  " .. entry)
end

io.flush()
pcall(function() native.fcall_with_rax(stub, 6, uint64(fd)) end)
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid_val and " ALIVE" or " DEAD"))
print("=== 563b DONE ===")
