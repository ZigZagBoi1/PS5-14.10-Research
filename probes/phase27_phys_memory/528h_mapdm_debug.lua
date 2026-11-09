-- CRASH_CLASS: MODERATE
-- PROBE 528h: MapDirectMemory debug — isolate why it crashes
--
-- A2 in 528g proved: SROP inline pattern works (AllocateDirectMemory OK).
-- MapDirectMemory (libkernel+0x15020) crashes. Narrow down why:
--
-- [A] Allocate physical memory (fcall, known good)
-- [B] GetDirectMemorySize wrapper (0 args, should be trivial)
-- [C] MapDirectMemory with hint address (virtOut points to pre-mapped page)
-- [D] MapDirectMemory with larger alignment
-- [E] Raw syscall approach: call the underlying syscall directly via SROP

print("=== PROBE 528h: MAPDIRECTMEMORY DEBUG ===")
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
local function z(b, n) for o = 0, n - 4, 4 do wd(b + o, 0) end end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

-- Eboot
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
local function eaddr(off) return eboot + uint64(off) end
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- Libkernel
local ib2 = memory.alloc(0x200)
wd(N(ib2), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib2) end)
local lk_lo = rd(N(ib2) + 0x108) or 0
local lk_hi = rd(N(ib2) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
if lk_lo == 0 and lk_hi == 0 then
    for h = 0, 0x100 do
        local ib3 = memory.alloc(0x200)
        wd(N(ib3), 0x160)
        local ok3, r3 = pcall(function() return mk(593)(uint64(h), ib3) end)
        if ok3 and N(r3) == 0 then
            local name = ""
            for i = 0, 31 do
                local b = rd(N(ib3) + 8 + i)
                if b then local c = b % 256; if c == 0 then break end
                    if c >= 32 and c < 127 then name = name .. string.char(c) end
                end
            end
            if name:find("libkernel") then
                lk_lo = rd(N(ib3) + 0x108) or 0
                lk_hi = rd(N(ib3) + 0x10C) or 0
                if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
                if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
                break
            end
        end
    end
end
if lk_lo == 0 and lk_hi == 0 then print("FAIL: libkernel"); return end
local lk_text = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
print("libkernel=" .. fmt(lk_text))

local alloc_fn = lk_text + uint64(0x17EF0)
local map_fn   = lk_text + uint64(0x15020)
local getdms_fn = lk_text + uint64(0x17810)

-- Gadgets
local G = {
    pop_rax = 0x992, pop_rdi = 0xC9DFE, pop_rsi = 0xD77D,
    pop_rdx = 0x3B02D7, pop_rcx = 0xE64, mov_m = 0x92C67, bare_ret = 0x42,
}
local function vg(off, expect, nb)
    local d = rd(N(eboot) + off)
    if d == nil then return false end
    if d < 0 then d = d + 0x100000000 end
    local mask = 0
    for i = 0, nb - 1 do mask = mask + 0xFF * (2 ^ (i * 8)) end
    return (d % (mask + 1)) == expect
end
if not vg(G.pop_rax, 0xC358, 2) then print("GADGET FAIL"); return end
if not vg(G.pop_rdi, 0xC35F, 2) then
    G.pop_rdi = 0x75DFE
    if not vg(G.pop_rdi, 0xC35F, 2) then print("GADGET FAIL"); return end
end
if not vg(G.mov_m, 0xC3078948, 4) then print("GADGET FAIL"); return end
print("gadgets OK")

local MC = 0x40
local sc_gc = mk(421)
local sc_sr = mk(417)
local sc_mmap = mk(477)

-- ============================================================
-- SROP C-call helper (proven pattern from 528g A2)
-- fn_addr: target function
-- reg_args: {rdi, rsi, rdx, rcx, r8, r9} (nil = 0)
-- stack_arg: value for 7th arg (nil = none)
-- Returns: rax from function, or nil if died
-- ============================================================
local function srop_ccall(fn_addr, reg_args, stack_arg)
    local result = memory.alloc(8)
    wq(N(result), uint64("0xDEADDEADDEADDEAD"))

    local restore = memory.alloc(0x500)
    pcall(function() return sc_gc(uint64(restore)) end)

    local fs = sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    if not fs or N(fs) == 0 then return nil end
    local fn_rsp = N(fs) + 0x100000 + 8

    local p = fn_rsp
    local function stk(v) wq(p, v); p = p + 8 end

    stk(eaddr(G.pop_rdi))                -- [+0x00] ret addr
    stk(stack_arg or uint64(0))           -- [+0x08] 7th arg / pop_rdi junk
    stk(eaddr(G.pop_rdi))                -- [+0x10]
    stk(uint64(N(result)))                -- [+0x18]
    stk(eaddr(G.mov_m))                  -- [+0x20]
    stk(eaddr(G.pop_rax))                -- [+0x28]
    stk(uint64(417))                      -- [+0x30]
    stk(eaddr(G.pop_rdi))                -- [+0x38]
    stk(uint64(N(restore)))               -- [+0x40]
    stk(stub)                             -- [+0x48]

    local cc = memory.alloc(0x500)
    pcall(function() return sc_gc(uint64(cc)) end)
    wq(N(cc) + MC + 0xA0, fn_addr)
    wq(N(cc) + MC + 0xB8, uint64(fn_rsp))
    wq(N(cc) + MC + 0x48, uint64(fn_rsp - 8))

    local a = reg_args or {}
    if a[1] then wq(N(cc) + MC + 0x08, a[1]) end
    if a[2] then wq(N(cc) + MC + 0x10, a[2]) end
    if a[3] then wq(N(cc) + MC + 0x18, a[3]) end
    if a[4] then wq(N(cc) + MC + 0x50, a[4]) end
    if a[5] then wq(N(cc) + MC + 0x28, a[5]) end
    if a[6] then wq(N(cc) + MC + 0x30, a[6]) end

    pcall(function() return sc_sr(uint64(cc)) end)
    if not alive() then return nil end
    return rq(N(result))
end

-- ============================================================
-- [A] AllocateDirectMemory
-- ============================================================
print("")
print("[A] AllocateDirectMemory")
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))
local ok_a, rv_a = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)
if not ok_a or N(rv_a) ~= 0 then print("  FAILED"); return end
local phys_addr = rq(N(phys_out))
print("  phys=" .. fmt(phys_addr) .. " OK")

-- ============================================================
-- [B] GetDirectMemorySize via SROP (0-arg, trivial)
-- ============================================================
print("")
print("[B] GetDirectMemorySize via SROP")
local rv_b = srop_ccall(getdms_fn, {}, nil)
print("  rv=" .. fmt(rv_b))
if rv_b then
    local bh, bl = get_hi_lo(rv_b)
    if bl > 0 then print("  size=" .. string.format("0x%X", bl)) end
end
if not alive() then print("  DIED"); return end

-- ============================================================
-- [C] MapDirectMemory via SROP — with hint address
-- ============================================================
-- DEM9N101 notes say the wrapper is 7-arg. But what if the game's GOT
-- wrapper at +0x15020 has a DIFFERENT signature? The DEM9N101 doc says:
--   "MapDirectMemory (libkernel+0x15020) crashes because it's 7-arg
--    and fcall only forwards 6"
-- But maybe the crash is because the function at +0x15020 is NOT
-- MapDirectMemory, or has additional checks.
--
-- Let's try with a pre-allocated virtAddr hint instead of letting the
-- wrapper choose (maybe it expects non-NULL virtOut with a hint).
print("")
print("[C] MapDirectMemory via SROP (with hint)")

-- Allocate a page to use as hint address
local hint_page = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
if not hint_page or N(hint_page) == 0 then
    print("  hint mmap FAIL"); return
end
print("  hint_page=" .. fmt(hint_page))

-- Write hint address into virt_out
local virt_out_c = memory.alloc(8)
wq(N(virt_out_c), hint_page)  -- pre-set with hint

local rv_c = srop_ccall(map_fn, {
    uint64(N(virt_out_c)),     -- rdi = &virtOut (contains hint)
    uint64(0x4000),            -- rsi = len
    uint64(3),                 -- rdx = PROT_RW
    uint64(0),                 -- rcx = flags
    phys_addr,                 -- r8 = physAddr
    uint64(0x4000),            -- r9 = align
}, uint64(0))                  -- 7th arg: name = NULL

if rv_c then
    local va_c = rq(N(virt_out_c))
    print("  rv=" .. fmt(rv_c) .. " va=" .. fmt(va_c))
    if N(rv_c) == 0 then
        print("  *** MAP SUCCESS WITH HINT! ***")
    end
else
    print("  KILLED by MapDirectMemory")
end

if not alive() then
    print("")
    print("[D] Skipped (dead)")
    print("[E] Skipped (dead)")
    -- Try direct syscall approach in a separate section
    print("")
    print("MapDirectMemory KILLS the process.")
    print("Next: try the RAW SYSCALL that MapDirectMemory wraps.")
    print("528b section C already tried mmap_dmem(628) — all returned -1.")
    print("But 628 might have different args than MapDirectMemory.")
    print("Need to find which syscall MapDirectMemory uses internally.")
    print("=== 528h INCOMPLETE (process dead) ===")
    return
end

-- ============================================================
-- [D] Try different offsets near 0x15020 (maybe wrong export)
-- ============================================================
print("")
print("[D] Nearby offsets (±0x10)")
for delta = -0x20, 0x20, 0x10 do
    if not alive() then break end
    if delta ~= 0 then
        local test_fn = lk_text + uint64(0x15020 + delta)
        local virt_d = memory.alloc(8)
        wq(N(virt_d), uint64(0))
        local rv_d = srop_ccall(test_fn, {
            uint64(N(virt_d)), uint64(0x4000), uint64(3),
            uint64(0), phys_addr, uint64(0x4000),
        }, uint64(0))
        if rv_d then
            print(string.format("  +0x%X: rv=%s", 0x15020 + delta, fmt(rv_d)))
        else
            print(string.format("  +0x%X: KILLED", 0x15020 + delta))
            break
        end
    end
end

if not alive() then print("  DIED in offset scan"); return end

-- ============================================================
-- [E] Raw syscall via SROP — try the syscall MapDM probably uses
-- ============================================================
-- DEM9N101 says MapDirectMemory is the wrapper for the kernel call
-- that maps physical dmem to virtual addresses. On FreeBSD/PS5 this
-- is likely a Sony-specific syscall. Candidates from the sysent:
-- 547: sceKernelMapDirectMemory (name from 13.60 CSV)
-- 548: sceKernelMapDirectMemory2
-- 628: mmap_dmem (already tested in 528c/330a, all return -1)
--
-- srop_raw lets us call with all 7+ args via registers
print("")
print("[E] Raw syscall 547 (MapDirectMemory kernel)")
-- Signature guess: addr_out, len, prot, flags, physAddr, align
-- or: addr, len, prot, flags, fd, offset (like mmap)
local virt_e = memory.alloc(8)
wq(N(virt_e), uint64(0))

-- Use main-thread SROP for raw syscall (r10 for arg4 in syscall ABI)
local ctx_e = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx_e)) end)
local rip_val = rq(N(ctx_e) + MC + 0xA0)
local rh, rl = get_hi_lo(rip_val)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop_raw(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx_e)) end)
    wq(N(ctx_e) + MC + 0xA0, sc_addr)
    wq(N(ctx_e) + MC + 0x38, uint64(num))
    if a1 then wq(N(ctx_e) + MC + 0x08, a1) end
    if a2 then wq(N(ctx_e) + MC + 0x10, a2) end
    if a3 then wq(N(ctx_e) + MC + 0x18, a3) end
    if a4 then wq(N(ctx_e) + MC + 0x20, a4) end
    if a5 then wq(N(ctx_e) + MC + 0x28, a5) end
    if a6 then wq(N(ctx_e) + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx_e)) end)
    if ok then return rv end
    return nil
end

-- Try syscall 547 with various arg layouts
local shapes_547 = {
    -- shape 1: like the wrapper signature
    {uint64(N(virt_e)), uint64(0x4000), uint64(3), uint64(0), phys_addr, uint64(0x4000)},
    -- shape 2: addr=0, len, prot, flags=1
    {uint64(0), uint64(0x4000), uint64(3), uint64(1), phys_addr, uint64(0x4000)},
    -- shape 3: with dmem fd descriptor
}

-- Open dmem0 for shape 3
local devpath = memory.alloc(0x20)
local dname = "/dev/dmem0"
for i = 1, #dname do wd(N(devpath) + i - 1, string.byte(dname, i)) end
wd(N(devpath) + #dname, 0)
local ok_o, dmem_fd = pcall(function()
    return native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0))
end)
local fd_val = ok_o and N(dmem_fd) or -1
print("  dmem0 fd=" .. fd_val)

for si, shape in ipairs(shapes_547) do
    if not alive() then break end
    wq(N(virt_e), uint64(0))
    local rv547 = srop_raw(547, shape[1], shape[2], shape[3], shape[4], shape[5], shape[6])
    if not alive() then
        print(string.format("  547 shape %d: KILLED", si)); break
    end
    local va_e = rq(N(virt_e))
    print(string.format("  547 shape %d: rv=%s va=%s", si,
        rv547 and fmt(rv547) or "nil", fmt(va_e)))
    if rv547 and N(rv547) ~= 0 then
        local rvh, rvl = get_hi_lo(rv547)
        if rvh < 0 then rvh = rvh + 0x100000000 end
        if rvh ~= 0xFFFFFFFF and (rvh ~= 0 or rvl > 0x1000) then
            print("  *** 547 RETURNED A MAPPED ADDRESS! ***")
        end
    end
end

-- Try 548 (MapDirectMemory2)
if alive() then
    print("")
    print("[E2] Raw syscall 548")
    for si, shape in ipairs(shapes_547) do
        if not alive() then break end
        wq(N(virt_e), uint64(0))
        local rv548 = srop_raw(548, shape[1], shape[2], shape[3], shape[4], shape[5], shape[6])
        if not alive() then
            print(string.format("  548 shape %d: KILLED", si)); break
        end
        print(string.format("  548 shape %d: rv=%s", si, rv548 and fmt(rv548) or "nil"))
    end
end

-- Try 628 again with SROP (full register control)
if alive() then
    print("")
    print("[E3] Raw syscall 628 (mmap_dmem)")
    local shapes_628 = {
        {uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd_val >= 0 and fd_val or 0xFFFFFFFF), phys_addr},
        {uint64(0), uint64(0x4000), uint64(3), uint64(0x40), uint64(fd_val >= 0 and fd_val or 0xFFFFFFFF), phys_addr},
        {uint64(0), uint64(0x4000), uint64(3), uint64(0x41), uint64(0xFFFFFFFF), phys_addr},
    }
    for si, shape in ipairs(shapes_628) do
        if not alive() then break end
        local rv628 = srop_raw(628, shape[1], shape[2], shape[3], shape[4], shape[5], shape[6])
        if not alive() then
            print(string.format("  628 shape %d: KILLED", si)); break
        end
        print(string.format("  628 shape %d: rv=%s", si, rv628 and fmt(rv628) or "nil"))
        if rv628 then
            local rvh628 = get_hi_lo(rv628)
            if rvh628 < 0 then rvh628 = rvh628 + 0x100000000 end
            if rvh628 ~= 0xFFFFFFFF and N(rv628) > 0x1000 then
                print("  *** MAPPED! ***")
            end
        end
    end
end

if fd_val >= 0 then
    pcall(function() native.fcall_with_rax(stub, 6, uint64(fd_val)) end)
end

print("")
print("alive=" .. tostring(alive()))
print("=== 528h COMPLETE ===")
