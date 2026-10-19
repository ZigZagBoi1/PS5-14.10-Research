-- CRASH_CLASS: LOW
-- PROBE 79d: Test shm_open, POSIX semaphores, and message queues via make_syscall
--
-- Context: Three families of kernel objects NEVER tested via make_syscall:
--   A) shm_open(482) / shm_unlink(483) — shared memory objects
--      If shm_open works: mmap the shm, unlink it, close fd = classic UAF
--   B) ksem_open(405) / ksem_close(400) / ksem_post(401) / ksem_wait(402)
--      POSIX named semaphores — kernel-allocated sync objects
--   C) kmq_open(457) / kmq_send(460) / kmq_receive(461) / kmq_unlink(463)
--      POSIX message queues — kernel heap allocation per message
--      Large messages = controlled kernel heap spray
--
-- Each of these creates kernel objects that could be used for lifecycle attacks.

print("=== PROBE 79d: SHM + SEMAPHORE + MQUEUE ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end
local function write_str(buf, s)
    for i = 1, #s do
        pcall(function() memory.write_byte(buf + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(buf + #s, 0) end)
end

local sc_getpid = make_syscall(20)
local sc_close = make_syscall(6)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)
local sc_ftruncate = make_syscall(480)

local sc_shm_open = make_syscall(482)
local sc_shm_unlink = make_syscall(483)

local sc_ksem_init = make_syscall(404)
local sc_ksem_open = make_syscall(405)
local sc_ksem_close = make_syscall(400)
local sc_ksem_post = make_syscall(401)
local sc_ksem_wait = make_syscall(402)
local sc_ksem_trywait = make_syscall(403)
local sc_ksem_getvalue = make_syscall(406)
local sc_ksem_destroy = make_syscall(407)
local sc_ksem_unlink = make_syscall(408)

local sc_kmq_open = make_syscall(457)
local sc_kmq_unlink = make_syscall(463)

local function canary()
    local ok, pid = pcall(function() return sc_getpid():tonumber() end)
    return ok, pid
end

local alive_ok, pid = canary()
print("[0] canary pid=" .. tostring(pid) .. " ok=" .. tostring(alive_ok))

-- ==============================
-- SECTION A: shm_open / shm_unlink
-- ==============================
print("")
print("=== SECTION A: SHM_OPEN / SHM_UNLINK ===")

-- shm_open(const char *path, int flags, mode_t mode)
-- O_RDWR=2, O_CREAT=0x200, O_EXCL=0x800
local shm_names = {"/ps5test", "/probe79d", "SceShm"}
local shm_fd = -1

for _, name in ipairs(shm_names) do
    local nbuf = memory.alloc(64)
    zero(nbuf, 64)
    write_str(nbuf, name)

    -- O_RDWR | O_CREAT = 0x202, mode 0666 = 0x1B6
    local ok, rv = pcall(function()
        return sc_shm_open(uint64(nbuf), uint64(0x202), uint64(0x1B6))
    end)
    local rv_num = to_num(rv)
    print(string.format("[A] shm_open(\"%s\", O_RDWR|O_CREAT): ok=%s rv=%d", name, tostring(ok), rv_num))

    if rv_num >= 0 then
        shm_fd = rv_num
        print("[A] *** SHM_OPEN SUCCESS! fd=" .. shm_fd .. " ***")

        -- ftruncate to set size
        local ok_ft, rv_ft = pcall(function()
            return sc_ftruncate(uint64(shm_fd), uint64(0x4000))
        end)
        print("[A] ftruncate: ok=" .. tostring(ok_ft) .. " rv=" .. tostring(rv_ft))

        -- mmap the shm
        local ok_mm, maddr = pcall(function()
            return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
                uint64(1), uint64(shm_fd), uint64(0))
        end)
        print("[A] mmap: ok=" .. tostring(ok_mm) .. " addr=" .. q(maddr))

        if ok_mm and maddr then
            -- Write a marker
            local h, l = get_hi_lo(maddr)
            if not (h == 0xFFFFFFFF and l == 0xFFFFFFFF) then
                local wok = wq(maddr, uint64(string.format("0x%X", 0xDEADBEEF)))
                local rval = rq(maddr)
                print("[A] write+read shm: write_ok=" .. tostring(wok) .. " read=" .. q(rval))
            end

            -- NOW: unlink while mapped (the UAF setup)
            local nbuf2 = memory.alloc(64)
            zero(nbuf2, 64)
            write_str(nbuf2, name)
            local ok_ul, rv_ul = pcall(function()
                return sc_shm_unlink(uint64(nbuf2))
            end)
            print("[A] shm_unlink: ok=" .. tostring(ok_ul) .. " rv=" .. tostring(rv_ul))

            -- Close the fd (frees the kernel object if refcount hits 0)
            pcall(function() sc_close(uint64(shm_fd)) end)
            print("[A] fd closed")

            -- Check if mapping survives (UAF indicator!)
            local rval2 = rq(maddr)
            print("[A] post-close-unlink read: " .. q(rval2))
            if rval2 then
                local h2, l2 = get_hi_lo(rval2)
                if h2 >= 0xFFFF8000 then
                    print("[A] *** KERNEL POINTER IN FREED SHM! ***")
                end
            end
        end

        break
    end
end

local c1_ok, c1_pid = canary()
print("[A] canary ok=" .. tostring(c1_ok) .. " pid=" .. tostring(c1_pid))

-- ==============================
-- SECTION B: POSIX semaphores (ksem_*)
-- ==============================
print("")
print("=== SECTION B: POSIX SEMAPHORES ===")

-- ksem_init(semid_t *idp, unsigned int value)
local sem_id_buf = memory.alloc(8)
zero(sem_id_buf, 8)
wd(sem_id_buf, 0xDEAD)

local ok_si, rv_si = pcall(function()
    return sc_ksem_init(uint64(sem_id_buf), uint64(1))
end)
local sem_id = rd(sem_id_buf)
print(string.format("[B] ksem_init(value=1): ok=%s rv=%s id=%s",
    tostring(ok_si), tostring(rv_si), tostring(sem_id)))

if to_num(rv_si) == 0 and sem_id and sem_id ~= 0xDEAD then
    print("[B] *** KSEM_INIT SUCCESS! id=" .. sem_id .. " ***")

    -- Get value
    local val_buf = memory.alloc(8)
    zero(val_buf, 8)
    local ok_gv, rv_gv = pcall(function()
        return sc_ksem_getvalue(uint64(sem_id), uint64(val_buf))
    end)
    print("[B] ksem_getvalue: ok=" .. tostring(ok_gv) .. " rv=" .. tostring(rv_gv) .. " val=" .. tostring(rd(val_buf)))

    -- Post (increment)
    local ok_p, rv_p = pcall(function() return sc_ksem_post(uint64(sem_id)) end)
    print("[B] ksem_post: ok=" .. tostring(ok_p) .. " rv=" .. tostring(rv_p))

    -- Trywait (decrement non-blocking)
    local ok_tw, rv_tw = pcall(function() return sc_ksem_trywait(uint64(sem_id)) end)
    print("[B] ksem_trywait: ok=" .. tostring(ok_tw) .. " rv=" .. tostring(rv_tw))

    -- Destroy
    local ok_d, rv_d = pcall(function() return sc_ksem_destroy(uint64(sem_id)) end)
    print("[B] ksem_destroy: ok=" .. tostring(ok_d) .. " rv=" .. tostring(rv_d))

    -- Use-after-destroy: try to post on destroyed semaphore
    local ok_uaf, rv_uaf = pcall(function() return sc_ksem_post(uint64(sem_id)) end)
    print("[B] post-after-destroy: ok=" .. tostring(ok_uaf) .. " rv=" .. tostring(rv_uaf))
else
    -- Try named semaphore via ksem_open
    print("[B] ksem_init failed, trying ksem_open...")
    local name_buf = memory.alloc(64)
    zero(name_buf, 64)
    write_str(name_buf, "/ps5sem")

    zero(sem_id_buf, 8)
    wd(sem_id_buf, 0xDEAD)

    -- ksem_open(semid_t *idp, const char *name, int oflag, mode_t mode, unsigned int value)
    local ok_so, rv_so = pcall(function()
        return sc_ksem_open(uint64(sem_id_buf), uint64(name_buf), uint64(0x202), uint64(0x1B6), uint64(1))
    end)
    sem_id = rd(sem_id_buf)
    print(string.format("[B] ksem_open: ok=%s rv=%s id=%s", tostring(ok_so), tostring(rv_so), tostring(sem_id)))

    if to_num(rv_so) == 0 and sem_id and sem_id ~= 0xDEAD then
        print("[B] *** KSEM_OPEN SUCCESS! ***")
        -- Clean up
        pcall(function() sc_ksem_close(uint64(sem_id)) end)
        local ubuf = memory.alloc(64)
        zero(ubuf, 64)
        write_str(ubuf, "/ps5sem")
        pcall(function() sc_ksem_unlink(uint64(ubuf)) end)
    end
end

local c2_ok, c2_pid = canary()
print("[B] canary ok=" .. tostring(c2_ok) .. " pid=" .. tostring(c2_pid))

-- ==============================
-- SECTION C: POSIX message queues (kmq_*)
-- ==============================
print("")
print("=== SECTION C: POSIX MESSAGE QUEUES ===")

-- kmq_open(const char *path, int flags, mode_t mode, const struct mq_attr *attr)
-- struct mq_attr: { long mq_flags, long mq_maxmsg, long mq_msgsize, long mq_curmsgs }
local mqname = memory.alloc(64)
zero(mqname, 64)
write_str(mqname, "/ps5mq")

-- Try with NULL attr first (system defaults)
local ok_mq1, rv_mq1 = pcall(function()
    return sc_kmq_open(uint64(mqname), uint64(0x202), uint64(0x1B6), uint64(0))
end)
local mq_fd1 = to_num(rv_mq1)
print(string.format("[C] kmq_open(\"/ps5mq\", O_RDWR|O_CREAT, NULL attr): ok=%s rv=%d",
    tostring(ok_mq1), mq_fd1))

if mq_fd1 >= 0 then
    print("[C] *** KMQ_OPEN SUCCESS! fd=" .. mq_fd1 .. " ***")

    -- Send a message
    local msg = memory.alloc(64)
    zero(msg, 64)
    write_str(msg, "AAAA")

    -- kmq_timedsend(int mqdes, const char *msg_ptr, size_t msg_len, unsigned msg_prio, ...)
    local sc_kmq_send_t = make_syscall(460)
    local ok_ms, rv_ms = pcall(function()
        return sc_kmq_send_t(uint64(mq_fd1), uint64(msg), uint64(4), uint64(0), uint64(0))
    end)
    print("[C] kmq_timedsend: ok=" .. tostring(ok_ms) .. " rv=" .. tostring(rv_ms))

    -- Receive
    local rcv_buf = memory.alloc(0x100)
    zero(rcv_buf, 0x100)
    local prio_buf = memory.alloc(8)
    zero(prio_buf, 8)

    local sc_kmq_recv_t = make_syscall(461)
    local ok_mr, rv_mr = pcall(function()
        return sc_kmq_recv_t(uint64(mq_fd1), uint64(rcv_buf), uint64(0x100), uint64(prio_buf), uint64(0))
    end)
    local recv_d0 = rd(rcv_buf)
    print(string.format("[C] kmq_timedreceive: ok=%s rv=%s data=0x%08X",
        tostring(ok_mr), tostring(rv_mr), recv_d0 or 0))

    -- Close and unlink
    pcall(function() sc_close(uint64(mq_fd1)) end)
    local ulbuf = memory.alloc(64)
    zero(ulbuf, 64)
    write_str(ulbuf, "/ps5mq")
    local ok_ul, rv_ul = pcall(function() return sc_kmq_unlink(uint64(ulbuf)) end)
    print("[C] kmq_unlink: ok=" .. tostring(ok_ul) .. " rv=" .. tostring(rv_ul))
else
    -- Try with explicit attr
    local attr = memory.alloc(0x20)
    zero(attr, 0x20)
    wq(attr + 0x00, uint64(0))    -- mq_flags
    wq(attr + 0x08, uint64(10))   -- mq_maxmsg
    wq(attr + 0x10, uint64(256))  -- mq_msgsize
    wq(attr + 0x18, uint64(0))    -- mq_curmsgs

    local mqname2 = memory.alloc(64)
    zero(mqname2, 64)
    write_str(mqname2, "/ps5mq2")

    local ok_mq2, rv_mq2 = pcall(function()
        return sc_kmq_open(uint64(mqname2), uint64(0x202), uint64(0x1B6), uint64(attr))
    end)
    print(string.format("[C] kmq_open with attr: ok=%s rv=%d", tostring(ok_mq2), to_num(rv_mq2)))
end

local c3_ok, c3_pid = canary()
print("[C] canary ok=" .. tostring(c3_ok) .. " pid=" .. tostring(c3_pid))

-- ==============================
-- SECTION D: Rapid create/destroy lifecycle test
-- ==============================
print("")
print("=== SECTION D: RAPID LIFECYCLE ===")

-- Create 10 anonymous semaphores rapidly, then destroy in reverse order
local sem_ids = {}
for i = 1, 10 do
    local sbuf = memory.alloc(8)
    zero(sbuf, 8)
    wd(sbuf, 0xDEAD)
    local ok, rv = pcall(function() return sc_ksem_init(uint64(sbuf), uint64(i)) end)
    local sid = rd(sbuf)
    if to_num(rv) == 0 and sid ~= 0xDEAD then
        sem_ids[#sem_ids + 1] = sid
    end
    if i <= 3 or i == 10 then
        print(string.format("[D] ksem_init[%d] rv=%s id=%s", i, tostring(rv), tostring(sid)))
    end
end
print("[D] created " .. #sem_ids .. " semaphores")

-- Destroy in reverse (LIFO = slab allocator pattern)
for i = #sem_ids, 1, -1 do
    pcall(function() sc_ksem_destroy(uint64(sem_ids[i])) end)
end
print("[D] destroyed all in reverse order")

-- Try to use the first destroyed one (UAF probe)
if #sem_ids > 0 then
    local ok_uaf, rv_uaf = pcall(function() return sc_ksem_post(uint64(sem_ids[1])) end)
    print("[D] post-after-destroy[1]: ok=" .. tostring(ok_uaf) .. " rv=" .. tostring(rv_uaf))
end

local cf_ok, cf_pid = canary()
print("[D] canary ok=" .. tostring(cf_ok) .. " pid=" .. tostring(cf_pid))

print("")
print("=== PROBE 79d COMPLETE ===")
