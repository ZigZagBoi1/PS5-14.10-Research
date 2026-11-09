-- CRASH_CLASS: MODERATE
-- PROBE 506a: poll/close race diagnostic — why did 500a/502a crash?
--
-- 500a and 502a both died at the first race iteration.
-- This probe does a careful step-by-step diagnostic:
-- 1) Can we poll() a socket at all? (baseline)
-- 2) Can we close() while NOT polling? (no race)
-- 3) Does the child thread work? (thread sanity check)
-- 4) Single race attempt with full logging

print("=== PROBE 506a: poll/close race diagnostic ===")
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

local sc20  = make_syscall(20)   -- getpid
local sc97  = make_syscall(97)   -- socket
local sc6   = make_syscall(6)    -- close
local sc209 = make_syscall(209)  -- poll
local sc135 = make_syscall(135)  -- socketpair

local pid = to_num(sc20())
print("pid: " .. pid)

------------------------------------------------------------------ [A] baseline: can poll() work?
print("")
print("[A] Baseline poll test...")

-- create a socket
local fd = to_num(sc97(uint64(1), uint64(2), uint64(0)))  -- AF_UNIX, SOCK_DGRAM
print("  socket fd=" .. fd)

if fd < 0 then
    print("  FATAL: cannot create socket")
    return
end

-- set up pollfd struct: {int fd; short events; short revents}
local pollfd = memory.alloc(16)
safe_wd(pollfd, fd)                      -- fd at +0
safe_wd(pollfd + 4, 0x0001)             -- events=POLLIN at +4 (short), revents at +6

-- poll with timeout=0 (non-blocking)
local ok_poll, ret_poll = pcall(function()
    return sc209(uint64(to_num(pollfd)), uint64(1), uint64(0))
end)

if ok_poll then
    local rv = to_num(ret_poll)
    local revents = safe_rd(pollfd + 4)
    print(string.format("  poll(fd=%d, timeout=0) ret=%d revents=0x%04X", fd, rv, (revents or 0) % 65536))
else
    print("  poll CRASHED")
end

-- close it
local cret = to_num(sc6(uint64(fd)))
print("  close(fd=" .. fd .. ") ret=" .. cret)

------------------------------------------------------------------ [B] poll with short timeout
print("")
print("[B] Poll with 1ms timeout...")

local fd2 = to_num(sc97(uint64(1), uint64(2), uint64(0)))
print("  socket fd=" .. fd2)

safe_wd(pollfd, fd2)
safe_wd(pollfd + 4, 0x0001)

local ok_t, ret_t = pcall(function()
    return sc209(uint64(to_num(pollfd)), uint64(1), uint64(1))  -- 1ms timeout
end)

if ok_t then
    print(string.format("  poll(fd=%d, timeout=1ms) ret=%d", fd2, to_num(ret_t)))
else
    print("  poll(1ms) CRASHED")
end

sc6(uint64(fd2))

------------------------------------------------------------------ [C] close already-closed fd
print("")
print("[C] Close already-closed fd test...")

local fd3 = to_num(sc97(uint64(1), uint64(2), uint64(0)))
print("  socket fd=" .. fd3)
local c1 = to_num(sc6(uint64(fd3)))
print("  first close ret=" .. c1)
local c2 = to_num(sc6(uint64(fd3)))
print("  second close ret=" .. c2 .. " (expected -1)")

------------------------------------------------------------------ [D] socketpair + poll
print("")
print("[D] Socketpair + poll read end...")

local sv = memory.alloc(8)
safe_wd(sv, 0)
safe_wd(sv + 4, 0)
local sp_ret = to_num(sc135(uint64(1), uint64(2), uint64(0), uint64(to_num(sv))))
local sv0 = safe_rd(sv)
local sv1 = safe_rd(sv + 4)
print(string.format("  socketpair ret=%d fds=[%d, %d]", sp_ret, sv0 or -1, sv1 or -1))

if sp_ret == 0 and sv0 and sv0 > 0 then
    safe_wd(pollfd, sv0)
    safe_wd(pollfd + 4, 0x0001)

    local ok_sp, ret_sp = pcall(function()
        return sc209(uint64(to_num(pollfd)), uint64(1), uint64(0))
    end)
    if ok_sp then
        print(string.format("  poll(sv[0], timeout=0) ret=%d", to_num(ret_sp)))
    else
        print("  poll(sv[0]) CRASHED")
    end

    -- close sv[1] then poll sv[0] (should get POLLHUP)
    sc6(uint64(sv1))
    safe_wd(pollfd + 4, 0x0001)
    local ok_hup, ret_hup = pcall(function()
        return sc209(uint64(to_num(pollfd)), uint64(1), uint64(0))
    end)
    if ok_hup then
        local rev = safe_rd(pollfd + 4)
        local revents_lo = (rev or 0) % 65536
        print(string.format("  poll after close(peer) ret=%d revents=0x%04X", to_num(ret_hup), revents_lo))
    end

    sc6(uint64(sv0))
end

------------------------------------------------------------------ [E] can we use thr_new from this probe?
print("")
print("[E] Thread creation test (thr_new 455)...")

-- get eboot base for gadgets
local sc593 = make_syscall(593)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc593(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("  eboot base: " .. fmt_hex(eboot_base))

-- we need: pop_rax_ret at +0x992, syscall_ret gadget (fn_addr)
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
print("  fn_addr: " .. (fn_str or "nil"))

if not fn_str then
    print("  no fn_addr — skip thread test")
else
    -- marker page for thread result
    local marker = memory.alloc(0x1000)
    safe_wq(marker, uint64(0xAAAAAAAA))
    print("  marker at " .. fmt_hex(marker) .. " initial=" .. fmt_hex(safe_rq(marker)))

    -- mov_rdi_rax_ret gadget at eboot+0x92C67
    local mov_rdi_rax_ret = eboot_base + uint64(0x92C67)

    -- stack for child: just write marker and exit
    local STACK_SIZE = 0x200000  -- 2 MiB
    local sc477 = make_syscall(477)
    local child_stack = sc477(uint64(0), uint64(STACK_SIZE), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    print("  child stack at " .. fmt_hex(child_stack))

    -- build minimal ROP: just thr_exit(431) with status=0
    local pop_rax_ret = eboot_base + uint64(0x992)
    local fn_addr = uint64(fn_str)

    -- RSP = ((stack_base + stack_size) & ~0xF) - 8
    local rsp = (child_stack + uint64(STACK_SIZE))
    -- align to 16
    local rsp_lo = to_num(rsp) % 16
    if rsp_lo ~= 0 then
        rsp = rsp - uint64(rsp_lo)
    end
    rsp = rsp - uint64(8)

    -- chain: pop_rax(431) -> fn_addr (syscall;ret) -> done
    local pos = rsp
    safe_wq(pos, pop_rax_ret);       pos = pos + uint64(8)  -- pop rax; ret
    safe_wq(pos, uint64(431));        pos = pos + uint64(8)  -- rax = 431 (thr_exit)
    safe_wq(pos, fn_addr);            pos = pos + uint64(8)  -- syscall; ret

    -- thr_new(455) with struct thr_param
    local sc455 = make_syscall(455)
    local thr_param = memory.alloc(0x100)
    for i = 0, 0x3C, 4 do safe_wd(thr_param + i, 0) end

    safe_wq(thr_param + 0x00, pop_rax_ret)      -- start_func (RIP)
    safe_wq(thr_param + 0x08, uint64(0))         -- arg (rdi)
    safe_wq(thr_param + 0x10, child_stack)        -- stack_base
    safe_wq(thr_param + 0x18, uint64(STACK_SIZE)) -- stack_size

    local tid_buf = memory.alloc(8)
    safe_wq(tid_buf, uint64(0))
    safe_wq(thr_param + 0x30, tid_buf)            -- child_tid ptr

    local thr_ret = to_num(sc455(uint64(to_num(thr_param)), uint64(0x38)))
    local child_tid = safe_rd(tid_buf)
    print(string.format("  thr_new ret=%d child_tid=%d", thr_ret, child_tid or 0))

    -- give child a moment to exit
    local sc240 = make_syscall(240)  -- nanosleep
    local ts = memory.alloc(16)
    safe_wq(ts, uint64(0))           -- tv_sec = 0
    safe_wq(ts + 8, uint64(50000000)) -- tv_nsec = 50ms
    pcall(function() sc240(uint64(to_num(ts)), uint64(0)) end)

    print("  thread test done (child should have exited)")
end

------------------------------------------------------------------ [F] sequential close-then-poll (no race, just logic)
print("")
print("[F] Sequential close-then-poll (no threading)...")

local fd4 = to_num(sc97(uint64(1), uint64(2), uint64(0)))
print("  fd=" .. fd4)

-- close it first
sc6(uint64(fd4))
print("  closed fd " .. fd4)

-- now poll the closed fd
safe_wd(pollfd, fd4)
safe_wd(pollfd + 4, 0x0001)
local ok_closed, ret_closed = pcall(function()
    return sc209(uint64(to_num(pollfd)), uint64(1), uint64(0))
end)
if ok_closed then
    local rev = safe_rd(pollfd + 4)
    print(string.format("  poll(closed fd=%d) ret=%d revents=0x%04X",
        fd4, to_num(ret_closed), (rev or 0) % 65536))
else
    print("  poll(closed fd) CRASHED")
end

------------------------------------------------------------------ verification
print("")
print("=== VERIFICATION ===")
local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " [OK]" or " [CHANGED!]"))
print("")
print("=== PROBE 506a COMPLETE ===")
