-- CRASH_CLASS: LOW
-- PROBE 58f: kevent timeout matrix — the untested cell and its interaction
--
-- Context: two saved captures disagree about kevent(363). Probe 20's split
-- register/poll calls and probe 21's combined add+poll calls all succeed with
-- a zero timeout (31 signals, 20 user events, 2000 knotes). Probe 30c PART 6's
-- combined add+poll with a 100ms timeout returns -1. The variable that differs
-- is the timeout, but "split call with a nonzero timeout" has never been run,
-- so the 2x2 is missing a cell: if B fails, the timeout alone is the variable;
-- if B succeeds, the failure needs the combined shape plus a live timeout.
--
-- This probe fills the matrix on fresh state per cell: each cell gets its own
-- kqueue and its own pipe, with one byte already written so a working call
-- returns immediately instead of waiting out the timeout. Cell E re-polls D's
-- kqueue with a zero timeout, separating "timeout argument rejected" from
-- "kqueue left unusable".
--
--   cell  shape     timeout  prior evidence
--   A     split     zero     probe 20: rv=0 then events
--   B     split     100ms    never run
--   C     combined  zero     probe 21: works
--   D     combined  100ms    probe 30c PART 6: rv=-1
--   E     poll-only zero     recovery check on D's kqueue
--
-- Nothing here contacts a console. PREPARED — NOT RUN.

print("=== PROBE 58f: KEVENT TIMEOUT MATRIX ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
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
local function safe_ww(addr, val)
    local ok = pcall(function() memory.write_word(addr, val) end)
    return ok
end

local KEVENT_SIZE = 32
local EV_ADD = 0x0001
local EVFILT_READ = 0xFFFF   -- -1 as unsigned short

-- Returns the call's return value, or nil plus an error tag when pcall failed.
local function call_kevent(kq, change, nchanges, events, nevents, timeout)
    local ok, rv = pcall(function()
        return syscall.sc_kevent(kq, change, nchanges, events, nevents, timeout)
    end)
    if not ok then return nil, tostring(rv) end
    return to_num(rv), nil
end

local function describe_events(events, n, limit)
    local out = {}
    for i = 0, math.min(n - 1, limit - 1) do
        local off = i * KEVENT_SIZE
        local ident = 0
        local flags = 0
        local data = 0
        local ok_i, v_i = pcall(function() return memory.read_qword(events + off) end)
        if ok_i then ident = to_num(v_i) end
        local ok_f, v_f = pcall(function() return memory.read_word(events + off + 10) end)
        if ok_f then flags = to_num(v_f) end
        local ok_d, v_d = pcall(function() return memory.read_qword(events + off + 16) end)
        if ok_d then data = to_num(v_d) end
        out[#out + 1] = string.format("ev%d ident=%d flags=0x%04X data=%d",
            i, ident, flags, data)
    end
    return table.concat(out, "; ")
end

-- One pipe pair per cell: a used pipe would make cell N depend on cell N-1.
local function make_pipe()
    local fds = memory.alloc(8)
    safe_wd(fds, 0xFFFFFFFF)
    safe_wd(fds + 4, 0xFFFFFFFF)
    local ok = pcall(function() return syscall.sc_pipe2(fds, 0) end)
    local r = safe_rd(fds) or 0
    local w = safe_rd(fds + 4) or 0
    if ok and r > 0 and w > 0 then
        return { rfd = r, wfd = w, how = "pipe2" }
    end
    local sp = memory.alloc(8)
    safe_wd(sp, 0xFFFFFFFF)
    safe_wd(sp + 4, 0xFFFFFFFF)
    local sp_ok = pcall(function() return syscall.sc_socketpair(1, 1, 0, sp) end)
    local s0 = safe_rd(sp) or 0
    local s1 = safe_rd(sp + 4) or 0
    if sp_ok and s0 > 0 and s1 > 0 then
        return { rfd = s0, wfd = s1, how = "socketpair" }
    end
    return nil
end

local function make_timeout(nsec)
    local t = memory.alloc(16)
    safe_wq(t, 0)
    safe_wq(t + 8, nsec)
    return t
end

local function make_change(ident)
    local c = memory.alloc(KEVENT_SIZE)
    safe_wq(c + 0, ident)
    safe_ww(c + 8, EVFILT_READ)
    safe_ww(c + 10, EV_ADD)
    safe_wd(c + 12, 0)
    safe_wq(c + 16, 0)
    safe_wq(c + 24, 0)
    return c
end

-- Put one byte in the pipe so the event is ready before the poll.
local function prime(wfd)
    local buf = memory.alloc(8)
    safe_wq(buf, 0x41)
    local ok, rv = pcall(function() return syscall.sc_write(wfd, buf, 1) end)
    return ok and to_num(rv) or -999
end

local events = memory.alloc(8 * KEVENT_SIZE)
for off = 0, 8 * KEVENT_SIZE - 8, 8 do safe_wq(events + off, 0) end
local t_zero = make_timeout(0)
local t_100ms = make_timeout(100000000)

print("[0] shared buffers ready; timeout structs at zero and 100ms")
print("")

-- A: split, zero timeout (the known-good shape).
do
    print("[A] split, zero timeout (control)")
    local kq_ok, kq = pcall(function() return to_num(syscall.sc_kqueue()) end)
    local p = make_pipe()
    if not kq_ok or not p then
        print("  [SKIP] A: kqueue or pipe setup failed")
    else
        local ch = make_change(p.rfd)
        print(string.format("  kq=%d fd=%d(%s)", kq, p.rfd, p.how))
        print("  [BEFORE] A1 register nchanges=1 nevents=0 timeout=0")
        local r1, e1 = call_kevent(kq, ch, 1, events, 0, t_zero)
        print(string.format("  [RETURNED] A1 rv=%s err=%s",
            r1 == nil and "PCALL-FAIL" or tostring(r1), e1 or "none"))
        print(string.format("  prime write rv=%d", prime(p.wfd)))
        print("  [BEFORE] A2 poll nchanges=0 nevents=1 timeout=0")
        local r2, e2 = call_kevent(kq, ch, 0, events, 1, t_zero)
        print(string.format("  [RETURNED] A2 rv=%s err=%s",
            r2 == nil and "PCALL-FAIL" or tostring(r2), e2 or "none"))
        if r2 and r2 > 0 then print("  " .. describe_events(events, r2, 3)) end
        pcall(function() syscall.sc_close(kq) end)
        pcall(function() syscall.sc_close(p.rfd) end)
        pcall(function() syscall.sc_close(p.wfd) end)
    end
    print("")
end

-- B: split, 100ms timeout. The cell PR #17's note leaves open.
do
    print("[B] split, 100ms timeout (the untested cell)")
    local kq_ok, kq = pcall(function() return to_num(syscall.sc_kqueue()) end)
    local p = make_pipe()
    if not kq_ok or not p then
        print("  [SKIP] B: kqueue or pipe setup failed")
    else
        local ch = make_change(p.rfd)
        print(string.format("  kq=%d fd=%d(%s)", kq, p.rfd, p.how))
        print("  [BEFORE] B1 register nchanges=1 nevents=0 timeout=0")
        local r1, e1 = call_kevent(kq, ch, 1, events, 0, t_zero)
        print(string.format("  [RETURNED] B1 rv=%s err=%s",
            r1 == nil and "PCALL-FAIL" or tostring(r1), e1 or "none"))
        print(string.format("  prime write rv=%d", prime(p.wfd)))
        print("  [BEFORE] B2 poll nchanges=0 nevents=1 timeout=100ms")
        local r2, e2 = call_kevent(kq, ch, 0, events, 1, t_100ms)
        print(string.format("  [RETURNED] B2 rv=%s err=%s",
            r2 == nil and "PCALL-FAIL" or tostring(r2), e2 or "none"))
        if r2 and r2 > 0 then print("  " .. describe_events(events, r2, 3)) end
        print("  [BEFORE] B3 recovery poll nchanges=0 nevents=1 timeout=0")
        local r3, e3 = call_kevent(kq, ch, 0, events, 1, t_zero)
        print(string.format("  [RETURNED] B3 rv=%s err=%s",
            r3 == nil and "PCALL-FAIL" or tostring(r3), e3 or "none"))
        if r3 and r3 > 0 then print("  " .. describe_events(events, r3, 3)) end
        pcall(function() syscall.sc_close(kq) end)
        pcall(function() syscall.sc_close(p.rfd) end)
        pcall(function() syscall.sc_close(p.wfd) end)
    end
    print("")
end

-- C: combined add+poll, zero timeout (probe 21's working shape).
do
    print("[C] combined, zero timeout (control)")
    local kq_ok, kq = pcall(function() return to_num(syscall.sc_kqueue()) end)
    local p = make_pipe()
    if not kq_ok or not p then
        print("  [SKIP] C: kqueue or pipe setup failed")
    else
        local ch = make_change(p.rfd)
        print(string.format("  kq=%d fd=%d(%s)", kq, p.rfd, p.how))
        print(string.format("  prime write rv=%d", prime(p.wfd)))
        print("  [BEFORE] C1 add+poll nchanges=1 nevents=1 timeout=0")
        local r1, e1 = call_kevent(kq, ch, 1, events, 1, t_zero)
        print(string.format("  [RETURNED] C1 rv=%s err=%s",
            r1 == nil and "PCALL-FAIL" or tostring(r1), e1 or "none"))
        if r1 and r1 > 0 then print("  " .. describe_events(events, r1, 3)) end
        pcall(function() syscall.sc_close(kq) end)
        pcall(function() syscall.sc_close(p.rfd) end)
        pcall(function() syscall.sc_close(p.wfd) end)
    end
    print("")
end

-- D: combined add+poll, 100ms timeout (probe 30c PART 6's failing shape).
local d_kq = nil
do
    print("[D] combined, 100ms timeout (30c's failing shape)")
    local kq_ok, kq = pcall(function() return to_num(syscall.sc_kqueue()) end)
    local p = make_pipe()
    if not kq_ok or not p then
        print("  [SKIP] D: kqueue or pipe setup failed")
    else
        d_kq = kq
        local ch = make_change(p.rfd)
        print(string.format("  kq=%d fd=%d(%s)", kq, p.rfd, p.how))
        print(string.format("  prime write rv=%d", prime(p.wfd)))
        print("  [BEFORE] D1 add+poll nchanges=1 nevents=1 timeout=100ms")
        local r1, e1 = call_kevent(kq, ch, 1, events, 1, t_100ms)
        print(string.format("  [RETURNED] D1 rv=%s err=%s",
            r1 == nil and "PCALL-FAIL" or tostring(r1), e1 or "none"))
        if r1 and r1 > 0 then print("  " .. describe_events(events, r1, 3)) end
        pcall(function() syscall.sc_close(p.rfd) end)
        pcall(function() syscall.sc_close(p.wfd) end)
    end
    print("")
end

-- E: is D's kqueue still usable? Same fd, zero timeout, no changes.
do
    print("[E] recovery poll on D's kqueue, zero timeout")
    if d_kq == nil then
        print("  [SKIP] E: no kqueue from D")
    else
        print("  [BEFORE] E1 poll nchanges=0 nevents=1 timeout=0")
        local r1, e1 = call_kevent(d_kq, events, 0, events, 1, t_zero)
        print(string.format("  [RETURNED] E1 rv=%s err=%s",
            r1 == nil and "PCALL-FAIL" or tostring(r1), e1 or "none"))
        pcall(function() syscall.sc_close(d_kq) end)
    end
    print("")
end

print("=== PROBE 58f COMPLETE ===")
print("Reading: A and C are controls and must succeed on a working loader.")
print("B2 failing with B3 returning the event isolates the timeout.")
print("B2 failing with B3 also failing means the failed call damaged that kqueue.")
print("E1 rv=1 means D1's EV_ADD took effect before the timeout rejection;")
print("E1 rv=0 means no registration reached that kqueue, so D1 failed earlier.")
