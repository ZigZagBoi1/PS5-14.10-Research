-- CRASH_CLASS: MODERATE
-- PROBE 388a: BSD-native top-5 syscall exploration
--
-- Context: Sony range (532-676) exhausted. BSD range (1-530) has ~129 present
-- syscalls never called with real args. This probe tests the top 5 most
-- promising:
--   [A] kqueueex(141) — already returns fd on zeros; what's the extended API?
--   [B] ksem_init(404) / ksem family — POSIX kernel semaphores
--   [C] getcontext(421) / setcontext(422) — register state manipulation
--   [D] socketex(113) / socketclose(114) — Sony socket extensions
--   [E] ffclock_getestimate(241) — potential info leak

print("=== PROBE 388a: BSD top-5 exploration ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local SENTINEL = 0xDEADBEEF
local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sc_close = mk(6)

local function dump_buf(label, addr, len)
    local parts = {}
    for i = 0, len - 4, 4 do
        local dw = rd(N(addr) + i)
        if dw == nil then break end
        if dw < 0 then dw = dw + 0x100000000 end
        parts[#parts + 1] = string.format("%08X", dw)
        if #parts >= 32 then break end
    end
    print("  " .. label .. ": " .. table.concat(parts, " "))
end

local function check_kptr(addr, len)
    local found = {}
    for i = 0, len - 8, 8 do
        local q = rq(N(addr) + i)
        if q then
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                found[#found + 1] = string.format("+0x%X: h=0x%08X l=0x%08X", i, h, l)
            end
        end
    end
    return found
end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end

local function fill_sentinel(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, SENTINEL) end
end

-- ===================================================================
-- [A] kqueueex(141) — extended kqueue
-- ===================================================================
print("[A] kqueueex(141)")

local sc141 = mk(141)

-- A1: zero args (baseline — expected fd)
local ok, rv = pcall(function() return sc141(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
local fd141_0 = ok and N(rv) or -999
print("  zeros: ret=" .. fd141_0)

-- A2: close and reopen to see if fd is real
if fd141_0 >= 0 and fd141_0 < 0x10000 then
    pcall(function() sc_close(uint64(fd141_0)) end)
    -- reopen
    ok, rv = pcall(function() return sc141(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    local fd141_1 = ok and N(rv) or -999
    print("  reopen: ret=" .. fd141_1)
    if fd141_1 >= 0 and fd141_1 < 0x10000 then
        pcall(function() sc_close(uint64(fd141_1)) end)
    end
end

-- A3: try different arg1 values (flags? type?)
local a3_fds = {}
for _, arg1 in ipairs({1, 2, 4, 8, 0x10, 0x100, 0x1000, 0xFFFFFFFF}) do
    if not alive() then break end
    ok, rv = pcall(function() return sc141(uint64(arg1), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    local ret = ok and N(rv) or -999
    if ret ~= fd141_0 or ret < 0 then
        print(string.format("  arg1=0x%X: ret=%d", arg1, ret))
    end
    if ret >= 0 and ret < 0x10000 then
        a3_fds[#a3_fds + 1] = ret
    end
end
for _, fd in ipairs(a3_fds) do pcall(function() sc_close(uint64(fd)) end) end

-- A4: try kevent on kqueueex fd
local fd141 = nil
ok, rv = pcall(function() return sc141(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
if ok and N(rv) >= 0 and N(rv) < 0x10000 then
    fd141 = N(rv)
    local sc_kevent = mk(363)
    -- Add EVFILT_TIMER(-7) to kqueueex fd
    local changelist = memory.alloc(0x40)
    zero_buf(changelist, 0x40)
    -- struct kevent: ident(8), filter(2), flags(2), fflags(4), data(8), udata(8) = 32 bytes
    wq(N(changelist), uint64(1))                   -- ident = 1
    wd(N(changelist) + 8, 0xFFF90001)              -- filter=-7 (EVFILT_TIMER) | flags=EV_ADD(1) shifted
    -- Actually FreeBSD kevent64: ident(8), filter(i16 at +8), flags(u16 at +10), fflags(u32 at +12), data(i64 at +16), udata(u64 at +24)
    zero_buf(changelist, 0x40)
    wq(N(changelist), uint64(1))                   -- ident = 1
    wd(N(changelist) + 8, 0x0001FFF9)              -- filter=0xFFF9=-7(EVFILT_TIMER), flags=EV_ADD(1)
    wq(N(changelist) + 16, uint64(100))             -- data = 100ms

    local eventlist = memory.alloc(0x40)
    fill_sentinel(eventlist, 0x40)
    ok, rv = pcall(function()
        return sc_kevent(uint64(fd141), changelist, uint64(1), eventlist, uint64(1), uint64(0))
    end)
    local kev_ret = ok and N(rv) or -999
    print("  kevent(kqueueex_fd, EVFILT_TIMER): ret=" .. kev_ret)
    if kev_ret >= 0 then
        dump_buf("eventlist", eventlist, 32)
    end
    pcall(function() sc_close(uint64(fd141)) end)
end

if not alive() then print("DEAD after [A]"); return end
print("")

-- ===================================================================
-- [B] ksem family — POSIX kernel semaphores
-- ===================================================================
print("[B] ksem_init(404) / ksem family")

local sc404 = mk(404) -- ksem_init(semid_t *idp, unsigned int value)
local sc405 = mk(405) -- ksem_open(semid_t *idp, const char *name, int oflag, mode_t mode, unsigned int value)

-- B1: ksem_init — allocate output pointer for semid
local sem_id_buf = memory.alloc(16)
zero_buf(sem_id_buf, 16)

-- ksem_init(idp, value=1)
ok, rv = pcall(function() return sc404(sem_id_buf, uint64(1)) end)
local ksem_ret = ok and N(rv) or -999
local sem_id = rd(N(sem_id_buf))
print(string.format("  ksem_init(idp, 1): ret=%d, *idp=0x%X", ksem_ret, sem_id or 0))

if ksem_ret == 0 and sem_id and sem_id > 0 then
    print("  *** KSEM WORKS — got semid=" .. sem_id .. " ***")

    -- B2: ksem_getvalue(407)
    local sc407 = mk(407)
    local val_buf = memory.alloc(8)
    zero_buf(val_buf, 8)
    ok, rv = pcall(function() return sc407(uint64(sem_id), val_buf) end)
    local gv_ret = ok and N(rv) or -999
    local sem_val = rd(N(val_buf))
    print(string.format("  ksem_getvalue(%d): ret=%d, val=%d", sem_id, gv_ret, sem_val or -1))

    -- B3: ksem_post(402) — increment
    local sc402 = mk(402)
    ok, rv = pcall(function() return sc402(uint64(sem_id)) end)
    print("  ksem_post: ret=" .. (ok and N(rv) or -999))

    -- B4: re-read value
    zero_buf(val_buf, 8)
    ok, rv = pcall(function() return sc407(uint64(sem_id), val_buf) end)
    gv_ret = ok and N(rv) or -999
    sem_val = rd(N(val_buf))
    print(string.format("  after post: ret=%d, val=%d", gv_ret, sem_val or -1))

    -- B5: ksem_destroy(406)
    local sc406 = mk(406)
    ok, rv = pcall(function() return sc406(uint64(sem_id)) end)
    print("  ksem_destroy: ret=" .. (ok and N(rv) or -999))

    -- B6: use-after-destroy (double destroy)
    ok, rv = pcall(function() return sc406(uint64(sem_id)) end)
    print("  double destroy: ret=" .. (ok and N(rv) or -999))

    -- B7: create multiple, check for id reuse
    local ids = {}
    for i = 1, 5 do
        zero_buf(sem_id_buf, 16)
        ok, rv = pcall(function() return sc404(sem_id_buf, uint64(i)) end)
        local r = ok and N(rv) or -999
        local id = rd(N(sem_id_buf))
        ids[#ids + 1] = {ret = r, id = id or 0}
    end
    local id_strs = {}
    for _, e in ipairs(ids) do
        id_strs[#id_strs + 1] = string.format("ret=%d id=0x%X", e.ret, e.id)
    end
    print("  batch create: " .. table.concat(id_strs, ", "))
    -- cleanup
    for _, e in ipairs(ids) do
        if e.ret == 0 and e.id > 0 then
            pcall(function() mk(406)(uint64(e.id)) end)
        end
    end
else
    print("  ksem_init FAILED — trying ksem_open(405)")

    -- B8: ksem_open(idp, name, O_CREAT|O_EXCL, 0777, 1)
    local name_buf = memory.alloc(32)
    zero_buf(name_buf, 32)
    -- write "/test_sem"
    wd(N(name_buf), 0x7365742F)     -- /tes
    wd(N(name_buf) + 4, 0x65735F74) -- t_se
    wd(N(name_buf) + 8, 0x0000006D) -- m\0

    zero_buf(sem_id_buf, 16)
    -- O_CREAT=0x200, O_EXCL=0x800
    ok, rv = pcall(function() return sc405(sem_id_buf, name_buf, uint64(0xA00), uint64(0x1FF), uint64(1)) end)
    local open_ret = ok and N(rv) or -999
    local open_id = rd(N(sem_id_buf))
    print(string.format("  ksem_open('/test_sem', O_CREAT|O_EXCL): ret=%d, *idp=0x%X", open_ret, open_id or 0))
end

if not alive() then print("DEAD after [B]"); return end
print("")

-- ===================================================================
-- [C] getcontext(421) / setcontext(422) / swapcontext(423)
-- ===================================================================
print("[C] getcontext(421) / setcontext(422)")

local sc421 = mk(421) -- getcontext(ucontext_t *)
local sc422 = mk(422) -- setcontext(const ucontext_t *)

-- C1: getcontext — needs a ucontext_t buffer (0x500 should be enough based on thr_create)
local uctx = memory.alloc(0x500)
fill_sentinel(uctx, 0x500)

ok, rv = pcall(function() return sc421(uctx) end)
local gc_ret = ok and N(rv) or -999
print("  getcontext: ret=" .. gc_ret)

if gc_ret == 0 then
    -- C2: dump the context to see what's there
    dump_buf("uctx[0x00-0x3F]", uctx, 0x40)
    dump_buf("uctx[0x40-0x7F]", uint64(N(uctx) + 0x40), 0x40)
    dump_buf("uctx[0x80-0xBF]", uint64(N(uctx) + 0x80), 0x40)
    dump_buf("uctx[0xC0-0xFF]", uint64(N(uctx) + 0xC0), 0x40)
    dump_buf("uctx[0x100-0x13F]", uint64(N(uctx) + 0x100), 0x40)

    -- C3: check for kernel pointers in the context
    local kptrs = check_kptr(uctx, 0x500)
    if #kptrs > 0 then
        print("  *** KERNEL POINTERS IN UCONTEXT ***")
        for _, s in ipairs(kptrs) do print("    " .. s) end
    else
        print("  zero kernel pointers in ucontext")
    end

    -- C4: read key register offsets (same layout as thr_create?)
    -- mcontext: RIP at +0xE0, CS at +0xE8, RFLAGS at +0xF0, RSP at +0xF8, SS at +0x100
    -- But ucontext has uc_sigmask and uc_stack before mcontext
    -- FreeBSD ucontext_t: uc_sigmask(16), uc_mcontext(at +0x10), ...
    -- Or: uc_flags(4), pad(4), uc_link(8), uc_sigmask(16), uc_stack(24), uc_mcontext(at +0x38)
    -- Let's check both layouts by looking for known values

    -- Look for our PID or known addresses in the context
    local modified = 0
    local max_off = 0
    for i = 0, 0x4FC, 4 do
        local dw = rd(N(uctx) + i)
        if dw and dw ~= 0 then
            if dw < 0 then dw = dw + 0x100000000 end
            if dw ~= SENTINEL then
                modified = modified + 1
                max_off = i
            end
        end
    end
    print(string.format("  modified dwords: %d, max offset: 0x%X", modified, max_off))

    -- C5: Try setcontext with unmodified context (should return to right after getcontext)
    -- DANGEROUS: setcontext doesn't return — it replaces execution state
    -- Instead, let's check if setcontext is even available
    -- Try with a clearly invalid context first (NULL)
    ok, rv = pcall(function() return sc422(uint64(0)) end)
    local sc_null = ok and N(rv) or -999
    print("  setcontext(NULL): ret=" .. sc_null)

    -- C6: swapcontext(423) — saves current to oucp, loads from ucp
    local sc423 = mk(423)
    local oucp = memory.alloc(0x500)
    fill_sentinel(oucp, 0x500)
    -- Pass our getcontext result as the new context — this should be a near-noop
    -- Actually this is risky because it would execute from the setcontext point
    -- Just test with NULL to see if the call is present
    ok, rv = pcall(function() return sc423(oucp, uint64(0)) end)
    local swap_ret = ok and N(rv) or -999
    print("  swapcontext(oucp, NULL): ret=" .. swap_ret)
else
    print("  getcontext not available")
end

if not alive() then print("DEAD after [C]"); return end
print("")

-- ===================================================================
-- [D] socketex(113) / socketclose(114)
-- ===================================================================
print("[D] socketex(113) / socketclose(114)")

local sc113 = mk(113) -- socketex(domain, type, protocol, ???)
local sc114 = mk(114) -- socketclose(fd, ???)

-- D1: socketex with AF_INET/SOCK_STREAM/0 (like socket(97))
ok, rv = pcall(function() return sc113(uint64(2), uint64(1), uint64(0), uint64(0), uint64(0), uint64(0)) end)
local sex_ret = ok and N(rv) or -999
print("  socketex(AF_INET, STREAM, 0, 0, 0, 0): ret=" .. sex_ret)

if sex_ret >= 0 and sex_ret < 0x10000 then
    -- D2: is the fd a real socket? Try getsockopt
    local sc118 = mk(118) -- getsockopt
    local optbuf = memory.alloc(16)
    local optlen = memory.alloc(8)
    zero_buf(optbuf, 16)
    wd(N(optlen), 4)
    ok, rv = pcall(function()
        return sc118(uint64(sex_ret), uint64(0xFFFF), uint64(0x1007), optbuf, optlen)
    end) -- SO_TYPE
    local so_type = rd(N(optbuf))
    print(string.format("  getsockopt(SO_TYPE): ret=%d, type=%d", ok and N(rv) or -999, so_type or -1))

    -- D3: socketclose vs regular close
    ok, rv = pcall(function() return sc114(uint64(sex_ret), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    print("  socketclose(fd): ret=" .. (ok and N(rv) or -999))
else
    -- D4: try with different arg4 values (maybe it's flags)
    for _, flags in ipairs({1, 2, 4, 8, 0x10, 0x100, 0x800, 0x1000}) do
        if not alive() then break end
        ok, rv = pcall(function() return sc113(uint64(2), uint64(1), uint64(0), uint64(flags), uint64(0), uint64(0)) end)
        local r = ok and N(rv) or -999
        if r ~= sex_ret then
            print(string.format("  socketex(AF_INET, STREAM, 0, 0x%X): ret=%d", flags, r))
        end
    end
    if sex_ret == -999 then
        -- try simpler: maybe it's (domain, type, protocol) like normal socket
        ok, rv = pcall(function() return sc113(uint64(2), uint64(2), uint64(0)) end)
        print("  socketex(AF_INET, DGRAM, 0): ret=" .. (ok and N(rv) or -999))
    end
end

if not alive() then print("DEAD after [D]"); return end
print("")

-- ===================================================================
-- [E] ffclock_getestimate(241) / ffclock_getcounter(243)
-- ===================================================================
print("[E] ffclock(241-243)")

local sc241 = mk(241) -- ffclock_getcounter(ffcounter *ffcount)
local sc242 = mk(242) -- ffclock_setestimate(struct ffclock_estimate *)
local sc243 = mk(243) -- ffclock_getestimate(struct ffclock_estimate *)
-- Note: numbering may differ — check both orderings

-- E1: ffclock_getcounter(241)
local ff_buf = memory.alloc(0x100)
fill_sentinel(ff_buf, 0x100)
ok, rv = pcall(function() return sc241(ff_buf) end)
local ff241_ret = ok and N(rv) or -999
print("  sys 241 (ff counter?): ret=" .. ff241_ret)
if ff241_ret == 0 then
    dump_buf("buf", ff_buf, 0x40)
    local kp = check_kptr(ff_buf, 0x100)
    if #kp > 0 then
        print("  *** KERNEL POINTERS ***")
        for _, s in ipairs(kp) do print("    " .. s) end
    end
end

-- E2: ffclock_getestimate(243)
fill_sentinel(ff_buf, 0x100)
ok, rv = pcall(function() return sc243(ff_buf) end)
local ff243_ret = ok and N(rv) or -999
print("  sys 243 (ff estimate?): ret=" .. ff243_ret)
if ff243_ret == 0 then
    dump_buf("buf[0x00]", ff_buf, 0x40)
    dump_buf("buf[0x40]", uint64(N(ff_buf) + 0x40), 0x40)
    local kp = check_kptr(ff_buf, 0x100)
    if #kp > 0 then
        print("  *** KERNEL POINTERS ***")
        for _, s in ipairs(kp) do print("    " .. s) end
    end
end

-- E3: try the other direction (maybe 241 is getestimate)
if ff241_ret ~= 0 and ff243_ret ~= 0 then
    fill_sentinel(ff_buf, 0x100)
    ok, rv = pcall(function() return sc242(ff_buf) end)
    print("  sys 242: ret=" .. (ok and N(rv) or -999))
end

if not alive() then print("DEAD after [E]"); return end
print("")

-- ===================================================================
-- [F] Bonus: fcntl(92), __cap_rights_get(515), rtprio_thread(466)
-- ===================================================================
print("[F] bonus syscalls")

-- F1: fcntl(92) — F_GETFL=3, F_GETFD=1, F_DUPFD=0
local sc92 = mk(92)
-- Use a known good fd (stdin=0 or create a socket)
local sc97 = mk(97)
ok, rv = pcall(function() return sc97(uint64(2), uint64(1), uint64(0)) end)
local test_fd = ok and N(rv) or -1
if test_fd >= 0 and test_fd < 0x10000 then
    ok, rv = pcall(function() return sc92(uint64(test_fd), uint64(3)) end)
    print("  fcntl(fd, F_GETFL): ret=" .. (ok and N(rv) or -999))
    ok, rv = pcall(function() return sc92(uint64(test_fd), uint64(1)) end)
    print("  fcntl(fd, F_GETFD): ret=" .. (ok and N(rv) or -999))
    -- Try Sony-specific commands (high values)
    for _, cmd in ipairs({0x10, 0x11, 0x12, 0x13, 0x14, 0x100, 0x200}) do
        ok, rv = pcall(function() return sc92(uint64(test_fd), uint64(cmd)) end)
        local r = ok and N(rv) or -999
        if r ~= -1 then
            print(string.format("  fcntl(fd, 0x%X): ret=%d ***", cmd, r))
        end
    end
    pcall(function() sc_close(uint64(test_fd)) end)
end

-- F2: __cap_rights_get(515)
local sc515 = mk(515)
local cap_buf = memory.alloc(0x40)
fill_sentinel(cap_buf, 0x40)
ok, rv = pcall(function() return sc97(uint64(2), uint64(1), uint64(0)) end)
test_fd = ok and N(rv) or -1
if test_fd >= 0 and test_fd < 0x10000 then
    -- __cap_rights_get(version, fd, rightsp)
    ok, rv = pcall(function() return sc515(uint64(0), uint64(test_fd), cap_buf) end)
    local cap_ret = ok and N(rv) or -999
    print("  __cap_rights_get(0, fd): ret=" .. cap_ret)
    if cap_ret == 0 then
        dump_buf("rights", cap_buf, 0x20)
    end
    -- Try version 1
    fill_sentinel(cap_buf, 0x40)
    ok, rv = pcall(function() return sc515(uint64(1), uint64(test_fd), cap_buf) end)
    cap_ret = ok and N(rv) or -999
    if cap_ret ~= -999 then
        print("  __cap_rights_get(1, fd): ret=" .. cap_ret)
        if cap_ret == 0 then dump_buf("rights", cap_buf, 0x20) end
    end
    pcall(function() sc_close(uint64(test_fd)) end)
end

-- F3: rtprio_thread(466) — get current thread priority
local sc466 = mk(466)
local rtp_buf = memory.alloc(16)
zero_buf(rtp_buf, 16)
-- rtprio_thread(RTP_LOOKUP=0, lwpid=0 (self), rtp)
ok, rv = pcall(function() return sc466(uint64(0), uint64(0), rtp_buf) end)
local rtp_ret = ok and N(rv) or -999
if rtp_ret == 0 then
    local rtp_type = rd(N(rtp_buf))
    local rtp_prio = rd(N(rtp_buf) + 4)
    print(string.format("  rtprio_thread(LOOKUP, self): ret=0, type=%d, prio=%d", rtp_type or -1, rtp_prio or -1))
end

-- F4: sigqueue(456)
local sc456 = mk(456)
ok, rv = pcall(function() return sc456(uint64(pid_val), uint64(0), uint64(0)) end)
print("  sigqueue(self, 0, 0): ret=" .. (ok and N(rv) or -999))

if not alive() then print("DEAD after [F]"); return end

-- ===================================================================
-- [G] Summary
-- ===================================================================
print("")
print("[G] SUMMARY")
print("  kqueueex(141): " .. (fd141_0 >= 0 and "ALLOCATES fd" or "dead"))
print("  ksem_init(404): " .. (ksem_ret == 0 and "WORKS" or "ret=" .. ksem_ret))
print("  getcontext(421): " .. (gc_ret == 0 and "WORKS — dumps registers" or "ret=" .. gc_ret))
print("  socketex(113): " .. (sex_ret >= 0 and "ALLOCATES fd" or "ret=" .. sex_ret))
print("  ffclock(241): " .. (ff241_ret == 0 and "returns data" or "ret=" .. ff241_ret))
print("  ffclock(243): " .. (ff243_ret == 0 and "returns data" or "ret=" .. ff243_ret))

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 388a COMPLETE ===")
