-- CRASH_CLASS: LOW
-- PROBE 785a: can a timer signal break a blocking syscall?
--
-- Context: a probe that blocks inside a kernel sleep (e.g. aio_multi_wait with
-- a zero timeout) wedges the loader's Lua thread and costs a full console
-- reboot. If SIGALRM is ignored (SIG_IGN) and SA_RESTART is NOT set, a
-- setitimer expiry should interrupt an interruptible sleep with EINTR and the
-- Lua thread should continue.
--
-- This probe proves the mechanism on nanosleep, which always returns, so no
-- state can be wedged here. If it works, every risky probe can arm the same
-- watchdog before a call that might block.

print("=== PROBE 785a: SIGNAL WATCHDOG ===")

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
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function U(a)
    a = to_num(a)
    return uint64(string.format("0x%08X%08X", math.floor(a / 4294967296), a % 4294967296))
end
local Z = uint64(0)
local function rd(a) return to_num(memory.read_dword(a)) end
local function wd(a, v) memory.write_dword(a, v) end
local function wq(a, v) memory.write_qword(a, v) end

local SIGACTION, SETITIMER, NANOSLEEP, CLOCK = 416, 83, 240, 232
local SIGALRM = 14

local ts  = to_num(memory.alloc(0x40))   -- timespec for clock_gettime
local sa  = to_num(memory.alloc(0x40))   -- struct sigaction
local sao = to_num(memory.alloc(0x40))   -- old sigaction
local itv = to_num(memory.alloc(0x40))   -- struct itimerval
local slp = to_num(memory.alloc(0x40))   -- timespec for nanosleep

local function clear(buf, n)
    for i = 0, n - 1 do wd(buf + i * 4, 0) end
end
local function now_ms()
    clear(ts, 16)
    make_syscall(CLOCK)(U(4), U(ts), Z)
    local sec = rd(ts)
    local nsec = rd(ts + 8)
    return sec * 1000 + math.floor(nsec / 1000000)
end
local function sleep_ms(ms)
    clear(slp, 16)
    wq(slp, U(math.floor(ms / 1000)))
    wq(slp + 8, U((ms % 1000) * 1000000))
    return sgn(make_syscall(NANOSLEEP)(U(slp), Z, Z))
end

-- [A] ignore SIGALRM without SA_RESTART
clear(sa, 32)
wq(sa, U(1))          -- sa_handler = SIG_IGN
wd(sa + 8, 0)         -- sa_flags = 0 (no SA_RESTART)
local ar = sgn(make_syscall(SIGACTION)(U(SIGALRM), U(sa), U(sao)))
print(string.format("[A] sigaction(SIGALRM, SIG_IGN)=%d old_handler=%s flags=%s",
    ar, string.format("%08X", rd(sao)), string.format("%08X", rd(sao + 8))))

-- [B] arm a 2 s timer, then sleep 10 s
clear(itv, 32)
wq(itv + 16, U(2))    -- it_value.tv_sec = 2
wq(itv + 24, U(0))    -- it_value.tv_usec = 0
local br = sgn(make_syscall(SETITIMER)(U(0), U(itv), Z))
print(string.format("[B] setitimer(REAL, 2s)=%d", br))

if ar == 0 and br == 0 then
    local t0 = now_ms()
    local sr = sleep_ms(10000)
    local dt = now_ms() - t0
    print(string.format("[B1] nanosleep(10000ms) ret=%d elapsed=%dms", sr, dt))
    if dt < 6000 then
        print("[B2] INTERRUPTED - the watchdog works")
    else
        print("[B2] not interrupted - the sleep ran to completion")
    end
else
    print("[B] skipping the interrupt test: setup failed")
end

-- [C] control: cancel the timer, sleep 1 s, expect a full 1 s
clear(itv, 32)
sgn(make_syscall(SETITIMER)(U(0), U(itv), Z))
local t1 = now_ms()
sleep_ms(1000)
print(string.format("[C] plain sleep 1000ms elapsed=%dms", now_ms() - t1))

print("=== PROBE 785a DONE ===")
