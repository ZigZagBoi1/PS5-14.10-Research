-- CRASH_CLASS: MODERATE
-- PROBE 786a: a real (non-ignored) SIGALRM handler to break a blocking sleep
--
-- Context: 785a installed SIG_IGN for SIGALRM and nanosleep(10s) still ran to
-- completion - an ignored signal never wakes an interruptible sleep. The
-- kernel only kicks a thread out of msleep when the signal is actually
-- deliverable, so the handler must be a real userland address.
--
-- A handler whose body is a single `ret` returns straight into the kernel's
-- sigreturn trampoline that FreeBSD pushes on the signal frame, which is the
-- whole handler contract. If this interrupts the sleep, every risky probe can
-- arm a watchdog and stop costing a console reboot when it blocks.
--
-- The previous SIGALRM action is restored at the end.

print("=== PROBE 786a: REAL SIGNAL HANDLER ===")

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

local ts  = to_num(memory.alloc(0x40))
local sa  = to_num(memory.alloc(0x40))
local sao = to_num(memory.alloc(0x40))
local itv = to_num(memory.alloc(0x40))
local slp = to_num(memory.alloc(0x40))

local function clear(buf, n)
    for i = 0, n - 1 do wd(buf + i * 4, 0) end
end
local function now_ms()
    clear(ts, 16)
    make_syscall(CLOCK)(U(4), U(ts), Z)
    return rd(ts) * 1000 + math.floor(rd(ts + 8) / 1000000)
end
local function sleep_ms(ms)
    clear(slp, 16)
    wq(slp, U(math.floor(ms / 1000)))
    wq(slp + 8, U((ms % 1000) * 1000000))
    return sgn(make_syscall(NANOSLEEP)(U(slp), Z, Z))
end

-- [A] find a `ret` (0xC3) that is followed by int3 padding: a real function end
local base = 0x1A880000
local size = 0x494000
local ret_gadget = nil
local scanned = 0
for off = 0, math.min(size, 0x180000) - 8, 4 do
    local v = rd(base + off)
    local b0 = v % 256
    local b1 = math.floor(v / 256) % 256
    local b2 = math.floor(v / 65536) % 256
    local b3 = math.floor(v / 16777216) % 256
    if b0 == 0xC3 and b1 == 0xCC then ret_gadget = base + off; break end
    if b1 == 0xC3 and b2 == 0xCC then ret_gadget = base + off + 1; break end
    if b2 == 0xC3 and b3 == 0xCC then ret_gadget = base + off + 2; break end
    scanned = off
end
print(string.format("[A] ret gadget=%s scanned=0x%X", ret_gadget and string.format("%08X", ret_gadget) or "none", scanned))
if not ret_gadget then
    print("[A] no ret found; aborting")
    return
end

-- [B] install it for SIGALRM without SA_RESTART
clear(sa, 32)
wq(sa, U(ret_gadget))
wd(sa + 8, 0)
local ar = sgn(make_syscall(SIGACTION)(U(SIGALRM), U(sa), U(sao)))
print(string.format("[B] sigaction=%d old_handler=%08X old_flags=%08X", ar, rd(sao), rd(sao + 8)))

if ar == 0 then
    clear(itv, 32)
    wq(itv + 16, U(2))
    local br = sgn(make_syscall(SETITIMER)(U(0), U(itv), Z))
    print(string.format("[B1] setitimer(2s)=%d", br))
    local t0 = now_ms()
    local sr = sleep_ms(10000)
    local dt = now_ms() - t0
    print(string.format("[B2] nanosleep(10000) ret=%d elapsed=%dms", sr, dt))
    if dt < 6000 then print("[B3] INTERRUPTED") else print("[B3] not interrupted") end
    clear(itv, 32)
    sgn(make_syscall(SETITIMER)(U(0), U(itv), Z))
end

-- [C] restore the previous action
local cr = sgn(make_syscall(SIGACTION)(U(SIGALRM), U(sao), Z))
print(string.format("[C] restore=%d", cr))

local t1 = now_ms()
sleep_ms(500)
print(string.format("[D] control sleep 500ms elapsed=%dms", now_ms() - t1))
print("=== PROBE 786a DONE ===")
