-- CRASH_CLASS: MODERATE
-- PROBE 787a: the watchdog against the real wedge (aio_multi_wait, no timeout)
--
-- Context: 786b proved a real SIGALRM handler plus setitimer breaks
-- nanosleep(10s) after 2 s with EINTR. The wedge that costs console reboots is
-- aio_multi_wait with a zero timeout on a pending request - it sleeps until
-- the request completes, which never happens on an empty socket.
--
-- If the wait is interruptible, this returns EINTR after 3 s and the loader
-- survives. It also matters for the primitive: an interrupted wait may leave
-- its waiter list linked after the array is freed, which is a window we can
-- reach from userland.

print("=== PROBE 787a: WATCHDOG VS A BLOCKING WAIT ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "string" then return #v == 1 and string.byte(v) or 0 end
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
local function hx(v) return string.format("%08X", to_num(v) % 4294967296) end
local function ascii(a, n)
    local s = {}
    for i = 0, n - 1 do
        local b = to_num(memory.read_byte(a + i))
        if b == 0 then break end
        s[#s + 1] = string.char(b)
    end
    return table.concat(s)
end

local SIGACTION, SETITIMER, NANOSLEEP, CLOCK = 416, 83, 240, 232
local SOCKETPAIR = 135
local AIO_WAIT, AIO_POLL, AIO_SUBMIT = 663, 664, 669
local SIGALRM = 14

local ts   = to_num(memory.alloc(0x40))
local sa   = to_num(memory.alloc(0x40))
local sao  = to_num(memory.alloc(0x40))
local itv  = to_num(memory.alloc(0x40))
local sink = to_num(memory.alloc(0x4000))
local req  = to_num(memory.alloc(0x1000))
local ids  = to_num(memory.alloc(0x400))
local states = to_num(memory.alloc(0x400))
local idout = to_num(memory.alloc(0x40))
local fds   = to_num(memory.alloc(64))

local function clear(buf, n)
    for i = 0, n - 1 do wd(buf + i * 4, 0) end
end
local function now_ms()
    clear(ts, 16)
    make_syscall(CLOCK)(U(4), U(ts), Z)
    return rd(ts) * 1000 + math.floor(rd(ts + 8) / 1000000)
end

-- [0] watchdog setup
local STRIDE, MAX = 72, 512
local rbuf = to_num(memory.alloc(STRIDE * MAX + 0x100))
local countp = to_num(memory.alloc(16))
wq(countp, Z)
pcall(function() return make_syscall(674)(U(rbuf), U(STRIDE), U(MAX), U(countp), U(0x40000000), Z) end)
local count = rd(countp)
if count > MAX then count = MAX end
local exec_lo, exec_hi = nil, nil
for i = 0, count - 1 do
    local b = rbuf + i * STRIDE
    if (rd(b + 0x18) % 8) >= 4 then
        local lo = rd(b) + rd(b + 4) * 4294967296
        local hi = rd(b + 8) + rd(b + 12) * 4294967296
        if ascii(b + 0x20, 0x18):find("executable") and (exec_hi == nil or (hi - lo) > (exec_hi - exec_lo)) then
            exec_lo, exec_hi = lo, hi
        end
    end
end
if not exec_lo then print("[0] no executable region"); return end
local ret_gadget = nil
for off = 0, math.min(exec_hi - exec_lo - 4, 0x180000), 4 do
    local v = rd(exec_lo + off)
    if v % 256 == 0xC3 then ret_gadget = exec_lo + off; break end
    if math.floor(v / 256) % 256 == 0xC3 then ret_gadget = exec_lo + off + 1; break end
    if math.floor(v / 65536) % 256 == 0xC3 then ret_gadget = exec_lo + off + 2; break end
    if math.floor(v / 16777216) % 256 == 0xC3 then ret_gadget = exec_lo + off + 3; break end
end
if not ret_gadget then print("[0] no ret gadget"); return end
clear(sa, 32)
wq(sa, U(ret_gadget))
wd(sa + 8, 0)
local ar = sgn(make_syscall(SIGACTION)(U(SIGALRM), U(sa), U(sao)))
print(string.format("[0] ret=%s sigaction=%d", string.format("%08X", ret_gadget), ar))
if ar ~= 0 then return end

local function arm(seconds)
    clear(itv, 32)
    wq(itv + 16, U(seconds))
    return sgn(make_syscall(SETITIMER)(U(0), U(itv), Z))
end
local function disarm()
    clear(itv, 32)
    return sgn(make_syscall(SETITIMER)(U(0), U(itv), Z))
end

-- [A] one in-flight request on an empty socket
local sr0 = sgn(make_syscall(SOCKETPAIR)(U(1), U(1), U(0), U(fds), Z, Z))
local rfd = rd(fds)
wq(req + 0x00, Z)
wq(req + 0x08, U(16))
wq(req + 0x10, U(sink))
wq(req + 0x18, U(sink + 0x2000))
wd(req + 0x20, rfd)
wd(req + 0x24, 0)
local sr, id = sgn(make_syscall(AIO_SUBMIT)(U(1), U(req), U(1), U(3), U(idout), Z)), rd(idout)
wd(ids, id)
wd(states, 0xDEADBEEF)
local pr = sgn(make_syscall(AIO_POLL)(U(ids), U(1), U(states), Z, Z, Z))
print(string.format("[A] socketpair=%d submit=%d id=%s poll=%d state=%s", sr0, sr, hx(id), pr, hx(rd(states))))

-- [B] blocking wait with a 3 s watchdog
print(string.format("[B] arm(3)=%d", arm(3)))
wd(states, 0xDEADBEEF)
local t0 = now_ms()
local wr = sgn(make_syscall(AIO_WAIT)(U(ids), U(1), U(states), Z, Z, Z))
local dt = now_ms() - t0
disarm()
print(string.format("[B1] wait ret=%d elapsed=%dms state=%s", wr, dt, hx(rd(states))))
if dt >= 2500 and dt < 6000 then
    print("[B2] INTERRUPTED by the watchdog")
elseif dt >= 6000 then
    print("[B2] not interrupted")
else
    print("[B2] returned on its own")
end

-- [C] the request afterwards
wd(states, 0xDEADBEEF)
local pr2 = sgn(make_syscall(AIO_POLL)(U(ids), U(1), U(states), Z, Z, Z))
print(string.format("[C] poll=%d state=%s", pr2, hx(rd(states))))

-- [D] a timed wait now returns the same way it always did
print(string.format("[D] arm(3)=%d", arm(3)))
wd(states, 0xDEADBEEF)
local t1 = now_ms()
local wr2 = sgn(make_syscall(AIO_WAIT)(U(ids), U(1), U(states), Z, U(10000), Z))
print(string.format("[D1] wait(us=10000) ret=%d elapsed=%dms", wr2, now_ms() - t1))
disarm()

sgn(make_syscall(SIGACTION)(U(SIGALRM), U(sao), Z))
print("=== PROBE 787a DONE ===")
