-- CRASH_CLASS: LOW
-- PROBE 779a: aio_multi_wait across completion
--
-- Context: 778b showed multi_wait on in-flight (state 2) requests returns -1
-- with no status writeback -- a timeout, since the reads never complete. The
-- 13.60 body calls the wait helper 0x8aa63af0 only when the boot-tunable gate
-- 0x8b4c78d0 is open and a waiter array (count*0x18) was allocated, and it
-- frees that array at 0x8ad70a87 immediately before its own cleanup loop walks
-- the same records at 0x8ad70de3.
--
-- This probe feeds the socket first, so the requests reach state 3 before the
-- wait is issued, and records exactly what a completed wait returns and what it
-- writes to the status array. No corruption is attempted.

print("=== PROBE 779a: MULTI_WAIT ACROSS COMPLETION ===")

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

local D      = to_num(memory.alloc(0x4000))
local sink   = to_num(memory.alloc(0x2000))
local req    = to_num(memory.alloc(0x1000))
local ids    = to_num(memory.alloc(0x400))
local states = to_num(memory.alloc(0x400))
local idout  = to_num(memory.alloc(0x40))
local tmo    = to_num(memory.alloc(0x40))
local feed   = to_num(memory.alloc(0x100))
for i = 0, 0x3FF do wd(D + i * 4, 0) end
for i = 0, 0x3FF do wd(req + i * 4, 0) end
for i = 0, 0x3F do memory.write_byte(feed + i, 0x41 + (i % 26)) end

local SOCKETPAIR, IOCTL = 135, 54
local AIO_DEL, AIO_WAIT, AIO_POLL, AIO_CANCEL, AIO_SUBMIT = 662, 663, 664, 666, 669
local WRITE = 4

local fds = to_num(memory.alloc(64))
local sr = sgn(make_syscall(SOCKETPAIR)(U(1), U(1), U(0), U(fds), Z, Z))
local rfd = rd(fds)
local wfd = rd(fds + 4)
print(string.format("[0] socketpair rv=%d rfd=%d wfd=%d", sr, rfd, wfd))
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
local function show(tag, r, s, n)
    local parts = {}
    for i = 0, n - 1 do parts[#parts + 1] = hx(s[i]) end
    print(string.format("[%s] ret=%d states=%s", tag, r, table.concat(parts, " ")))
end

local N = 3
for i = 0, N - 1 do
    local r, id = submit(i, rfd)
    wd(ids + i * 4, id)
    print(string.format("[A%d] submit ret=%d id=%s", i, r, hx(id)))
end
local pr, ps = poll_n(N)
show("A", pr, ps, N)

-- feed the socket so the reads can complete
local wr = sgn(make_syscall(WRITE)(U(wfd), U(feed), U(48), Z, Z, Z))
print(string.format("[B] write ret=%d", wr))

local pr2, ps2 = poll_n(N)
show("B2", pr2, ps2, N)
local pr3, ps3 = poll_n(N)
show("B3", pr3, ps3, N)

-- wait on the completed ids: 10 ms
wd(tmo, 10000)
wd(tmo + 4, 0)
wd(states, 0xDEADBEEF)
local t0 = os.time()
local w1 = sgn(make_syscall(AIO_WAIT)(U(ids), U(N), U(states), Z, U(tmo), Z))
print(string.format("[C] wait completed ret=%d states=%s %s %s elapsed=%ds", w1,
    hx(rd(states)), hx(rd(states + 4)), hx(rd(states + 8)), os.time() - t0))

local pr4, ps4 = poll_n(N)
show("C2", pr4, ps4, N)

-- and a wait issued with a longer timeout for comparison
wd(tmo, 200000)
wd(states, 0xDEADBEEF)
local t1 = os.time()
local w2 = sgn(make_syscall(AIO_WAIT)(U(ids), U(N), U(states), Z, U(tmo), Z))
print(string.format("[D] wait 200ms ret=%d states=%s %s %s elapsed=%ds", w2,
    hx(rd(states)), hx(rd(states + 4)), hx(rd(states + 8)), os.time() - t1))

-- delete everything
local dr = sgn(make_syscall(AIO_DEL)(U(ids), U(N), U(states), Z, Z, Z))
print(string.format("[E] delete ret=%d status=%s %s %s", dr,
    hx(rd(states)), hx(rd(states + 4)), hx(rd(states + 8))))

-- health
wq(D + 0x00, Z); wq(D + 0x08, U(16)); wq(D + 0x10, U(sink)); wq(D + 0x18, U(sink + 0x1000))
wd(D + 0x20, rfd); wd(D + 0x24, 0)
local hc = sgn(make_syscall(AIO_SUBMIT)(U(1), U(D), U(1), U(3), U(idout), Z))
local hid = rd(idout)
wd(ids, hid)
wd(states, 0xDEADBEEF)
sgn(make_syscall(AIO_POLL)(U(ids), U(1), U(states), Z, Z, Z))
local hstate = rd(states)
sgn(make_syscall(AIO_CANCEL)(U(ids), U(1), U(states), Z, Z, Z))
local hd = sgn(make_syscall(AIO_DEL)(U(ids), U(1), U(states), Z, Z, Z))
print(string.format("[F] health create=%d id=%s state=%s delete=%d status=%s",
    hc, hx(hid), hx(hstate), hd, hx(rd(states))))
print("=== PROBE 779a DONE ===")
