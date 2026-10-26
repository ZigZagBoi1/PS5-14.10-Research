-- CRASH_CLASS: LOW
-- PROBE 783a: aio_multi_wait argument order
--
-- Context: 663(ids, n, states, 0, ptr_10000) returns -1 instantly and never
-- writes the status array, while 663(ids, n, states, 0, ptr_0) blocked forever
-- (778a). A wait that failed its own argument validation returns before the
-- per-id loop at 0x8ad705f2, which fills a local status array and copies it
-- out - so an untouched states buffer means an early return.
--
-- 663's body does `mov edx,4` before a 4-byte copyin, so exactly one uint32 is
-- read from a user pointer. This probe puts a 1.5 s timeout (1500000) in every
-- argument position that could hold it. Every request used here is COMPLETED
-- before the wait, so no case can block the loader even if a timeout of 0 means
-- infinite.

print("=== PROBE 783a: MULTI_WAIT ARG ORDER ===")

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

local sink   = to_num(memory.alloc(0x4000))
local req    = to_num(memory.alloc(0x2000))
local ids    = to_num(memory.alloc(0x400))
local states = to_num(memory.alloc(0x400))
local idout  = to_num(memory.alloc(0x40))
local fds    = to_num(memory.alloc(64))
local tmo    = to_num(memory.alloc(0x40))
wd(tmo, 1500000)          -- 1.5 s in microseconds
wd(tmo + 4, 0)

local SOCKETPAIR = 135
local AIO_WAIT, AIO_POLL, AIO_SUBMIT = 663, 664, 669
local WRITE, READ = 4, 3

local function pairsock()
    local r = sgn(make_syscall(SOCKETPAIR)(U(1), U(1), U(0), U(fds), Z, Z))
    if r ~= 0 then return nil, nil end
    return rd(fds), rd(fds + 4)
end

local function submit(slot, fd)
    wq(req + slot * 0x40 + 0x00, Z)
    wq(req + slot * 0x40 + 0x08, U(16))
    wq(req + slot * 0x40 + 0x10, U(sink + slot * 0x40))
    wq(req + slot * 0x40 + 0x18, U(sink + 0x2000 + slot * 8))
    wd(req + slot * 0x40 + 0x20, fd)
    wd(req + slot * 0x40 + 0x24, 0)
    local r = sgn(make_syscall(AIO_SUBMIT)(U(1), U(req + slot * 0x40), U(1), U(3), U(idout), Z))
    return r, rd(idout)
end

local function poll_n(n)
    wd(states, 0xDEADBEEF)
    local r = sgn(make_syscall(AIO_POLL)(U(ids), U(n), U(states), Z, Z, Z))
    local parts = {}
    for i = 0, n - 1 do parts[#parts + 1] = hx(rd(states + i * 4)) end
    return r, table.concat(parts, " ")
end

-- [A] a completed request: the peer is fed before the submit (probe 578a)
local rfd, wfd = pairsock()
print(string.format("[A] socketpair r=%s w=%s", tostring(rfd), tostring(wfd)))
if not rfd then return end
local fbuf = to_num(memory.alloc(0x100))
for i = 0, 47 do wd(fbuf + i, 0x41) end
local wsp = to_num(memory.alloc(0x100))
wd(wsp, 0x41)
wd(wsp + 4, 0)
local wz = sgn(make_syscall(WRITE)(U(wfd), U(wsp), U(48), Z, Z, Z))
local sr, id = submit(0, rfd)
wd(ids, id)
local pr, st = poll_n(1)
print(string.format("[A1] write=%d submit=%d id=%s poll=%d state=%s", wz, sr, hx(id), pr, st))

if st ~= "00000003" then
    print("[A2] request did not complete; the wait cases would be meaningless")
end

-- [B] timeout permutations, all with a completed id
local function wait_case(tag, a4, a5)
    wd(states, 0xDEADBEEF)
    local t0 = os.clock()
    local r = sgn(make_syscall(AIO_WAIT)(U(ids), U(1), U(states), a4, a5, Z))
    local dt = os.clock() - t0
    print(string.format("[%s] ret=%d state=%s cpu=%.3fs", tag, r, hx(rd(states)), dt))
end
wait_case("B1", Z, Z)
wait_case("B2", U(tmo), Z)
wait_case("B3", Z, U(tmo))
wait_case("B4", U(tmo), U(tmo))
wait_case("B5", U(1500000), Z)
wait_case("B6", Z, U(1500000))

-- [C] after all of that, the request is still pollable
local pr2, st2 = poll_n(1)
print(string.format("[C] poll=%d state=%s", pr2, st2))
print("=== PROBE 783a DONE ===")
