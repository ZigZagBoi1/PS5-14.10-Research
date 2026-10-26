-- CRASH_CLASS: MODERATE
-- PROBE 467a: does a registered waiter stop its own request from completing
--
-- 460a showed a pending request completes when the peer writes, observed by a
-- later aio_multi_wait.  466a showed the same write changing nothing while a
-- thread was asleep in 663 on that id.  This probe puts both in one process:
-- two identical requests, a waiter on the second only, one write to each peer.
-- If the first reports state 3 and the second does not, the sleeping waiter is
-- holding the lock the completion path needs.

print("=== PROBE 467a: AIO WAIT LOCK ===")
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

local sc_mmap  = make_syscall(477)
local AIO_SUBMIT = make_syscall(669)
local AIO_WAIT   = make_syscall(663)
local THR_CREATE = make_syscall(430)
local GETPID     = make_syscall(20)

print(string.format("canary getpid=%s", fmt(sgn(GETPID(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))))))

local info = memory.alloc(0x300)
wr(info, 0x160)
local sc593 = make_syscall(593)
local rv593 = sgn(sc593(uint64(0), uint64(to_num(info)), uint64(0), uint64(0), uint64(0), uint64(0)))
local base_hi = rd(to_num(info) + 0x10C)
local base_lo = rd(to_num(info) + 0x108)
local base = u64(base_hi, base_lo)
local sa = to_num(syscall.syscall_address or 0)
print(string.format("593 rv=%s eboot=0x%X%08X syscall=0x%X", fmt(rv593), base_hi, base_lo, sa))

local text = memory.read_buffer(base, 0x60000)
local pop_rax, park = nil, nil
for i = 1, #text - 1 do
    if not pop_rax and text:byte(i) == 0x58 and text:byte(i + 1) == 0xC3 then pop_rax = base + (i - 1) end
    if not park and text:byte(i) == 0xEB and text:byte(i + 1) == 0xFE then park = base + (i - 1) end
end
print(string.format("pop_rax=0x%X park=0x%X", to_num(pop_rax), to_num(park)))
if not pop_rax or not park or sa == 0 then print("scan failed"); return end

local PAGE = 0x8000
local p = to_num(sc_mmap(uint64(0), uint64(PAGE), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
if p <= 0 or p >= 0x800000000000 then print("mmap failed"); return end
for i = 0, PAGE - 1, 8 do memory.write_qword(u64(0, p + i), uint64(0)) end
local CTX = p + 0x1000
local STACK = p + 0x2000

local function open_node(path, flags)
    local b = memory.alloc(#path + 1)
    for i = 1, #path do memory.write_byte(b + i - 1, path:byte(i)) end
    memory.write_byte(b + #path, 0)
    return sgn(make_syscall(5)(uint64(to_num(b)), uint64(flags), uint64(0), uint64(0), uint64(0), uint64(0)))
end

-- two identical pending requests on two socketpairs
local function submit_pair(tag, req, ids, data, result)
    local pair = memory.alloc(8)
    local sp = sgn(make_syscall(135)(uint64(1), uint64(1), uint64(0), uint64(to_num(pair)), uint64(0), uint64(0)))
    local rd_fd = rd(to_num(pair))
    local wr_fd = rd(to_num(pair) + 4)
    for i = 0, 0x27, 8 do wrq(req + i, 0) end
    wrq(req + 0x08, 16)
    wrq(req + 0x10, data)
    wrq(req + 0x18, result)
    wr(req + 0x20, rd_fd)
    wrq(ids, 0)
    local sub = sgn(AIO_SUBMIT(uint64(1), uint64(req), uint64(1), uint64(1), uint64(ids), uint64(0)))
    print(string.format("  %s socketpair=%s read=%d write=%d submit=%s id=0x%X",
        tag, fmt(sp), rd_fd, wr_fd, fmt(sub), rd(ids)))
    return wr_fd
end

local REQ1, IDS1, S1, T1 = p + 0x100, p + 0x180, p + 0x6100, p + 0x290
local REQ2, IDS2, S2, T2 = p + 0x200, p + 0x280, p + 0x6200, p + 0x2A0
local DATA1, DATA2 = p + 0x3000, p + 0x3200
local RES1, RES2 = p + 0x3400, p + 0x3600
print("[A] two pending requests")
local w1 = submit_pair("req1", REQ1, IDS1, DATA1, RES1)
local w2 = submit_pair("req2", REQ2, IDS2, DATA2, RES2)

print("[B] one waiter on req2")
local top = STACK + 0x4000 - 0x40
wrq(top, pop_rax)
wrq(top + 8, 431)
wrq(top + 16, u64(0, sa))
wrq(top + 24, park)
wrq(CTX + 0x108, 0x480)
wrq(CTX + 0x0d0, 0)
wrq(CTX + 0x110, 0x10000)
wrq(CTX + 0x0c0, 0x43)
wrq(CTX + 0x0f0, 0x202)
wrq(CTX + 0x0e0, u64(0, sa))
wrq(CTX + 0x0f8, top)
wrq(CTX + 0x100, 0x3b)
wrq(CTX + 0x048, IDS2)
wrq(CTX + 0x050, 1)
wrq(CTX + 0x058, S2)
wrq(CTX + 0x060, 0)
wrq(CTX + 0x068, T2)
wrq(CTX + 0x078, 663)
wr(T2, 8000)
local out = p + 0x7000
wrq(out, 0)
local crv = sgn(THR_CREATE(uint64(CTX), uint64(out), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("  thr_create rv=%s tid=0x%X", fmt(crv), rd(out)))

print("[C] write to both peers")
local msg = memory.alloc(16)
for i = 0, 15 do memory.write_byte(to_num(msg) + i, 0x42) end
print(string.format("  write req1=%s", fmt(sgn(make_syscall(4)(uint64(w1), uint64(to_num(msg)), uint64(16), uint64(0), uint64(0), uint64(0))))))
print(string.format("  write req2=%s", fmt(sgn(make_syscall(4)(uint64(w2), uint64(to_num(msg)), uint64(16), uint64(0), uint64(0), uint64(0))))))

local burn = 0
for i = 1, 3000000 do burn = burn + i end

print("[D] where each request stands")
wr(T1, 400)
local r1 = sgn(AIO_WAIT(uint64(IDS1), uint64(1), uint64(S1), uint64(0), uint64(T1), uint64(0)))
print(string.format("  req1 (no waiter): rv=%s states=0x%X data=0x%X", fmt(r1), rd(S1), rd(DATA1)))
wr(T2, 400)
local r2 = sgn(AIO_WAIT(uint64(IDS2), uint64(1), uint64(S2), uint64(0), uint64(T2), uint64(0)))
print(string.format("  req2 (waiter asleep): rv=%s states=0x%X data=0x%X", fmt(r2), rd(S2), rd(DATA2)))
print(string.format("  canary getpid=%s", fmt(sgn(GETPID(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))))))
print("")
print("=== 467a DONE ===")
