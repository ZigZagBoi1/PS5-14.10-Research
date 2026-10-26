-- CRASH_CLASS: MODERATE
-- PROBE 397a: a thread that does nothing, to separate "thread" from "storm"
--
-- 395a died before its first print after creating threads that loop a syscall through
-- the gadget. The read ladder (396a) proves the setup path is clean on a freshly
-- booted console, so the remaining variable is the thread itself.
--
-- This creates one child whose RIP is a `jmp $` (EB FE) and which executes no syscall
-- at all, waits two seconds, checks the thread is alive with thr_kill(tid, 0), then
-- parks the main thread on the same instruction. If the console dies here, threads
-- alone are implicated; if it survives, the storm loop is what matters.

print("=== PROBE 397a: IDLE THREAD ===")

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

-- [A] eboot text base + a park gadget
local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
pcall(function() memory.write_dword(info, 0x160) end)
local rv = -999
pcall(function() rv = sgn(sc_info(uint64(0), uint64(info), uint64(0), uint64(0), uint64(0), uint64(0))) end)
local base_hi = to_num(memory.read_dword(info + 0x10C))
local base_lo = to_num(memory.read_dword(info + 0x108))
local base = base_hi * 4294967296 + base_lo
print(string.format("[A] 593 rv=%d base=0x%X", rv, base))
if base <= 0 then print("no base") print("=== 397a DONE ===") return end

local park = 0
repeat
    local ok, buf = pcall(function() return memory.read_buffer(base, 0x40000) end)
    if not ok or type(buf) ~= "string" then break end
    local i = 1
    while i < #buf - 1 do
        local a, b = buf:byte(i, i + 1)
        if a == 0xEB and b == 0xFE then park = base + i - 1; break end
        i = i + 1
    end
until true
print(string.format("[B] park gadget=0x%X", park))
if park <= 0 then print("no park") print("=== 397a DONE ===") return end

-- [C] stack from the GPU pool
local sc_mmap = make_syscall(477)
local stack = 0
pcall(function() stack = sgn(sc_mmap(uint64(0), uint64(0x8000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))) end)
print(string.format("[C] stack=0x%X", stack))
if stack <= 0 then print("no stack") print("=== 397a DONE ===") return end

-- [D] context: gates + CS/RIP/RSP/SS, GP registers zero
local ctx = memory.alloc(0x500)
do
    local i = 0
    while i < 0x500 do
        pcall(function() memory.write_dword(ctx + i, 0) end)
        i = i + 4
    end
end
memory.write_qword(ctx + 0x108, u64(0, 0x480))
memory.write_qword(ctx + 0x0d0, u64(0, 0))
memory.write_qword(ctx + 0x110, u64(0, 0x10000))
memory.write_qword(ctx + 0x0c0, u64(0, 0x43))
memory.write_qword(ctx + 0x0e0, u64(math.floor(park / 4294967296), park % 4294967296))
memory.write_qword(ctx + 0x0f8, u64(math.floor((stack + 0x8000) / 4294967296), (stack + 0x8000) % 4294967296))
memory.write_qword(ctx + 0x100, u64(0, 0x3b))
print("[D] context ready")

-- [E] create it
local sc_thr = make_syscall(430)
local out = memory.alloc(0x20)
memory.write_qword(out, u64(0, 0))
local trv = -999
pcall(function() trv = sgn(sc_thr(uint64(ctx), uint64(out), uint64(0))) end)
local tq = memory.read_qword(out)
local th = 0
local tl = 0
if type(tq) == "table" then th = to_num(tq.h); tl = to_num(tq.l) else tl = to_num(tq) end
print(string.format("[E] thr_create rv=%d tid=0x%08X%08X", trv, th, tl))
if trv ~= 0 then print("=== 397a DONE ===") return end

-- [F] give it two seconds to do nothing
local t = 0
while t < 2000000 do t = t + 1 end
local sc_kill = make_syscall(431)
local k1 = -999
pcall(function() k1 = sgn(sc_kill(u64(th, tl), uint64(0))) end)
print(string.format("[F] thr_kill(tid,0)=%d (0 = alive)", k1))

print("")
print("=== 397a DONE ===")
