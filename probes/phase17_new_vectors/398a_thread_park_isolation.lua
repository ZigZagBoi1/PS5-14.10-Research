-- CRASH_CLASS: MODERATE
-- PROBE 398a: does a created thread that parks kill the process, or is it thr_kill
--
-- 397a created one child at a `jmp $` park and printed thr_create rv=0 / tid, then the
-- loader stopped answering: the main Lua thread never reached its marker, so the death
-- is between the [E] print and the marker. Two candidates remain - the child executing
-- the park, and thr_kill(tid, 0) on a parked thread.
--
-- This probe prints a marker after each of those separately:
--   [E] thr_create -> rv, tid
--   [F] marker, immediately after creation (no loop)
--   [G] thr_kill(tid, 0) -> rv
--   [H] marker
-- Whichever marker is missing names the step.

print("=== PROBE 398a: PARK ISOLATION ===")

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
print(string.format("[A] base=0x%X", base))
if base <= 0 then print("=== 398a DONE ===") return end

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
print(string.format("[B] park=0x%X", park))
if park <= 0 then print("=== 398a DONE ===") return end

local sc_mmap = make_syscall(477)
local stack = 0
pcall(function() stack = sgn(sc_mmap(uint64(0), uint64(0x8000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))) end)
print(string.format("[C] stack=0x%X", stack))
if stack <= 0 then print("=== 398a DONE ===") return end

local ctx = memory.alloc(0x500)
do
    local i = 0
    while i < 0x500 do
        pcall(function() memory.write_dword(ctx + i, 0) end)
        i = i + 4
    end
end
memory.write_qword(ctx + 0x108, u64(0, 0x480))
memory.write_qword(ctx + 0x110, u64(0, 0x10000))
memory.write_qword(ctx + 0x0c0, u64(0, 0x43))
memory.write_qword(ctx + 0x0e0, u64(math.floor(park / 4294967296), park % 4294967296))
-- RFLAGS: IF must be set. 397a left the field zero, so the child ran with
-- interrupts disabled and the machine stopped scheduling (loader wedged after
-- its last print). 0x202 = IF | reserved bit 1.
memory.write_qword(ctx + 0x0f0, u64(0, 0x202))
memory.write_qword(ctx + 0x0f8, u64(math.floor((stack + 0x8000) / 4294967296), (stack + 0x8000) % 4294967296))
memory.write_qword(ctx + 0x100, u64(0, 0x3b))
print("[D] context ready")

local sc_thr = make_syscall(430)
local out = memory.alloc(0x20)
memory.write_qword(out, u64(0, 0))
local trv = -999
pcall(function() trv = sgn(sc_thr(uint64(ctx), uint64(out), uint64(0))) end)
local tq = memory.read_qword(out)
local th, tl = 0, 0
if type(tq) == "table" then th = to_num(tq.h); tl = to_num(tq.l) else tl = to_num(tq) end
print(string.format("[E] thr_create rv=%d tid=0x%08X%08X", trv, th, tl))

print("[F] thread created, still here")
print(string.format("[F] tid nonzero=%s", tostring(th + tl > 0)))

local sc_kill = make_syscall(431)
local k1 = -999
pcall(function() k1 = sgn(sc_kill(u64(th, tl), uint64(0))) end)
print(string.format("[G] thr_kill(tid,0)=%d (0 = alive)", k1))

print("[H] done")
print("")
print("=== 398a DONE ===")
