-- CRASH_CLASS: LOW
-- PROBE 241a: give the waiter a proper return path, then cancel it
--
-- Context: 239a and 240a both died at the moment a parked waiter was touched
-- (546 cancel in one, 544 set in the other), and the console stream turned to
-- binary garbage. That is not yet a kernel result. A child spawned with
-- `RIP = syscall_address` resumes inside the loader's syscall wrapper when the
-- call returns, and its stack page was zeroed, so the wrapper's `ret` pops 0
-- and the thread runs off into address zero with registers the kernel just
-- filled in. That thread can clobber the loader's own buffers - which is what
-- garbage on stdout looks like - before it faults.
--
-- Fix: put the `jmp $` gadget at the top of the child's stack, so the return
-- from the wrapper lands in an infinite loop inside the thread and nothing else
-- runs. With the child parked properly:
--
--   A  block a waiter on bit 2, confirm the page is untouched
--   B  544(H,2) - the completion that killed 240a
--   C  546(H,2) - the cancel that killed 239a
--   D  544(H,1) and 546 on a fresh flag with no waiter, as controls
--
-- Surviving all four means the earlier deaths were the probe's own child
-- running wild, not the cancel or completion path, and the 546 result has to be
-- retracted before it is written anywhere.

print("=== PROBE 241a: waiter with a parked return path ===")
print("")

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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_getpid = make_syscall(20)
local sc_mmap = make_syscall(477)
local sc_create = make_syscall(538)
local sc_delete = make_syscall(539)
local sc_set = make_syscall(544)
local sc_cancel = make_syscall(546)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)

local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100
local C_RDI, C_RSI, C_RDX, C_RCX = 0x048, 0x050, 0x058, 0x060
local C_R8, C_RAX = 0x068, 0x078

local dead = false
local function pid()
    local ok, v = pcall(function() return sc_getpid():tonumber() end)
    if ok then return v end
    dead = true
    return nil
end
print("[0] canary pid=" .. tostring(pid()))

local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
if not text_lo then
    print("[0] module query returned nothing; aborting")
    return
end
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
local jmp_self = eboot_base + 0x15481
local b0 = rq(jmp_self)
print("[0] jmp$=" .. q(jmp_self) .. " bytes=" .. q(b0))

local SW = syscall.syscall_address
local function map(n)
    return sc_mmap(uint64(0), uint64(n), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end

local function spawn_wait(h, bits, out)
    local stack = map(0x4000)
    -- The wrapper's ret lands on the jmp $ loop, so the thread parks instead of
    -- running the loader's code with registers it did not choose.
    for i = 0, 8 do wq(stack + 0x3000 + i * 8, jmp_self) end
    local ctx = map(0x1000)
    zero(ctx, 0x500)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wd(ctx + C_TYPE, 0x10000)
    wd(ctx + C_CS, 0x43)
    wq(ctx + C_RIP, SW)
    wq(ctx + C_RSP, stack + 0x3000)
    wd(ctx + C_SS, 0x3B)
    wq(ctx + C_RAX, uint64(542))
    wq(ctx + C_RDI, uint64(h))
    wq(ctx + C_RSI, uint64(bits))
    wq(ctx + C_RDX, uint64(1))
    wq(ctx + C_RCX, out)
    wq(ctx + C_R8, uint64(0))
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    local ok, rv = pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    return rq(id_buf), ok
end

local NAME = memory.alloc(0x40)
local function put_str(addr, s)
    for i = 1, #s do
        pcall(function() memory.write_byte(addr + i - 1, uint64(string.format("0x%02X", s:byte(i)))) end)
    end
    pcall(function() memory.write_byte(addr + #s, uint64(0)) end)
end
local function create(name)
    put_str(NAME, name)
    local ok, h = pcall(function() return sc_create(uint64(NAME), uint64(0), uint64(0)):tonumber() end)
    if ok then return h end
    return nil
end
local function delay(n)
    local x = 0
    for k = 1, n do x = x + k end
    return x
end
local function step(label, fn)
    local ok, r = pcall(fn)
    local rv = nil
    if ok and r ~= nil then rv = to_num(r) end
    print(string.format("    %-18s ret=%s  pid=%s", label,
        rv == nil and "killed" or tostring(rv), tostring(pid())))
    return rv
end

local H = create("evf_241a")
print("")
print("[A] waiter on bit 2, parked return path")
print("    538 -> " .. tostring(H))
if H == nil then return end
local OUT = map(0x4000)
wd(OUT, 0xDEADBEEF)
pcall(function() sc_set(uint64(H), uint64(1)) end)
local tid = spawn_wait(H, 2, OUT)
print("    tid=" .. q(tid) .. "  page=" .. q(rd(OUT)))
delay(40000)
print("    page after 40k spins=" .. q(rd(OUT)))

print("")
print("[B] complete it")
step("544(H,2)", function() return sc_set(uint64(H), uint64(2)) end)
delay(40000)
print("    page=" .. q(rd(OUT)) .. "  tid alive=" .. tostring((function()
    local ok, v = pcall(function() return sc_thr_kill(tid, uint64(0)):tonumber() end)
    if ok then return v end
    return "killed"
end)()))
step("546(H,2) after completion", function() return sc_cancel(uint64(H), uint64(2), uint64(0)) end)

print("")
print("[C] fresh flag, waiter, cancel it directly")
local H2 = create("evf_241a_b")
if H2 ~= nil then
    local OUT2 = map(0x4000)
    wd(OUT2, 0xDEADBEEF)
    local tid2 = spawn_wait(H2, 4, OUT2)
    print("    538 -> " .. tostring(H2) .. " tid=" .. q(tid2) .. " page=" .. q(rd(OUT2)))
    delay(40000)
    step("546(H2,4)", function() return sc_cancel(uint64(H2), uint64(4), uint64(0)) end)
    delay(40000)
    print("    page=" .. q(rd(OUT2)))
    step("539 delete H2", function() return sc_delete(uint64(H2)) end)
end

print("")
print("[D] controls")
local H3 = create("evf_241a_c")
if H3 ~= nil then
    step("546(H3)", function() return sc_cancel(uint64(H3), uint64(0), uint64(0)) end)
    step("546(H3,1)", function() return sc_cancel(uint64(H3), uint64(1), uint64(0)) end)
    step("539 delete H3", function() return sc_delete(uint64(H3)) end)
end
step("539 delete H", function() return sc_delete(uint64(H)) end)

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 241a COMPLETE ===")
