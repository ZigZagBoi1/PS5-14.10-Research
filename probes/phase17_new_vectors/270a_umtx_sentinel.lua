-- CRASH_CLASS: MODERATE
-- PROBE 270a: does the op return, or does it block - told apart by a sentinel
--
-- 269a ran ops 16-22 in parked children and every word came back zero, which
-- cannot distinguish "returned 0" from "blocked before writing". The parked
-- return stub stores rax through rdi, and for 454 rdi is the word itself, so a
-- completed call leaves the return value where the word was.
--
-- That makes the sentinel the instrument: a word pre-filled with A5A5.. stays
-- A5A5.. only if the call never returned. A word that comes back 0 returned 0,
-- and any other value is that return value.
--
--   A  ops 18-21 each on a zeroed word
--   B  the same four ops each on a word filled with 0xA5A5A5A5A5A5A5A5
--
-- Eight children in total, which is the per-probe budget, and a blocked child
-- costs a thread slot rather than the probe.

print("=== PROBE 270a: umtx sentinel ===")
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



local function mm(addr)
    local ok, v = pcall(function() return memory.read_qword(addr) end)
    if ok and v ~= nil then return string.format("%08X%08X", v.h, v.l) end
    return "read failed"
end

local function fill(a, n, val)
    pcall(function() for o = 0, n - 8, 8 do memory.write_qword(a + o, val) end end)
end

print("[0] canary pid=" .. tostring(pid()))
local SW = syscall.syscall_address

local function spawn_op(op, word)
    local stack = map(0x4000)
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
    wq(ctx + C_RAX, uint64(454))
    wq(ctx + C_RDI, uint64(word))
    wq(ctx + C_RSI, uint64(op))
    wq(ctx + C_RDX, uint64(0))
    wq(ctx + C_RCX, uint64(0))
    wq(ctx + C_R8, uint64(0))
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    local tid = rq(id_buf)
    if tid ~= nil and type(tid) == "table" then return tid.l + tid.h * 4294967296 end
    return nil
end

local function spin(n)
    local x = 0
    for k = 1, n do x = x + k end
    return x
end

local A5 = 0xA5A5A5A5
local function a5()
    return uint64(string.format("0x%08X%08X", A5, A5))
end

print("")
print("[A] zeroed word")
local ops = { 18, 19, 20, 21 }
for i = 1, #ops do
    local word = map(0x1000)
    fill(word, 0x1000, uint64(0))
    spawn_op(ops[i], word)
    spin(300000)
    print(string.format("    op=%-2d word=%s  pid=%s", ops[i], mm(word), tostring(pid())))
end

print("")
print("[B] word filled with A5A5A5A5A5A5A5A5")
for i = 1, #ops do
    local word = map(0x1000)
    fill(word, 0x1000, a5())
    spawn_op(ops[i], word)
    spin(300000)
    print(string.format("    op=%-2d word=%s  pid=%s", ops[i], mm(word), tostring(pid())))
end

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 270a COMPLETE ===")
