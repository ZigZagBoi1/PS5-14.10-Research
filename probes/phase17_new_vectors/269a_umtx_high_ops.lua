-- CRASH_CLASS: MODERATE
-- PROBE 269a: which umtx ops past 15 block, and what they write
--
-- Ops 0-17 were mapped one thread each in 161a and every one that takes a mutex
-- blocked forever, because no reachable op returns a held mutex. The ops above
-- that range were never enumerated: 18-22 are the PI and CV paths, which
-- allocate kernel objects the ordinary mutex ops do not.
--
-- This runs each op in its own child, on its own word, so a blocking op costs
-- one thread instead of the probe. Each row records the word after the child
-- runs and whether the child is still alive under thr_kill.
--
-- A word that gains a value means the op ran; a word that stays zero while the
-- child is alive means it blocked; a dead child is a kill.
--
-- The return value is not captured: for 454 the first argument is the word
-- itself, and the parked return stub stores rax through rdi, so capturing the
-- value would overwrite the word it needs to observe.

print("=== PROBE 269a: umtx ops 16-22 ===")
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

local function zero_page(a, n)
    pcall(function() for o = 0, n - 8, 8 do memory.write_qword(a + o, 0) end end)
end

print("[0] canary pid=" .. tostring(pid()))
local SW = syscall.syscall_address
print("    syscall entry " .. q(SW) .. "  jmp$ " .. q(jmp_self))

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
    local ok, rv = pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    local tid = rq(id_buf)
    local t = nil
    if tid ~= nil and type(tid) == "table" then t = tid.l + tid.h * 4294967296 end
    return t, ok
end

local function alive(tid)
    if tid == nil or tid == 0 then return "no tid" end
    local ok, rv = pcall(function() return make_syscall(433)(uint64(tid), uint64(0)):tonumber() end)
    if not ok then return "call failed" end
    return tostring(rv)
end

local function spin(n)
    local x = 0
    for k = 1, n do x = x + k end
    return x
end

local ops = { 16, 17, 18, 19, 20, 21, 22 }
print("")
print("[A] one op per child, on its own word")
for i = 1, #ops do
    local op = ops[i]
    local word = map(0x1000)
    zero_page(word, 0x1000)
    local tid = spawn_op(op, word)
    spin(300000)
    print(string.format("    op=%-2d word=%s  tid=%s  alive=%s  pid=%s",
        op, mm(word), tostring(tid), alive(tid), tostring(pid())))
end

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 269a COMPLETE ===")
