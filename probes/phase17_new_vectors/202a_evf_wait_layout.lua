-- CRASH_CLASS: HIGH (child threads park inside a kernel wait)
-- PROBE 202a: which argument of 542 is the timeout
--
-- Context: 200a showed the wait blocks and wakes. With the bit clear and a null
-- fifth argument, a child in 542 slept; 30 ms later the main thread set the bit
-- and the child's fourth argument, a page we own, went from DEADBEEF to 1. That
-- is the satisfied mask, which only the wait can write.
--
-- The same probe found that putting a 200 ms timespec in the fifth slot makes
-- the wait return with 0 in that page even when the bit was already set at
-- creation. Two readings fit: the fourth argument is not always the result
-- pointer, or the fifth is not the timeout and a pointer there is rejected.
--
-- This probe settles it by giving each candidate layout both a result page and
-- a timespec page, filling both with canaries, and reporting which page the
-- kernel writes to. Nothing sets the flag, so a layout that carries a working
-- timeout must return on its own; a layout that does not will leave the child
-- parked, and the canary at the end proves the process survived.

print("=== PROBE 202a: evf wait argument layout ===")
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
local C_R8, C_R9, C_RAX = 0x068, 0x070, 0x078

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
print("[0] eboot=" .. q(eboot_base))

local function page(n)
    local p = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    for off = 0, (n or 0x38), 8 do wq(p + off, uint64(0)) end
    return p
end

local function spawn(rax, rdi, rsi, rdx, rcx, r8, r9, rsp)
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
    wq(ctx + C_R9, r9)
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

local function call(num, a1, a2, a3, a4, a5, a6)
    local ok, rv = pcall(function()
        return make_syscall(num)(u64(a1 or 0), u64(a2 or 0), u64(a3 or 0),
            u64(a4 or 0), u64(a5 or 0), u64(a6 or 0))
    end)
    if not ok then return nil end
    return rv:tonumber()
end

local function create(init)
    put_str(NAME, "evf_202a")
    return call(538, NAME, init or 0, 0)
end

-- pages: RESULT for the mask, TIME for the timespec
local RESULT = page(0x38)
local TIME = page(0x38)
local function arm()
    wd(RESULT, 0xDEADBEEF)
    wq(TIME, uint64(0))
    wq(TIME + 8, uint64(120000000))   -- 120 ms
end
local function report(label, tid)
    print(string.format("    %-24s tid=%s result=%08X time=%08X", label, q(tid),
        rd(RESULT) or 0, rd(TIME) or 0))
end

-- each entry: label, then the four trailing arguments after (handle, 1, 1)
local layouts = {
    { "arg4=RES arg5=TIME",   RESULT, TIME, 0 },
    { "arg4=TIME arg5=RES",   TIME, RESULT, 0 },
    { "arg4=RES arg5=0 arg6=TIME", RESULT, 0, TIME },
    { "arg4=0 arg5=RES arg6=TIME", 0, RESULT, TIME },
    { "arg4=RES arg5=0 arg6=0", RESULT, 0, 0 },
}

print("[A] bit clear, no set, 120 ms timespec in each candidate slot")
for _, L in ipairs(layouts) do
    local h = create(0)
    if h == nil then
        print("    create failed; stopping")
        break
    end
    arm()
    local stack = page(0x38)
    wq(stack, jmp_self)
    local tid = spawn(uint64(542), uint64(h), uint64(1), uint64(1), uint64(L[2]), uint64(L[3]), uint64(L[4]), stack)
    delay(1500000)
    report(L[1], tid)
    call(433, tid, 0)
    call(539, h)
end
print("")

print("[B] bit already set, same five layouts")
for _, L in ipairs(layouts) do
    local h = create(1)
    if h == nil then
        print("    create failed; stopping")
        break
    end
    arm()
    local stack = page(0x38)
    wq(stack, jmp_self)
    local tid = spawn(uint64(542), uint64(h), uint64(1), uint64(1), uint64(L[2]), uint64(L[3]), uint64(L[4]), stack)
    delay(800000)
    report(L[1], tid)
    call(433, tid, 0)
    call(539, h)
end
print("")

local ok5, pid1 = pcall(function() return sc_getpid():tonumber() end)
print("[C] canary ok=" .. tostring(ok5) .. " pid=" .. tostring(pid1) .. " first=" .. tostring(pid0))
print("")
print("=== PROBE 202a COMPLETE ===")
