-- CRASH_CLASS: HIGH (child threads park inside a kernel wait)
-- PROBE 200a: does 542 block, and is its fourth argument the result pointer
--
-- Context: 195a established that 543 is (handle, bits, mode) — only bits=1 with
-- mode 1 or 2 succeeds on a flag whose bit 1 is set — and that 542 accepts the
-- same three leading arguments when the bit is already set, returning 0 for all
-- five layouts it was given. That left two unknowns: what 542 does when the bit
-- is clear, and which of its remaining arguments is the output slot.
--
-- Sony's wait call writes the satisfied bit mask to a result pointer, so a
-- child thread blocked in 542 and woken by a set from the main thread should
-- leave that mask in a page we own. A child cannot print, so the page is the
-- entire channel:
--
--   A  control: bit already set, child waits, result page must change at once
--   B  bit clear, child waits, main sets after 30 ms, result page must change
--   C  as B but with a null timeout, to see whether the wait blocks at all
--
-- If A leaves the page untouched, the fourth argument is not the result
-- pointer and B and C can only be read through their return values, which a
-- parked thread cannot show. Every child parks on `jmp $` rather than the store
-- gadget, because RDI holds the handle and the store gadget would write there.

print("=== PROBE 200a: evf wait blocking and result pointer ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
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
print("[0] eboot=" .. q(eboot_base) .. " sw=" .. q(SW))

local jmp_self = eboot_base + 0x15481
if not (rb(jmp_self) == 0xEB and rb(jmp_self + 1) == 0xFE) then
    print("[0] jmp $ mismatch at " .. q(jmp_self) .. "; aborting")
    return
end

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
local function u64(v)
    if type(v) == "number" then return uint64(string.format("0x%08X", v)) end
    return v
end
local function put_str(addr, s)
    for i = 1, #s do
        pcall(function() memory.write_byte(addr + i - 1, u64(string.byte(s, i))) end)
    end
    pcall(function() memory.write_byte(addr + #s, u64(0)) end)
end

local OUT = page(0x38)
local TS = memory.alloc(0x10)
wq(TS, uint64(0))
wq(TS + 8, uint64(200000000))   -- 200 ms

local function create(init)
    put_str(NAME, "evf_200a")
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    local ok, rv = pcall(function()
        return make_syscall(538)(uint64(NAME), uint64(init), uint64(0))
    end)
    return ok and rv and rv:tonumber() or nil
end

local function show_result(label, tid, before, after)
    local kill_ok, kill_rv = pcall(function()
        return sc_thr_kill(uint64(tid or 0), uint64(0))
    end)
    print(string.format("    %s tid=%s out=%s->%s kill=%s", label, q(tid),
        string.format("%08X", before), string.format("%08X", after or 0),
        kill_ok and q(kill_rv) or "failed"))
end

---------------------------------------------------------------------------
-- [A] control: the bit is already set, so the wait must not block
---------------------------------------------------------------------------
print("[A] control, bit already set")
local hA = create(1)
print("    create(init=1) -> " .. tostring(hA))
if hA then
    wd(OUT, 0xDEADBEEF)
    local stack = page(0x38)
    wq(stack, jmp_self)
    local tid = spawn(uint64(542), uint64(hA), uint64(1), uint64(1), uint64(OUT), uint64(TS), stack)
    delay(2000000)
    local before = 0xDEADBEEF
    local after = rd(OUT)
    show_result("542(H,1,1,OUT,TS)", tid, before, after)
end
print("")

---------------------------------------------------------------------------
-- [B] bit clear, main sets 30 ms into a 200 ms wait
---------------------------------------------------------------------------
print("[B] bit clear, main sets during the wait")
local hB = create(0)
print("    create(init=0) -> " .. tostring(hB))
if hB then
    wd(OUT, 0xDEADBEEF)
    local stack = page(0x38)
    wq(stack, jmp_self)
    local tid = spawn(uint64(542), uint64(hB), uint64(1), uint64(1), uint64(OUT), uint64(TS), stack)
    delay(400000)
    local sok, srv = pcall(function()
        return make_syscall(544)(uint64(hB), uint64(1), uint64(0))
    end)
    print("    set(H,1) -> " .. (sok and srv:tonumber() or "pcall failed"))
    delay(2000000)
    show_result("542(H,1,1,OUT,TS)", tid, 0xDEADBEEF, rd(OUT))
end
print("")

---------------------------------------------------------------------------
-- [C] as B, but the timeout slot is null
---------------------------------------------------------------------------
print("[C] bit clear, null timeout")
local hC = create(0)
print("    create(init=0) -> " .. tostring(hC))
if hC then
    wd(OUT, 0xDEADBEEF)
    local stack = page(0x38)
    wq(stack, jmp_self)
    local tid = spawn(uint64(542), uint64(hC), uint64(1), uint64(1), uint64(OUT), uint64(0), stack)
    delay(400000)
    local sok2, srv2 = pcall(function()
        return make_syscall(544)(uint64(hC), uint64(1), uint64(0))
    end)
    print("    set(H,1) -> " .. (sok2 and srv2:tonumber() or "pcall failed"))
    delay(2000000)
    show_result("542(H,1,1,OUT,0)", tid, 0xDEADBEEF, rd(OUT))
end
print("")

local ok5, pid1 = pcall(function() return sc_getpid():tonumber() end)
print("[D] canary after the waits: ok=" .. tostring(ok5) .. " pid=" .. tostring(pid1))
print("")
print("=== PROBE 200a COMPLETE ===")
