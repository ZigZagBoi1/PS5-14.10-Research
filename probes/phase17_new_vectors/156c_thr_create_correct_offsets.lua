-- CRASH_CLASS: HIGH (creates a thread; a wrong CS still panics the console)
-- PROBE 156c: thr_create(430) with the CORRECT ucontext offsets
--
-- Why 80a/156a could not answer the question: they wrote CS/RIP/RSP/SS at
-- ctx+0x90..0xB0 and the magic at ctx+0x118. The 13.60 decode of the handler
-- (docs/THR_CREATE_430_CONTEXT.md §5, docs/THR_CREATE_PANIC_PATH_13.60.md §3)
-- puts them elsewhere, and the handler rejects the context before it ever
-- looks at CS unless the magic matches:
--
--   ctx+0x108 == 0x480                magic      (reject -> EINVAL)
--   ctx+0x0d0 (dword) <= 7            flags
--   ctx+0x110 in {0x10000, 0x10002}   type
--   ctx+0x118 in {0x20000..0x20002}   subtype (only for type 0x10002)
--   ctx+0x048..0x0B8                  fifteen GPRs
--   ctx+0x0C0 -> tf+0x0F0             CS      <- the field 58e left at 0
--   ctx+0x0E0 -> tf+0x0E8             RIP
--   ctx+0x0F8 -> tf+0x100             RSP
--   ctx+0x100 -> tf+0x108             SS
--
-- 58e section D passed exactly magic+flags+type and the console died, which is
-- the accepted-context path with CS=0. 80a/156a passed none of the three gates,
-- got rv=-1 and a TID that thr_kill(433, sig=0) then reported absent. This
-- probe passes the gates AND CS=0x43, and gives the child a `jmp $` so an
-- accepted thread cannot fault:
--
--   thr_kill(tid, 0) == 0   -> the child exists: threading works on 14.10
--   thr_kill(tid, 0) == -1  -> still rejected, and the dump says why
--   console panic/reboot    -> CS=0x43 is not enough; the panic is not (only) CS

print("=== PROBE 156c: thr_create CORRECT OFFSETS + SPIN ===")
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
local sc_thr_self = make_syscall(432)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)
local sc_thr_suspend = make_syscall(442)
local sc_nanosleep = make_syscall(240)
local sc_mmap = make_syscall(477)

-- Offsets from the 13.60 handler decode
local CTX_SIZE   = 0x500
local C_MAGIC    = 0x108      -- qword 0x480
local C_FLAGS    = 0x0D0      -- dword <= 7
local C_TYPE     = 0x110      -- qword 0x10000 / 0x10002
local C_CS       = 0x0C0      -- tf_cs source
local C_RIP      = 0x0E0      -- tf_rip source
local C_RSP      = 0x0F8      -- tf_rsp source
local C_SS       = 0x100      -- tf_ss source

local USER_CS = 0x43
local USER_SS = 0x3B

local ok0, pid0 = pcall(function() return sc_getpid():tonumber() end)
print("[0] canary pid=" .. tostring(pid0))

local tid_buf = memory.alloc(8)
zero(tid_buf, 8)
pcall(function() sc_thr_self(uint64(tid_buf)) end)
local main_tid = rq(tid_buf)
print("[0] main TID=" .. q(main_tid))

local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
if not text_lo then
    print("[0] module query returned nothing; aborting")
    return
end
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[0] eboot text base=" .. q(eboot_base))

-- jmp $ (EB FE) somewhere in eboot's RX .text
local function find_jmp_self(base, limit)
    local off = 0
    while off < limit do
        local v = rd(base + off)
        if not v then return nil, off end
        local b0 = v % 0x100
        local b1 = math.floor(v / 0x100) % 0x100
        local b2 = math.floor(v / 0x10000) % 0x100
        local b3 = math.floor(v / 0x1000000) % 0x100
        if b0 == 0xEB and b1 == 0xFE then return base + off, off end
        if b1 == 0xEB and b2 == 0xFE then return base + off + 1, off end
        if b2 == 0xEB and b3 == 0xFE then return base + off + 2, off end
        if b3 == 0xEB then
            local v2 = rd(base + off + 4)
            if v2 and (v2 % 0x100) == 0xFE then return base + off + 3, off end
        end
        off = off + 4
    end
    return nil, limit
end

local jmp_self, scanned = find_jmp_self(eboot_base, 0x100000)
if not jmp_self then
    print("[0] no EB FE in the first " .. tostring(scanned) .. " bytes; aborting")
    return
end
print("[0] jmp $ gadget=" .. q(jmp_self) .. " (scanned " .. tostring(scanned) .. " bytes)")
if rb(jmp_self) ~= 0xEB or rb(jmp_self + 1) ~= 0xFE then
    print("[0] gadget verify failed; aborting")
    return
end

-- Child stack
local stack_size = 4 * 0x4000
local ok_mm, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(stack_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local sh, sl = get_hi_lo(stack_base)
if not ok_mm or (sh == 0 and sl == 0) then
    print("[0] stack mmap failed; aborting")
    return
end
print("[0] stack=" .. q(stack_base) .. " size=" .. string.format("0x%X", stack_size))
local stack_top = stack_base + stack_size - 0x100
wq(stack_top, jmp_self)

local ctx = memory.alloc(CTX_SIZE)
zero(ctx, CTX_SIZE)
wq(ctx + C_MAGIC, uint64(0x480))
wd(ctx + C_FLAGS, 0)
wq(ctx + C_TYPE, uint64(0x10000))
wq(ctx + C_CS, uint64(USER_CS))
wq(ctx + C_RIP, jmp_self)
wq(ctx + C_RSP, stack_top)
wq(ctx + C_SS, uint64(USER_SS))

print("[1] context gates and registers:")
print("  magic  (+0x108): " .. q(rq(ctx + C_MAGIC)) .. " (need 0x480)")
print("  flags  (+0x0D0): " .. tostring(rd(ctx + C_FLAGS)) .. " (need <= 7)")
print("  type   (+0x110): " .. q(rq(ctx + C_TYPE)) .. " (need 0x10000/0x10002)")
print("  CS     (+0x0C0): " .. q(rq(ctx + C_CS)))
print("  RIP    (+0x0E0): " .. q(rq(ctx + C_RIP)))
print("  RSP    (+0x0F8): " .. q(rq(ctx + C_RSP)))
print("  SS     (+0x100): " .. q(rq(ctx + C_SS)))
print("  [rsp]         : " .. q(rq(stack_top)))

zero(tid_buf, 8)
wq(tid_buf, uint64(0xDEADDEAD))
print("[1] calling thr_create ...")
local ok_tc, rv_tc = pcall(function()
    return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
end)
local child_tid = rq(tid_buf)
print("[1] thr_create: ok=" .. tostring(ok_tc) .. " rv=" .. tostring(to_num(rv_tc)) ..
    " tid=" .. q(child_tid))
if not ok_tc then
    print("[1] thr_create raised")
    return
end

local ts = memory.alloc(16)
wq(ts, 0); wq(ts + 8, 200000000)
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

local ok_c, pid_c = pcall(function() return sc_getpid():tonumber() end)
print("[2] canary after 200ms: ok=" .. tostring(ok_c) .. " pid=" .. tostring(pid_c))

local ok_k0, rv_k0 = pcall(function() return sc_thr_kill(main_tid, uint64(0)) end)
print("[2] control thr_kill(main_tid, 0): rv=" .. tostring(to_num(rv_k0)))

local ok_k, rv_k = pcall(function() return sc_thr_kill(child_tid, uint64(0)) end)
print("[2] thr_kill(child_tid=" .. q(child_tid) .. ", 0): rv=" .. tostring(to_num(rv_k)))

if ok_k and to_num(rv_k) == 0 then
    print("[2] *** THREAD EXISTS: thr_create(430) started a user thread on 14.10 ***")
else
    print("[2] *** no such thread: the context was still rejected ***")
end

local ok_s, rv_s = pcall(function() return sc_thr_suspend(child_tid) end)
print("[3] thr_suspend(child_tid): rv=" .. tostring(to_num(rv_s)))

local ok_c2, pid_c2 = pcall(function() return sc_getpid():tonumber() end)
print("[3] final canary: ok=" .. tostring(ok_c2) .. " pid=" .. tostring(pid_c2))
print("")
print("=== PROBE 156c COMPLETE ===")
print("=== PROBE 156c COMPLETE ===")
