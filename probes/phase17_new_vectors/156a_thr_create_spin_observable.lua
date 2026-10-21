-- CRASH_CLASS: HIGH (creates a thread and lets it run)
-- PROBE 156a: thr_create(430) with CS=0x43 and a child that cannot fault
--
-- Context: 80a section 1 set CS=0x43/SS=0x3B with RIP=0 and the console did
-- NOT panic (results/phase17_new_vectors/80a_thr_create_cs43_threading_
-- 20261020_163406.txt). That is ambiguous: thr_create returns -1 for a null
-- context, a zeroed context and a rejected context alike (58e sections A-C),
-- so the survival only proves "no child faulted in kernel mode". It does not
-- prove a thread was created, because RIP=0 makes an accepted child fault
-- (or be swallowed) just as invisibly as a rejection.
--
-- This probe removes the ambiguity with two changes:
--   1. The child cannot fault: RIP = a `ret` in eboot and [RSP] = a `jmp $`
--      gadget scanned out of eboot's RX .text, so the child spins forever in
--      user mode instead of dereferencing anything.
--   2. The parent asks the kernel whether that TID exists: thr_kill(tid, 0)
--      (syscall 433, null signal) returns 0 only if the thread is real.
--
-- Outcomes:
--   tid alive (kill rv=0)                     -> THREADING WORKS under CS=0x43
--   tid dead (kill rv=-1) + canary alive      -> context rejected, no thread
--   kernel panic / reboot                     -> CS=0x43 wrong for 14.10
--
-- The spinning child is suspended at the end (thr_suspend, 442) so the
-- console does not lose a core to `jmp $` after the probe finishes.

print("=== PROBE 156a: THR_CREATE CS=0x43 SPIN OBSERVABLE ===")
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
local sc_thr_wake = make_syscall(443)
local sc_nanosleep = make_syscall(240)
local sc_mmap = make_syscall(477)

local function canary()
    local ok, pid = pcall(function() return sc_getpid():tonumber() end)
    return ok, pid
end

local CTX_SIZE = 0x500
local MC_OFFSET = 0x10
local MC_RIP = MC_OFFSET + 0x80
local MC_CS = MC_OFFSET + 0x88
local MC_RFLAGS = MC_OFFSET + 0x90
local MC_RSP = MC_OFFSET + 0x98
local MC_SS = MC_OFFSET + 0xA0
local MC_LEN = MC_OFFSET + 0x108

local USER_CS = 0x43
local USER_SS = 0x3B
local USER_RFLAGS = 0x202

local ok0, pid0 = canary()
print("[0] canary pid=" .. tostring(pid0))

local tid_buf = memory.alloc(8)
zero(tid_buf, 8)
pcall(function() sc_thr_self(uint64(tid_buf)) end)
local main_tid = rq(tid_buf)
print("[0] main TID=" .. q(main_tid))

-- eboot text base (userland module query, no kernel pointers)
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
if not text_lo then
    print("[0] module query returned nothing, cannot continue")
    return
end
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[0] eboot text base=" .. q(eboot_base))

local ret_gadget = eboot_base + 0x42
local ret_byte = rb(ret_gadget)
print("[0] ret gadget=" .. q(ret_gadget) .. " first byte=0x" ..
    string.format("%02X", to_num(ret_byte)) .. " (expect C3)")
if to_num(ret_byte) ~= 0xC3 then
    print("[0] eboot+0x42 is no longer a ret; aborting rather than building a bad chain")
    return
end

-- Find `jmp $` (EB FE) in eboot .text. Unaligned scan over 32-bit reads.
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

print("[0] scanning eboot .text for EB FE ...")
local jmp_self, scanned = find_jmp_self(eboot_base, 0x100000)
if jmp_self then
    local j0 = rb(jmp_self)
    local j1 = rb(jmp_self + 1)
    print("[0] jmp $ gadget=" .. q(jmp_self) .. " bytes=0x" ..
        string.format("%02X", to_num(j0)) .. " 0x" .. string.format("%02X", to_num(j1)) ..
        " (scanned " .. tostring(scanned) .. " bytes)")
    if to_num(j0) ~= 0xEB or to_num(j1) ~= 0xFE then
        print("[0] gadget verification failed; aborting")
        return
    end
else
    print("[0] no EB FE found in the first " .. tostring(scanned) .. " bytes; aborting")
    return
end

-- Child stack: plain RW mapping, 64 KB
local stack_size = 4 * 0x4000
local ok_mm, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(stack_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if not ok_mm then
    print("[0] stack mmap failed; aborting")
    return
end
local sh, sl = get_hi_lo(stack_base)
if sh == 0 and sl == 0 then
    print("[0] stack mmap returned 0; aborting")
    return
end
print("[0] stack=" .. q(stack_base) .. " size=" .. string.format("0x%X", stack_size))

-- 16-byte aligned top, one qword for the ret gadget to consume
local stack_top = stack_base + stack_size - 0x100
wq(stack_top, jmp_self)

local ctx = memory.alloc(CTX_SIZE)
zero(ctx, CTX_SIZE)
wq(ctx + MC_CS, uint64(USER_CS))
wq(ctx + MC_SS, uint64(USER_SS))
wq(ctx + MC_RFLAGS, uint64(USER_RFLAGS))
wq(ctx + MC_LEN, uint64(0x480))
wq(ctx + MC_RIP, ret_gadget)
wq(ctx + MC_RSP, stack_top)

print("[1] ctx dump:")
print("  MC_RIP    (+0x" .. string.format("%X", MC_RIP) .. "): " .. q(rq(ctx + MC_RIP)))
print("  MC_CS     (+0x" .. string.format("%X", MC_CS) .. "): " .. q(rq(ctx + MC_CS)))
print("  MC_RFLAGS (+0x" .. string.format("%X", MC_RFLAGS) .. "): " .. q(rq(ctx + MC_RFLAGS)))
print("  MC_RSP    (+0x" .. string.format("%X", MC_RSP) .. "): " .. q(rq(ctx + MC_RSP)))
print("  MC_SS     (+0x" .. string.format("%X", MC_SS) .. "): " .. q(rq(ctx + MC_SS)))
print("  MC_LEN    (+0x" .. string.format("%X", MC_LEN) .. "): " .. q(rq(ctx + MC_LEN)))
print("  [rsp]     = " .. q(rq(stack_top)))

zero(tid_buf, 8)
wq(tid_buf, uint64(0xDEADDEAD))
print("[1] calling thr_create ...")
local ok_tc, rv_tc = pcall(function()
    return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
end)
local child_tid = rq(tid_buf)
print("[1] thr_create: ok=" .. tostring(ok_tc) .. " rv=" .. q(rv_tc) .. " tid=" .. q(child_tid))

if not ok_tc then
    print("[1] thr_create raised; nothing to observe")
    return
end

-- Give the child time to be scheduled and reach `jmp $`
local ts = memory.alloc(16)
wq(ts, 0); wq(ts + 8, 200000000)
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

local ok_c, pid_c = canary()
print("[1] canary after 200ms: ok=" .. tostring(ok_c) .. " pid=" .. tostring(pid_c))

local tid_lo = 0
do
    local th, tl = get_hi_lo(child_tid)
    tid_lo = tl
end

-- Control: the main thread must be signalable
local ok_k0, rv_k0 = pcall(function()
    return sc_thr_kill(main_tid, uint64(0))
end)
print("[2] control thr_kill(main_tid, 0): ok=" .. tostring(ok_k0) .. " rv=" .. tostring(to_num(rv_k0)))

-- The test: does the child's TID exist?
local ok_k, rv_k = pcall(function()
    return sc_thr_kill(child_tid, uint64(0))
end)
print("[2] thr_kill(child_tid=" .. q(child_tid) .. ", 0): ok=" .. tostring(ok_k) ..
    " rv=" .. tostring(to_num(rv_k)))

if ok_k and to_num(rv_k) == 0 then
    print("[2] *** THREAD EXISTS — thr_create(430) created a live user thread ***")
    if tid_lo ~= 0 and tid_lo ~= 0xDEADDEAD then
        print("[2] *** tid " .. q(child_tid) .. " differs from main " .. q(main_tid) .. " ***")
    end
else
    print("[2] *** no such thread: the kernel rejected the context (or the TID is stale) ***")
end

-- Stop the spin so the console keeps its core
local ok_s, rv_s = pcall(function()
    return sc_thr_suspend(child_tid)
end)
print("[3] thr_suspend(child_tid): ok=" .. tostring(ok_s) .. " rv=" .. tostring(to_num(rv_s)))

local ok_c2, pid_c2 = canary()
print("[3] final canary: ok=" .. tostring(ok_c2) .. " pid=" .. tostring(pid_c2))

print("")
print("=== PROBE 156a COMPLETE ===")
print("=== PROBE 156a COMPLETE ===")
