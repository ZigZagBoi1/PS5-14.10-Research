-- CRASH_CLASS: HIGH (some CS values will panic)
-- PROBE 80e: CS value sweep for thr_create
--
-- Context: CS=0 gets rv=0 but panics. CS=0x43 gets rv=-1 (rejected).
-- This probe sweeps CS values to find which ones return rv=0.
-- IMPORTANT: We do NOT actually create threads with rv=0 values here.
-- We only test the return value. A separate probe will use safe values.
--
-- Strategy: Test CS values and record rv for each.
-- Also test: what if we set CS AFTER thr_create via a race? (future)
-- Also: what if mc_flags controls whether CS is checked?
--
-- Section A: Sweep CS 0x00-0xFF, record rv for each
-- Section B: Test mc_flags values with CS=0x43

print("=== PROBE 80e: CS VALUE SWEEP ===")
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
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

syscall.resolve({ sc_getpid = 20 })
print("[*] pid=" .. tostring(syscall.sc_getpid():tonumber()))

-- Eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
local eboot = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[*] eboot=" .. q(eboot))

local ret_gadget = eboot + 0x42

-- Stack (need a valid RSP)
local sc_mmap = make_syscall(477)
local s_ok, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(4 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local stack_top = stack_base + (3 * 0x4000)
zero(stack_top, 0x100)
print("[*] stack=" .. q(stack_top))

-- ============================================================
-- A: Sweep CS values — which get rv=0 vs rv=-1?
--    We use RIP=0 so any rv=0 thread will SIGSEGV (or panic if CS is bad)
--    But RIP=0 with bad CS = kernel panic. So use RIP=ret_gadget.
--    With ret_gadget + RSP pointing at zeros → thread faults at addr 0
--    after executing ret. If CS has RPL=3, this is user-mode SIGSEGV.
--    If CS has RPL=0, this is kernel panic.
--
--    SAFE APPROACH: Only test rv, never let rv=0 threads run.
--    Set RIP=0 and RSP=0 for all tests. If rv=0, the thread WILL crash.
--    We accept the risk for rv=0 values — they'll either SIGSEGV (safe)
--    or panic (crash). We test non-zero CS first (RPL=3 values).
-- ============================================================
print("")
print("=== A: CS sweep (RPL=3 values only — safest) ===")
print("Format: CS → rv")
print("")

-- RPL=3 means low 2 bits = 11 (binary) = 3
-- Standard: CS=0x43 (index=8, TI=0, RPL=3)
-- Test all RPL=3 values from 0x03 to 0xFF (step 4, since RPL=low 2 bits)
local ctx = memory.alloc(0x600)
local tid_buf = memory.alloc(8)

local rv0_values = {}

for cs = 0x03, 0xFF, 4 do  -- RPL=3 only (cs & 3 == 3)
    zero(ctx, 0x600)
    -- 58e proven fields
    wq(ctx + 0x108, uint64(0x480))
    wd(ctx + 0x0D0, 0)
    wq(ctx + 0x110, uint64(0x10000))
    -- RIP = ret gadget (safe if CS has RPL=3)
    wq(ctx + 0x90, ret_gadget)
    wq(ctx + 0xA8, stack_top)
    -- CS and SS
    wq(ctx + 0x98, uint64(cs))
    wq(ctx + 0xB0, uint64(0x3B))  -- SS always 0x3B
    wq(ctx + 0xA0, uint64(0x202)) -- RFLAGS

    zero(tid_buf, 8)
    local ok, rv = pcall(function()
        local sc = make_syscall(430)
        return sc(uint64(ctx), uint64(tid_buf), uint64(0))
    end)

    local rv_num = to_num(rv)
    local tid_val = rq(tid_buf)
    local tid_h, tid_l = 0, 0
    if tid_val then tid_h, tid_l = (type(tid_val) == "table" and tid_val.h or 0), to_num(tid_val) end

    if rv_num == 0 or (type(rv) == "table" and rv.h == 0 and rv.l == 0) then
        print("  CS=0x" .. string.format("%02X", cs) .. " → rv=0 tid=" .. q(tid_val) .. " *** RV=0! ***")
        table.insert(rv0_values, cs)
    elseif rv_num ~= 0xFFFFFFFF and not (type(rv) == "table" and rv.l == 0xFFFFFFFF) then
        print("  CS=0x" .. string.format("%02X", cs) .. " → rv=" .. tostring(rv) .. " (unusual)")
    end
    -- Skip printing rv=-1 (too many)
end

print("")
print("rv=0 CS values: " .. #rv0_values)
for _, cs in ipairs(rv0_values) do
    print("  0x" .. string.format("%02X", cs))
end

-- ============================================================
-- B: Test mc_flags values with CS=0x43
-- ============================================================
print("")
print("=== B: mc_flags sweep with CS=0x43 ===")

local flags_rv0 = {}

for _, flags in ipairs({0, 1, 2, 3, 4, 0x10000, 0x10001, 0x10002, 0x10003, 0x20000, 0x20001}) do
    zero(ctx, 0x600)
    wq(ctx + 0x108, uint64(0x480))
    wd(ctx + 0x0D0, 0)
    wq(ctx + 0x110, uint64(flags))
    wq(ctx + 0x90, ret_gadget)
    wq(ctx + 0xA8, stack_top)
    wq(ctx + 0x98, uint64(0x43))
    wq(ctx + 0xB0, uint64(0x3B))
    wq(ctx + 0xA0, uint64(0x202))

    zero(tid_buf, 8)
    local ok, rv = pcall(function()
        local sc = make_syscall(430)
        return sc(uint64(ctx), uint64(tid_buf), uint64(0))
    end)

    local rv_num = to_num(rv)
    local is_zero = (rv_num == 0) or (type(rv) == "table" and rv.h == 0 and rv.l == 0)
    print("  flags=0x" .. string.format("%X", flags) .. " → rv=" .. tostring(rv_num) ..
        (is_zero and " *** RV=0! ***" or ""))
    if is_zero then table.insert(flags_rv0, flags) end
end

-- ============================================================
-- C: Test SS values with CS=0x43
-- ============================================================
print("")
print("=== C: SS sweep with CS=0x43 ===")

for _, ss in ipairs({0, 0x3B, 0x2B, 0x33, 0x23, 0x1B, 0x13, 0x0B, 0x03}) do
    zero(ctx, 0x600)
    wq(ctx + 0x108, uint64(0x480))
    wd(ctx + 0x0D0, 0)
    wq(ctx + 0x110, uint64(0x10000))
    wq(ctx + 0x90, ret_gadget)
    wq(ctx + 0xA8, stack_top)
    wq(ctx + 0x98, uint64(0x43))
    wq(ctx + 0xB0, uint64(ss))
    wq(ctx + 0xA0, uint64(0x202))

    zero(tid_buf, 8)
    local ok, rv = pcall(function()
        local sc = make_syscall(430)
        return sc(uint64(ctx), uint64(tid_buf), uint64(0))
    end)

    local rv_num = to_num(rv)
    local is_zero = (rv_num == 0) or (type(rv) == "table" and rv.h == 0 and rv.l == 0)
    print("  SS=0x" .. string.format("%02X", ss) .. " → rv=" .. tostring(rv_num) ..
        (is_zero and " *** RV=0! ***" or ""))
end

-- ============================================================
-- D: What if we DON'T set CS/SS but DO set RFLAGS?
-- ============================================================
print("")
print("=== D: No CS/SS, various RFLAGS ===")

for _, rf in ipairs({0, 0x202, 0x246, 0x200}) do
    zero(ctx, 0x600)
    wq(ctx + 0x108, uint64(0x480))
    wd(ctx + 0x0D0, 0)
    wq(ctx + 0x110, uint64(0x10000))
    wq(ctx + 0x90, ret_gadget)
    wq(ctx + 0xA8, stack_top)
    -- NO CS/SS
    wq(ctx + 0xA0, uint64(rf))

    zero(tid_buf, 8)
    local ok, rv = pcall(function()
        local sc = make_syscall(430)
        return sc(uint64(ctx), uint64(tid_buf), uint64(0))
    end)

    local rv_num = to_num(rv)
    local is_zero = (rv_num == 0) or (type(rv) == "table" and rv.h == 0 and rv.l == 0)
    print("  RFLAGS=0x" .. string.format("%X", rf) .. " → rv=" .. tostring(rv_num) ..
        (is_zero and " *** RV=0 (WILL PANIC - CS=0)! ***" or ""))
end

local alive = pcall(function() return syscall.sc_getpid():tonumber() end)
print("")
print("[*] canary: " .. tostring(alive))
print("=== PROBE 80e COMPLETE ===")
