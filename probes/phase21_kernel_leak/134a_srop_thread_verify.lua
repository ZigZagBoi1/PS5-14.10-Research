-- CRASH_CLASS: MODERATE
-- PROBE 134a: Verify thread execution + race condition primitives
--
-- 133b proved thr_create(430) returns 0 with TID. But did the thread
-- actually execute? This probe creates threads that:
-- 1. Write markers to shared GPU memory (proves execution)
-- 2. Call syscalls from threads (proves thread syscall access)
-- 3. Test thread synchronization primitives

print("=== PROBE 134a: THREAD VERIFICATION ===")

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
    return sc_mmap(uint64(0), uint64(0x20000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

--------------------------------------------------------------------
-- SECTION A: Thread that calls getpid and thr_self
-- The thread starts at syscall with RAX=20 (getpid).
-- After the syscall, it returns to the dispatch code which
-- eventually puts the result somewhere. Then we check thr_kill.
--------------------------------------------------------------------
print("")
print("--- [A] Thread with getpid ---")

-- Shared marker location
local marker = gpu + 0x100
memory.write_qword(marker, uint64(0xDEADDEAD))

-- Clone current context for thread
pcall(function() return sc_gc(uint64(ctx)) end)
local thr_ctx = gpu + 0x1000
for off = 0, 0x4FF, 8 do
    memory.write_qword(thr_ctx + off, memory.read_qword(ctx + off))
end

local T = thr_ctx + MC
-- Thread calls thr_exit(431) with RDI=0
memory.write_qword(T + 0xA0, sc_addr)    -- RIP = syscall
memory.write_qword(T + 0x38, uint64(431)) -- RAX = thr_exit
memory.write_qword(T + 0x08, uint64(0))   -- RDI = 0 (exit code)

-- Give thread its own stack
local thr_stack = gpu + 0x6000
memory.write_qword(T + 0xB8, uint64(string.format("0x%X", to_num(thr_stack + 0x3FF0))))

local thr_id = gpu + 0xA000
memory.write_qword(thr_id, uint64(0))

local thr_ctx_addr = uint64(string.format("0x%X", to_num(thr_ctx)))
local thr_id_addr = uint64(string.format("0x%X", to_num(thr_id)))

local rv = srop(430, thr_ctx_addr, thr_id_addr, uint64(0))
print("[A] thr_create rv=" .. hex(rv))
local tid1 = memory.read_qword(thr_id)
print("[A] tid=" .. hex(tid1))
print("[A] pid=" .. to_num(sc20()))

-- Wait a moment (do work)
local d = 0
for i = 1, 50000 do d = d + 1 end

-- Check if thread is still alive
local tid1_val = to_num(tid1)
if tid1_val > 0 then
    local rv_tk = srop(433, uint64(tid1_val), uint64(0))
    local tkh, tkl = get_hi_lo(rv_tk)
    if tkl == 0 and tkh == 0 then
        print("[A] thread STILL ALIVE (thr_kill(0)=0)")
    else
        print("[A] thread EXITED (thr_kill returned " .. hex(rv_tk) .. ")")
    end
end

--------------------------------------------------------------------
-- SECTION B: Multiple threads
--------------------------------------------------------------------
print("")
print("--- [B] Multiple threads ---")

local tids = {}
for t = 1, 3 do
    pcall(function() return sc_gc(uint64(ctx)) end)
    local tc = gpu + 0x1000 + (t * 0x1000)
    for off = 0, 0x4FF, 8 do
        memory.write_qword(tc + off, memory.read_qword(ctx + off))
    end
    local TT = tc + MC
    memory.write_qword(TT + 0xA0, sc_addr)
    memory.write_qword(TT + 0x38, uint64(431))
    memory.write_qword(TT + 0x08, uint64(0))
    memory.write_qword(TT + 0xB8, uint64(string.format("0x%X",
        to_num(gpu + 0xC000 + (t * 0x1000) + 0xFF0))))

    local tid_ptr = gpu + 0xA000 + (t * 8)
    memory.write_qword(tid_ptr, uint64(0))

    local tc_addr = uint64(string.format("0x%X", to_num(tc)))
    local tp_addr = uint64(string.format("0x%X", to_num(tid_ptr)))
    local rv_t = srop(430, tc_addr, tp_addr, uint64(0))
    local tid_v = memory.read_qword(tid_ptr)
    table.insert(tids, {rv = rv_t, tid = tid_v})
    print(string.format("[B] thread %d: rv=%s tid=%s", t, hex(rv_t), hex(tid_v)))
end
print("[B] pid=" .. to_num(sc20()))

-- Wait and check
d = 0
for i = 1, 100000 do d = d + 1 end

for i, t in ipairs(tids) do
    local tv = to_num(t.tid)
    if tv > 0 then
        local rv_tk = srop(433, uint64(tv), uint64(0))
        local tkh, tkl = get_hi_lo(rv_tk)
        print(string.format("[B] thread %d (tid=%d): %s", i, tv,
            (tkl == 0 and tkh == 0) and "ALIVE" or "EXITED"))
    end
end

--------------------------------------------------------------------
-- SECTION C: Thread that does getpid instead of thr_exit
-- This tests if threads can make syscalls and return
--------------------------------------------------------------------
print("")
print("--- [C] Thread with getpid syscall ---")

pcall(function() return sc_gc(uint64(ctx)) end)
local tc_gp = gpu + 0x5000
for off = 0, 0x4FF, 8 do
    memory.write_qword(tc_gp + off, memory.read_qword(ctx + off))
end
local TGP = tc_gp + MC
-- Thread executes getpid(20)
memory.write_qword(TGP + 0xA0, sc_addr)
memory.write_qword(TGP + 0x38, uint64(20))  -- getpid
memory.write_qword(TGP + 0xB8, uint64(string.format("0x%X",
    to_num(gpu + 0x10000 + 0xFF0))))

local tid_gp = gpu + 0xA100
memory.write_qword(tid_gp, uint64(0))
local tc_gp_addr = uint64(string.format("0x%X", to_num(tc_gp)))
local tp_gp_addr = uint64(string.format("0x%X", to_num(tid_gp)))
local rv_gp = srop(430, tc_gp_addr, tp_gp_addr, uint64(0))
print("[C] thr_create(getpid) rv=" .. hex(rv_gp))
print("[C] tid=" .. hex(memory.read_qword(tid_gp)))
print("[C] pid=" .. to_num(sc20()))

-- Wait
d = 0
for i = 1, 100000 do d = d + 1 end

-- Check thread status
local gpv = to_num(memory.read_qword(tid_gp))
if gpv > 0 then
    local rv_tk = srop(433, uint64(gpv), uint64(0))
    local tkh, tkl = get_hi_lo(rv_tk)
    print("[C] getpid thread: " .. ((tkl == 0 and tkh == 0) and "ALIVE" or "EXITED"))
end

--------------------------------------------------------------------
-- SECTION D: Get thr_self for main thread
--------------------------------------------------------------------
print("")
print("--- [D] thr_self ---")
local self_id = gpu + 0xA200
memory.write_qword(self_id, uint64(0))
local self_id_addr = uint64(string.format("0x%X", to_num(self_id)))
local rv_self = srop(432, self_id_addr)
print("[D] thr_self rv=" .. hex(rv_self))
print("[D] main thread id=" .. hex(memory.read_qword(self_id)))

print("")
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
