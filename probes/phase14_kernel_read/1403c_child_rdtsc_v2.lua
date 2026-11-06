-- CRASH_CLASS: LOW
-- PROBE 1403c: rdtsc via child thread — dword-write version
--
-- 1403b output corrupted: memory.write_qword to GPU mmap'd stack
-- generates 77-byte garbage per call. Fix:
--   1. Allocate stack via memory.alloc (heap, not GPU mmap)
--   2. Write ROP chain as dword pairs (no write_qword in loop)
--   3. Pre-compute all addresses as hi/lo Lua numbers

print("=== 1403c: child rdtsc v2 ===")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

-- Write a qword as two dwords (avoids write_qword entirely)
local function wq2(addr, hi, lo)
    wd(addr, lo)
    wd(addr + 4, hi)
end

-- Helper: add offset to hi/lo address
local function add_off(hi, lo, off)
    lo = lo + off
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return hi, lo
end

-- Get eboot
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- ============================================================
-- [A] Syscall gadget via SROP
-- ============================================================
print("")
print("=== [A] syscall ===")
local ctx = memory.alloc(0x500)
local sc_gc = mk(421)
pcall(function() return sc_gc(uint64(N(ctx))) end)
local brip = rq(N(ctx) + 0x40 + 0xA0)
if not brip then print("FAIL: no RIP") return end
local sc_hi, sc_lo = get_hi_lo(brip)
sc_lo = sc_lo - 2  -- RIP-2 = syscall instruction
if sc_lo < 0 then sc_hi = sc_hi - 1; sc_lo = sc_lo + 0x100000000 end
print(string.format("sc=0x%X%08X", sc_hi, sc_lo))

-- Validate via SROP getpid
local sc_sr = mk(417)
local function wq_ctx(off, hi, lo)
    wd(N(ctx) + 0x40 + off, lo)
    wd(N(ctx) + 0x40 + off + 4, hi)
end
pcall(function() return sc_gc(uint64(N(ctx))) end)
wq_ctx(0xA0, sc_hi, sc_lo)      -- RIP = syscall
wq_ctx(0x38, 0, 20)             -- RAX = getpid
local ok, rv = pcall(function() return sc_sr(uint64(N(ctx))) end)
if ok and rv then
    print("pid=" .. N(rv))
else
    print("SROP FAIL") return
end

-- ============================================================
-- [B] Pre-compute gadget addresses (all as hi/lo pairs)
-- ============================================================
print("")
print("=== [B] gadgets ===")

local g = {}
local offsets = {
    pop_rax  = 0x992,
    pop_rdi  = 0xC9DFE,
    pop_rsi  = 0xD77D,
    pop_rcx  = 0xE64,
    mov_w    = 0x92C67,    -- mov [rdi], rax; ret
    rdtsc    = 0x6A109,
    ret      = 0x42,
}
for name, off in pairs(offsets) do
    local hi, lo = add_off(eb_hi, eb_lo, off)
    g[name] = {hi, lo}
end
-- Verify mov [rdi],rax bytes
local mg = rd(N(uint64(string.format("0x%X%08X", g.mov_w[1], g.mov_w[2]))))
if mg then
    local b0, b1 = mg % 256, math.floor(mg / 256) % 256
    local b2, b3 = math.floor(mg / 65536) % 256, math.floor(mg / 16777216) % 256
    print(string.format("mov_w=%02X%02X%02X%02X (48890743)", b0, b1, b2, b3))
end

-- ============================================================
-- [C] Allocate resources (ALL via memory.alloc — no GPU mmap)
-- ============================================================
print("")
print("=== [C] alloc ===")

-- Result buffer
local result = memory.alloc(0x100)
for i = 0, 0x100 - 4, 4 do wd(N(result) + i, 0xDEADDEAD) end
local res_n = N(result)
local res_hi, res_lo = get_hi_lo(result)
print(string.format("result=0x%X", res_n))

-- Null buffer (for rdtsc gadget RCX)
local null_buf = memory.alloc(16)
wd(N(null_buf), 0)
wd(N(null_buf) + 4, 0)
local nb_hi, nb_lo = get_hi_lo(null_buf)

-- Fake TCB (self-referencing)
local tcb = memory.alloc(0x1000)
local tcb_n = N(tcb)
local tcb_hi, tcb_lo = get_hi_lo(tcb)
for i = 0, 0x1000 - 4, 4 do
    wd(tcb_n + i, (i % 8 == 0) and tcb_lo or tcb_hi)
end

-- Stack via memory.alloc (NOT mmap!)
-- Allocate extra headroom above RSP for the ROP chain.
-- ret increments RSP, so chain entries are ABOVE initial RSP.
-- Allocate 32KB, report 30KB to thr_new → 2KB headroom for chain.
local STACK_ALLOC = 0x8000  -- 32KB actual allocation
local STACK_REPORT = 0x7800 -- 30KB reported to thr_new (leaves 2KB above RSP)
local stack = memory.alloc(STACK_ALLOC)
local stack_n = N(stack)
-- Zero it
for i = 0, STACK_ALLOC - 4, 4 do wd(stack_n + i, 0) end

-- RSP = ((stack + STACK_REPORT) & ~0xF) - 8
local rsp_raw = stack_n + STACK_REPORT
rsp_raw = (math.floor(rsp_raw / 16) * 16) - 8
print(string.format("stack=0x%X rsp=0x%X top=0x%X", stack_n, rsp_raw, stack_n + STACK_ALLOC))

-- Child TID
local ctid = memory.alloc(8)
wd(N(ctid), 0); wd(N(ctid) + 4, 0)

-- Pointer-to-TCB (sysarch reads FS base from this pointer)
local tcb_ptr = memory.alloc(8)
wq2(N(tcb_ptr), tcb_hi, tcb_lo)
local tp_hi, tp_lo = get_hi_lo(tcb_ptr)

print("alloc done")
collectgarbage("collect")

-- ============================================================
-- [D] Build ROP chain (dword pairs only)
-- ============================================================
print("")
print("=== [D] ROP ===")

local slot = 0
local function push(hi, lo)
    wd(rsp_raw + slot, lo)
    wd(rsp_raw + slot + 4, hi)
    slot = slot + 8
end

-- start_func = pop_rax; ret → first thing popped is ROP[0]
-- arg (in RDI) = result buffer address

-- [0] sysarch(165): op=129(SET_FSBASE), parms=&tcb_value
push(0, 165)                       -- pop rax → 165 (sysarch syscall#)
push(g.pop_rdi[1], g.pop_rdi[2])  -- pop rdi
push(0, 129)                       -- rdi = 129 (AMD64_SET_FSBASE)
push(g.pop_rsi[1], g.pop_rsi[2])  -- pop rsi
push(tp_hi, tp_lo)                 -- rsi = &tcb_ptr (pointer to FS base)
push(sc_hi, sc_lo)                 -- syscall;ret → sysarch(129, &tcb)

-- [1] Set RCX for rdtsc gadget
push(g.pop_rcx[1], g.pop_rcx[2])
push(nb_hi, nb_lo)

-- [2] FIRST rdtsc
push(g.rdtsc[1], g.rdtsc[2])

-- [3] Store RAX → result[0]
push(g.pop_rdi[1], g.pop_rdi[2])
local r0_hi, r0_lo = add_off(res_hi, res_lo, 0)
push(r0_hi, r0_lo)
push(g.mov_w[1], g.mov_w[2])

-- [4] Reset RCX, second rdtsc
push(g.pop_rcx[1], g.pop_rcx[2])
push(nb_hi, nb_lo)
push(g.rdtsc[1], g.rdtsc[2])

-- [5] Store RAX → result[8]
push(g.pop_rdi[1], g.pop_rdi[2])
local r8_hi, r8_lo = add_off(res_hi, res_lo, 8)
push(r8_hi, r8_lo)
push(g.mov_w[1], g.mov_w[2])

-- [6] Reset RCX, third rdtsc
push(g.pop_rcx[1], g.pop_rcx[2])
push(nb_hi, nb_lo)
push(g.rdtsc[1], g.rdtsc[2])

-- [7] Store RAX → result[16]
push(g.pop_rdi[1], g.pop_rdi[2])
local r16_hi, r16_lo = add_off(res_hi, res_lo, 16)
push(r16_hi, r16_lo)
push(g.mov_w[1], g.mov_w[2])

-- [8] Completion marker → result[24]
push(g.pop_rdi[1], g.pop_rdi[2])
local r24_hi, r24_lo = add_off(res_hi, res_lo, 24)
push(r24_hi, r24_lo)
push(0, 0xCAFEBABE)               -- pop rax → marker
-- wait, that pop rax is missing. Let me fix:
-- Actually, we need pop_rax BEFORE the value. Let me restructure:

-- Oops, I pushed pop_rdi and result addr, then 0xCAFEBABE. But 0xCAFEBABE
-- will be popped by the NEXT ret... no, after mov_w returns, the next value
-- on stack is consumed. Let me redo this section properly.

-- Let me re-think. After the last mov_w;ret, the stack has:
-- [next] = whatever we push next
-- We need: pop_rax → CAFEBABE, pop_rdi → &result[24], mov_w → store

-- But I already pushed pop_rdi and r24 and CAFEBABE above. That's wrong.
-- Let me restart section [8]:

-- Undo the last 3 pushes (they were wrong)
slot = slot - 24

-- [8] Correct: store completion marker
push(g.pop_rax[1], g.pop_rax[2])  -- need pop_rax first!
-- wait, I don't have pop_rax in g table. Let me add it:
-- g.pop_rax was offsets.pop_rax = 0x992. It IS in the table.
-- Hmm, I defined offsets but the loop creates g entries. Let me check...
-- Yes: offsets has pop_rax = 0x992, and the for loop creates g.pop_rax.
-- But wait, in the loop I used `for name, off in pairs(offsets)` and the
-- name is "pop_rax". So g["pop_rax"] should exist. Let me verify.

-- Actually I realize the issue: I defined offsets table with string keys,
-- and the g table gets populated via the pairs loop. This should work.
-- Let me just continue properly:

-- REDO [8]: completion marker
push(g.pop_rax[1], g.pop_rax[2])
push(0, 0xCAFEBABE)                -- rax = 0xCAFEBABE
push(g.pop_rdi[1], g.pop_rdi[2])
push(r24_hi, r24_lo)               -- rdi = &result[24]
push(g.mov_w[1], g.mov_w[2])       -- [rdi] = rax

-- [9] thr_exit(431, 0)
push(g.pop_rax[1], g.pop_rax[2])
push(0, 431)                        -- rax = 431
push(g.pop_rdi[1], g.pop_rdi[2])
push(0, 0)                          -- rdi = 0 (NULL)
push(sc_hi, sc_lo)                  -- syscall;ret → thr_exit

print("chain: " .. (slot / 8) .. " slots (" .. slot .. " bytes)")

-- ============================================================
-- [E] Launch child via thr_new(455)
-- ============================================================
print("")
print("=== [E] launch ===")

-- thr_param at heap
local param = memory.alloc(0x40)
local param_n = N(param)

-- start_func = pop_rax; ret
wq2(param_n + 0x00, g.pop_rax[1], g.pop_rax[2])
-- arg = result (RDI, not used directly by ROP but available)
wq2(param_n + 0x08, res_hi, res_lo)
-- stack_base
wq2(param_n + 0x10, get_hi_lo(stack))
-- stack_size (use REPORT size, not alloc size — leaves headroom for ROP)
wq2(param_n + 0x18, 0, STACK_REPORT)
-- tls_base = 0
wq2(param_n + 0x20, 0, 0)
-- tls_size = 0
wq2(param_n + 0x28, 0, 0)
-- child_tid
wq2(param_n + 0x30, get_hi_lo(ctid))

collectgarbage("collect")

local sc_thr = mk(455)
local ok_t, rv_t = pcall(function()
    return sc_thr(uint64(N(param)), uint64(0x38))
end)
if ok_t then
    print("thr_new=" .. N(rv_t))
else
    print("thr_new FAIL")
    return
end

local tid = rq(N(ctid))
if tid then print("tid=" .. N(tid)) end

-- ============================================================
-- [F] Wait and read results
-- ============================================================
print("")
print("=== [F] results ===")

-- Spin-wait for marker at result[24]
local found = false
for i = 1, 50000 do
    local m = rd(res_n + 24)
    if m == 0xCAFEBABE then
        found = true
        print("done after " .. i .. " polls")
        break
    end
end

if not found then
    local m = rd(res_n + 24)
    local m2 = rd(res_n + 28)
    print(string.format("marker=0x%08X_%08X (expect CAFEBABE)", m2 or 0, m or 0))
end

-- Read TSC values
for i = 0, 2 do
    local lo = rd(res_n + i * 8)
    local hi = rd(res_n + i * 8 + 4)
    if lo and hi then
        print(string.format("TSC%d=0x%08X%08X lo_byte=%d", i+1, hi, lo, lo % 256))
    else
        print(string.format("TSC%d=UNREADABLE", i+1))
    end
end

-- Deltas
local t1_lo = rd(res_n) or 0
local t2_lo = rd(res_n + 8) or 0
local t3_lo = rd(res_n + 16) or 0

-- Clear low byte (always 1 from gadget)
t1_lo = t1_lo - (t1_lo % 256)
t2_lo = t2_lo - (t2_lo % 256)
t3_lo = t3_lo - (t3_lo % 256)

local d12 = t2_lo - t1_lo
if d12 < 0 then d12 = d12 + 0x100000000 end
local d23 = t3_lo - t2_lo
if d23 < 0 then d23 = d23 + 0x100000000 end

print(string.format("d12=%d cycles (~%d ns)", d12, math.floor(d12 / 3.5)))
print(string.format("d23=%d cycles (~%d ns)", d23, math.floor(d23 / 3.5)))

if d12 > 0 and d12 < 100000000 and d23 > 0 and d23 < 100000000 then
    print("*** rdtsc WORKS — CR4.TSD not set ***")
elseif t1_lo == 0xDEADDEAD - (0xDEADDEAD % 256) then
    print("*** SENTINEL — child never wrote ***")
else
    print(string.format("*** raw: t1=0x%X t2=0x%X t3=0x%X ***", t1_lo, t2_lo, t3_lo))
end

-- Raw dump
print("")
for off = 0, 31, 4 do
    local v = rd(res_n + off)
    print(string.format("+%02X: 0x%08X", off, v or 0))
end

print("")
print("=== 1403c DONE ===")
