-- CRASH_CLASS: HIGH
-- PROBE 531y: MapDirectMemory diagnostic — test each part
--
-- S2 works (sysarch chain). Chain crashes when MapDirectMemory added.
-- Test: after sysarch, do the register setup but DON'T call map_fn.
-- Instead store rcx value and park. Verify the chain up to that point.
-- Then test: call map_fn but with a known-safe function instead.

print("=== PROBE 531y: MAPDM DIAG ===")
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

-- Alloc phys
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
if not phys or to_num(phys) == 0 then print("FAIL") return end

-- Setup
local ok_s, shared = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(shared, 0x4000)

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

-- =============================================
-- TEST A: Full register setup, NO map_fn call
-- Verify chain executes pop_rdx_ret and pop_rcx_ret correctly
-- =============================================
print("")
print("[T-A] Register setup only (no MapDM call)")
wq(shared, uint64(0x1111))
wq(shared + 8, uint64(0x2222))
wq(shared + 0x10, uint64(0x3333))

local chain = stack_base + 0x200000 - 0x800
local i = 0
local function emit(v) wq(chain + i, v); i = i + 8 end

-- sysarch(165)
emit(uint64(165))
emit(pop_rdi_ret); emit(uint64(129))
emit(pop_rsi_ret); emit(uint64(tcb_ptr))
emit(syscall_ret)

-- Setup regs as if for MapDM, but just store markers
emit(pop_rdi_ret); emit(shared)       -- rdi = &shared[0]
emit(pop_rsi_ret); emit(uint64(0x4000)) -- rsi = len
emit(pop_rdx_ret); emit(uint64(3))      -- rdx = prot
emit(pop_rcx_ret); emit(uint64(0))      -- rcx = flags

-- Store rax (which is 0 from pop_rcx → rcx=0, then... wait, rax is still sysarch rv)
-- Actually rax = sysarch rv (0) from the syscall.
-- Store marker to confirm we got here
emit(pop_rax_ret); emit(uint64(0x52454753))  -- "REGS"
emit(mov_rdi_rax_ret)   -- shared[0] = "REGS"

-- Store a second marker
emit(pop_rdi_ret); emit(shared + 8)
emit(pop_rax_ret); emit(uint64(0x4F4B))  -- "OK"
emit(mov_rdi_rax_ret)

emit(jmp_self)

print(string.format("  chain=%d bytes", i))

local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + 0x108, uint64(0x480)); wd(ctx + 0x0D0, 0); wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x0C0, uint64(0x43)); wq(ctx + 0x100, uint64(0x3B))
wq(ctx + 0x0F0, uint64(0x202))
wq(ctx + 0x0E0, pop_rax_ret); wq(ctx + 0x0F8, chain)
wq(ctx + 0x068, phys); wq(ctx + 0x070, uint64(0x4000))

local tid_buf = memory.alloc(8); wq(tid_buf, uint64(0))
local ok_tc, rv_tc = pcall(function()
    return sc_430(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(to_num(rv_tc)))

local ts = memory.alloc(16); wq(ts, 0); wq(ts + 8, 300000000)
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

print("  s[0]=" .. q(rq(shared)) .. " s[8]=" .. q(rq(shared + 8)))

local s0 = to_num(rq(shared))
if s0 < 0 then s0 = s0 + 0x100000000 end
if s0 == 0x52454753 then
    print("  T-A PASS: all register pops work")
else
    print("  T-A FAIL: chain crashed during register setup")
    print("=== 531y DONE ===")
    return
end

-- =============================================
-- TEST B: Call getpid() as a safe function call
-- This tests that a library call works from the chain
-- =============================================
print("")
print("[T-B] Call getpid via chain (safe function call)")
-- getpid is a simple syscall wrapper, should work without TLS
-- Actually, let's just do a raw getpid syscall to verify ABI
wq(shared + 0x10, uint64(0xEEEE))

local chain2 = stack_base + 0x200000 - 0x400
i = 0
local function emit2(v) wq(chain2 + i, v); i = i + 8 end

-- sysarch first
emit2(uint64(165))
emit2(pop_rdi_ret); emit2(uint64(129))
emit2(pop_rsi_ret); emit2(uint64(tcb_ptr))
emit2(syscall_ret)

-- getpid syscall (rax=20)
emit2(uint64(20))
emit2(syscall_ret)

-- store pid → shared[0x10]
emit2(pop_rdi_ret); emit2(shared + 0x10)
emit2(mov_rdi_rax_ret)

emit2(jmp_self)

local ctx2 = memory.alloc(0x500)
zero(ctx2, 0x500)
wq(ctx2 + 0x108, uint64(0x480)); wd(ctx2 + 0x0D0, 0); wq(ctx2 + 0x110, uint64(0x10000))
wq(ctx2 + 0x0C0, uint64(0x43)); wq(ctx2 + 0x100, uint64(0x3B))
wq(ctx2 + 0x0F0, uint64(0x202))
wq(ctx2 + 0x0E0, pop_rax_ret); wq(ctx2 + 0x0F8, chain2)

wq(tid_buf, uint64(0))
local ok_tc2, rv_tc2 = pcall(function()
    return sc_430(uint64(ctx2), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(to_num(rv_tc2)))

pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
print("  child_pid=" .. q(rq(shared + 0x10)))

-- =============================================
-- TEST C: Call MapDirectMemory with TLS
-- =============================================
print("")
print("[T-C] MapDirectMemory call")
wq(shared + 0x00, uint64(0))        -- VA out
wq(shared + 0x08, uint64(0xDDDD))   -- map rv
wq(shared + 0x10, uint64(0xFFFF))   -- done

-- New fake TCB for this child
local ok_t3, tcb3 = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
for off = 0, 0x100, 8 do wq(tcb3 + off, tcb3) end
local tcb3_ptr = memory.alloc(8)
wq(tcb3_ptr, tcb3)

local chain3 = stack_base + 0x200000 - 0xC00
i = 0
local function emit3(v) wq(chain3 + i, v); i = i + 8 end

-- sysarch
emit3(uint64(165))
emit3(pop_rdi_ret); emit3(uint64(129))
emit3(pop_rsi_ret); emit3(uint64(tcb3_ptr))
emit3(syscall_ret)

-- MapDirectMemory args
emit3(pop_rdi_ret); emit3(shared + 0x00)      -- out_ptr
emit3(pop_rsi_ret); emit3(uint64(0x4000))      -- len
emit3(pop_rdx_ret); emit3(uint64(3))            -- prot
emit3(pop_rcx_ret); emit3(uint64(0))            -- flags

-- "call" map_fn
emit3(map_fn)

-- Stack frame for map_fn: [rsp]=ret, [rsp+8]=7th arg
local post3 = chain3 + i + 16
emit3(uint64(post3))     -- return addr
emit3(uint64(0))          -- name = NULL

-- post-call: store rv
emit3(pop_rdi_ret)        -- = post3
emit3(shared + 0x08)
emit3(mov_rdi_rax_ret)

-- done marker
emit3(pop_rdi_ret)
emit3(shared + 0x10)
emit3(pop_rax_ret)
emit3(uint64(0x444F4E45))
emit3(mov_rdi_rax_ret)

-- thr_exit
emit3(pop_rax_ret)
emit3(uint64(431))
emit3(syscall_ret)

print(string.format("  chain3=%d bytes", i))

local ctx3 = memory.alloc(0x500)
zero(ctx3, 0x500)
wq(ctx3 + 0x108, uint64(0x480)); wd(ctx3 + 0x0D0, 0); wq(ctx3 + 0x110, uint64(0x10000))
wq(ctx3 + 0x0C0, uint64(0x43)); wq(ctx3 + 0x100, uint64(0x3B))
wq(ctx3 + 0x0F0, uint64(0x202))
wq(ctx3 + 0x0E0, pop_rax_ret); wq(ctx3 + 0x0F8, chain3)
wq(ctx3 + 0x068, phys); wq(ctx3 + 0x070, uint64(0x4000))

wq(tid_buf, uint64(0))
local ok_tc3, rv_tc3 = pcall(function()
    return sc_430(uint64(ctx3), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(to_num(rv_tc3)))

-- Wait up to 3s
for attempt = 1, 30 do
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local m = rq(shared + 0x10)
    if m then
        local mn = to_num(m)
        if mn < 0 then mn = mn + 0x100000000 end
        if mn ~= 0 and mn ~= 0xFFFF then break end
    end
end

print("  map_rv=" .. q(rq(shared + 0x08)))
print("  va=" .. q(rq(shared + 0x00)))
print("  done=" .. q(rq(shared + 0x10)))

print("=== 531y DONE ===")
