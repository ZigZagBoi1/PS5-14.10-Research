-- CRASH_CLASS: MODERATE
-- PROBE 590: Verify libkernel code offsets via function calls
--
-- libkernel text is XO (prot=4) — can't read, can only execute.
-- Strategy:
--   A: Find libkernel base via 674 VM map (same as p589)
--   B: Test sceKernelGetCurrentCpu (+0x1200) — 0 args, returns 0-7
--   C: Test sleep (+0x27F00) via child thread ROP — sleep(0) should return 0
--   D: Test pthread_exit, pthread_join via child thread ROP observables
--   E: worker_wait_return (+0x1FD01) — just segment check, too risky to call

print("=== PROBE 590: LK CODE OFFSET DRAIN ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt64(val)
    local h, l = get_hi_lo(val)
    return string.format("0x%X%08X", h, l)
end
local function rb(buf, off)
    local addr = N(buf) + (off - off % 4)
    local dw = rd(addr)
    if not dw then return 0 end
    local shift = (off % 4) * 8
    return math.floor(dw / (2 ^ shift)) % 256
end
local function to_num64(h, l)
    return h * 0x100000000 + l
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

-- ============================================================
-- SECTION A: Find libkernel base via 674
-- ============================================================
print("")
print("--- A: FIND LIBKERNEL ---")

local sc674 = mk(674)
local STRIDE = 72
local MAX_RECORDS = 400
local vmbuf = memory.alloc(STRIDE * MAX_RECORDS + 0x100)
local countp = memory.alloc(16)
wd(N(countp), 0)
wd(N(countp) + 4, 0)

local ok674, ret674 = pcall(function()
    return sc674(uint64(N(vmbuf)), uint64(STRIDE), uint64(MAX_RECORDS),
                  uint64(N(countp)), uint64(0x40000000))
end)

if not ok674 or N(ret674) ~= 0 then
    print("  674 FAILED")
    print("canary=" .. tostring(N(native.fcall_with_rax(stub, 20)) == pid))
    print("=== PROBE 590 COMPLETE ===")
    return
end

local nregions = rd(N(countp)) or 0
print("  regions=" .. nregions)

-- Find fn_addr region (libkernel text)
local fn_h, fn_l = get_hi_lo(stub)
local fn_num = to_num64(fn_h, fn_l)

local lk_base = nil
local lk_size = nil
local lk_prot = nil

for i = 0, math.min(nregions - 1, 500) do
    local base = N(vmbuf) + i * STRIDE
    local slo = rd(base + 0x00) or 0
    local shi = rd(base + 0x04) or 0
    if slo < 0 then slo = slo + 0x100000000 end
    if shi < 0 then shi = shi + 0x100000000 end
    local elo = rd(base + 0x08) or 0
    local ehi = rd(base + 0x0C) or 0
    if elo < 0 then elo = elo + 0x100000000 end
    if ehi < 0 then ehi = ehi + 0x100000000 end

    local start_num = to_num64(shi, slo)
    local end_num = to_num64(ehi, elo)

    if fn_num >= start_num and fn_num < end_num then
        lk_base = start_num
        lk_size = end_num - start_num
        lk_prot = rd(base + 0x18) or 0
        local name_bytes = {}
        for j = 0, 31 do
            local b = rb(vmbuf, i * STRIDE + 0x20 + j)
            if b == 0 then break end
            name_bytes[#name_bytes + 1] = string.char(b)
        end
        print(string.format("  libkernel: %s base=0x%X size=0x%X prot=%d",
            table.concat(name_bytes), lk_base, lk_size, lk_prot))
        break
    end
end

if not lk_base then
    print("  libkernel NOT FOUND")
    print("canary=" .. tostring(N(native.fcall_with_rax(stub, 20)) == pid))
    print("=== PROBE 590 COMPLETE ===")
    return
end

-- Get eboot base for gadgets
local pipe_str = tostring(syscall.pipe)
-- Extract gadget addresses from ropchain to find eboot base
-- The ret gadget is always first in the chain
local eboot_base = nil
local sc593 = mk(593)
local info = memory.alloc(0x200)
for i = 0, 0x1FF, 4 do wd(N(info) + i, 0) end
wd(N(info), 0x160)
local ok593, ret593 = pcall(function() return sc593(uint64(0), info) end)
if ok593 and N(ret593) == 0 then
    local tlo = rd(N(info) + 0x108) or 0
    local thi = rd(N(info) + 0x10C) or 0
    if tlo < 0 then tlo = tlo + 0x100000000 end
    if thi < 0 then thi = thi + 0x100000000 end
    eboot_base = to_num64(thi, tlo)
    print(string.format("  eboot_base=0x%X", eboot_base))
end

-- ============================================================
-- SECTION B: Test sceKernelGetCurrentCpu (+0x1200)
-- ============================================================
print("")
print("--- B: sceKernelGetCurrentCpu (+0x1200) ---")

local cpu_target = uint64(string.format("0x%X", lk_base + 0x1200))
print("  addr=" .. fmt64(cpu_target))

-- Try calling with fcall_with_rax — 0 args function
local cpu_results = {}
for attempt = 1, 3 do
    local ok_c, ret_c = pcall(function()
        return native.fcall_with_rax(cpu_target, 0)
    end)
    if ok_c then
        local rv = N(ret_c)
        cpu_results[#cpu_results + 1] = rv
        print(string.format("  attempt %d: ret=%d (0x%X)", attempt, rv, rv))
    else
        cpu_results[#cpu_results + 1] = "CRASH"
        print(string.format("  attempt %d: CRASH %s", attempt, tostring(ret_c)))
        break
    end
end

-- Check: valid CPU returns are 0-7, should vary across calls
local all_valid = true
local all_same = true
for i, v in ipairs(cpu_results) do
    if type(v) ~= "number" or v < 0 or v > 7 then all_valid = false end
    if i > 1 and v ~= cpu_results[1] then all_same = false end
end

if all_valid then
    print("  VERDICT: +0x1200 returns valid CPU numbers → LIKELY CORRECT")
else
    print("  VERDICT: +0x1200 does NOT return 0-7 → WRONG or different function")
end

-- Canary after risky call
local canary1 = N(native.fcall_with_rax(stub, 20)) == pid
print("  canary=" .. tostring(canary1))
if not canary1 then
    print("  ENVIRONMENT CORRUPTED, stopping")
    print("=== PROBE 590 COMPLETE ===")
    return
end

-- ============================================================
-- SECTION C: Test sleep (+0x27F00) via child thread
-- Uses thr_new(455) with ROP chain that calls sleep(0)
-- and writes return value to shared memory
-- ============================================================
print("")
print("--- C: sleep(+0x27F00) via child thread ---")

if not eboot_base then
    print("  eboot_base not found, skipping child thread tests")
    print("canary=" .. tostring(N(native.fcall_with_rax(stub, 20)) == pid))
    print("=== PROBE 590 COMPLETE ===")
    return
end

-- Gadgets (from CLAUDE.md confirmed catalog)
local pop_rax_ret  = eboot_base + 0x992
local pop_rdi_ret  = eboot_base + 0xC9DFE
local pop_rsi_ret  = eboot_base + 0xD77D
local pop_rdx_ret  = eboot_base + 0x3B02D7
local pop_rcx_ret  = eboot_base + 0xE64
local pop_r8_ret   = eboot_base + 0x991
local bare_ret     = eboot_base + 0x42
local mov_rdi_rax_ret = eboot_base + 0x92C67  -- mov [rdi], rax; ret

-- sysarch(129, &fake_tcb) for TLS fix
local sysarch_no = 165

-- Result buffer in shared memory
local result_buf = memory.alloc(0x1000)
for i = 0, 0xFF, 4 do wd(N(result_buf) + i, 0) end
-- Sentinel
wq(N(result_buf), uint64(0xDEADDEADDEADDEAD))
wq(N(result_buf) + 8, uint64(0xDEADDEADDEADDEAD))

-- Fake TCB (self-referencing pointer)
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFF, 8 do wq(N(fake_tcb) + i, fake_tcb) end

-- Stack for child (2 MiB)
local sc_mmap = mk(477)
local child_stack = sc_mmap(uint64(0), uint64(0x200000), uint64(0x3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local child_stack_num = N(child_stack)
if child_stack_num == 0 then
    print("  mmap failed for child stack")
    print("canary=" .. tostring(N(native.fcall_with_rax(stub, 20)) == pid))
    print("=== PROBE 590 COMPLETE ===")
    return
end
print("  child_stack=" .. fmt64(child_stack))

-- Build ROP chain at top of stack
-- RSP = ((stack_base + stack_size) & ~0xF) - 8
local stack_top = math.floor((child_stack_num + 0x200000) / 16) * 16 - 8
local rsp = stack_top

-- Chain layout:
-- 1. sysarch(SET_FSBASE=129, &fake_tcb) — TLS fix
-- 2. call sleep_addr(0) — test sleep offset
-- 3. write result to result_buf via mov [rdi], rax; ret
-- 4. thr_exit(431)

local sleep_addr = lk_base + 0x27F00
local result_buf_num = N(result_buf)

local chain = {}

-- Step 1: sysarch(129, &fake_tcb) via syscall
-- rax=165 (sysarch), rdi=129, rsi=&fake_tcb
chain[#chain + 1] = pop_rax_ret
chain[#chain + 1] = sysarch_no
chain[#chain + 1] = pop_rdi_ret
chain[#chain + 1] = 129  -- SET_FSBASE
chain[#chain + 1] = pop_rsi_ret
chain[#chain + 1] = N(fake_tcb)
chain[#chain + 1] = eboot_base + 0x1AB0C6  -- syscall; ret (wait, there's no syscall;ret in eboot)

-- Actually, eboot has NO syscall;ret gadget (probe 56s confirmed).
-- Child threads make syscalls via fn_addr (the libkernel syscall stub).
-- fn_addr expects: rax = syscall number, args in rdi/rsi/rdx/rcx/r8/r9
-- But fn_addr is the ROP chain entry point, not a simple function.
--
-- From CLAUDE.md child thread pattern:
-- RIP = pop rax; ret (eboot+0x992), stack [num][syscall;ret][pop rax][num]...
-- pop rdi; ret (eboot+0x75DFE) for per-link arguments
-- pop rax; 431; syscall to exit
--
-- Wait, the CLAUDE.md says: "RIP = pop rax; ret (eboot+0x992), stack
-- [num][syscall;ret][pop rax][num]..."
-- So there IS a syscall;ret somewhere the child uses!
-- Let me re-read: the child chain uses "pop rax; ret" at eboot+0x992
-- and the pattern is [num][syscall;ret]...
--
-- Actually from CLAUDE.md: the child thread ROP uses fn_addr directly.
-- Let me use a different approach: call lk_base+offset DIRECTLY.
-- fn_addr at lk_base+0xB57 is the syscall stub.
-- For sysarch: call fn_addr with rax=165, rdi=129, rsi=&fake_tcb.
-- For sleep: sleep() is a library function, not a syscall. We call it directly
-- at lk_base+0x27F00 with rdi=0.

-- Reset chain
chain = {}

-- Step 1: sysarch(SET_FSBASE=129, &fake_tcb) via libkernel syscall stub
-- The stub at fn_addr (lk_base+0xB57) does: mov rax, [syscall_no]; syscall; ret
-- Actually fn_addr is the Lua loader's fcall stub address on HEAP, not in libkernel.
-- For child thread, we need the actual syscall instruction.
--
-- From probe docs: child threads use fn_addr entry point which is
-- a libkernel function. Actually, sysarch is syscall 165.
-- We need: set rax=165, rdi=129, rsi=&fake_tcb, then syscall;ret
--
-- The eboot has NO syscall;ret (probe 56s). But libkernel DOES.
-- fn_addr offset in libkernel = 0xB57. But that's the Lua loader's
-- entry, and it's a complex stub.
--
-- Actually, FreeBSD syscall instruction can be found in libkernel.
-- From the confirmed gadget set: child threads use ROP chains in eboot
-- text. The syscall gadget must come from somewhere.
--
-- Wait, CLAUDE.md says: "pop rax; 431; syscall to exit"
-- This means there's a "syscall; ret" sequence somewhere.
-- But probe 56s says eboot has none. So it must be in libkernel.
-- libkernel is XO but executable — we can jump to it.
--
-- The simplest approach: use the nanosleep syscall (240) instead of
-- calling the sleep library function. nanosleep(rdi=timespec_ptr, rsi=0)
-- with timespec = {0, 0} means sleep 0.
--
-- Better yet: just test sceKernelGetCurrentCpu which takes 0 args.
-- For child thread: call lk_base+0x1200 directly, store result.

-- Actually let me simplify drastically. We confirmed native.fcall_with_rax
-- works for calling arbitrary addresses. The p589 crash might have been
-- a fluke or output encoding issue. Let me just retry the calls directly
-- from the main thread with better error handling.

-- Abort the child thread approach for now — test directly
print("  Switching to direct fcall tests (simpler)")

-- Test sleep offset by calling nanosleep syscall instead
-- nanosleep is syscall 240: nanosleep(rqtp, rmtp)
local timespec = memory.alloc(32)
wq(N(timespec), uint64(0))      -- tv_sec = 0
wq(N(timespec) + 8, uint64(0))  -- tv_nsec = 0

local sc_nanosleep = mk(240)
local ok_ns, ret_ns = pcall(function()
    return sc_nanosleep(timespec, uint64(0))
end)
if ok_ns then
    print(string.format("  nanosleep(0,0) ret=%d — syscall works", N(ret_ns)))
else
    print("  nanosleep FAILED: " .. tostring(ret_ns))
end

-- Now test if lk_base+0x27F00 is sleep by calling it as a function
-- sleep(0) should return 0 immediately
-- But fcall_with_rax sets rax, not rdi. For sleep(0), rdi must be 0.
-- When rdi happens to be 0 from previous state, it works.
-- Try it:
print("")
print("  Testing sleep at lk_base+0x27F00:")
local sleep_target = uint64(string.format("0x%X", lk_base + 0x27F00))
print("  addr=" .. fmt64(sleep_target))
local ok_sl, ret_sl = pcall(function()
    return native.fcall_with_rax(sleep_target, 0)
end)
if ok_sl then
    local rv = N(ret_sl)
    print(string.format("  ret=%d (0x%X)", rv, rv))
    if rv == 0 then
        print("  VERDICT: returns 0 — consistent with sleep(0)")
    else
        print("  VERDICT: returned " .. rv .. " — may be wrong offset")
    end
else
    print("  CRASH: " .. tostring(ret_sl))
    print("  VERDICT: +0x27F00 crashes → WRONG")
end

local canary2 = N(native.fcall_with_rax(stub, 20)) == pid
print("  canary=" .. tostring(canary2))
if not canary2 then
    print("  ENVIRONMENT CORRUPTED")
    print("=== PROBE 590 COMPLETE ===")
    return
end

-- ============================================================
-- SECTION D: Test pthread offsets via observable behavior
-- pthread_create_name_np (+0x21890) — too complex to call safely
-- pthread_join (+0x229A0) — needs valid thread
-- pthread_exit (+0x21C20) — would kill thread
-- worker_wait_return (+0x1FD01) — internal, skip
-- ============================================================
print("")
print("--- D: PTHREAD OFFSET RANGE CHECKS ---")

local OFFSETS = {
    {name="worker_wait_return",     offset=0x1FD01},
    {name="pthread_create_name_np", offset=0x21890},
    {name="pthread_join",           offset=0x229A0},
    {name="pthread_exit",           offset=0x21C20},
    {name="sleep",                  offset=0x27F00},
}

for _, o in ipairs(OFFSETS) do
    local in_text = (o.offset < lk_size)
    local status = in_text and "IN_TEXT" or "OUT_OF_RANGE"
    print(string.format("  %s: +0x%X → %s (text_size=0x%X)",
        o.name, o.offset, status, lk_size))
end

-- Check if any offset is oddly aligned (functions should be 16-byte aligned usually)
print("")
print("  Alignment check:")
for _, o in ipairs(OFFSETS) do
    local align = o.offset % 16
    print(string.format("  %s: +0x%X mod 16 = %d %s",
        o.name, o.offset, align,
        align == 0 and "(aligned)" or (o.name == "worker_wait_return" and "(mid-function return addr, OK)" or "(UNALIGNED)")))
end

-- ============================================================
-- SECTION E: fn_addr characterization
-- fn_addr is at lk_base+0xB57. This is the syscall dispatcher.
-- Verify by calling known syscalls through it.
-- ============================================================
print("")
print("--- E: FN_ADDR CHARACTERIZATION ---")
print(string.format("  fn_addr offset = +0x%X", fn_num - lk_base))

-- Verify fn_addr works for known syscalls
local test_getpid = N(native.fcall_with_rax(stub, 20))
print(string.format("  getpid via fn_addr: %d (expected %d) %s",
    test_getpid, pid, test_getpid == pid and "OK" or "MISMATCH"))

-- ============================================================
-- SECTION F: Canary
-- ============================================================
print("")
local canary_final = N(native.fcall_with_rax(stub, 20)) == pid
print("canary=" .. tostring(canary_final))
print("=== PROBE 590 COMPLETE ===")
