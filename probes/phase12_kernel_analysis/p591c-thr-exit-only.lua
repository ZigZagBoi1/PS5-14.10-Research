-- CRASH_CLASS: LOW
-- PROBE 591c: Ultra-minimal child — thr_exit only
--
-- v4: FIX RSP calculation.
-- CLAUDE.md says: RSP = ((stack_base + stack_size) & ~0xF) - 8
-- Previous versions computed aligned_top WITHOUT the -8, so the child's
-- first pop read garbage 8 bytes before the chain → crash.
-- Also uses native.fcall_with_rax to avoid make_syscall binary dump.

print("=== PROBE 591c: THR_EXIT ONLY (v3 native) ===")
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
local function mk_u64(hi, lo)
    return uint64(string.format("0x%X%08X", hi, lo))
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

-- Eboot for gadgets
local info = memory.alloc(0x200)
for i = 0, 0x1FF, 4 do wd(N(info) + i, 0) end
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local tlo = rd(N(info) + 0x108) or 0
local thi = rd(N(info) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end
local eb = mk_u64(thi, tlo)
print("eb=" .. fmt64(eb))

local pop_rax_ret = eb + uint64(0x992)
local pop_rdi_ret = eb + uint64(0xC9DFE)

-- Stack (2 MiB mmap via make_syscall — this one is safe, it's mmap not thr_new)
local cstack = mk(477)(uint64(0), uint64(0x200000), uint64(0x3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
if N(cstack) == 0 then print("mmap FAILED"); return end
local sh, sl = get_hi_lo(cstack)
local stack_u64 = mk_u64(sh, sl)
local sn = N(cstack)
print("stack=" .. fmt64(cstack))

local THR_STACK = 0x1FF000
local aligned_top = math.floor((sn + THR_STACK) / 16) * 16
local rsp = aligned_top - 8

-- Chain at RSP. start_func = pop_rax_ret consumes [RSP] first.
-- [RSP+0] = 431 (pop_rax), [RSP+8] = pop_rdi_ret (ret target),
-- [RSP+16] = 0 (pop_rdi), [RSP+24] = stub (ret → thr_exit)
local chain = {
    uint64(431),     -- [RSP+0] pop_rax consumes: rax = 431
    pop_rdi_ret,     -- [RSP+8] ret jumps here
    uint64(0),       -- [RSP+16] pop_rdi: rdi = 0
    stub,            -- [RSP+24] ret → stub: syscall(431, 0) = thr_exit
}

for i, w in ipairs(chain) do
    wq(rsp + (i - 1) * 8, w)
end
print("chain=" .. #chain .. " at rsp=0x" .. string.format("%X", rsp) ..
      " aligned_top=0x" .. string.format("%X", aligned_top))

-- thr_param (0x38 bytes)
local param = memory.alloc(0x100)
for i = 0, 0x3F, 4 do wd(N(param) + i, 0) end
wq(N(param) + 0x00, pop_rax_ret)           -- start_func
wq(N(param) + 0x08, uint64(0))             -- arg
wq(N(param) + 0x10, stack_u64)             -- stack_base
wq(N(param) + 0x18, uint64(THR_STACK))     -- stack_size
local tid_buf = memory.alloc(16)
wq(N(tid_buf), uint64(0))
wq(N(param) + 0x30, tid_buf)               -- child_tid

print("CALL_NATIVE")

-- Use native.fcall_with_rax instead of make_syscall to avoid binary dump
local ok_t, rv_t = pcall(function()
    return native.fcall_with_rax(stub, 455, param, uint64(0x38))
end)

print("ok=" .. tostring(ok_t))
print("A")
print("B")
print("C")

-- Diagnostic: is the problem rv_t access or child crash?
if ok_t then
    print("D_type=" .. type(rv_t))
    local ok_n, val_n = pcall(function() return N(rv_t) end)
    print("E_ok=" .. tostring(ok_n))
    if ok_n then print("rv=" .. val_n) end
    local ok_tid, tid_v = pcall(function()
        local t = rd(N(tid_buf)) or 0
        if t < 0 then t = t + 0x100000000 end
        return t
    end)
    print("F_ok=" .. tostring(ok_tid))
    if ok_tid then print("tid=" .. tid_v) end
else
    print("ERR=" .. tostring(rv_t))
end

print("G")
for i = 1, 3 do
    print("alive_" .. i)
end
print("=== 591c COMPLETE ===")
