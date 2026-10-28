-- CRASH_CLASS: LOW
-- PROBE 112c: credential-bit oracle — does any bit that sys 643 can OR into
--             the process open a gated handler?
--
-- Context: every interesting handler measured so far answers -1 for a game
-- process no matter what arguments it is given:
--   * 605 returns -1 for 0..31, powers of two, the crypto device id 0x3CC80700
--     and 64-bit values (probe 112a, 2026-10-23),
--   * 662 returns -1 for five different register orders with mapped buffers and
--     count=0x81, a count the 13.60 guard accepts (probe 111b),
--   * 622 answers 0x800E0001 (no device context) for every command.
-- Sys 643 ORs a caller-supplied bitmask into process+0xa34 with no privilege
-- check. Probe 55a OR'd 0xFFFFFFFF there and checked mprotect, fork and kldstat
-- only; it never asked whether the bits unlock these handlers.
--
-- So: OR one bit at a time and re-ask the same three questions. A bit that moves
-- any answer off -1 / 0x800E0001 is the credential gate.

print("=== PROBE 112c: CREDENTIAL-BIT ORACLE ===")
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
local function hexval(val)
    if val == nil then return "nil" end
    if type(val) == "table" and val.h then
        return string.format("0x%X_%08X", val.h, val.l)
    end
    return string.format("0x%X", to_num(val))
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

local sc20 = make_syscall(20)
local pid = to_num(select(2, pcall(function() return sc20() end)))
print("PID: " .. pid)

local sc605 = make_syscall(605)
local sc622 = make_syscall(622)
local sc643 = make_syscall(643)
local sc662 = make_syscall(662)

local inp = memory.alloc(0x300)
local out = memory.alloc(0x1000)
local ctl = memory.alloc(0x200)
for i = 0, 0x2FF, 4 do safe_wd(inp + i, 0) end
for i = 0, 0xFFF, 4 do safe_wd(out + i, 0) end
for i = 0, 0x1FF, 4 do safe_wd(ctl + i, 0) end

local function q605()
    local ok, ret = pcall(function()
        return sc605(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if not ok then return "PCALL" end
    return hexval(ret)
end

local function q605dev()
    local ok, ret = pcall(function()
        return sc605(uint64(0x3CC80700), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if not ok then return "PCALL" end
    return hexval(ret)
end

local function q622()
    local ok, ret = pcall(function()
        return sc622(uint64(0x200), uint64(0), uint64(ctl), uint64(ctl), uint64(0x100))
    end)
    if not ok then return "PCALL" end
    local first = 0
    local ok2, v = pcall(function() return memory.read_dword(ctl) end)
    if ok2 then first = to_num(v) end
    return hexval(ret) .. "/buf=" .. string.format("%08X", first)
end

local function q662()
    local ok, ret = pcall(function()
        return sc662(uint64(inp), uint64(0x81), uint64(out), uint64(0), uint64(0), uint64(0))
    end)
    if not ok then return "PCALL" end
    return hexval(ret)
end

print("[A] baseline before any 643 call")
local base = { q605(), q605dev(), q622(), q662() }
print(string.format("  605=%s 605dev=%s 622=%s 662=%s",
    base[1], base[2], base[3], base[4]))

print("")
print("[B] one bit at a time")
local base605, base605d, base622, base662 = base[1], base[2], base[3], base[4]
for bit = 0, 31 do
    local ok, ret = pcall(function() return sc643(uint64(1), uint64(2 ^ bit)) end)
    local mask_ret = ok and hexval(ret) or "PCALL"

    local a, b, c, d = q605(), q605dev(), q622(), q662()
    local changed = (a ~= base605) or (b ~= base605d) or (c ~= base622) or (d ~= base662)
    if changed then
        print(string.format("  bit %2d (643 ret=%s) CHANGED: 605=%s 605dev=%s 622=%s 662=%s",
            bit, mask_ret, a, b, c, d))
    else
        print(string.format("  bit %2d (643 ret=%s) unchanged", bit, mask_ret))
    end
end

print("")
print("[C] after the sweep, all bits at once")
local ok, ret = pcall(function() return sc643(uint64(1), uint64(0xFFFFFFFF)) end)
print("  643(0xFFFFFFFF) = " .. (ok and hexval(ret) or "PCALL"))
print(string.format("  605=%s 605dev=%s 622=%s 662=%s", q605(), q605dev(), q622(), q662()))

print("")
print("=== END PROBE 112c ===")
