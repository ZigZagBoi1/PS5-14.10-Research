-- CRASH_CLASS: MODERATE
-- PROBE 54i: sys 567 PMC counter read (corrected handler mapping)
--
-- 13.60 reference bytes at RVA 0x6039d0 show:
--   arg1 = process ID, arg2 = counter index 0..5, arg3 = 8-byte output
--   six RDMSR sites for 0xC0010201..0xC001020B
--   one 8-byte copyout from the selected counter slot
-- sys 563/564 are the enable/disable counterparts. sys 565/566 configure PMCs.
-- These are performance-counter values, not expected kernel pointers.

print("=== PROBE 54i: SYS 567 PMC READ ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wq(addr, val)
    return pcall(function() memory.write_qword(addr, val) end)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function signed32(v)
    if type(v) == "table" and v.h then
        if v.h == 0xFFFFFFFF then return v.l - 0x100000000 end
        if v.h == 0 and v.l >= 0x80000000 then return v.l - 0x100000000 end
    end
    local n = to_num(v)
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end

local sc20 = make_syscall(20)
local sc563 = make_syscall(563)
local sc564 = make_syscall(564)
local sc567 = make_syscall(567)
local outbuf = memory.alloc(0x1000)
local SENTINEL = uint64("0x4141414141414141")
local GUARD = uint64("0x4242424242424242")

local ok_pid, pid_ret = pcall(function() return sc20() end)
local pid = ok_pid and to_num(pid_ret) or 0
print("[*] PID: " .. pid)
if pid == 0 then
    print("[!] Valid PID required; stopping")
    return
end

local function call_simple(sc, num)
    local ok, ret = pcall(function()
        return sc(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        print(string.format("  sys %d(0) ret=%d", num, signed32(ret)))
        return signed32(ret)
    end
    print(string.format("  sys %d(0) pcall failed: %s", num, tostring(ret)))
    return nil
end

local function read_counter(index)
    safe_wq(outbuf, SENTINEL)
    safe_wq(outbuf + 8, GUARD)
    local ok, ret = pcall(function()
        return sc567(uint64(pid), uint64(index), uint64(outbuf),
            uint64(0), uint64(0), uint64(0))
    end)
    if not ok then
        print(string.format("  567(pid, %d, out) pcall failed: %s", index, tostring(ret)))
        return nil
    end
    local rv = signed32(ret)
    local value = safe_rq(outbuf)
    local guard = safe_rq(outbuf + 8)
    local vh, vl = get_hi_lo(value)
    local gh, gl = get_hi_lo(guard)
    local changed = not (vh == 0x41414141 and vl == 0x41414141)
    local guard_intact = gh == 0x42424242 and gl == 0x42424242
    print(string.format("  567(pid, %d, out) ret=%d value=%s changed=%s guard8_intact=%s",
        index, rv, hexval(value), tostring(changed), tostring(guard_intact)))
    return {rv=rv, value=value, changed=changed, guard=guard_intact}
end

print("[*] Baseline before explicit enable")
read_counter(0)
print("")

print("[*] Enable PMC for current process")
local enable_rv = call_simple(sc563, 563)
print("")

print("[*] Read all six counter slots twice")
for round = 1, 2 do
    print("  Round " .. round)
    for index = 0, 5 do read_counter(index) end
end
print("")

print("[*] Disable PMC for current process")
call_simple(sc564, 564)
print("")

print("[*] Post-disable check")
read_counter(0)
print("")
print("=== PROBE 54i COMPLETE ===")
