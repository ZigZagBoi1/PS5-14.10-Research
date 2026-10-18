-- CRASH_CLASS: MODERATE
-- PROBE 53d: Recheck CClosure qword offsets, especially the untested +0 field.
-- Reopens: results/47b_cclosure_hijack_20261016_200459.txt; its write loop
-- tested {16,24,32,40,48}, while its +0 interpretation conflicts internally.
-- Each sentinel is restored immediately. This probe does not redirect or call a changed pointer.

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local function fmt_addr(val)
    if val == nil then return "UNREADABLE" end
    local hi, lo = get_hi_lo(val)
    return string.format("%08X_%08X", hi, lo)
end

local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end

local function same_qword(a, b)
    if a == nil or b == nil then return false end
    local ah, al = get_hi_lo(a)
    local bh, bl = get_hi_lo(b)
    return ah == bh and al == bl
end

local function parse_func_addr(fn)
    local s = tostring(fn)
    local hex = s:match("0x([0-9a-fA-F]+)") or s:match(":%s*([0-9a-fA-F][0-9a-fA-F]+)%s*$")
    if hex then return uint64("0x" .. hex), hex end
    return nil, nil
end

print("=== PROBE 53d: CCLOSURE OFFSET RETEST ===")
local mt = getmetatable(syscall.pipe)
if type(mt) ~= "table" or type(mt.__call) ~= "function" then
    print("ERROR: syscall.pipe.__call CClosure unavailable")
    print("=== PROBE 53d COMPLETE ===")
    return
end

local fn_obj, fn_hex = parse_func_addr(mt.__call)
if not fn_obj then
    print("ERROR: could not parse CClosure address from " .. tostring(mt.__call))
    print("=== PROBE 53d COMPLETE ===")
    return
end
print("CClosure address=0x" .. fn_hex)
print("Offsets tested: 0,8,16,24,32,40,48. No redirect/call is attempted.")

local gc_ok = pcall(function() collectgarbage("stop") end)
if not gc_ok then
    print("ERROR: could not stop Lua GC; skipping writes to avoid changing a live GC object")
    print("=== PROBE 53d COMPLETE ===")
    return
end
print("Lua GC stopped for the short sentinel/write/restore sequence")

local sentinel = uint64("0xDEADC0DEDEADC0DE")
local counts = {writable=0, readonly=0, unknown=0, unreadable=0, restore_failed=0}
local offset_classes = {}

for _, off in ipairs({0, 8, 16, 24, 32, 40, 48}) do
    local slot = fn_obj + off
    local old = safe_rq(slot)
    if old == nil then
        counts.unreadable = counts.unreadable + 1
        offset_classes[off] = "UNREADABLE"
        print(string.format("+0x%02X: UNREADABLE", off))
    else
        print(string.format("+0x%02X: BEFORE write old=%s", off, fmt_addr(old)))
        local write_ok = safe_wq(slot, sentinel)
        local readback = safe_rq(slot)
        local class
        if not write_ok or readback == nil then
            class = "WRITE-UNKNOWN"
        elseif same_qword(readback, sentinel) then
            class = "WRITABLE"
        elseif same_qword(readback, old) then
            class = "READ-ONLY (write ignored)"
        else
            class = "WRITE-UNKNOWN"
        end

        -- Restore immediately before formatting or testing another offset.
        local restore_ok = safe_wq(slot, old)
        local restored = safe_rq(slot)
        if not restore_ok or not same_qword(restored, old) then
            counts.restore_failed = counts.restore_failed + 1
            class = "RESTORE-FAILED (original value not confirmed)"
        end

        offset_classes[off] = class
        if class == "WRITABLE" then
            counts.writable = counts.writable + 1
        elseif class == "READ-ONLY (write ignored)" then
            counts.readonly = counts.readonly + 1
        else
            counts.unknown = counts.unknown + 1
        end
        print(string.format("+0x%02X: old=%s readback=%s class=%s restored=%s",
            off, fmt_addr(old), fmt_addr(readback), class, tostring(restore_ok and same_qword(restored, old))))
    end
end

local gc_restart_ok = pcall(function() collectgarbage("restart") end)
print("Lua GC restart: " .. tostring(gc_restart_ok))
print(string.format("SUMMARY: writable=%d read-only=%d unknown=%d unreadable=%d restore_failed=%d",
    counts.writable, counts.readonly, counts.unknown, counts.unreadable, counts.restore_failed))
print("+0 verdict: " .. tostring(offset_classes[0] or "UNKNOWN"))
print("A writable offset is a memory-write observation only; control-flow impact remains untested.")
print("=== PROBE 53d COMPLETE ===")
