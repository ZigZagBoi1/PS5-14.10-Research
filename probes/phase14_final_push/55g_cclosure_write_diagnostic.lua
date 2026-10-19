-- CRASH_CLASS: MODERATE
-- PROBE 55g: CClosure +0x20 write hang diagnostic
--
-- Context: 54q hung for 15s when writing a DIFFERENT value to type()'s +0x20.
-- Writing the SAME value back (no-op) succeeded instantly in [A].
-- The hang occurred at the safe_wq call itself, not at the redirected call.
-- This probe investigates:
--   1. What VM region does the CClosure live in? (use sys 674 VM map)
--   2. What protection bits does that region have?
--   3. Does writing +1 to the value also hang? (minimal change)
--   4. Does writing to OTHER CClosure offsets hang? (+0x00, +0x08, +0x10, +0x18)
--   5. Does writing to a DIFFERENT function's +0x20 also hang?
--   6. Timing: how long do writes take?

print("=== PROBE 55g: CCLOSURE WRITE HANG DIAGNOSTIC ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

local function parse_func_addr(fn)
    local s = tostring(fn)
    local hex = s:match("0x([0-9a-fA-F]+)")
    if not hex then hex = s:match(":%s*([0-9a-fA-F]+)%s*$") end
    if not hex then hex = s:match("([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)") end
    if hex then return uint64("0x" .. hex) end
    return nil
end

-- ============================================================
-- [A] Locate CClosure in VM map using sys 674
-- ============================================================
print("[A] CClosure location in VM map")

local type_addr = parse_func_addr(type)
local tonumber_addr = parse_func_addr(tonumber)
local tostring_addr = parse_func_addr(tostring)
print("  type object:     " .. hexval(type_addr))
print("  tonumber object: " .. hexval(tonumber_addr))
print("  tostring object: " .. hexval(tostring_addr))

if not type_addr then
    print("  FAILED to parse type address")
    print("=== PROBE 55g ABORTED ===")
    return
end

local type_h, type_l = get_hi_lo(type_addr)

local sc674 = make_syscall(674)
local STRIDE = 72
local MAX = 512
local buf = memory.alloc(STRIDE * MAX + 0x100)
for i = 0, STRIDE * 4 - 1, 4 do safe_wd(buf + i, 0) end
local countp = memory.alloc(16)
safe_wq(countp, uint64(0))
local ok674, ret674 = pcall(function()
    return sc674(uint64(buf), uint64(STRIDE), uint64(MAX),
                  uint64(countp), uint64(0x40000000))
end)
if ok674 then
    local count = safe_rd(countp) or 0
    print("  VM regions: " .. count)
    local limit = count
    if limit > MAX then limit = MAX end
    for i = 0, limit - 1 do
        local base = buf + i * STRIDE
        local s_lo = safe_rd(base) or 0
        local s_hi = safe_rd(base + 4) or 0
        local e_lo = safe_rd(base + 8) or 0
        local e_hi = safe_rd(base + 12) or 0
        local prot = safe_rd(base + 0x18) or 0
        local flags = safe_rd(base + 0x1C) or 0
        -- Check if type_addr falls in this region
        if s_hi == type_h and e_hi == type_h then
            if type_l >= s_lo and type_l < e_lo then
                local name = ""
                for b = 0, 39 do
                    local byte_off = 0x20 + b
                    local dw = safe_rd(base + (math.floor(byte_off / 4)) * 4) or 0
                    local shift = (byte_off % 4) * 8
                    local ch = math.floor(dw / (2 ^ shift)) % 256
                    if ch >= 0x20 and ch < 0x7F then name = name .. string.char(ch)
                    elseif ch == 0 and #name > 0 then break end
                end
                print(string.format("  MATCH rec[%d]: 0x%08X_%08X - 0x%08X_%08X prot=0x%X flags=0x%X name=%s",
                    i, s_hi, s_lo, e_hi, e_lo, prot, flags, name))
            end
        elseif s_hi <= type_h and e_hi >= type_h then
            if (s_hi < type_h or type_l >= s_lo) and (e_hi > type_h or type_l < e_lo) then
                print(string.format("  MATCH rec[%d]: prot=0x%X flags=0x%X", i, prot, flags))
            end
        end
    end
else
    print("  sys 674 failed")
end

-- ============================================================
-- [B] Read full CClosure layout for type()
-- ============================================================
print("")
print("[B] type() CClosure full layout (10 qwords)")
for off = 0, 0x48, 8 do
    local val = safe_rq(type_addr + off)
    print(string.format("  +0x%02X: %s", off, hexval(val)))
end

-- ============================================================
-- [C] Timed no-op write (same value) to +0x20
-- ============================================================
print("")
print("[C] Timed no-op write to type()+0x20")
local old_val = safe_rq(type_addr + 0x20)
print("  current +0x20: " .. hexval(old_val))
local t0 = os.clock()
local noop_ok = safe_wq(type_addr + 0x20, old_val)
local t1 = os.clock()
print(string.format("  no-op write: ok=%s time=%.4fs", tostring(noop_ok), t1 - t0))
print("  verify type(42): " .. tostring(type(42)))

-- ============================================================
-- [D] Timed writes to OTHER offsets (NOT +0x20) with restore
-- These should be safe based on 53d
-- ============================================================
print("")
print("[D] Timed writes to other CClosure offsets (with restore)")
collectgarbage("stop")
for _, off in ipairs({0x00, 0x08, 0x10, 0x18, 0x28, 0x30}) do
    local orig = safe_rq(type_addr + off)
    if orig then
        t0 = os.clock()
        local w_ok = safe_wq(type_addr + off, orig)
        t1 = os.clock()
        print(string.format("  +0x%02X: no-op ok=%s time=%.4fs val=%s",
            off, tostring(w_ok), t1 - t0, hexval(orig)))
    else
        print(string.format("  +0x%02X: UNREADABLE", off))
    end
end

-- ============================================================
-- [E] Write a DIFFERENT value to +0x18 (env pointer, non-critical)
-- 53d confirmed this is writable. Does a different value hang?
-- ============================================================
print("")
print("[E] Different-value write to +0x18 (with restore)")
local old_18 = safe_rq(type_addr + 0x18)
if old_18 then
    local h18, l18 = get_hi_lo(old_18)
    local modified_18 = uint64(string.format("0x%X%08X", h18, l18 + 1))
    t0 = os.clock()
    local w18 = safe_wq(type_addr + 0x18, modified_18)
    t1 = os.clock()
    print(string.format("  write different: ok=%s time=%.4fs", tostring(w18), t1 - t0))
    -- Restore immediately
    safe_wq(type_addr + 0x18, old_18)
    print("  restored, verify type(42): " .. tostring(type(42)))
else
    print("  +0x18 UNREADABLE")
end

-- ============================================================
-- [F] Write a DIFFERENT value to +0x00 (next pointer)
-- 53d confirmed writable
-- ============================================================
print("")
print("[F] Different-value write to +0x00 (with restore)")
local old_00 = safe_rq(type_addr + 0x00)
if old_00 then
    local h00, l00 = get_hi_lo(old_00)
    local modified_00 = uint64(string.format("0x%X%08X", h00, l00 + 1))
    t0 = os.clock()
    local w00 = safe_wq(type_addr + 0x00, modified_00)
    t1 = os.clock()
    print(string.format("  write different: ok=%s time=%.4fs", tostring(w00), t1 - t0))
    safe_wq(type_addr + 0x00, old_00)
    print("  restored")
else
    print("  +0x00 UNREADABLE")
end

-- ============================================================
-- [G] Write SAME+1 to +0x20 — does +0x20 specifically hang?
-- THIS IS THE KEY TEST. 54q hung here.
-- Using dword writes instead of qword to isolate.
-- ============================================================
print("")
print("[G] DWORD write to +0x20 low half (same value = no-op)")
local old_20_lo = safe_rd(type_addr + 0x20)
local old_20_hi = safe_rd(type_addr + 0x24)
print("  +0x20 lo: " .. string.format("0x%08X", old_20_lo or 0))
print("  +0x24 hi: " .. string.format("0x%08X", old_20_hi or 0))
t0 = os.clock()
local wd_ok = safe_wd(type_addr + 0x20, old_20_lo)
t1 = os.clock()
print(string.format("  dword no-op write +0x20: ok=%s time=%.4fs", tostring(wd_ok), t1 - t0))

-- Now write +1 to the LOW dword only (minimal change)
print("")
print("[H] DWORD write +0x20 low half +1 (DIFFERENT value)")
print("  MARKER_BEFORE_DIFFERENT_WRITE")
t0 = os.clock()
local wd_diff = safe_wd(type_addr + 0x20, old_20_lo + 1)
t1 = os.clock()
print(string.format("  MARKER_AFTER_DIFFERENT_WRITE ok=%s time=%.4fs", tostring(wd_diff), t1 - t0))

-- Restore
safe_wd(type_addr + 0x20, old_20_lo)
print("  restored +0x20")

collectgarbage("restart")
print("  verify type(42): " .. tostring(type(42)))

print("")
print("=== PROBE 55g COMPLETE ===")
