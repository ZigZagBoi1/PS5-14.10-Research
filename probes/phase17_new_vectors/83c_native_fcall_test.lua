-- CRASH_CLASS: MODERATE
-- PROBE 83c: Test native.fcall to make native function calls
-- 83b confirmed fcall chain is finalized with real arg addresses.
-- The ROP primitive should let us call arbitrary native functions.
-- Use it to call getpid, then try sysctl for kernel info.

print("=== PROBE 83c: NATIVE FCALL TEST ===")

-- First check what native.fcall expects
print("--- FCALL INFO ---")
print("type=" .. type(native.fcall))
print("fcall_with_rax type=" .. type(native.fcall_with_rax))

-- Check native.gen_fcall_chain
print("gen_fcall_chain type=" .. type(native.gen_fcall_chain))

-- Try getting libkernel function addresses via dynlib
print("")
print("--- RESOLVE FUNCTIONS ---")

-- Use the pivot to call getpid natively
-- fcall.arg_addr has: fn_addr, syscall_no, rdi, rsi, rdx, rcx, r8, r9
-- The chain should: write fn_addr -> call -> return value

-- First, let's understand what native.fcall actually does
-- It's a Lua function, so it takes Lua arguments
-- Let's try calling it with the getpid syscall number

print("")
print("--- TEST 1: native.fcall getpid ---")
local ok1, ret1 = pcall(function()
    -- Try calling getpid (20) through native.fcall
    return native.fcall(20)
end)
print("ok=" .. tostring(ok1) .. " ret=" .. tostring(ret1))

print("")
print("--- TEST 2: native.fcall with args ---")
local ok2, ret2 = pcall(function()
    return native.fcall(20, 0, 0, 0, 0, 0, 0)
end)
print("ok=" .. tostring(ok2) .. " ret=" .. tostring(ret2))

-- Try using fcall as a callable object
print("")
print("--- TEST 3: fcall() direct ---")
local ok3, ret3 = pcall(function()
    -- Write syscall number to arg_addr.syscall_no
    memory.write_qword(fcall.arg_addr.syscall_no, uint64(20))
    -- Write fn_addr (0 = use syscall path?)
    memory.write_qword(fcall.arg_addr.fn_addr, uint64(0))
    -- Call the chain
    return fcall()
end)
print("ok=" .. tostring(ok3) .. " ret=" .. tostring(ret3))

-- Try native.fcall_with_rax
print("")
print("--- TEST 4: fcall_with_rax ---")
local ok4, ret4 = pcall(function()
    return native.fcall_with_rax(20)
end)
print("ok=" .. tostring(ok4) .. " ret=" .. tostring(ret4))

-- Check what get_lua_opt does
print("")
print("--- GET_LUA_OPT ---")
local ok5, ret5 = pcall(function()
    return native.get_lua_opt("debug")
end)
print("lua_opt debug ok=" .. tostring(ok5) .. " ret=" .. tostring(ret5))

local ok6, ret6 = pcall(function()
    return native.get_lua_opt("fw_version")
end)
print("lua_opt fw ok=" .. tostring(ok6) .. " ret=" .. tostring(ret6))

local ok7, ret7 = pcall(function()
    return native.get_lua_opt("kernel_base")
end)
print("lua_opt kbase ok=" .. tostring(ok7) .. " ret=" .. tostring(ret7))

-- Try reading the retval after a call
print("")
print("--- RETVAL ---")
if fcall.chain and fcall.chain.retval_addr then
    local rv = memory.read_qword(fcall.chain.retval_addr)
    print("retval=" .. tostring(rv))
end

-- Check native.register
print("")
print("--- NATIVE.REGISTER ---")
local ok8, ret8 = pcall(function()
    return native.register("test_cmd", function() return 42 end)
end)
print("register ok=" .. tostring(ok8) .. " ret=" .. tostring(ret8))

-- Try creating a new fcall chain for our own use
print("")
print("--- NEW FCALL ---")
local ok9, ret9 = pcall(function()
    local new_fc = fcall.new()
    print("new_fcall type=" .. type(new_fc))
    if new_fc then
        for k, v in pairs(new_fc) do
            print("NF:" .. tostring(k) .. "=" .. tostring(v))
        end
    end
    return new_fc
end)
print("new_fcall ok=" .. tostring(ok9))
if not ok9 then print("err=" .. tostring(ret9)) end

print("=== PROBE 83c COMPLETE ===")
