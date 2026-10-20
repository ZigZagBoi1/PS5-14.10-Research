-- CRASH_CLASS: MODERATE
-- PROBE 83g: Try calling native_invoke directly to trigger fcall chain
-- The fcall chain is finalized with fn_addr=Mtx_init. Can we trigger it?
-- Also try: fcall:__call() which may be the intended interface

print("=== PROBE 83g: DIRECT INVOKE ===")

-- First dump what __call does
print("--- FCALL __CALL ---")
if fcall and fcall.__call then
    local ok, src = pcall(string.dump, fcall.__call)
    if ok then
        local strs = {}
        local i = 1
        while i <= #src do
            local s = ""
            while i <= #src and src:byte(i) >= 32 and src:byte(i) <= 126 do
                s = s .. src:sub(i, i)
                i = i + 1
            end
            if #s >= 3 then strs[#strs+1] = s end
            i = i + 1
        end
        print("strings:")
        for _, s in ipairs(strs) do print("  " .. s) end
    end
end

-- Try writing getpid syscall number and calling
-- First save current fn_addr
print("")
print("--- SETUP GETPID ---")
local saved_fn = memory.read_qword(fcall.arg_addr.fn_addr)
local saved_sn = memory.read_qword(fcall.arg_addr.syscall_no)
print("saved_fn=" .. tostring(saved_fn))
print("saved_sn=" .. tostring(saved_sn))

-- Write getpid syscall (20) - BUT we need to know if fcall uses fn_addr or syscall_no
-- From bytecode: native.fcall calls native_invoke(native_cmd_handler, "fcall")
-- native.fcall_with_rax references: fn_addr, native_invoke, native_cmd_handler, native_cmd, fcall

-- Let's try the simplest approach: call fcall() as a callable
print("")
print("--- TEST: fcall() ---")
local ok1, ret1 = pcall(function()
    -- Set fn_addr to getpid (need to know the address)
    -- Actually, let's just call with current Mtx_init and see what happens
    return fcall()
end)
print("ok=" .. tostring(ok1) .. " ret=" .. tostring(ret1))

-- Check retval
if fcall.chain and fcall.chain.retval_addr then
    local ok, rv = pcall(function() return memory.read_qword(fcall.chain.retval_addr) end)
    if ok then print("retval=" .. tostring(rv)) end
end

-- Restore
pcall(function()
    memory.write_qword(fcall.arg_addr.fn_addr, saved_fn)
    memory.write_qword(fcall.arg_addr.syscall_no, saved_sn)
end)

print("=== PROBE 83g COMPLETE ===")
