-- CRASH_CLASS: MODERATE
-- PROBE 143n: Focused native_invoke testing
--
-- Context: 143k crashed on native_invoke(2,sc_addr,20), 143l output stopped
-- silently at cmd=0 test. Need to determine correct argument format.
-- native_invoke is the CClosure stack-pivot arbitrary function caller.
-- cmd=0: read_buffer(addr, size) → string
-- cmd=1: write_buffer(dest, data) → writes
-- cmd=2: fcall(fn, rax, rdi, rsi, rdx, rcx, r8, r9) → calls function

print("=== PROBE 143n: NATIVE_INVOKE FOCUSED ===")
print("")

--------------------------------------------------------------------
-- [A] Inspect native_invoke and fcall structure
--------------------------------------------------------------------
print("--- [A] Inspect types ---")
print("[A] native_invoke type=" .. type(native_invoke))
print("[A] fcall type=" .. type(fcall))

if type(fcall) == "table" then
    for k,v in pairs(fcall) do
        print("[A] fcall." .. tostring(k) .. " = " .. tostring(v) .. " (" .. type(v) .. ")")
    end
end

-- Check if syscall entries are callable
if syscall then
    print("[A] syscall.getpid type=" .. type(syscall.getpid))
    print("[A] syscall.getuid type=" .. type(syscall.getuid))
    if syscall.write then print("[A] syscall.write type=" .. type(syscall.write)) end
end

-- Print eboot_base and syscall_address
if eboot_base then print("[A] eboot_base=" .. hex(eboot_base)) end
if syscall and syscall.syscall_address then
    print("[A] syscall_address=" .. hex(syscall.syscall_address))
end
if libkernel_base then print("[A] libkernel_base=" .. hex(libkernel_base)) end

--------------------------------------------------------------------
-- [B] Try syscall.getpid directly (uses loader's fcall mechanism)
--------------------------------------------------------------------
print("")
print("--- [B] syscall.getpid() ---")
if syscall.getpid then
    local ok, rv = pcall(function() return syscall.getpid() end)
    if ok then
        print("[B] getpid=" .. tostring(rv))
        if type(rv) == "table" and rv.tonumber then
            print("[B] getpid num=" .. rv:tonumber())
        end
    else
        print("[B] getpid FAIL: " .. tostring(rv))
    end
else
    print("[B] syscall.getpid nil")
end

--------------------------------------------------------------------
-- [C] Try syscall.getuid directly
--------------------------------------------------------------------
print("")
print("--- [C] syscall.getuid() ---")
if syscall.getuid then
    local ok, rv = pcall(function() return syscall.getuid() end)
    if ok then
        print("[C] getuid=" .. tostring(rv))
        if type(rv) == "table" and rv.tonumber then
            print("[C] getuid num=" .. rv:tonumber())
        end
    else
        print("[C] getuid FAIL: " .. tostring(rv))
    end
else
    print("[C] syscall.getuid nil")
end

--------------------------------------------------------------------
-- [D] Try native_invoke cmd=0 with uint64 args
--------------------------------------------------------------------
print("")
print("--- [D] native_invoke cmd=0 read_buffer ---")
if native_invoke then
    -- First try with very small read from eboot_base
    print("[D] BEFORE native_invoke(0, eboot_base, 4)")
    local ok, rv = pcall(function()
        return native_invoke(0, eboot_base, 4)
    end)
    print("[D] AFTER pcall ok=" .. tostring(ok))
    if ok then
        print("[D] rv type=" .. type(rv))
        if type(rv) == "string" then
            local bytes = ""
            for i = 1, math.min(#rv, 16) do
                bytes = bytes .. string.format("%02X ", string.byte(rv, i))
            end
            print("[D] bytes=" .. bytes)
            print("[D] len=" .. #rv)
        elseif rv == nil then
            print("[D] rv=nil")
        else
            print("[D] rv=" .. tostring(rv))
        end
    else
        print("[D] FAIL: " .. tostring(rv))
    end
else
    print("[D] native_invoke nil")
end

--------------------------------------------------------------------
-- [E] Try native_invoke cmd=2 fcall with getpid
--------------------------------------------------------------------
print("")
print("--- [E] native_invoke cmd=2 fcall ---")
if native_invoke and syscall and syscall.syscall_address then
    -- Try getpid: native_invoke(2, sc_addr, 20)
    -- 20 goes in rax (syscall number)
    print("[E] BEFORE native_invoke(2, syscall_address, 20)")
    local ok, rv = pcall(function()
        return native_invoke(2, syscall.syscall_address, 20)
    end)
    print("[E] AFTER pcall ok=" .. tostring(ok))
    if ok then
        print("[E] getpid rv=" .. tostring(rv))
        if type(rv) == "table" and rv.tonumber then
            print("[E] num=" .. rv:tonumber())
        end
    else
        print("[E] FAIL: " .. tostring(rv))
    end
else
    print("[E] prereqs missing")
end

--------------------------------------------------------------------
-- [F] Try calling libc functions via native_invoke
--------------------------------------------------------------------
print("")
print("--- [F] libc function calls ---")
if native_invoke and libc_addrofs then
    -- getpid via libc wrapper
    if libc_addrofs.gettimeofday_import then
        print("[F] gettimeofday_import=" .. hex(libc_addrofs.gettimeofday_import))
    end

    -- Try calling strerror(0) to get "Unknown error"
    if libc_addrofs.strerror then
        print("[F] BEFORE strerror(0)")
        local ok, rv = pcall(function()
            return native_invoke(2, libc_addrofs.strerror, 0, 0)
        end)
        print("[F] AFTER strerror ok=" .. tostring(ok))
        if ok then
            print("[F] strerror rv=" .. tostring(rv))
        else
            print("[F] strerror FAIL: " .. tostring(rv))
        end
    end
end

--------------------------------------------------------------------
-- [G] Alternative: try fcall_with_rax if it exists
--------------------------------------------------------------------
print("")
print("--- [G] fcall_with_rax ---")

-- Check if the loader has fcall_with_rax
if type(fcall) == "table" then
    -- Try to call fcall as a function (maybe it has __call metamethods)
    print("[G] trying fcall(syscall_address, 20)()")
    local ok, rv = pcall(function()
        local caller = fcall(syscall.syscall_address, 20)
        print("[G] caller type=" .. type(caller))
        if type(caller) == "function" then
            return caller()
        elseif type(caller) == "table" then
            -- Check if it's callable
            local mt = getmetatable(caller)
            if mt and mt.__call then
                print("[G] caller has __call")
                return caller()
            else
                print("[G] caller not callable, keys:")
                for k,v in pairs(caller) do
                    print("[G]   " .. tostring(k) .. "=" .. tostring(v))
                end
                return nil
            end
        end
        return caller
    end)
    print("[G] ok=" .. tostring(ok) .. " rv=" .. tostring(rv))
end

--------------------------------------------------------------------
-- [H] Check what ropchain looks like
--------------------------------------------------------------------
print("")
print("--- [H] ropchain ---")
if ropchain then
    print("[H] ropchain type=" .. type(ropchain))
    if type(ropchain) == "table" then
        local count = 0
        for k,v in pairs(ropchain) do
            if count < 10 then
                print("[H] rc." .. tostring(k) .. " type=" .. type(v))
                count = count + 1
            end
        end
    end
end

-- Check native module
if native then
    print("[H] native type=" .. type(native))
    if type(native) == "table" then
        for k,v in pairs(native) do
            print("[H] nat." .. tostring(k) .. " type=" .. type(v))
        end
    end
end

print("")
print("=== PROBE 143n COMPLETE ===")
