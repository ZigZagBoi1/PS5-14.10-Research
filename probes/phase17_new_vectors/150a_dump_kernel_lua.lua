-- CRASH_CLASS: LOW
-- PROBE 150a: Dump kernel.lua source to understand initialize_kernel_rw
--
-- Context: The loader has a complete kernel exploit framework in /savedata0/kernel.lua
-- with ipv6_kread/kwrite, initialize_kernel_rw, etc. We need to read the source
-- to understand what kernel addresses it needs and how to bootstrap it.
-- Previous probes only dumped lua.lua, syscall.lua, gpu.lua - kernel.lua was missed.

print("=== PROBE 150a: DUMP KERNEL.LUA ===")

-- Read the file
local f = io.open("/savedata0/kernel.lua", "r")
if not f then
    print("ERROR: cannot open /savedata0/kernel.lua")
    -- Try alternate paths
    for _, path in ipairs({
        "/savedata0/kernel.lua",
        "kernel.lua",
        "/app0/savedata0/kernel.lua",
    }) do
        f = io.open(path, "r")
        if f then
            print("FOUND at: " .. path)
            break
        end
    end
end

if f then
    local content = f:read("*a")
    f:close()
    print("--- KERNEL.LUA (" .. #content .. " bytes) ---")
    -- Print in chunks to avoid output truncation
    local chunk_size = 4000
    for i = 1, #content, chunk_size do
        local chunk = content:sub(i, i + chunk_size - 1)
        print(chunk)
    end
    print("--- END KERNEL.LUA ---")
else
    print("ERROR: kernel.lua not found at any path")

    -- Fallback: use debug.getinfo to read function source lines
    print("")
    print("--- FALLBACK: FUNCTION INTROSPECTION ---")

    -- Try to get initialize_kernel_rw info
    if initialize_kernel_rw then
        local info = debug.getinfo(initialize_kernel_rw, "SLn")
        print("initialize_kernel_rw:")
        for k, v in pairs(info) do
            print("  " .. tostring(k) .. " = " .. tostring(v))
        end
    end

    -- Try kernel module functions
    if kernel then
        for k, v in pairs(kernel) do
            if type(v) == "function" then
                local info = debug.getinfo(v, "SLn")
                print(k .. ": " .. tostring(info.source) .. " lines " ..
                    tostring(info.linedefined) .. "-" .. tostring(info.lastlinedefined))
            end
        end
    end

    -- Try ipv6_kernel_rw
    if ipv6_kernel_rw then
        for k, v in pairs(ipv6_kernel_rw) do
            if type(v) == "function" then
                local info = debug.getinfo(v, "SLn")
                print("ipv6_kernel_rw." .. k .. ": " .. tostring(info.source) ..
                    " lines " .. tostring(info.linedefined) .. "-" .. tostring(info.lastlinedefined))
            end
        end
    end
end

-- Also dump native.lua and ropchain.lua if accessible
for _, fname in ipairs({"native.lua", "ropchain.lua", "kernel_offset.lua"}) do
    local f2 = io.open("/savedata0/" .. fname, "r")
    if f2 then
        local c = f2:read("*a")
        f2:close()
        print("")
        print("--- /savedata0/" .. fname .. " (" .. #c .. " bytes) ---")
        local chunk_size = 4000
        for i = 1, #c, chunk_size do
            print(c:sub(i, i + chunk_size - 1))
        end
        print("--- END " .. fname .. " ---")
    end
end

print("=== PROBE 150a COMPLETE ===")
