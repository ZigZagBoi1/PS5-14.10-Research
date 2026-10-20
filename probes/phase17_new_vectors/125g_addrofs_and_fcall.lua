-- CRASH_CLASS: LOW (no fcall in this probe)
-- PROBE 125g: Dump eboot_addrofs, libc_addrofs, and other resolved addresses
-- These contain the real C function addresses needed for native.fcall

print("=== PROBE 125g: ADDROFS DUMP ===")
print("pid=" .. tostring(syscall.getpid()))

-- Dump eboot_addrofs
print("")
print("--- EBOOT_ADDROFS ---")
if eboot_addrofs then
    local keys = {}
    for k, v in pairs(eboot_addrofs) do keys[#keys+1] = k end
    table.sort(keys)
    for _, k in ipairs(keys) do
        print(string.format("  %s = %s", k, tostring(eboot_addrofs[k])))
    end
else
    print("NOT FOUND")
end

-- Dump libc_addrofs
print("")
print("--- LIBC_ADDROFS ---")
if libc_addrofs then
    local keys = {}
    for k, v in pairs(libc_addrofs) do keys[#keys+1] = k end
    table.sort(keys)
    for _, k in ipairs(keys) do
        print(string.format("  %s = %s", k, tostring(libc_addrofs[k])))
    end
else
    print("NOT FOUND")
end

-- Dump gadgets.stack_pivot
print("")
print("--- STACK PIVOT ---")
if gadgets and gadgets.stack_pivot then
    for i, sp in ipairs(gadgets.stack_pivot) do
        print(string.format("  [%d]:", i))
        if type(sp) == "table" then
            for k, v in pairs(sp) do
                print(string.format("    %s = %s", tostring(k), tostring(v)))
            end
        end
    end
end

-- Check for sceKernelGetProcParam or similar kernel-related functions
print("")
print("--- KEY GLOBALS ---")
local check = {
    "game_name", "libc_base", "libkernel_base", "eboot_base",
    "eboot_addrofs", "libc_addrofs", "gadgets",
    "fcall", "map_fixed_address", "ropchain",
    "create_pipe", "PAGE_SIZE", "libc_pivot",
    "initialize_kernel_rw", "trigger_exploit",
    "sceKernelGetProcParam", "sceKernelDlsym"
}
for _, name in ipairs(check) do
    local val = _G[name]
    if val ~= nil then
        local extra = ""
        if type(val) == "number" then
            extra = string.format(" (0x%x)", val)
        end
        print(string.format("  %s = %s%s", name, tostring(val), extra))
    end
end

-- Check if there's an initialize_kernel_rw function
print("")
print("--- INIT KERNEL RW ---")
if initialize_kernel_rw then
    local di = debug.getinfo(initialize_kernel_rw, "SLnu")
    print("src=" .. tostring(di.source) .. " line=" .. di.linedefined .. "-" .. di.lastlinedefined)
end

-- List all Lua source files loaded
print("")
print("--- LOADED FILES ---")
local seen = {}
for k, v in pairs(_G) do
    if type(v) == "function" then
        local di = debug.getinfo(v, "S")
        if di.source and di.source:sub(1,1) == "@" and not seen[di.source] then
            seen[di.source] = true
            print("  " .. di.source)
        end
    end
    if type(v) == "table" and k ~= "_G" and k ~= "package" then
        for k2, v2 in pairs(v) do
            if type(v2) == "function" then
                local di = debug.getinfo(v2, "S")
                if di.source and di.source:sub(1,1) == "@" and not seen[di.source] then
                    seen[di.source] = true
                    print("  " .. di.source)
                end
            end
        end
    end
end

print("=== PROBE 125g COMPLETE ===")
