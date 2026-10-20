-- CRASH_CLASS: MODERATE
-- PROBE 82b: Explore kernel R/W initialization path
-- 81a revealed: kernel table, ipv6_kernel_rw, initialize_kernel_rw,
-- initialize_kernel_offsets, find_proc_by_pid, etc.

print("=== PROBE 82b: KERNEL RW INIT ===")

-- Check if kernel R/W is already available
print("--- KERNEL RW STATUS ---")
if is_kernel_rw_available then
    local ok, avail = pcall(is_kernel_rw_available)
    print("is_kernel_rw_available=" .. tostring(ok) .. " val=" .. tostring(avail))
end
if check_kernel_rw then
    local ok, result = pcall(check_kernel_rw)
    print("check_kernel_rw=" .. tostring(ok) .. " val=" .. tostring(result))
end
if is_jailbroken then
    local ok, result = pcall(is_jailbroken)
    print("is_jailbroken=" .. tostring(ok) .. " val=" .. tostring(result))
end

-- Dump kernel table
print("")
print("--- KERNEL TABLE ---")
if type(kernel) == "table" then
    for k, v in pairs(kernel) do
        local t = type(v)
        local extra = ""
        if t == "function" then
            local is_lua = pcall(string.dump, v)
            extra = is_lua and " lua" or " C"
        elseif t == "table" then
            local n = 0
            for k2, v2 in pairs(v) do
                n = n + 1
                if n <= 5 then extra = extra .. " " .. tostring(k2) .. "=" .. tostring(v2) end
            end
            extra = " keys=" .. n .. extra
        elseif t == "number" then
            extra = " val=" .. tostring(v)
        elseif t == "string" then
            extra = " val=" .. v:sub(1, 60)
        end
        print("K:" .. tostring(k) .. " " .. t .. extra)
    end
end

-- Dump ipv6_kernel_rw table
print("")
print("--- IPV6_KERNEL_RW TABLE ---")
if type(ipv6_kernel_rw) == "table" then
    for k, v in pairs(ipv6_kernel_rw) do
        local t = type(v)
        local extra = ""
        if t == "function" then
            local is_lua = pcall(string.dump, v)
            extra = is_lua and " lua" or " C"
        elseif t == "table" then
            local n = 0
            for _ in pairs(v) do n = n + 1 end
            extra = " keys=" .. n
        elseif t == "number" then
            extra = " val=" .. tostring(v)
        end
        print("I6:" .. tostring(k) .. " " .. t .. extra)
    end
end

-- Dump fcall table
print("")
print("--- FCALL TABLE ---")
if type(fcall) == "table" then
    for k, v in pairs(fcall) do
        local t = type(v)
        local extra = ""
        if t == "function" then
            local is_lua = pcall(string.dump, v)
            extra = is_lua and " lua" or " C"
        elseif t == "table" then
            local n = 0
            for _ in pairs(v) do n = n + 1 end
            extra = " keys=" .. n
        end
        print("FC:" .. tostring(k) .. " " .. t .. extra)
    end
end

-- Dump thread table
print("")
print("--- THREAD TABLE ---")
if type(thread) == "table" then
    for k, v in pairs(thread) do
        local t = type(v)
        local extra = ""
        if t == "function" then
            local is_lua = pcall(string.dump, v)
            extra = is_lua and " lua" or " C"
        end
        print("TH:" .. tostring(k) .. " " .. t .. extra)
    end
end

-- Dump gadgets table
print("")
print("--- GADGETS TABLE ---")
if type(gadgets) == "table" then
    for k, v in pairs(gadgets) do
        print("GAD:" .. tostring(k) .. "=" .. tostring(v))
    end
end

-- Dump gadget_table
print("")
print("--- GADGET_TABLE ---")
if type(gadget_table) == "table" then
    for k, v in pairs(gadget_table) do
        print("GT:" .. tostring(k) .. "=" .. tostring(v))
    end
end

-- Check kernel_offset table
print("")
print("--- KERNEL_OFFSET TABLE ---")
if type(kernel_offset) == "table" then
    for k, v in pairs(kernel_offset) do
        print("KO:" .. tostring(k) .. "=" .. tostring(v))
    end
end

-- Check ps5_kernel_offset_list
print("")
print("--- PS5_KERNEL_OFFSET_LIST ---")
if type(ps5_kernel_offset_list) == "table" then
    for k, v in pairs(ps5_kernel_offset_list) do
        print("P5KO:" .. tostring(k) .. "=" .. tostring(v))
    end
end

-- Dump native table details
print("")
print("--- NATIVE TABLE ---")
if type(native) == "table" then
    for k, v in pairs(native) do
        local t = type(v)
        local extra = ""
        if t == "function" then
            local is_lua = pcall(string.dump, v)
            extra = is_lua and " lua" or " C"
        elseif t == "table" then
            local n = 0
            for k2, v2 in pairs(v) do
                n = n + 1
                if n <= 8 then extra = extra .. " " .. tostring(k2) .. "=" .. tostring(v2) end
            end
            extra = " keys=" .. n .. extra
        elseif t == "number" then
            extra = " val=" .. string.format("0x%X", v)
        end
        print("N:" .. tostring(k) .. " " .. t .. extra)
    end
end

-- Check native_cmd_handler
print("")
print("native_cmd_handler=" .. tostring(native_cmd_handler))
if type(native_cmd_handler) == "number" then
    print("native_cmd_handler_hex=" .. string.format("0x%X", native_cmd_handler))
end

-- Check ropchain table keys
print("")
print("--- ROPCHAIN TABLE (keys only) ---")
if type(ropchain) == "table" then
    local keys = {}
    for k, _ in pairs(ropchain) do keys[#keys+1] = tostring(k) end
    table.sort(keys)
    for _, k in ipairs(keys) do
        print("RC:" .. k)
    end
end

-- Check FW_VERSION and PLATFORM
print("")
print("FW_VERSION=" .. tostring(FW_VERSION))
print("PLATFORM=" .. tostring(PLATFORM))
print("PAGE_SIZE=" .. tostring(PAGE_SIZE))
print("PHYS_PAGE_SIZE=" .. tostring(PHYS_PAGE_SIZE))

-- Check eboot_base and libkernel_base
print("")
print("eboot_base=" .. tostring(eboot_base))
if type(eboot_base) == "table" then
    for k, v in pairs(eboot_base) do print("  " .. k .. "=" .. tostring(v)) end
end
print("libkernel_base=" .. tostring(libkernel_base))
if type(libkernel_base) == "table" then
    for k, v in pairs(libkernel_base) do print("  " .. k .. "=" .. tostring(v)) end
end
print("libc_base=" .. tostring(libc_base))
if type(libc_base) == "table" then
    for k, v in pairs(libc_base) do print("  " .. k .. "=" .. tostring(v)) end
end

-- Try calling initialize_kernel_rw to see what it does
print("")
print("--- TRYING INITIALIZE_KERNEL_RW ---")
local ok, err = pcall(function()
    if initialize_kernel_offsets then
        print("calling initialize_kernel_offsets...")
        initialize_kernel_offsets()
        print("initialize_kernel_offsets OK")
    end
end)
if not ok then print("initialize_kernel_offsets err=" .. tostring(err)) end

local ok2, err2 = pcall(function()
    if initialize_kernel_rw then
        print("calling initialize_kernel_rw...")
        initialize_kernel_rw()
        print("initialize_kernel_rw OK")
    end
end)
if not ok2 then print("initialize_kernel_rw err=" .. tostring(err2)) end

-- Check if kernel R/W is now available
if is_kernel_rw_available then
    local ok3, avail = pcall(is_kernel_rw_available)
    print("post_init is_kernel_rw_available=" .. tostring(ok3) .. " val=" .. tostring(avail))
end

-- If kernel R/W works, try reading kernel base
if check_kernel_rw then
    local ok4, result = pcall(check_kernel_rw)
    print("post_init check_kernel_rw=" .. tostring(ok4) .. " val=" .. tostring(result))
end

print("=== PROBE 82b COMPLETE ===")
