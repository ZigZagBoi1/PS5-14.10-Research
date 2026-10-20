-- CRASH_CLASS: MODERATE
-- PROBE 83a: Initialize native pivot handler then kernel offsets
-- 82b showed: initialize_kernel_offsets fails because native.pivot_handler_rop.read_buffer is nil
-- The pivot handler needs setup first. Sequence: setup_pivot_handler -> setup_cmd_handler -> initialize_kernel_offsets

print("=== PROBE 83a: PIVOT INIT SEQUENCE ===")

-- Check current pivot state
print("--- PIVOT STATE ---")
if native and native.pivot_handler_rop then
    local p = native.pivot_handler_rop
    for k, v in pairs(p) do
        local t = type(v)
        if t == "table" then
            local n = 0
            for _ in pairs(v) do n = n + 1 end
            print("PHR:" .. tostring(k) .. " table keys=" .. n)
        elseif t == "number" then
            print("PHR:" .. tostring(k) .. "=" .. string.format("0x%X", v))
        else
            print("PHR:" .. tostring(k) .. " " .. t .. "=" .. tostring(v))
        end
    end
end

-- Check if setup_pivot_handler needs args
print("")
print("--- SETUP FUNCTIONS ---")
if native.setup_pivot_handler then
    local ok, src = pcall(string.dump, native.setup_pivot_handler)
    print("setup_pivot_handler lua=" .. tostring(ok) .. " len=" .. (ok and #src or 0))
end
if native.setup_cmd_handler then
    local ok, src = pcall(string.dump, native.setup_cmd_handler)
    print("setup_cmd_handler lua=" .. tostring(ok) .. " len=" .. (ok and #src or 0))
end
if native.create_cmd_handler then
    local ok, src = pcall(string.dump, native.create_cmd_handler)
    print("create_cmd_handler lua=" .. tostring(ok) .. " len=" .. (ok and #src or 0))
end

-- Dump fcall.chain and fcall.arg_addr
print("")
print("--- FCALL CHAIN ---")
if fcall and fcall.chain then
    for k, v in pairs(fcall.chain) do
        print("CHAIN:" .. tostring(k) .. "=" .. tostring(v))
    end
end
if fcall and fcall.arg_addr then
    for k, v in pairs(fcall.arg_addr) do
        print("ARG:" .. tostring(k) .. "=" .. tostring(v))
    end
end

-- Check the game-specific gadget table
print("")
print("--- GAME GADGET TABLE ---")
if gadget_table and gadget_table.hamidashi_creative then
    local gt = gadget_table.hamidashi_creative
    local count = 0
    for k, v in pairs(gt) do
        count = count + 1
        if count <= 40 then
            print("HG:" .. tostring(k) .. "=" .. tostring(v))
        end
    end
    print("hamidashi_total=" .. count)
end

-- Try the initialization sequence
print("")
print("--- INIT SEQUENCE ---")

-- Step 1: Try setup_pivot_handler
print("step1: setup_pivot_handler")
local ok1, err1 = pcall(function()
    native.setup_pivot_handler()
end)
print("pivot_ok=" .. tostring(ok1))
if not ok1 then print("pivot_err=" .. tostring(err1)) end

-- Check if read_buffer is now available
if ok1 and native.pivot_handler_rop then
    print("post_pivot read_buffer=" .. tostring(native.pivot_handler_rop.read_buffer))
    print("post_pivot write_buffer=" .. tostring(native.pivot_handler_rop.write_buffer))
    for k, v in pairs(native.pivot_handler_rop) do
        if type(v) ~= "table" then
            print("PP:" .. tostring(k) .. "=" .. tostring(v))
        end
    end
end

-- Step 2: Try setup_cmd_handler
print("")
print("step2: setup_cmd_handler")
local ok2, err2 = pcall(function()
    native.setup_cmd_handler()
end)
print("cmd_ok=" .. tostring(ok2))
if not ok2 then print("cmd_err=" .. tostring(err2)) end

-- Step 3: Try initialize_kernel_offsets again
print("")
print("step3: initialize_kernel_offsets")
local ok3, err3 = pcall(function()
    initialize_kernel_offsets()
end)
print("offsets_ok=" .. tostring(ok3))
if not ok3 then print("offsets_err=" .. tostring(err3)) end

-- Step 4: Try initialize_kernel_rw again
print("")
print("step4: initialize_kernel_rw")
local ok4, err4 = pcall(function()
    initialize_kernel_rw()
end)
print("krw_ok=" .. tostring(ok4))
if not ok4 then print("krw_err=" .. tostring(err4)) end

-- Final check
print("")
print("--- FINAL STATUS ---")
if is_kernel_rw_available then
    local ok, val = pcall(is_kernel_rw_available)
    print("krw_available=" .. tostring(ok) .. " val=" .. tostring(val))
end
if check_kernel_rw then
    local ok, val = pcall(check_kernel_rw)
    print("check_krw=" .. tostring(ok) .. " val=" .. tostring(val))
end
if check_jailbroken then
    local ok, val = pcall(check_jailbroken)
    print("jailbroken=" .. tostring(ok) .. " val=" .. tostring(val))
end

-- Check kernel.addr after init
print("")
print("--- KERNEL ADDR ---")
if kernel and kernel.addr then
    for k, v in pairs(kernel.addr) do
        print("KA:" .. tostring(k) .. "=" .. tostring(v))
    end
end

-- Try reading kernel base if available
if kernel and kernel.read_qword then
    print("")
    print("--- KERNEL READ TEST ---")
    local ok5, val = pcall(function()
        return kernel.read_qword(uint64(0xFFFF800000000000))
    end)
    print("kread_test=" .. tostring(ok5) .. " val=" .. tostring(val))
end

-- Dump ps5_kernel_offset_list properly (it uses table keys)
print("")
print("--- PS5 OFFSET LIST DETAIL ---")
if ps5_kernel_offset_list then
    local idx = 0
    for k, v in pairs(ps5_kernel_offset_list) do
        idx = idx + 1
        if idx <= 15 then
            print("OL" .. idx .. ":")
            if type(k) == "table" then
                for k2, v2 in pairs(k) do
                    print("  K:" .. tostring(k2) .. "=" .. tostring(v2))
                end
            end
            if type(v) == "table" then
                for k2, v2 in pairs(v) do
                    print("  V:" .. tostring(k2) .. "=" .. tostring(v2))
                end
            end
        end
    end
end

print("=== PROBE 83a COMPLETE ===")
