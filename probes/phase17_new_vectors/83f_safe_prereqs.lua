-- CRASH_CLASS: LOW
-- PROBE 83f: Check prerequisites with ONLY table reads, NO function calls

print("=== PROBE 83f: SAFE PREREQS ===")

-- Dump gadget_table.c.libc_addrofs
print("--- C.LIBC_ADDROFS ---")
if gadget_table and gadget_table.c and gadget_table.c.libc_addrofs then
    for k, v in pairs(gadget_table.c.libc_addrofs) do
        print("CLA:" .. tostring(k) .. "=" .. tostring(v))
    end
end

-- Dump gadget_table.c.eboot_addrofs
print("")
print("--- C.EBOOT_ADDROFS ---")
if gadget_table and gadget_table.c and gadget_table.c.eboot_addrofs then
    for k, v in pairs(gadget_table.c.eboot_addrofs) do
        print("CEA:" .. tostring(k) .. "=" .. tostring(v))
    end
end

-- Dump gadget_table.c.gadgets
print("")
print("--- C.GADGETS ---")
if gadget_table and gadget_table.c and gadget_table.c.gadgets then
    for k, v in pairs(gadget_table.c.gadgets) do
        print("CGD:" .. tostring(k) .. "=" .. tostring(v))
    end
end

-- Check hamidashi libc_addrofs
print("")
print("--- HC.LIBC_ADDROFS ---")
if gadget_table and gadget_table.hamidashi_creative and gadget_table.hamidashi_creative.libc_addrofs then
    for k, v in pairs(gadget_table.hamidashi_creative.libc_addrofs) do
        print("HLA:" .. tostring(k) .. "=" .. tostring(v))
    end
end

-- Check globals
print("")
print("--- GLOBALS ---")
print("map_fixed_address=" .. tostring(map_fixed_address))
print("native_invoke=" .. tostring(native_invoke))
print("resolve_value=" .. tostring(resolve_value))
print("game_name=" .. tostring(game_name))
print("GAME_NAME=" .. tostring(GAME_NAME))
print("storage=" .. tostring(storage))
print("native_cmd_handler=" .. tostring(native_cmd_handler))

-- Check storage table
if type(storage) == "table" then
    print("")
    print("--- STORAGE ---")
    for k, v in pairs(storage) do
        print("S:" .. tostring(k) .. " " .. type(v))
    end
end

-- Check if fcall_stub has actual addresses
print("")
print("--- FCALL STUB MEMORY ---")
if fcall and fcall.chain and fcall.chain.fcall_stub then
    local stub = fcall.chain.fcall_stub
    print("fn_addr=" .. tostring(stub.fn_addr))
    print("return_addr=" .. tostring(stub.return_addr))
    -- Read the actual values at these addresses
    if stub.fn_addr then
        local ok, v = pcall(function() return memory.read_qword(stub.fn_addr) end)
        if ok then print("*fn_addr=" .. tostring(v)) end
    end
    if stub.return_addr then
        local ok, v = pcall(function() return memory.read_qword(stub.return_addr) end)
        if ok then print("*return_addr=" .. tostring(v)) end
    end
end

-- Read what's at the arg addresses
print("")
print("--- ARG ADDR VALUES ---")
if fcall and fcall.arg_addr then
    for k, v in pairs(fcall.arg_addr) do
        local ok, val = pcall(function() return memory.read_qword(v) end)
        if ok then
            print("*" .. tostring(k) .. "=" .. tostring(val))
        end
    end
end

print("=== PROBE 83f COMPLETE ===")
