-- CRASH_CLASS: LOW
-- PROBE 83e: Check pivot handler prerequisites
-- setup_pivot_handler needs: fcall, libc_addrofs, map_fixed_address, ropchain
-- Check if all prerequisites are available

print("=== PROBE 83e: PIVOT PREREQS ===")

-- Check libc_addrofs (needed by setup_pivot_handler)
print("--- LIBC_ADDROFS ---")
if gadget_table and gadget_table.c and gadget_table.c.libc_addrofs then
    local la = gadget_table.c.libc_addrofs
    local count = 0
    for k, v in pairs(la) do
        count = count + 1
        if count <= 40 then
            print("LA:" .. tostring(k) .. "=" .. tostring(v))
        end
    end
    print("total=" .. count)
else
    print("NOT FOUND in gadget_table.c")
end

-- Check hamidashi_creative libc_addrofs
print("")
print("--- HAMIDASHI LIBC_ADDROFS ---")
if gadget_table and gadget_table.hamidashi_creative then
    local hc = gadget_table.hamidashi_creative
    if hc.libc_addrofs then
        local count = 0
        for k, v in pairs(hc.libc_addrofs) do
            count = count + 1
            if count <= 40 then
                print("HLA:" .. tostring(k) .. "=" .. tostring(v))
            end
        end
        print("total=" .. count)
    end
    if hc.eboot_addrofs then
        local count = 0
        for k, v in pairs(hc.eboot_addrofs) do
            count = count + 1
            if count <= 40 then
                print("HEA:" .. tostring(k) .. "=" .. tostring(v))
            end
        end
        print("total=" .. count)
    end
    if hc.gadgets then
        local count = 0
        for k, v in pairs(hc.gadgets) do
            count = count + 1
            if count <= 40 then
                print("HGD:" .. tostring(k) .. "=" .. tostring(v))
            end
        end
        print("total=" .. count)
    end
end

-- Check eboot_addrofs
print("")
print("--- EBOOT_ADDROFS ---")
if gadget_table and gadget_table.c and gadget_table.c.eboot_addrofs then
    local ea = gadget_table.c.eboot_addrofs
    local count = 0
    for k, v in pairs(ea) do
        count = count + 1
        if count <= 40 then
            print("EA:" .. tostring(k) .. "=" .. tostring(v))
        end
    end
    print("total=" .. count)
end

-- Check map_fixed_address
print("")
print("--- MAP_FIXED_ADDRESS ---")
print("map_fixed_address=" .. tostring(map_fixed_address))
if type(map_fixed_address) == "function" then
    local ok, src = pcall(string.dump, map_fixed_address)
    print("lua=" .. tostring(ok) .. " len=" .. (ok and #src or 0))
end

-- Check native_invoke
print("")
print("--- NATIVE_INVOKE ---")
print("native_invoke=" .. tostring(native_invoke))
if type(native_invoke) == "function" then
    local is_lua = pcall(string.dump, native_invoke)
    print("lua=" .. tostring(is_lua))
end

-- Check if fcall is working (just read state, don't call)
print("")
print("--- FCALL STATE ---")
if fcall and fcall.chain then
    print("finalized=" .. tostring(fcall.chain.finalized))
    print("stack_base=" .. tostring(fcall.chain.stack_base))
    print("stack_size=" .. tostring(fcall.chain.stack_size))
    print("jmpbuf=" .. tostring(fcall.chain.jmpbuf))
    if fcall.chain.fcall_stub then
        for k, v in pairs(fcall.chain.fcall_stub) do
            print("stub." .. tostring(k) .. "=" .. tostring(v))
        end
    end
end

-- Check native.get_lua_opt (non-crashing)
print("")
print("--- LUA OPTS ---")
local opts = {"debug", "fw_version", "kernel_base", "game_name", "platform",
    "eboot_base", "libkernel_base", "libc_base", "pivot_base"}
for _, name in ipairs(opts) do
    local ok, val = pcall(function()
        return native.get_lua_opt(name)
    end)
    if ok then
        print("opt." .. name .. "=" .. tostring(val))
    end
end

-- Check storage table
print("")
print("--- STORAGE ---")
if storage then
    print("storage type=" .. type(storage))
    if type(storage) == "table" then
        for k, v in pairs(storage) do
            print("S:" .. tostring(k) .. " " .. type(v) .. "=" .. tostring(v))
        end
    end
end

-- Check resolve_value
print("")
print("resolve_value=" .. tostring(resolve_value))

-- Check if there's a way to get the game gadget set activated
print("")
print("--- GAME NAME ---")
if game_name then print("game_name=" .. tostring(game_name)) end
if GAME_NAME then print("GAME_NAME=" .. tostring(GAME_NAME)) end

print("=== PROBE 83e COMPLETE ===")
