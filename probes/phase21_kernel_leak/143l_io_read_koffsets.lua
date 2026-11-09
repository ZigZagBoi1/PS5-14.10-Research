-- CRASH_CLASS: LOW
-- PROBE 143l: Read kernel_offset.lua + offsets.lua via io.open
-- Also try native_invoke with uint64 args (previous crash was arg format)

print("=== PROBE 143l: IO READ + NATIVE TEST ===")

--------------------------------------------------------------------
-- [A] Read kernel_offset.lua — find entries for 6.00+
--------------------------------------------------------------------
print("--- [A] kernel_offset.lua versions 6.00+ ---")

local f = io.open("/savedata0/kernel_offset.lua", "r")
if f then
    local content = f:read("*all")
    f:close()
    print("[A] size=" .. #content)

    -- Find all version blocks from 6.00 onward
    local in_block = false
    local block_text = ""
    for line in content:gmatch("[^\n]+") do
        if line:match('%[{%s*"') then
            -- Check if this line has versions >= 6
            local ver = line:match('"(%d+%.%d+)"')
            if ver then
                local major = tonumber(ver:match("^(%d+)"))
                if major and major >= 6 then
                    in_block = true
                    block_text = ""
                end
            end
        end

        if in_block then
            print(line)
            if line:match("^%s*},?%s*$") and not line:match("DATA_") then
                in_block = false
                print("")
            end
        end
    end
else
    print("[A] io.open failed")
end

--------------------------------------------------------------------
-- [B] Read offsets.lua — game-specific addresses
--------------------------------------------------------------------
print("")
print("--- [B] offsets.lua ---")

f = io.open("/savedata0/offsets.lua", "r")
if f then
    local content = f:read("*all")
    f:close()
    print("[B] size=" .. #content)

    -- Print the first 6000 chars
    local pos = 1
    while pos <= #content and pos <= 6000 do
        local nl = content:find("\n", pos) or math.min(pos + 200, #content + 1)
        print(content:sub(pos, nl - 1))
        pos = nl + 1
    end
    if #content > 6000 then
        print("... (truncated " .. (#content - 6000) .. " bytes)")
    end
else
    print("[B] io.open failed")
end

--------------------------------------------------------------------
-- [C] List all files in /savedata0/ with sizes
--------------------------------------------------------------------
print("")
print("--- [C] savedata0 files ---")

local files = {
    "globals.lua", "offsets.lua", "misc.lua", "bit32.lua",
    "hash.lua", "uint64.lua", "struct.lua", "lua.lua",
    "memory.lua", "ropchain.lua", "syscall.lua", "signal.lua",
    "native.lua", "thread.lua", "kernel_offset.lua", "kernel.lua",
    "gpu.lua", "main.lua", "loader.lua", "init.lua",
    "exploit.lua", "config.lua", "constants.lua"
}

for _, name in ipairs(files) do
    local path = "/savedata0/" .. name
    local fh = io.open(path, "r")
    if fh then
        local size = 0
        local c = fh:read("*all")
        if c then size = #c end
        fh:close()
        print("[C] " .. name .. " = " .. size .. "B")
    end
end

--------------------------------------------------------------------
-- [D] Try native_invoke carefully with uint64 args
--------------------------------------------------------------------
print("")
print("--- [D] native_invoke test ---")

if native_invoke then
    -- Try the simplest possible call: just native_invoke with cmd=0 (read)
    -- reading 4 bytes from eboot_base (we know this works)
    print("[D] testing cmd=0 read_buffer...")
    local ok, result = pcall(function()
        return native_invoke(0, eboot_base, 4)
    end)
    if ok then
        if type(result) == "string" then
            local bytes = ""
            for i = 1, math.min(#result, 4) do
                bytes = bytes .. string.format("%02X ", string.byte(result, i))
            end
            print("[D] read OK: " .. bytes)
        else
            print("[D] read returned: " .. type(result) .. "=" .. tostring(result))
        end
    else
        print("[D] read FAIL: " .. tostring(result))
    end

    -- If read works, try fcall with getpid
    if ok then
        print("[D] testing cmd=2 fcall (getpid)...")
        local ok2, rv2 = pcall(function()
            return native_invoke(2, syscall.syscall_address, 20, 0, 0, 0, 0, 0, 0)
        end)
        if ok2 then
            print("[D] fcall getpid=" .. tostring(rv2))
        else
            print("[D] fcall FAIL: " .. tostring(rv2))
        end
    end
else
    print("[D] native_invoke nil")
end

--------------------------------------------------------------------
-- [E] Read thread.lua — threading primitives
--------------------------------------------------------------------
print("")
print("--- [E] thread.lua ---")

f = io.open("/savedata0/thread.lua", "r")
if f then
    local content = f:read("*all")
    f:close()
    print("[E] size=" .. #content)
    local pos = 1
    while pos <= #content and pos <= 4000 do
        local nl = content:find("\n", pos) or math.min(pos + 200, #content + 1)
        print(content:sub(pos, nl - 1))
        pos = nl + 1
    end
else
    print("[E] io.open failed")
end

print("")
print("=== DONE ===")
