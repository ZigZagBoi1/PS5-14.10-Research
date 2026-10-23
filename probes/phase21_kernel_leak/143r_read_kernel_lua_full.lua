-- CRASH_CLASS: LOW
-- PROBE 143r: Read full kernel.lua from loader
--
-- Context: Need to understand ipv6_kernel_rw implementation

print("=== PROBE 143r: READ KERNEL.LUA ===")
print("")

local f = io.open("/savedata0/kernel.lua", "r")
if f then
    local c = f:read("*all")
    f:close()
    print("[*] kernel.lua size=" .. #c)
    print("")
    print("--- BEGIN kernel.lua ---")
    local pos = 1
    while pos <= #c do
        local nl = c:find("\n", pos)
        if nl then
            print(c:sub(pos, nl - 1))
            pos = nl + 1
        else
            print(c:sub(pos))
            break
        end
    end
    print("--- END kernel.lua ---")
else
    print("[!] Failed to open /savedata0/kernel.lua")
end

print("")
print("=== PROBE 143r COMPLETE ===")
